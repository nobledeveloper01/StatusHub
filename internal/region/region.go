// Package region is what a multi-region deployment needs to be operable.
//
// The topology itself is one line of policy (ADR-006): receivers everywhere,
// dispatchers in exactly one place. What that leaves is the part that decides
// whether an operator can act during an incident — knowing which region a
// metric came from, knowing how far behind the replica is before promoting
// it, and being stopped from running two dispatchers at once.
package region

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Role is what a region's deployment is allowed to do.
type Role string

const (
	// Primary runs everything: receiver, normaliser, dispatcher, API. Exactly
	// one region holds this at a time.
	Primary Role = "primary"

	// Edge runs receivers only. It writes to the primary's database across
	// the network, which is one round trip rather than a consensus protocol,
	// and is the whole reason the topology is shaped this way.
	Edge Role = "edge"
)

// Valid reports whether r is a known role.
func (r Role) Valid() bool { return r == Primary || r == Edge }

func (r Role) String() string { return string(r) }

// RunsDispatcher reports whether this region may dispatch.
//
// The check exists because the ordering guarantee is a database claim, and a
// claim only serialises against claimants reading the same rows under the
// same locks. Two regions dispatching is two sets of claimants, and the
// customer gets the same events twice, out of order.
func (r Role) RunsDispatcher() bool { return r == Primary }

// Config describes where this process is running.
type Config struct {
	// Name is the region, as the operator knows it — eu-west-1, af-south-1.
	// It labels every metric, so a regional problem shows up as one rather
	// than as a global degradation nobody can locate.
	Name string

	Role Role

	// WriteBudget is how long a receiver's single INSERT may take before it
	// is worth telling somebody.
	//
	// An edge region's write crosses the network, so the number is
	// necessarily larger than a same-region deployment's — but it is still
	// bounded, and exceeding it means providers are about to start retrying.
	WriteBudget time.Duration
}

// DefaultWriteBudget is the ceiling for a same-region write.
//
// 25 ms of the receiver's 50 ms. The rest is signature verification, JSON
// handling and the response itself, none of which is close to that — so a
// receiver that misses its SLO is almost always a receiver waiting on this.
const DefaultWriteBudget = 25 * time.Millisecond

// DefaultEdgeWriteBudget is the ceiling for a cross-region write.
//
// 120 ms, which is deliberately larger than the receiver's own 50 ms target.
// That is not a contradiction: the SLO is measured at the receiver, and an
// edge receiver that takes 120 ms to write has still saved the provider the
// 150 ms it would have spent reaching another continent. What the budget
// bounds is the point at which the arrangement stops paying for itself.
const DefaultEdgeWriteBudget = 120 * time.Millisecond

// Validate rejects a configuration that would produce a second dispatcher.
func (c Config) Validate() error {
	if strings.TrimSpace(c.Name) == "" {
		return errors.New("region name is required in a multi-region deployment: " +
			"without it every metric is unattributable and a regional problem looks global")
	}
	if !c.Role.Valid() {
		return fmt.Errorf("region role %q is not primary or edge", c.Role)
	}
	return nil
}

// Budget returns the write ceiling, defaulted by role.
func (c Config) Budget() time.Duration {
	if c.WriteBudget > 0 {
		return c.WriteBudget
	}
	if c.Role == Edge {
		return DefaultEdgeWriteBudget
	}
	return DefaultWriteBudget
}

// ReplicaState is what an operator needs before deciding to promote.
type ReplicaState struct {
	// IsReplica is false on the primary. Reported rather than assumed,
	// because "am I actually the replica" is the first thing to establish
	// when somebody is about to promote something.
	IsReplica bool `json:"is_replica"`

	// Lag is how far behind the primary this replica is, in time.
	//
	// Time rather than bytes: bytes are what Postgres reports most readily
	// and what nobody can reason about under pressure. "Four seconds behind"
	// answers the question an operator is actually asking, which is how much
	// they lose by promoting now.
	Lag time.Duration `json:"lag"`

	// LastReplayed is when the replica last applied a transaction. A replica
	// with low lag that has not applied anything in ten minutes is not
	// healthy — it is disconnected, and the lag figure is stale.
	LastReplayed time.Time `json:"last_replayed"`

	// Receiving is whether the WAL stream is live.
	Receiving bool `json:"receiving"`
}

// Assessment turns the numbers into the sentence somebody needs at 3am.
func (s ReplicaState) Assessment() string {
	switch {
	case !s.IsReplica:
		return "this is the primary, not a replica. Promoting it is not the operation you want."
	case !s.Receiving:
		return "the WAL stream is not connected. The lag figure below is stale and the true gap is " +
			"unknown — promoting now loses an unbounded amount. Establish why replication stopped first."
	case s.Lag > 5*time.Minute:
		return fmt.Sprintf("%s behind. Promoting now loses every event received in that window. "+
			"Those events are not recoverable: the provider will not resend.", s.Lag.Round(time.Second))
	case s.Lag > 30*time.Second:
		return fmt.Sprintf("%s behind. Promoting loses that window of events. Wait if the primary "+
			"might come back; promote if it will not.", s.Lag.Round(time.Second))
	default:
		return fmt.Sprintf("%s behind, stream healthy. Safe to promote if the primary is genuinely gone.",
			s.Lag.Round(time.Millisecond))
	}
}

// CheckReplica reads the replica's state.
//
// Works against a primary too, where it reports IsReplica false — which is
// the useful answer, because running this against the wrong host is exactly
// the mistake somebody makes under pressure.
func CheckReplica(ctx context.Context, pool *pgxpool.Pool) (ReplicaState, error) {
	var s ReplicaState

	if err := pool.QueryRow(ctx, `SELECT pg_is_in_recovery()`).Scan(&s.IsReplica); err != nil {
		return s, fmt.Errorf("asking whether this host is a replica: %w", err)
	}
	if !s.IsReplica {
		return s, nil
	}

	// COALESCE, because a replica that has applied everything reports NULL
	// for the timestamp difference rather than zero — and treating NULL as
	// "unknown" would report a fully caught-up replica as unassessable.
	var lagSeconds float64
	err := pool.QueryRow(ctx, `
		SELECT COALESCE(EXTRACT(EPOCH FROM (now() - pg_last_xact_replay_timestamp())), 0),
		       COALESCE(pg_last_xact_replay_timestamp(), now()),
		       EXISTS (SELECT 1 FROM pg_stat_wal_receiver)
	`).Scan(&lagSeconds, &s.LastReplayed, &s.Receiving)
	if err != nil {
		return s, fmt.Errorf("reading replication state: %w", err)
	}
	if lagSeconds < 0 {
		// Clock skew between the hosts. Reported as zero rather than
		// negative, because a negative lag is a number nobody can act on.
		lagSeconds = 0
	}
	s.Lag = time.Duration(lagSeconds * float64(time.Second))
	return s, nil
}

// GuardDispatcher refuses to start a dispatcher outside the primary region.
//
// A configuration mistake here does not fail loudly on its own: a second
// dispatcher works perfectly, claims its own rows, and delivers events the
// first one also delivered — out of order, to a customer whose state machine
// then corrupts. The failure surfaces days later as "your ordering guarantee
// does not work", which is the worst possible way to discover it.
func GuardDispatcher(c Config) error {
	if c.Role.RunsDispatcher() {
		return nil
	}
	return fmt.Errorf(
		"region %q has role %s, which must not run a dispatcher (ADR-006). "+
			"Ordering is enforced by a database claim, and a claim only serialises against claimants "+
			"reading the same rows — a second dispatching region delivers the same events twice, out of "+
			"order, and nothing errors while it happens — run --mode receiver here",
		c.Name, c.Role)
}
