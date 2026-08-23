package tests

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/nobledeveloper01/StatusHub/internal/region"
	"github.com/nobledeveloper01/StatusHub/internal/server"
)

// TestRegionRefusesASecondDispatcher is the assertion the whole topology
// rests on.
//
// A dispatcher in a second region does not fail loudly. It works, claims its
// own rows, and delivers events the primary also delivered — out of order, to
// a customer whose state machine then corrupts. The failure surfaces days
// later as "your ordering guarantee does not work", which is the worst
// possible way to discover it, so it is refused at start-up.
func TestRegionRefusesASecondDispatcher(t *testing.T) {
	edge := region.Config{Name: "af-south-1", Role: region.Edge}
	err := region.GuardDispatcher(edge)
	if err == nil {
		t.Fatal("an edge region was allowed to run a dispatcher")
	}
	// The message has to explain the consequence, not just state the rule.
	// Somebody hitting this is mid-deploy and will otherwise work around it.
	//
	// Compared with whitespace collapsed, because the message wraps and an
	// assertion that depends on where it wraps breaks whenever the prose is
	// edited around it.
	msg := strings.Join(strings.Fields(err.Error()), " ")
	for _, want := range []string{"twice", "out of order", "ADR-006", "--mode receiver"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal does not mention %q: %v", want, err)
		}
	}

	if err := region.GuardDispatcher(region.Config{Name: "us-east-1", Role: region.Primary}); err != nil {
		t.Fatalf("the primary region was refused a dispatcher: %v", err)
	}
}

func TestRegionServerConfigRefusesADispatchingEdge(t *testing.T) {
	// The same guard, reached the way an operator would actually reach it:
	// by setting the mode and the role and starting the process.
	cfg := server.Defaults()
	cfg.DatabaseURL = "postgres://localhost/x"
	cfg.Region = "af-south-1"
	cfg.RegionRole = string(region.Edge)

	for _, mode := range []server.Mode{server.ModeDispatcher, server.ModeAll} {
		cfg.Mode = mode
		if err := cfg.Validate(); err == nil {
			t.Errorf("--mode %s was accepted in an edge region", mode)
		}
	}

	// A receiver is exactly what an edge region is for.
	cfg.Mode = server.ModeReceiver
	if err := cfg.Validate(); err != nil {
		t.Fatalf("an edge receiver was refused: %v", err)
	}
}

func TestRegionSingleRegionNeedsNoConfiguration(t *testing.T) {
	// A deployment that has never thought about regions should not have to.
	cfg := server.Defaults()
	cfg.DatabaseURL = "postgres://localhost/x"
	cfg.Mode = server.ModeAll
	mustNoErr(t, cfg.Validate(), "an unconfigured single-region deployment")

	rc := cfg.RegionConfig()
	if rc.Role != region.Primary {
		t.Errorf("default role = %q, want primary", rc.Role)
	}
	// Still labelled, though, or its metrics are unattributable the day a
	// second region appears.
	if rc.Name != "default" {
		t.Errorf("default region name = %q", rc.Name)
	}
}

func TestRegionWriteBudgetDiffersByRole(t *testing.T) {
	// An edge region's write crosses the network, so the same ceiling would
	// alert constantly and be turned off.
	primary := region.Config{Name: "us-east-1", Role: region.Primary}
	edge := region.Config{Name: "af-south-1", Role: region.Edge}

	if primary.Budget() != region.DefaultWriteBudget {
		t.Errorf("primary budget = %s", primary.Budget())
	}
	if edge.Budget() <= primary.Budget() {
		t.Errorf("edge budget %s is not above the primary's %s; a cross-region write cannot meet the same ceiling",
			edge.Budget(), primary.Budget())
	}
	// But still bounded. An unbounded edge budget would mean nobody notices
	// when the arrangement stops paying for itself.
	if edge.Budget() > time.Second {
		t.Errorf("edge budget %s is not a bound", edge.Budget())
	}

	explicit := region.Config{Name: "x", Role: region.Edge, WriteBudget: 40 * time.Millisecond}
	if explicit.Budget() != 40*time.Millisecond {
		t.Errorf("an explicit budget was overridden: %s", explicit.Budget())
	}
}

func TestRegionRequiresANameWhenConfigured(t *testing.T) {
	// Without one every metric is unattributable, and a regional problem
	// looks like a global degradation nobody can locate.
	if err := (region.Config{Role: region.Primary}).Validate(); err == nil {
		t.Fatal("a region with no name was accepted")
	}
	if err := (region.Config{Name: "x", Role: "somewhere"}).Validate(); err == nil {
		t.Fatal("an unrecognised role was accepted")
	}
}

func TestRegionReplicaAssessmentIsADecisionNotAMeasurement(t *testing.T) {
	// "4s behind" is a measurement. "promoting now loses every event in that
	// window, and the provider will not resend" is what somebody at 3am
	// actually needs.
	cases := []struct {
		name  string
		state region.ReplicaState
		want  []string
	}{
		{
			"the primary", region.ReplicaState{IsReplica: false},
			[]string{"this is the primary", "not the operation you want"},
		},
		{
			"stream down",
			region.ReplicaState{IsReplica: true, Receiving: false, Lag: time.Second},
			// The critical case: low lag with a dead stream is the most
			// misleading reading available, because the number looks fine.
			[]string{"stale", "unbounded"},
		},
		{
			"far behind",
			region.ReplicaState{IsReplica: true, Receiving: true, Lag: 10 * time.Minute},
			[]string{"10m0s behind", "will not resend"},
		},
		{
			"slightly behind",
			region.ReplicaState{IsReplica: true, Receiving: true, Lag: time.Minute},
			[]string{"1m0s behind", "Wait if the primary might come back"},
		},
		{
			"caught up",
			region.ReplicaState{IsReplica: true, Receiving: true, Lag: 5 * time.Millisecond},
			[]string{"stream healthy", "genuinely gone"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := c.state.Assessment()
			for _, want := range c.want {
				if !strings.Contains(got, want) {
					t.Errorf("assessment %q does not mention %q", got, want)
				}
			}
		})
	}
}

func TestRegionCheckReplicaAgainstAPrimary(t *testing.T) {
	// Running this against the wrong host is exactly the mistake somebody
	// makes under pressure, so the answer has to be useful rather than an
	// error.
	dsn := os.Getenv("STATUSHUB_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("STATUSHUB_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	mustNoErr(t, err, "connecting")
	defer pool.Close()

	state, err := region.CheckReplica(ctx, pool)
	mustNoErr(t, err, "checking a primary")
	if state.IsReplica {
		t.Fatal("the test database reported itself as a replica")
	}
	if !strings.Contains(state.Assessment(), "primary") {
		t.Errorf("assessment = %q", state.Assessment())
	}
}
