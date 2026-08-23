package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nobledeveloper01/StatusHub/internal/domain"
)

// --- Deliveries ---

func (p *Postgres) EnqueueDelivery(ctx context.Context, d domain.Delivery) (int64, error) {
	// The transaction reference is denormalised onto the delivery row. It is
	// duplicated data, and it earns its place: the claim query below groups
	// on it, and joining canonical_events on every claim would put the
	// largest table in the system on the dispatcher's hot path.
	ref := d.TransactionRef
	if ref == "" {
		if err := p.pool.QueryRow(ctx,
			`SELECT transaction_ref FROM canonical_events WHERE tenant_id=$1 AND id=$2`,
			d.TenantID, d.EventID).Scan(&ref); err != nil {
			return 0, mapError(err)
		}
	}

	var id int64
	err := p.pool.QueryRow(ctx,
		`INSERT INTO deliveries
		   (tenant_id, event_id, destination_id, transaction_ref, shard, sequence,
		    attempt, status, is_replay, next_retry_at, created_at, updated_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$11)
		 RETURNING id`,
		d.TenantID, d.EventID, d.DestinationID, ref, d.Shard, d.Sequence,
		d.Attempt, string(domain.DeliveryPending), d.IsReplay,
		nilTime(d.NextRetryAt), orNow(d.CreatedAt)).Scan(&id)
	return id, mapError(err)
}

// NextSequence allocates the ordering position for a transaction reference.
//
// An upsert returning the incremented value, so two dispatcher replicas
// enqueueing concurrently cannot be handed the same sequence. Read-then-write
// would be a race, and a race here produces two events at the same position,
// which is precisely the ordering failure the sequence exists to prevent.
func (p *Postgres) NextSequence(ctx context.Context, tenantID, transactionRef string) (int64, error) {
	var seq int64
	err := p.pool.QueryRow(ctx,
		`INSERT INTO delivery_sequences (tenant_id, transaction_ref, last_sequence)
		 VALUES ($1, $2, 1)
		 ON CONFLICT (tenant_id, transaction_ref)
		 DO UPDATE SET last_sequence = delivery_sequences.last_sequence + 1
		 RETURNING last_sequence`, tenantID, transactionRef).Scan(&seq)
	return seq, mapError(err)
}

const deliveryColumns = `id, tenant_id, event_id, destination_id, transaction_ref, shard,
	sequence, attempt, status, response_code, response_body, error, duration_ms,
	is_replay, next_retry_at, created_at, updated_at`

// ClaimDue leases the deliveries a dispatcher may attempt now.
//
// This is the single most important query in the dispatcher and every clause
// is doing work:
//
//   - DISTINCT ON (destination_id, transaction_ref) with an ordering by
//     sequence takes only the earliest pending delivery for each transaction.
//     That is where per-transaction ordering is enforced (§4.5) — two events
//     about one transaction can never be claimed together, so a success can
//     never overtake the pending that preceded it.
//   - The NOT EXISTS clause excludes any reference that already has an
//     unexpired lease held by another replica, which extends the same
//     guarantee across processes rather than only within one.
//   - FOR UPDATE SKIP LOCKED lets several replicas claim in parallel without
//     blocking each other. Without SKIP LOCKED they would serialise on the
//     same rows and the shard count would buy nothing.
func (p *Postgres) ClaimDue(ctx context.Context, shard int, now time.Time, limit int, lease time.Duration) ([]domain.Delivery, error) {
	if limit <= 0 || limit > 200 {
		limit = 32
	}
	if lease <= 0 {
		lease = 2 * time.Minute
	}
	until := now.Add(lease)

	rows, err := p.pool.Query(ctx,
		`WITH claimable AS (
		   SELECT DISTINCT ON (d.destination_id, d.transaction_ref) d.id
		     FROM deliveries d
		    WHERE d.shard = $1
		      AND d.status IN ('pending','failed')
		      AND (d.next_retry_at IS NULL OR d.next_retry_at <= $2)
		      AND NOT EXISTS (
		            SELECT 1 FROM deliveries busy
		             WHERE busy.destination_id = d.destination_id
		               AND busy.transaction_ref = d.transaction_ref
		               AND busy.status = 'in_flight'
		               AND busy.leased_until > $2)
		    ORDER BY d.destination_id, d.transaction_ref, d.sequence, d.id
		 ), picked AS (
		   SELECT id FROM deliveries
		    WHERE id IN (SELECT id FROM claimable)
		    ORDER BY sequence, id
		    LIMIT $3
		    FOR UPDATE SKIP LOCKED
		 )
		 UPDATE deliveries d
		    SET status = 'in_flight', attempt = d.attempt + 1,
		        leased_until = $4, updated_at = $2
		  WHERE d.id IN (SELECT id FROM picked)
		 RETURNING `+deliveryColumns,
		shard, now, limit, until)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()

	var out []domain.Delivery
	for rows.Next() {
		d, err := scanDelivery(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, mapError(rows.Err())
}

// ReclaimExpiredLeases returns deliveries whose dispatcher died mid-attempt.
//
// Without it, a replica killed between claiming and completing leaves the
// delivery in_flight forever, and — because the claim query treats an
// in-flight delivery as blocking its transaction reference — that key stalls
// permanently. The lease is what bounds a crash to one lease interval.
func (p *Postgres) ReclaimExpiredLeases(ctx context.Context, now time.Time) (int64, error) {
	tag, err := p.pool.Exec(ctx,
		`UPDATE deliveries
		    SET status = 'failed', leased_until = NULL, updated_at = $1,
		        error = 'dispatcher lease expired; reclaimed for retry'
		  WHERE status = 'in_flight' AND leased_until IS NOT NULL AND leased_until <= $1`, now)
	if err != nil {
		return 0, mapError(err)
	}
	return tag.RowsAffected(), nil
}

func (p *Postgres) CompleteDelivery(ctx context.Context, d domain.Delivery) error {
	tag, err := p.pool.Exec(ctx,
		`UPDATE deliveries
		    SET status=$3, response_code=$4, response_body=$5, error=$6, duration_ms=$7,
		        next_retry_at=$8, leased_until=NULL, updated_at=now()
		  WHERE tenant_id=$1 AND id=$2`,
		d.TenantID, d.ID, string(d.Status), nilInt(d.ResponseCode), nilString(d.ResponseBody),
		nilString(d.Error), nilInt(d.DurationMS), nilTime(d.NextRetryAt))
	if err != nil {
		return mapError(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (p *Postgres) GetDelivery(ctx context.Context, tenantID string, id int64) (domain.Delivery, error) {
	row := p.pool.QueryRow(ctx,
		`SELECT `+deliveryColumns+` FROM deliveries WHERE tenant_id=$1 AND id=$2`, tenantID, id)
	return scanDelivery(row)
}

func (p *Postgres) ListDeliveriesForEvent(ctx context.Context, tenantID, eventID string) ([]domain.Delivery, error) {
	rows, err := p.pool.Query(ctx,
		`SELECT `+deliveryColumns+` FROM deliveries
		  WHERE tenant_id=$1 AND event_id=$2 ORDER BY id`, tenantID, eventID)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()
	return collectDeliveries(rows)
}

func (p *Postgres) QueryDeliveries(ctx context.Context, tenantID string, q DeliveryQuery) ([]domain.Delivery, error) {
	limit := q.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	where := []string{"tenant_id = $1"}
	args := []any{tenantID}
	add := func(clause string, v any) {
		args = append(args, v)
		where = append(where, fmt.Sprintf(clause, len(args)))
	}
	if q.DestinationID != "" {
		add("destination_id = $%d", q.DestinationID)
	}
	if q.Status != "" {
		add("status = $%d", string(q.Status))
	}
	if q.EventID != "" {
		add("event_id = $%d", q.EventID)
	}
	if !q.From.IsZero() {
		add("created_at >= $%d", q.From)
	}
	if !q.To.IsZero() {
		add("created_at <= $%d", q.To)
	}
	if q.Cursor != 0 {
		add("id < $%d", q.Cursor)
	}
	args = append(args, limit)

	rows, err := p.pool.Query(ctx,
		`SELECT `+deliveryColumns+` FROM deliveries
		  WHERE `+strings.Join(where, " AND ")+`
		  ORDER BY id DESC LIMIT $`+fmt.Sprint(len(args)), args...)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()
	return collectDeliveries(rows)
}

func (p *Postgres) QueueDepth(ctx context.Context) (map[int]int64, error) {
	rows, err := p.pool.Query(ctx,
		`SELECT shard, count(*) FROM deliveries
		  WHERE status IN ('pending','failed','in_flight') GROUP BY shard`)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()

	out := map[int]int64{}
	for rows.Next() {
		var shard int
		var n int64
		if err := rows.Scan(&shard, &n); err != nil {
			return nil, mapError(err)
		}
		out[shard] = n
	}
	return out, mapError(rows.Err())
}

// OldestPending backs statushub_shard_oldest_pending_seconds, which is how
// head-of-line blocking is seen before a customer reports it (§11.4).
func (p *Postgres) OldestPending(ctx context.Context) (map[int]time.Time, error) {
	rows, err := p.pool.Query(ctx,
		`SELECT shard, min(created_at) FROM deliveries
		  WHERE status IN ('pending','failed','in_flight') GROUP BY shard`)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()

	out := map[int]time.Time{}
	for rows.Next() {
		var shard int
		var t time.Time
		if err := rows.Scan(&shard, &t); err != nil {
			return nil, mapError(err)
		}
		out[shard] = t
	}
	return out, mapError(rows.Err())
}

func collectDeliveries(rows interface {
	Next() bool
	Scan(...any) error
	Err() error
}) ([]domain.Delivery, error) {
	var out []domain.Delivery
	for rows.Next() {
		d, err := scanDelivery(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, mapError(rows.Err())
}

func scanDelivery(row scanner) (domain.Delivery, error) {
	var (
		d       domain.Delivery
		status  string
		code    *int
		body    *string
		errStr  *string
		dur     *int
		nextRun *time.Time
	)
	err := row.Scan(&d.ID, &d.TenantID, &d.EventID, &d.DestinationID, &d.TransactionRef,
		&d.Shard, &d.Sequence, &d.Attempt, &status, &code, &body, &errStr, &dur,
		&d.IsReplay, &nextRun, &d.CreatedAt, &d.UpdatedAt)
	if err != nil {
		return domain.Delivery{}, mapError(err)
	}
	d.Status = domain.DeliveryStatus(status)
	if code != nil {
		d.ResponseCode = *code
	}
	d.ResponseBody = deref(body)
	d.Error = deref(errStr)
	if dur != nil {
		d.DurationMS = *dur
	}
	if nextRun != nil {
		d.NextRetryAt = *nextRun
	}
	return d, nil
}

func nilInt(n int) *int {
	if n == 0 {
		return nil
	}
	return &n
}

// --- Audit ---

// AppendAudit seals a record against the tenant's head and inserts it, in one
// transaction with the sequence allocation.
//
// The lock matters. Two concurrent appends that both read the same head would
// produce two records claiming the same predecessor, which breaks the chain
// and makes verification fail for reasons that have nothing to do with
// tampering. An advisory lock per tenant serialises appends for that tenant
// only.
func (p *Postgres) AppendAudit(ctx context.Context, r domain.AuditRecord) error {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return mapError(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, "audit:"+r.TenantID); err != nil {
		return mapError(err)
	}

	var (
		prev string
		seq  int64
	)
	err = tx.QueryRow(ctx,
		`SELECT hash, seq FROM audit_records WHERE tenant_id = $1 ORDER BY seq DESC LIMIT 1`,
		r.TenantID).Scan(&prev, &seq)
	if err != nil {
		if !errors.Is(mapError(err), ErrNotFound) {
			return mapError(err)
		}
		prev, seq = domain.GenesisHash, 0
	}

	if r.ID == "" {
		r.ID = domain.NewID(domain.PrefixAudit)
	}
	if err := r.Seal(prev); err != nil {
		return err
	}

	actor, err := json.Marshal(r.Actor)
	if err != nil {
		return err
	}
	subject, err := json.Marshal(r.Subject)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(orEmptyMap(r.Payload))
	if err != nil {
		return err
	}

	if _, err := tx.Exec(ctx,
		`INSERT INTO audit_records
		   (id, tenant_id, event_type, occurred_at, recorded_at, actor, subject, payload,
		    corrects, prev_hash, hash, seq)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		r.ID, r.TenantID, string(r.EventType), r.OccurredAt, r.RecordedAt,
		actor, subject, payload, nilString(r.Corrects), r.PrevHash, r.Hash, seq+1); err != nil {
		return mapError(err)
	}
	return mapError(tx.Commit(ctx))
}

func (p *Postgres) ListAudit(ctx context.Context, tenantID string, since time.Time, limit int) ([]domain.AuditRecord, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := p.pool.Query(ctx,
		`SELECT id, tenant_id, event_type, occurred_at, recorded_at, actor, subject,
		        payload, corrects, prev_hash, hash
		   FROM audit_records
		  WHERE tenant_id = $1 AND recorded_at >= $2
		  ORDER BY seq DESC LIMIT $3`, tenantID, since, limit)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()
	return collectAudit(rows)
}

func (p *Postgres) LastAuditHash(ctx context.Context, tenantID string) (string, error) {
	var h string
	err := p.pool.QueryRow(ctx,
		`SELECT hash FROM audit_records WHERE tenant_id=$1 ORDER BY seq DESC LIMIT 1`, tenantID).Scan(&h)
	if errors.Is(mapError(err), ErrNotFound) {
		return domain.GenesisHash, nil
	}
	return h, mapError(err)
}

// VerifyChain walks a tenant's records in order and recomputes every hash.
//
// Streamed rather than loaded: a tenant with a year of audit records has
// millions of them, and a verification that needs them all in memory is a
// verification nobody runs.
func (p *Postgres) VerifyChain(ctx context.Context, tenantID string) (domain.ChainProof, error) {
	proof := domain.ChainProof{TenantID: tenantID, Intact: true, VerifiedAt: time.Now().UTC()}

	rows, err := p.pool.Query(ctx,
		`SELECT id, tenant_id, event_type, occurred_at, recorded_at, actor, subject,
		        payload, corrects, prev_hash, hash, seq
		   FROM audit_records WHERE tenant_id = $1 ORDER BY seq`, tenantID)
	if err != nil {
		return proof, mapError(err)
	}
	defer rows.Close()

	prev := domain.GenesisHash
	var wantSeq int64
	for rows.Next() {
		var (
			r                       domain.AuditRecord
			actor, subject, payload []byte
			eventType, prevHash     string
			corrects                *string
			seq                     int64
		)
		if err := rows.Scan(&r.ID, &r.TenantID, &eventType, &r.OccurredAt, &r.RecordedAt,
			&actor, &subject, &payload, &corrects, &prevHash, &r.Hash, &seq); err != nil {
			return proof, mapError(err)
		}
		r.EventType = domain.AuditEventType(eventType)
		r.PrevHash = prevHash
		r.Corrects = deref(corrects)
		_ = json.Unmarshal(actor, &r.Actor)
		_ = json.Unmarshal(subject, &r.Subject)
		_ = json.Unmarshal(payload, &r.Payload)

		if proof.Records == 0 {
			proof.From = r.RecordedAt
		}
		proof.To = r.RecordedAt
		proof.Records++
		wantSeq++

		// A gap in the sequence is a deleted record. The hash chain would
		// catch it too, but naming it as a gap tells an investigator what
		// actually happened rather than only that something is wrong.
		if seq != wantSeq {
			proof.Intact, proof.BrokenAt = false, r.ID
			proof.Reason = fmt.Sprintf("sequence jumped from %d to %d; a record is missing", wantSeq-1, seq)
			return proof, nil
		}
		if r.PrevHash != prev {
			proof.Intact, proof.BrokenAt = false, r.ID
			proof.Reason = fmt.Sprintf("record links to %s but the previous record hashed to %s", r.PrevHash, prev)
			return proof, nil
		}
		want, err := r.ComputeHash()
		if err != nil {
			proof.Intact, proof.BrokenAt, proof.Reason = false, r.ID, err.Error()
			return proof, nil
		}
		if want != r.Hash {
			proof.Intact, proof.BrokenAt = false, r.ID
			proof.Reason = "record content does not match its stored hash"
			return proof, nil
		}
		prev = r.Hash
	}
	if err := rows.Err(); err != nil {
		return proof, mapError(err)
	}
	proof.Head = prev
	return proof, nil
}

func collectAudit(rows interface {
	Next() bool
	Scan(...any) error
	Err() error
}) ([]domain.AuditRecord, error) {
	var out []domain.AuditRecord
	for rows.Next() {
		var (
			r                       domain.AuditRecord
			actor, subject, payload []byte
			eventType               string
			corrects                *string
		)
		if err := rows.Scan(&r.ID, &r.TenantID, &eventType, &r.OccurredAt, &r.RecordedAt,
			&actor, &subject, &payload, &corrects, &r.PrevHash, &r.Hash); err != nil {
			return nil, mapError(err)
		}
		r.EventType = domain.AuditEventType(eventType)
		r.Corrects = deref(corrects)
		_ = json.Unmarshal(actor, &r.Actor)
		_ = json.Unmarshal(subject, &r.Subject)
		_ = json.Unmarshal(payload, &r.Payload)
		out = append(out, r)
	}
	return out, mapError(rows.Err())
}

func orEmptyMap(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return m
}

// Compile-time proof that Postgres implements the whole interface.
var _ Store = (*Postgres)(nil)
