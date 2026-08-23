// Package subject implements data subject export and erasure (§9, NDPR and
// GDPR).
//
// StatusHub holds very little about any individual, by design: customer
// identifiers are hashed with a per-tenant salt before storage, and card data
// is removed before it is written (§8.4). That makes both obligations
// narrower than they would otherwise be — but narrower is not zero, and a
// commitment to "documented and tested export and deletion procedures" is
// only worth something if the deletion is actually verified to have deleted.
//
// The one deliberate exception is the audit trail. Erasing the record that an
// erasure happened is not a defensible reading of either regulation, and an
// append-only trail cannot be selectively edited without destroying the
// property that makes it evidence. So audit *records* survive; the personal
// data inside their payloads does not, because none was ever put there.
package subject

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/nobledeveloper01/StatusHub/internal/domain"
)

// Ref identifies a data subject.
//
// By hash, not by email. The caller supplies the identifier they hold, it is
// hashed with the tenant's salt, and only the hash is used from there on — so
// an export request does not itself become a reason for a plaintext email
// address to appear in our logs.
type Ref struct {
	TenantID string
	Hash     string
}

// Resolve hashes a plaintext identifier the same way the normaliser does. If
// the two ever diverged, an erasure would silently match nothing and report
// success, which is the worst possible failure for this feature.
func Resolve(tenantID, salt, identifier string) Ref {
	m := hmac.New(sha256.New, []byte(salt))
	_, _ = m.Write([]byte(identifier))
	return Ref{TenantID: tenantID, Hash: "sha256:" + hex.EncodeToString(m.Sum(nil))}
}

// Service performs exports and erasures.
type Service struct {
	pool *pgxpool.Pool
	now  func() time.Time
}

// New builds a Service.
func New(pool *pgxpool.Pool, now func() time.Time) *Service {
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Service{pool: pool, now: now}
}

// Export is everything held about one subject.
type Export struct {
	TenantID    string    `json:"tenant_id"`
	SubjectHash string    `json:"subject_ref_hash"`
	GeneratedAt time.Time `json:"generated_at"`

	Events []ExportedEvent `json:"events"`

	// Note explains what is and is not here, because an export that silently
	// omits a category is indistinguishable from one where that category was
	// empty.
	Note string `json:"note"`
}

// ExportedEvent is one canonical event concerning the subject.
type ExportedEvent struct {
	EventID        string    `json:"event_id"`
	Provider       string    `json:"provider"`
	EventType      string    `json:"event_type"`
	TransactionRef string    `json:"transaction_ref"`
	Status         string    `json:"status"`
	AmountMinor    int64     `json:"amount_minor"`
	Currency       string    `json:"currency,omitempty"`
	OccurredAt     time.Time `json:"occurred_at"`
	ReceivedAt     time.Time `json:"received_at"`

	// ProviderExtra is included in full. It is the field most likely to hold
	// something about the subject that we did not map, and omitting it from a
	// subject access request because we do not know what is in it would be
	// exactly backwards.
	ProviderExtra map[string]any `json:"provider_extra,omitempty"`
}

// Export gathers everything held about a subject.
func (s *Service) Export(ctx context.Context, ref Ref) (Export, error) {
	e := Export{
		TenantID: ref.TenantID, SubjectHash: ref.Hash, GeneratedAt: s.now(),
		Note: "StatusHub stores customer identifiers only as a per-tenant salted hash, never in the " +
			"clear, and removes card data before storage. This export therefore contains the " +
			"transactions associated with that hash and any unmapped provider fields carried with " +
			"them. Raw provider payloads are excluded: they are the provider's own record, are " +
			"separately permissioned, and are available on request with an explicit reason.",
	}

	rows, err := s.pool.Query(ctx,
		`SELECT id, provider, event_type, transaction_ref, status, amount_minor,
		        COALESCE(currency, ''), provider_extra, occurred_at, received_at
		   FROM canonical_events
		  WHERE tenant_id = $1 AND customer_ref_hash = $2
		  ORDER BY occurred_at`, ref.TenantID, ref.Hash)
	if err != nil {
		return e, err
	}
	defer rows.Close()

	for rows.Next() {
		var (
			ev    ExportedEvent
			extra []byte
		)
		if err := rows.Scan(&ev.EventID, &ev.Provider, &ev.EventType, &ev.TransactionRef,
			&ev.Status, &ev.AmountMinor, &ev.Currency, &extra, &ev.OccurredAt, &ev.ReceivedAt); err != nil {
			return e, err
		}
		if len(extra) > 0 {
			_ = json.Unmarshal(extra, &ev.ProviderExtra)
		}
		e.Events = append(e.Events, ev)
	}
	return e, rows.Err()
}

// WriteJSON renders an export.
func (e Export) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(e)
}

// ErasureResult reports what an erasure did.
type ErasureResult struct {
	TenantID    string    `json:"tenant_id"`
	SubjectHash string    `json:"subject_ref_hash"`
	ErasedAt    time.Time `json:"erased_at"`
	DryRun      bool      `json:"dry_run"`

	EventsAffected int64 `json:"events_affected"`
	RawBodiesWiped int64 `json:"raw_bodies_wiped"`
	ExtraKeysWiped int64 `json:"provider_extra_keys_wiped"`

	// Retained states plainly what survives and why. An erasure report that
	// only lists deletions invites the reader to assume nothing is left,
	// which would be untrue and — when the regulator asks — worse than
	// saying so.
	Retained string `json:"retained"`
}

// Erase removes personal data for a subject.
//
// The transaction records themselves are kept and de-linked rather than
// deleted. Two reasons, and both are the customer's rather than ours: CBN and
// AML record-keeping obligations require a fintech to retain transaction
// records for years, and deleting a payment from the ledger because the payer
// asked would break the customer's own books. What is erased is everything
// that ties those records to a person.
func (s *Service) Erase(ctx context.Context, ref Ref, dryRun bool) (ErasureResult, error) {
	r := ErasureResult{
		TenantID: ref.TenantID, SubjectHash: ref.Hash, ErasedAt: s.now(), DryRun: dryRun,
		Retained: "The transactions themselves are retained, with every link to the subject removed. " +
			"They are kept because CBN and AML record-keeping obligations require the tenant to hold " +
			"transaction records for years, and because deleting a payment from a ledger at the payer's " +
			"request would break the tenant's own books. Audit records are also retained: erasing the " +
			"record that an erasure happened is not a defensible reading of either regulation, and no " +
			"personal data is written into audit payloads.",
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return r, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := tx.QueryRow(ctx,
		`SELECT count(*) FROM canonical_events WHERE tenant_id = $1 AND customer_ref_hash = $2`,
		ref.TenantID, ref.Hash).Scan(&r.EventsAffected); err != nil {
		return r, err
	}
	if r.EventsAffected == 0 {
		return r, nil
	}

	// Count the provider_extra keys that will go, so the report is specific
	// rather than reassuring.
	if err := tx.QueryRow(ctx,
		`SELECT COALESCE(sum(n), 0) FROM (
		   SELECT count(*) AS n FROM canonical_events e, jsonb_object_keys(e.provider_extra)
		    WHERE e.tenant_id = $1 AND e.customer_ref_hash = $2
		    GROUP BY e.id
		 ) counts`, ref.TenantID, ref.Hash).Scan(&r.ExtraKeysWiped); err != nil {
		return r, err
	}

	if err := tx.QueryRow(ctx,
		`SELECT count(*) FROM raw_events r
		  WHERE r.tenant_id = $1
		    AND EXISTS (SELECT 1 FROM canonical_events e
		                 WHERE e.raw_event_id = r.id AND e.customer_ref_hash = $2)`,
		ref.TenantID, ref.Hash).Scan(&r.RawBodiesWiped); err != nil {
		return r, err
	}

	if dryRun {
		return r, nil
	}

	// The raw bodies go first. They are the provider's verbatim payload and
	// therefore the one place a name, an email or a phone number is likely to
	// be sitting in the clear — precisely because we did not choose what went
	// into them.
	if _, err := tx.Exec(ctx,
		`UPDATE raw_events r
		    SET body = '\x'::bytea,
		        headers = '{}'::jsonb,
		        redaction_note = 'erased on data subject request'
		  WHERE r.tenant_id = $1
		    AND EXISTS (SELECT 1 FROM canonical_events e
		                 WHERE e.raw_event_id = r.id AND e.customer_ref_hash = $2)`,
		ref.TenantID, ref.Hash); err != nil {
		return r, err
	}

	// Then provider_extra, for the same reason: it holds whatever the
	// provider sent that we did not map, which is where an unmapped
	// `customer.phone` lives.
	if _, err := tx.Exec(ctx,
		`UPDATE canonical_events
		    SET provider_extra = '{"statushub_erased": true}'::jsonb,
		        customer_ref_hash = NULL
		  WHERE tenant_id = $1 AND customer_ref_hash = $2`,
		ref.TenantID, ref.Hash); err != nil {
		return r, err
	}

	// The erasure is itself audited, with the subject named only by hash.
	rec := domain.AuditRecord{
		TenantID:  ref.TenantID,
		EventType: domain.AuditEventType("subject.erased"),
		Actor:     domain.Actor{Type: domain.ActorUser},
		Subject:   domain.Subject{Type: "data_subject", ID: ref.Hash},
		Payload: map[string]any{
			"events_affected":  r.EventsAffected,
			"raw_bodies_wiped": r.RawBodiesWiped,
			"extra_keys_wiped": r.ExtraKeysWiped,
		},
	}
	if err := appendAuditTx(ctx, tx, rec); err != nil {
		return r, err
	}

	return r, tx.Commit(ctx)
}

// appendAuditTx writes an audit record inside an existing transaction, so the
// erasure and its record commit together. An erasure that succeeded without
// its audit record would be an unexplainable gap in the trail at exactly the
// moment somebody wants an explanation.
func appendAuditTx(ctx context.Context, tx pgx.Tx, r domain.AuditRecord) error {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, "audit:"+r.TenantID); err != nil {
		return err
	}

	var (
		prev string
		seq  int64
	)
	err := tx.QueryRow(ctx,
		`SELECT hash, seq FROM audit_records WHERE tenant_id = $1 ORDER BY seq DESC LIMIT 1`,
		r.TenantID).Scan(&prev, &seq)
	if err != nil {
		prev, seq = domain.GenesisHash, 0
	}

	if r.ID == "" {
		r.ID = domain.NewID(domain.PrefixAudit)
	}
	if err := r.Seal(prev); err != nil {
		return err
	}

	actor, _ := json.Marshal(r.Actor)
	subject, _ := json.Marshal(r.Subject)
	payload, _ := json.Marshal(r.Payload)

	_, err = tx.Exec(ctx,
		`INSERT INTO audit_records
		   (id, tenant_id, event_type, occurred_at, recorded_at, actor, subject, payload,
		    corrects, prev_hash, hash, seq)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NULL,$9,$10,$11)`,
		r.ID, r.TenantID, string(r.EventType), r.OccurredAt, r.RecordedAt,
		actor, subject, payload, r.PrevHash, r.Hash, seq+1)
	return err
}

// Verify confirms an erasure actually erased.
//
// This exists because the failure mode of an erasure is silence: a query that
// matches nothing reports success just as loudly as one that erased
// everything. §9 promises a *tested* deletion procedure, and this is the test
// that can be run against production on the day a regulator asks.
func (s *Service) Verify(ctx context.Context, ref Ref) (string, error) {
	var remaining int64
	if err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM canonical_events WHERE tenant_id = $1 AND customer_ref_hash = $2`,
		ref.TenantID, ref.Hash).Scan(&remaining); err != nil {
		return "", err
	}
	if remaining > 0 {
		return "", fmt.Errorf("%d events still carry this subject's hash", remaining)
	}

	var bodies int64
	if err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM raw_events
		  WHERE tenant_id = $1 AND length(body) > 0
		    AND redaction_note = 'erased on data subject request'`,
		ref.TenantID).Scan(&bodies); err != nil {
		return "", err
	}
	if bodies > 0 {
		return "", fmt.Errorf("%d raw bodies marked erased still hold content", bodies)
	}
	return "no canonical event carries this subject's hash, and every raw body marked erased is empty", nil
}
