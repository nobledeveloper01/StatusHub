package store

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/nobledeveloper01/StatusHub/internal/domain"
)

// --- Destinations ---

const destinationColumns = `id, tenant_id, name, url, signing_secret_ref, filter,
	retry_policy, include_raw, schema_version, enabled, created_at`

type retryPolicyJSON struct {
	BackoffSeconds []float64 `json:"backoff_seconds"`
	JitterFraction float64   `json:"jitter_fraction"`
	TimeoutSeconds float64   `json:"timeout_seconds"`
}

func encodeRetryPolicy(p domain.RetryPolicy) ([]byte, error) {
	j := retryPolicyJSON{JitterFraction: p.JitterFraction, TimeoutSeconds: p.Timeout.Seconds()}
	for _, b := range p.Backoff {
		j.BackoffSeconds = append(j.BackoffSeconds, b.Seconds())
	}
	return json.Marshal(j)
}

func decodeRetryPolicy(b []byte) domain.RetryPolicy {
	if len(b) == 0 {
		return domain.DefaultRetryPolicy()
	}
	var j retryPolicyJSON
	if err := json.Unmarshal(b, &j); err != nil || len(j.BackoffSeconds) == 0 {
		// A policy row we cannot read falls back to the documented default
		// rather than to no retries. Silently delivering once and giving up
		// would be the worst possible interpretation of a corrupt config.
		return domain.DefaultRetryPolicy()
	}
	p := domain.RetryPolicy{
		JitterFraction: j.JitterFraction,
		Timeout:        time.Duration(j.TimeoutSeconds * float64(time.Second)),
	}
	for _, s := range j.BackoffSeconds {
		p.Backoff = append(p.Backoff, time.Duration(s*float64(time.Second)))
	}
	if p.Timeout <= 0 {
		p.Timeout = 10 * time.Second
	}
	return p
}

func (p *Postgres) CreateDestination(ctx context.Context, d domain.Destination) error {
	filter, err := json.Marshal(d.Filter)
	if err != nil {
		return fmt.Errorf("encoding the destination filter: %w", err)
	}
	policy, err := encodeRetryPolicy(d.RetryPolicy)
	if err != nil {
		return fmt.Errorf("encoding the retry policy: %w", err)
	}
	_, err = p.pool.Exec(ctx,
		`INSERT INTO destinations (`+destinationColumns+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		d.ID, d.TenantID, d.Name, d.URL, d.SigningSecretRef, filter, policy,
		d.IncludeRaw, d.SchemaVersion, d.Enabled, orNow(d.CreatedAt))
	return mapError(err)
}

func (p *Postgres) GetDestination(ctx context.Context, tenantID, id string) (domain.Destination, error) {
	row := p.pool.QueryRow(ctx,
		`SELECT `+destinationColumns+` FROM destinations WHERE tenant_id=$1 AND id=$2`, tenantID, id)
	return scanDestination(row)
}

func (p *Postgres) ListDestinations(ctx context.Context, tenantID string) ([]domain.Destination, error) {
	rows, err := p.pool.Query(ctx,
		`SELECT `+destinationColumns+` FROM destinations WHERE tenant_id=$1 ORDER BY created_at`, tenantID)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()

	var out []domain.Destination
	for rows.Next() {
		d, err := scanDestination(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, mapError(rows.Err())
}

func (p *Postgres) UpdateDestination(ctx context.Context, tenantID string, d domain.Destination) error {
	filter, err := json.Marshal(d.Filter)
	if err != nil {
		return err
	}
	policy, err := encodeRetryPolicy(d.RetryPolicy)
	if err != nil {
		return err
	}
	tag, err := p.pool.Exec(ctx,
		`UPDATE destinations SET name=$3, url=$4, signing_secret_ref=$5, filter=$6,
		   retry_policy=$7, include_raw=$8, schema_version=$9, enabled=$10
		 WHERE tenant_id=$1 AND id=$2`,
		tenantID, d.ID, d.Name, d.URL, d.SigningSecretRef, filter, policy,
		d.IncludeRaw, d.SchemaVersion, d.Enabled)
	if err != nil {
		return mapError(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (p *Postgres) DeleteDestination(ctx context.Context, tenantID, id string) error {
	tag, err := p.pool.Exec(ctx, `DELETE FROM destinations WHERE tenant_id=$1 AND id=$2`, tenantID, id)
	if err != nil {
		return mapError(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func scanDestination(row scanner) (domain.Destination, error) {
	var (
		d      domain.Destination
		filter []byte
		policy []byte
	)
	err := row.Scan(&d.ID, &d.TenantID, &d.Name, &d.URL, &d.SigningSecretRef,
		&filter, &policy, &d.IncludeRaw, &d.SchemaVersion, &d.Enabled, &d.CreatedAt)
	if err != nil {
		return domain.Destination{}, mapError(err)
	}
	if len(filter) > 0 {
		_ = json.Unmarshal(filter, &d.Filter)
	}
	d.RetryPolicy = decodeRetryPolicy(policy)
	return d, nil
}

// --- Raw events ---

// PutRawEvent is the only write on the receiver's critical path.
//
// One INSERT, no transaction, no trigger, no join. The 200 that follows tells
// the provider it may forget the event, so this has to be durable before it
// returns and fast enough to fit inside a 50 ms budget (ADR-001).
func (p *Postgres) PutRawEvent(ctx context.Context, e domain.RawEvent) error {
	headers, err := json.Marshal(e.Headers)
	if err != nil {
		return fmt.Errorf("encoding headers: %w", err)
	}
	var ip *string
	if e.SourceIP.IsValid() {
		s := e.SourceIP.String()
		ip = &s
	}
	_, err = p.pool.Exec(ctx,
		`INSERT INTO raw_events
		   (id, tenant_id, endpoint_id, provider, headers, body, body_sha256,
		    source_ip, signature_valid, signature_error, redacted, redaction_note, received_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
		e.ID, e.TenantID, e.EndpointID, e.Provider, headers, e.Body, e.BodySHA256,
		ip, e.SignatureValid, e.SignatureError, e.Redacted, e.RedactionNote, orNow(e.ReceivedAt))
	return mapError(err)
}

// source_ip is read through host() rather than as inet. pgx cannot scan the
// binary inet representation into a string, and inet also carries a prefix
// length that would have to be stripped afterwards — host() gives the bare
// address, which is the only part we ever stored.
const rawColumns = `id, tenant_id, endpoint_id, provider, headers, body, body_sha256,
	host(source_ip), signature_valid, signature_error, redacted, redaction_note, received_at`

func (p *Postgres) GetRawEvent(ctx context.Context, tenantID, id string) (domain.RawEvent, error) {
	row := p.pool.QueryRow(ctx,
		`SELECT `+rawColumns+` FROM raw_events WHERE tenant_id=$1 AND id=$2`, tenantID, id)
	return scanRawEvent(row)
}

// ListUnnormalised is the normaliser's work queue.
//
// It reads the partial index on (signature_valid, normalised_at IS NULL,
// failure_reason IS NULL), so the pending set is found without scanning the
// largest table in the system. Forgeries are excluded here rather than
// downstream: an unverified event is evidence, not work (§10.1).
func (p *Postgres) ListUnnormalised(ctx context.Context, limit int) ([]domain.RawEvent, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := p.pool.Query(ctx,
		`SELECT `+rawColumns+` FROM raw_events
		  WHERE signature_valid AND normalised_at IS NULL AND failure_reason IS NULL
		  ORDER BY received_at
		  LIMIT $1`, limit)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()
	return collectRawEvents(rows)
}

func (p *Postgres) ListSignatureFailures(ctx context.Context, tenantID, endpointID string, since time.Time, limit int) ([]domain.RawEvent, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	args := []any{tenantID, since, limit}
	filter := ""
	if endpointID != "" {
		filter = " AND endpoint_id = $4"
		args = append(args, endpointID)
	}
	rows, err := p.pool.Query(ctx,
		`SELECT `+rawColumns+` FROM raw_events
		  WHERE tenant_id=$1 AND NOT signature_valid AND received_at >= $2`+filter+`
		  ORDER BY received_at DESC LIMIT $3`, args...)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()
	return collectRawEvents(rows)
}

func collectRawEvents(rows interface {
	Next() bool
	Scan(...any) error
	Err() error
}) ([]domain.RawEvent, error) {
	var out []domain.RawEvent
	for rows.Next() {
		e, err := scanRawEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, mapError(rows.Err())
}

func scanRawEvent(row scanner) (domain.RawEvent, error) {
	var (
		e       domain.RawEvent
		headers []byte
		ip      *string
	)
	err := row.Scan(&e.ID, &e.TenantID, &e.EndpointID, &e.Provider, &headers, &e.Body,
		&e.BodySHA256, &ip, &e.SignatureValid, &e.SignatureError, &e.Redacted,
		&e.RedactionNote, &e.ReceivedAt)
	if err != nil {
		return domain.RawEvent{}, mapError(err)
	}
	if len(headers) > 0 {
		_ = json.Unmarshal(headers, &e.Headers)
	}
	if ip != nil && *ip != "" {
		if a, perr := netip.ParseAddr(*ip); perr == nil {
			e.SourceIP = a
		}
	}
	return e, nil
}

// --- Canonical events ---

const canonColumns = `id, tenant_id, raw_event_id, provider, provider_event_id, event_type,
	transaction_ref, status, amount_minor, currency, customer_ref_hash, provider_extra,
	unmapped_status, occurred_at, received_at, normalised_at, mapping_complete`

// PutCanonicalEvent writes the event and marks its raw counterpart done, in
// one transaction.
//
// The two must move together. A canonical event without the raw event marked
// would be re-normalised on the next sweep and rejected as a duplicate — which
// is survivable — but a raw event marked done without a canonical event is an
// event that is silently never forwarded, which is not.
func (p *Postgres) PutCanonicalEvent(ctx context.Context, e domain.CanonicalEvent) error {
	extra, err := json.Marshal(e.ProviderExtra)
	if err != nil {
		return fmt.Errorf("encoding provider_extra: %w", err)
	}

	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return mapError(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	_, err = tx.Exec(ctx,
		`INSERT INTO canonical_events (`+canonColumns+`)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`,
		e.ID, e.TenantID, e.RawEventID, e.Provider, nilString(e.ProviderEventID),
		string(e.EventType), e.TransactionRef, string(e.Status), e.AmountMinor,
		nilString(e.Currency), nilString(e.CustomerRefHash), extra, e.UnmappedStatus,
		orNow(e.OccurredAt), orNow(e.ReceivedAt), orNow(e.NormalisedAt), e.MappingComplete)
	if err != nil {
		return mapError(err)
	}

	if e.RawEventID != "" {
		if _, err := tx.Exec(ctx,
			`UPDATE raw_events SET normalised_at = now(), canonical_id = $3
			  WHERE tenant_id = $1 AND id = $2`,
			e.TenantID, e.RawEventID, e.ID); err != nil {
			return mapError(err)
		}
	}
	return mapError(tx.Commit(ctx))
}

func (p *Postgres) GetCanonicalEvent(ctx context.Context, tenantID, id string) (domain.CanonicalEvent, error) {
	row := p.pool.QueryRow(ctx,
		`SELECT `+canonColumns+` FROM canonical_events WHERE tenant_id=$1 AND id=$2`, tenantID, id)
	return scanCanonicalEvent(row)
}

func (p *Postgres) GetCanonicalEventByDedupeKey(ctx context.Context, tenantID, provider, providerEventID string) (domain.CanonicalEvent, error) {
	row := p.pool.QueryRow(ctx,
		`SELECT `+canonColumns+` FROM canonical_events
		  WHERE tenant_id=$1 AND provider=$2 AND provider_event_id=$3`,
		tenantID, provider, providerEventID)
	return scanCanonicalEvent(row)
}

// QueryEvents is the event explorer's search.
//
// Keyset pagination on a descending ID, never OFFSET. This is the largest
// table an operator queries interactively, and OFFSET 50000 makes Postgres
// read fifty thousand rows in order to throw them away — which is fine on a
// demo and unusable on a real tenant.
func (p *Postgres) QueryEvents(ctx context.Context, tenantID string, q EventQuery) ([]domain.CanonicalEvent, error) {
	limit := q.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}

	var (
		where = []string{"tenant_id = $1"}
		args  = []any{tenantID}
	)
	add := func(clause string, v any) {
		args = append(args, v)
		where = append(where, fmt.Sprintf(clause, len(args)))
	}
	if q.Provider != "" {
		add("provider = $%d", strings.ToLower(q.Provider))
	}
	if q.Status != "" {
		add("status = $%d", string(q.Status))
	}
	if q.EventType != "" {
		add("event_type = $%d", string(q.EventType))
	}
	if q.TransactionRef != "" {
		add("transaction_ref = $%d", q.TransactionRef)
	}
	if q.MappingComplete != nil {
		add("mapping_complete = $%d", *q.MappingComplete)
	}
	if !q.From.IsZero() {
		add("occurred_at >= $%d", q.From)
	}
	if !q.To.IsZero() {
		add("occurred_at <= $%d", q.To)
	}
	if q.Cursor != "" {
		add("id < $%d", q.Cursor)
	}
	args = append(args, limit)

	rows, err := p.pool.Query(ctx,
		`SELECT `+canonColumns+` FROM canonical_events
		  WHERE `+strings.Join(where, " AND ")+`
		  ORDER BY id DESC LIMIT $`+fmt.Sprint(len(args)), args...)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()

	var out []domain.CanonicalEvent
	for rows.Next() {
		e, err := scanCanonicalEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, mapError(rows.Err())
}

// MarkNormalisationFailure records why an adapter could not read a payload.
// The raw event is untouched apart from the flag: the bytes are the evidence
// and the recovery path (runbook 11.5).
func (p *Postgres) MarkNormalisationFailure(ctx context.Context, tenantID, rawEventID, reason string) error {
	if len(reason) > 2000 {
		reason = reason[:2000]
	}
	tag, err := p.pool.Exec(ctx,
		`UPDATE raw_events SET failure_reason = $3 WHERE tenant_id = $1 AND id = $2`,
		tenantID, rawEventID, reason)
	if err != nil {
		return mapError(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// UnknownStatuses aggregates the provider values with no mapping.
func (p *Postgres) UnknownStatuses(ctx context.Context, tenantID string, since time.Time) ([]UnknownStatus, error) {
	rows, err := p.pool.Query(ctx,
		`SELECT provider, unmapped_status, count(*), min(normalised_at), max(normalised_at),
		        (array_agg(id ORDER BY normalised_at DESC))[1]
		   FROM canonical_events
		  WHERE tenant_id = $1 AND unmapped_status <> '' AND normalised_at >= $2
		  GROUP BY provider, unmapped_status
		  ORDER BY count(*) DESC, unmapped_status`, tenantID, since)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()

	var out []UnknownStatus
	for rows.Next() {
		var u UnknownStatus
		if err := rows.Scan(&u.Provider, &u.RawValue, &u.Count, &u.FirstSeen, &u.LastSeen, &u.SampleEvent); err != nil {
			return nil, mapError(err)
		}
		out = append(out, u)
	}
	return out, mapError(rows.Err())
}

func scanCanonicalEvent(row scanner) (domain.CanonicalEvent, error) {
	var (
		e          domain.CanonicalEvent
		providerID *string
		currency   *string
		custHash   *string
		extra      []byte
		eventType  string
		status     string
	)
	err := row.Scan(&e.ID, &e.TenantID, &e.RawEventID, &e.Provider, &providerID, &eventType,
		&e.TransactionRef, &status, &e.AmountMinor, &currency, &custHash, &extra,
		&e.UnmappedStatus, &e.OccurredAt, &e.ReceivedAt, &e.NormalisedAt, &e.MappingComplete)
	if err != nil {
		return domain.CanonicalEvent{}, mapError(err)
	}
	e.ProviderEventID = deref(providerID)
	e.Currency = deref(currency)
	e.CustomerRefHash = deref(custHash)
	e.EventType = domain.EventType(eventType)
	e.Status = domain.Status(status)
	if len(extra) > 0 {
		_ = json.Unmarshal(extra, &e.ProviderExtra)
	}
	if e.ProviderExtra == nil {
		e.ProviderExtra = map[string]any{}
	}
	return e, nil
}
