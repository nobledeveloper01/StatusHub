// Package receive is the provider-facing HTTP surface.
//
// It does four things and refuses to do a fifth: verify the signature, store
// the raw bytes durably, answer 200, and hand the event off for normalisation
// somewhere else. Everything the customer eventually sees is produced after
// the response has been written (ADR-001).
//
// The reason the ordering is enforced structurally rather than by convention
// is that every alternative ordering loses events, and a handler that grows
// one more "quick" synchronous step is how a 50 ms budget becomes a 2 s one.
package receive

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/nobledeveloper01/StatusHub/internal/adapter"
	"github.com/nobledeveloper01/StatusHub/internal/adapters"
	"github.com/nobledeveloper01/StatusHub/internal/domain"
	"github.com/nobledeveloper01/StatusHub/internal/metrics"
	"github.com/nobledeveloper01/StatusHub/internal/ratelimit"
	"github.com/nobledeveloper01/StatusHub/internal/redact"
	"github.com/nobledeveloper01/StatusHub/internal/secret"
	"github.com/nobledeveloper01/StatusHub/internal/store"
)

// MaxBodyBytes is the hard ceiling on a provider payload (§10).
//
// One megabyte. No legitimate webhook approaches it — the largest real
// payload in the test corpus is 14 KB — and the ceiling is what stops a
// single request from becoming a memory-exhaustion vector. It is enforced
// with a limited reader rather than by checking Content-Length, because
// Content-Length is a claim made by the caller.
const MaxBodyBytes = 1 << 20

// Notifier is told about a newly persisted raw event so normalisation can
// start. It is deliberately fire-and-forget from the receiver's point of
// view: a notifier that blocks, errors or is absent must not affect the
// response the provider gets. The normaliser also polls for unclaimed work,
// so a dropped notification costs latency and never an event.
type Notifier interface {
	Notify(rawEventID string)
}

// NotifierFunc adapts a function to Notifier.
type NotifierFunc func(string)

func (f NotifierFunc) Notify(id string) { f(id) }

// Receiver handles provider webhooks.
type Receiver struct {
	store    store.Store
	registry *adapters.Registry
	secrets  secret.Resolver
	metrics  *metrics.Registry
	log      *slog.Logger
	notify   Notifier

	// now is injectable so the timestamp-window tests do not have to sleep.
	now func() time.Time

	// region labels every metric this receiver emits, so a regional problem
	// is visible as one rather than as a global degradation nobody can
	// locate. writeBudget is the ceiling for the single durable write, which
	// is larger in an edge region because it crosses the network.
	region      string
	writeBudget time.Duration

	// limiter is per-tenant backpressure (§8.6). Its ceiling is deliberately
	// far above any legitimate volume: a refused webhook is an event lost,
	// because the provider may exhaust its retries against our 429. It exists
	// to stop one tenant taking the service down for every other tenant, not
	// to shape traffic.
	limiter *ratelimit.Limiter

	// inFlight bounds concurrent request handling. Without a ceiling, a burst
	// larger than the store can absorb turns into unbounded goroutines and
	// memory, and the process dies holding events it has acknowledged.
	inFlight *ratelimit.Bounded

	// trustProxyHeaders controls whether X-Forwarded-For is believed. Off by
	// default: behind no proxy, the header is caller-supplied, and a source
	// IP an attacker chooses is worse than no source IP at all — it is a
	// false trail in the forgery investigation.
	trustProxyHeaders bool
}

// Options configure a Receiver.
type Options struct {
	Store             store.Store
	Registry          *adapters.Registry
	Secrets           secret.Resolver
	Metrics           *metrics.Registry
	Logger            *slog.Logger
	Notifier          Notifier
	TrustProxyHeaders bool
	Now               func() time.Time

	// PerTenantPerSecond and Burst configure backpressure. Zero means the
	// defaults below, which are generous on purpose.
	PerTenantPerSecond float64
	Burst              float64

	// MaxInFlight bounds concurrent request handling.
	MaxInFlight int

	// Region and WriteBudget place this receiver in a multi-region
	// deployment (ADR-006).
	Region      string
	WriteBudget time.Duration
}

// New builds a Receiver.
func New(o Options) *Receiver {
	r := &Receiver{
		store:             o.Store,
		registry:          o.Registry,
		secrets:           o.Secrets,
		metrics:           o.Metrics,
		log:               o.Logger,
		notify:            o.Notifier,
		trustProxyHeaders: o.TrustProxyHeaders,
		now:               o.Now,
		region:            o.Region,
		writeBudget:       o.WriteBudget,
	}
	if r.region == "" {
		r.region = "default"
	}
	if r.writeBudget <= 0 {
		r.writeBudget = 25 * time.Millisecond
	}
	// The default matches the service's own load target: §11.9 specifies
	// 10,000 webhooks/sec, so a per-tenant ceiling below that would throttle
	// a single large tenant at a rate the service is specced to carry.
	//
	// An earlier default of 2,000/sec did exactly that, and the load test
	// found it — a tenant sending what the product promises to handle was
	// answered with 429s. The ceiling exists to stop one tenant taking the
	// service down for its neighbours, and at 10,000/sec the service is at
	// its stated capacity anyway, so that is the right place for it.
	//
	// The burst is double, because providers deliver in bursts after their
	// own outages and a bucket that cannot absorb one turns a provider's
	// recovery into our refusal.
	perSecond, burst := o.PerTenantPerSecond, o.Burst
	if perSecond <= 0 {
		perSecond = 10000
	}
	if burst <= 0 {
		burst = 20000
	}
	r.limiter = ratelimit.New(ratelimit.Options{PerSecond: perSecond, Burst: burst, Now: o.Now})

	maxInFlight := o.MaxInFlight
	if maxInFlight <= 0 {
		maxInFlight = 2048
	}
	r.inFlight = ratelimit.NewBounded("receiver_in_flight", maxInFlight)
	if r.log == nil {
		r.log = slog.Default()
	}
	if r.now == nil {
		r.now = func() time.Time { return time.Now().UTC() }
	}
	if r.metrics == nil {
		r.metrics = metrics.New()
	}
	return r
}

// Handler returns the provider-facing mux.
func (r *Receiver) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/hooks/{tenant}/{provider}/{env}/{token}", r.handleWebhook)

	// Readiness for the receiver workload is exactly "can I write a raw
	// event", and deliberately says nothing about the dispatcher (§11.1).
	// A shared probe would take the receiver out of rotation for a
	// dispatcher fault and lose the events this design exists to protect.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok\n")
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, req *http.Request) {
		ctx, cancel := context.WithTimeout(req.Context(), 2*time.Second)
		defer cancel()
		if err := r.store.Health(ctx); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = fmt.Fprintf(w, "raw event store unavailable: %v\n", err)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ready\n")
	})
	return mux
}

type receiveResponse struct {
	Received  bool   `json:"received"`
	EventID   string `json:"event_id,omitempty"`
	Duplicate bool   `json:"duplicate,omitempty"`
}

func (r *Receiver) handleWebhook(w http.ResponseWriter, req *http.Request) {
	start := r.now()
	ctx := req.Context()

	// The concurrency ceiling is checked before anything else, including the
	// endpoint lookup: a flood large enough to matter is a flood we should
	// not be doing database work for.
	if !r.inFlight.TryAcquire() {
		r.metrics.Inc("statushub_payload_rejected_total", metrics.Labels{"reason": "at_capacity"})
		// One second, not a computed value: this ceiling clears in
		// milliseconds once the burst passes, and telling a provider to wait
		// longer would risk their own retry budget for no reason.
		w.Header().Set("Retry-After", "1")
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "at_capacity"})
		return
	}
	defer r.inFlight.Release()
	r.metrics.Set("statushub_receiver_in_flight", nil, float64(r.inFlight.InUse()))

	tenantSlug := req.PathValue("tenant")
	provider := req.PathValue("provider")
	env := req.PathValue("env")
	token := req.PathValue("token")

	endpoint, tenant, err := r.store.ResolveReceiver(ctx, tenantSlug, provider, env, token)
	if err != nil {
		// An unresolvable URL gets 404 and nothing else. Distinguishing
		// "no such tenant" from "wrong token" would let someone enumerate
		// which tenants exist, one request at a time.
		r.metrics.Inc("statushub_payload_rejected_total", metrics.Labels{"reason": "unknown_endpoint"})
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found"})
		return
	}
	if !endpoint.Enabled {
		// 404 again, not 403. A disabled endpoint should look exactly like
		// one that was never created.
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found"})
		return
	}

	// Per-tenant backpressure, after the endpoint resolves so the limit is
	// keyed on the tenant rather than on an unauthenticated caller — an
	// attacker must not be able to consume a tenant's allowance by posting
	// nonsense at a URL they guessed.
	if d := r.limiter.Allow(tenant.ID); !d.Allowed {
		r.metrics.Inc("statushub_payload_rejected_total", metrics.Labels{
			"reason": "rate_limited", "provider": endpoint.Provider,
		})
		r.log.WarnContext(ctx, "tenant is over its receive rate limit; the provider is being told to retry",
			"tenant", tenant.ID, "provider", endpoint.Provider,
			"retry_after", d.RetryAfter, "limit", d.Limit)
		// A 429 with Retry-After, never a silent queue. Providers honour it,
		// and the alternative — accepting until we fall over — loses events
		// for every tenant rather than delaying them for one.
		w.Header().Set("Retry-After", d.Header())
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate_limited"})
		return
	}

	body, err := readBody(req)
	if err != nil {
		reason := "unreadable"
		status := http.StatusBadRequest
		if errors.Is(err, errBodyTooLarge) {
			reason, status = "too_large", http.StatusRequestEntityTooLarge
		}
		r.metrics.Inc("statushub_payload_rejected_total", metrics.Labels{"reason": reason, "provider": provider})
		r.log.WarnContext(ctx, "rejected provider payload",
			"provider", provider, "tenant", tenant.ID, "reason", reason)
		writeJSON(w, status, map[string]string{"error": reason})
		return
	}

	sourceIP := r.sourceAddr(req)

	// The hash covers the bytes that arrived, before any redaction. It is the
	// dedupe key for providers with no event ID, and the proof of what was
	// received even where the stored copy has been altered.
	sum := sha256.Sum256(body)
	bodyHash := hex.EncodeToString(sum[:])

	// Verification runs against the original bytes below; only what is
	// stored is redacted. Doing it the other way round would fail every
	// signature the moment a provider put a card number in a description
	// field.
	scan := redact.Scan(body)

	raw := domain.RawEvent{
		ID:            domain.NewID(domain.PrefixRawEvent),
		TenantID:      tenant.ID,
		EndpointID:    endpoint.ID,
		Provider:      endpoint.Provider,
		Headers:       sanitiseHeaders(req.Header),
		Body:          scan.Body,
		BodySHA256:    bodyHash,
		Redacted:      scan.Redacted,
		RedactionNote: scan.Describe(),
		SourceIP:      sourceIP,
		ReceivedAt:    start,
	}
	if scan.Redacted {
		r.metrics.Inc("statushub_payload_rejected_total", metrics.Labels{
			"reason": "pan_redacted", "provider": endpoint.Provider,
		})
		// Warn, not error: nothing is broken and the event is intact. It is
		// worth an operator noticing, because a provider that starts sending
		// card data is a conversation to have with that provider.
		r.log.WarnContext(ctx, "card data removed from a provider payload before storage",
			"provider", endpoint.Provider, "tenant", tenant.ID, "endpoint", endpoint.ID,
			"detail", scan.Describe())
	}

	// Verification. Failure does not stop the event being stored (§10.1):
	// discarding a forgery destroys the evidence of an attack in progress,
	// and forwarding it is the vulnerability. Stored and flagged gives the
	// security team the whole record while guaranteeing the customer's system
	// never sees one.
	if err := r.verify(ctx, endpoint, req.Header, body, sourceIP); err != nil {
		raw.SignatureValid = false
		raw.SignatureError = err.Error()
	} else {
		raw.SignatureValid = true
	}

	writeStart := r.now()
	err = r.store.PutRawEvent(ctx, raw)
	writeTook := r.now().Sub(writeStart)

	// Measured separately from the total. In an edge region this is the
	// cross-region hop and everything else is not, so one histogram covering
	// both would make a network problem look like a code problem.
	r.metrics.Observe("statushub_store_write_duration_seconds",
		metrics.Labels{"region": r.region}, writeTook)
	if writeTook > r.writeBudget {
		r.metrics.Inc("statushub_store_write_over_budget_total",
			metrics.Labels{"region": r.region, "provider": endpoint.Provider})
	}

	if err != nil {
		// The one failure worth a 500. The provider will retry, which is
		// exactly what we want: better a duplicate we can dedupe than an
		// event nobody has a record of.
		r.log.ErrorContext(ctx, "could not persist raw event",
			"provider", endpoint.Provider, "tenant", tenant.ID, "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "storage_unavailable"})
		return
	}

	r.metrics.Inc("statushub_webhooks_received_total", metrics.Labels{
		"provider":        endpoint.Provider,
		"tenant":          tenant.ID,
		"region":          r.region,
		"signature_valid": fmt.Sprintf("%t", raw.SignatureValid),
	})

	if !raw.SignatureValid {
		r.metrics.Inc("statushub_signature_failures_total", metrics.Labels{
			"provider":        endpoint.Provider,
			"source_ip_class": classifyIP(sourceIP),
		})
		// Logged at warn with the source, because a burst from one address is
		// a paging alert and the operator's first question is where from.
		r.log.WarnContext(ctx, "signature verification failed",
			"provider", endpoint.Provider, "tenant", tenant.ID, "endpoint", endpoint.ID,
			"source_ip", sourceIP.String(), "raw_event", raw.ID, "reason", raw.SignatureError)

		r.audit(ctx, domain.AuditRecord{
			TenantID:  tenant.ID,
			EventType: domain.AuditSignatureFailed,
			Actor:     domain.Actor{Type: domain.ActorSystem, IP: sourceIP.String()},
			Subject:   domain.Subject{Type: "raw_event", ID: raw.ID},
			Payload: map[string]any{
				"provider": endpoint.Provider,
				"endpoint": endpoint.ID,
				// The reason is recorded here, where only the operator sees
				// it. It is never in the response (§7.1).
				"reason": raw.SignatureError,
			},
		})

		r.observeDuration(start, endpoint.Provider)
		// 401 with no detail. Telling a forger which part of their signature
		// was wrong turns this endpoint into an oracle they can tune against.
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "signature_verification_failed"})
		return
	}

	r.audit(ctx, domain.AuditRecord{
		TenantID:  tenant.ID,
		EventType: domain.AuditEventReceived,
		Actor:     domain.Actor{Type: domain.ActorSystem, IP: sourceIP.String()},
		Subject:   domain.Subject{Type: "raw_event", ID: raw.ID},
		Payload: map[string]any{
			"provider":    endpoint.Provider,
			"endpoint":    endpoint.ID,
			"body_sha256": bodyHash,
			"bytes":       len(body),
		},
	})

	r.observeDuration(start, endpoint.Provider)

	// The response goes out before normalisation is even scheduled. Nothing
	// below this line may block on downstream work.
	writeJSON(w, http.StatusOK, receiveResponse{Received: true, EventID: raw.ID})

	if r.notify != nil {
		r.notify.Notify(raw.ID)
	}
}

func (r *Receiver) observeDuration(start time.Time, provider string) {
	r.metrics.Observe("statushub_receive_duration_seconds",
		metrics.Labels{"provider": provider, "region": r.region}, r.now().Sub(start))
}

// verify runs the endpoint's adapter against the request, trying every
// currently-valid secret so a rotation with an overlap window does not reject
// events signed with the outgoing secret (§8.2).
func (r *Receiver) verify(ctx context.Context, e domain.Endpoint, h http.Header, body []byte, src netip.Addr) error {
	a, err := r.registry.Get(e.TenantID, e.AdapterName)
	if err != nil {
		return fmt.Errorf("adapter %q is not available: %w", e.AdapterName, err)
	}

	// Providers with no signature scheme at all are gated on source address
	// instead. It is a weaker control and the endpoint had to opt into it.
	if sr, ok := a.(adapter.SourceRestricted); ok {
		if err := checkSource(src, allowedRanges(e, sr)); err != nil {
			return err
		}
	}

	secrets, err := r.secrets.ResolveAll(ctx, e.SecretRef)
	if err != nil {
		return fmt.Errorf("secret %q did not resolve: %w", e.SecretRef, err)
	}

	var last error
	for _, s := range secrets {
		if last = a.Verify(h, body, s); last == nil {
			return nil
		}
	}
	if last == nil {
		last = adapter.ErrNoSignature
	}
	return last
}

func allowedRanges(e domain.Endpoint, sr adapter.SourceRestricted) []string {
	if len(e.AllowedSourceCIDRs) > 0 {
		// A tenant's own list wins: providers add egress ranges without
		// announcing them, and waiting for a StatusHub release to accept a
		// new one would mean dropped events.
		return e.AllowedSourceCIDRs
	}
	return sr.AllowedSources()
}

func checkSource(src netip.Addr, cidrs []string) error {
	if !src.IsValid() {
		return adapter.Failf(adapter.ErrSourceNotAllowed, "no usable source address")
	}
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(strings.TrimSpace(c))
		if err != nil {
			continue
		}
		if p.Contains(src) {
			return nil
		}
	}
	return adapter.Failf(adapter.ErrSourceNotAllowed, "%s is not in the published ranges", src)
}

var errBodyTooLarge = errors.New("payload exceeds the maximum size")

// readBody reads at most MaxBodyBytes+1 and rejects anything that reaches the
// ceiling.
//
// Reading one byte past the limit is how the difference between "exactly at
// the limit" and "over it" is detected without trusting Content-Length. Go's
// http.MaxBytesReader would also work, but it writes a 413 itself, and this
// handler needs to count the rejection and log the provider first.
func readBody(req *http.Request) ([]byte, error) {
	defer func() { _ = req.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(req.Body, MaxBodyBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > MaxBodyBytes {
		return nil, errBodyTooLarge
	}
	if len(body) == 0 {
		return nil, errors.New("empty body")
	}
	return body, nil
}

// sensitiveHeaders are never stored.
//
// Storing a signature header beside the exact body it signs is storing a
// replay kit: anyone who reaches the database can resend the pair to any
// receiver that trusts that secret. The value adds nothing to an
// investigation that the signature_valid flag does not already record.
var sensitiveHeaders = map[string]struct{}{
	"authorization":           {},
	"proxy-authorization":     {},
	"cookie":                  {},
	"set-cookie":              {},
	"x-paystack-signature":    {},
	"verif-hash":              {},
	"verify-hash":             {},
	"stripe-signature":        {},
	"x-monnify-signature":     {},
	"x-interswitch-signature": {},
	"x-nibss-signature":       {},
	"x-api-key":               {},
	"x-auth-token":            {},
}

func sanitiseHeaders(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, vs := range h {
		lk := strings.ToLower(k)
		if _, bad := sensitiveHeaders[lk]; bad {
			// Recorded as present-and-redacted rather than omitted, so an
			// investigator can tell a request that carried no signature from
			// one whose signature we chose not to keep.
			out[lk] = "[redacted]"
			continue
		}
		if len(vs) == 0 {
			continue
		}
		v := vs[0]
		if len(v) > 1024 {
			v = v[:1024]
		}
		// CR and LF are stripped from every stored value. They are stripped
		// again on the way out when a header is forwarded (§10); doing it in
		// both places means neither has to trust the other.
		out[lk] = strings.NewReplacer("\r", "", "\n", "").Replace(v)
	}
	return out
}

// sourceAddr resolves the client address, believing X-Forwarded-For only when
// the deployment says there is a proxy in front.
func (r *Receiver) sourceAddr(req *http.Request) netip.Addr {
	if r.trustProxyHeaders {
		if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
			// The left-most entry is the original client. Behind exactly one
			// trusted proxy this is right; behind a chain the deployment is
			// responsible for collapsing it, which is stated in the runbook
			// rather than guessed at here.
			first, _, _ := strings.Cut(xff, ",")
			if a, err := netip.ParseAddr(strings.TrimSpace(first)); err == nil {
				return a
			}
		}
	}
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		host = req.RemoteAddr
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return a.Unmap()
}

// classifyIP labels the signature-failure metric without putting a raw
// address into it. An address is high-cardinality and, from a scanner, close
// to unbounded — the label would be the thing that takes the scrape endpoint
// down during exactly the incident it exists to surface. The full address is
// in the log line and the audit record.
func classifyIP(a netip.Addr) string {
	switch {
	case !a.IsValid():
		return "unknown"
	case a.IsLoopback():
		return "loopback"
	case a.IsPrivate():
		return "private"
	case a.IsLinkLocalUnicast(), a.IsLinkLocalMulticast():
		return "link_local"
	case a.Is4():
		return "public_v4"
	default:
		return "public_v6"
	}
}

func (r *Receiver) audit(ctx context.Context, rec domain.AuditRecord) {
	if err := r.store.AppendAudit(ctx, rec); err != nil {
		// An audit write that fails must not fail the request: the event is
		// already durable, and refusing it now would make the provider retry
		// something we successfully stored. It is logged at error because a
		// gap in the trail is a compliance finding.
		r.log.ErrorContext(ctx, "audit append failed",
			"tenant", rec.TenantID, "event_type", rec.EventType, "error", err)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
