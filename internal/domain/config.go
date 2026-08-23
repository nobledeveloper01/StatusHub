package domain

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Environment separates a tenant's test traffic from its live traffic. They
// are different receiver URLs, different secrets and different API keys, so a
// leaked test credential can do nothing to live data (§8.2).
type Environment string

const (
	EnvTest Environment = "test"
	EnvLive Environment = "live"
)

// Valid reports whether e is one of the two.
func (e Environment) Valid() bool { return e == EnvTest || e == EnvLive }

func (e Environment) String() string { return string(e) }

// Tenant is one customer. StatusHub is multi-tenant from the first commit
// even while it has one customer, because retrofitting tenancy is a rewrite
// and building it in costs a day (§8.1).
type Tenant struct {
	ID        string
	Slug      string
	Name      string
	CreatedAt time.Time
}

// Endpoint is one receiver URL: one provider, one environment, one tenant.
// The provider is pointed at this and nothing else changes in the customer's
// codebase.
type Endpoint struct {
	ID          string
	TenantID    string
	Provider    string
	Environment Environment

	// ReceiverToken is the unguessable path segment. It is obscurity, not
	// authentication — the signature is the gate — and it is rotatable
	// without changing the shape of the URL (§10).
	ReceiverToken string

	// SecretRef points into the secret manager. The database holds a
	// reference, never a usable secret, so a database dump is not a
	// credential breach (§10.2).
	SecretRef string

	AdapterName string

	// AdapterConfig is set for declarative adapters and nil for built-in
	// ones. Adapters being configuration rather than code is what lets a
	// customer support a provider we have never heard of (§4.4).
	AdapterConfig []byte

	// AllowedSourceCIDRs is used only by providers that offer no signature at
	// all. It is a weaker guarantee than a signature and is documented to the
	// customer as one.
	AllowedSourceCIDRs []string

	Enabled   bool
	CreatedAt time.Time
	RotatedAt time.Time
}

// ReceiverPath is the path providers POST to (§7.1). Built here rather than
// formatted at each call site so the receiver's router and the dashboard's
// display can never drift apart.
func (e *Endpoint) ReceiverPath(tenantSlug string) string {
	return fmt.Sprintf("/v1/hooks/%s/%s/%s/%s", tenantSlug, e.Provider, e.Environment, e.ReceiverToken)
}

// RetryPolicy is the delivery backoff schedule (§3.2 C1). It is explicit data
// rather than a formula so that a tenant can see exactly when the next
// attempt happens, and so the schedule can be asserted in a test rather than
// re-derived.
type RetryPolicy struct {
	// Backoff is the wait before each attempt after the first. len(Backoff)+1
	// is the total number of attempts.
	Backoff []time.Duration

	// JitterFraction spreads retries so that a destination coming back after
	// an outage is not hit by every pending delivery in the same instant.
	JitterFraction float64

	// Timeout is how long one attempt may take. Bounded, like everything
	// else, because an unbounded HTTP client is a queue that stops moving.
	Timeout time.Duration
}

// DefaultRetryPolicy is the schedule from §3.2 C1: 0s, 10s, 1m, 5m, 30m, 2h,
// 6h. Roughly nine hours of trying, which covers a customer deploy gone wrong
// on a Friday evening without an engineer having to notice before Monday.
func DefaultRetryPolicy() RetryPolicy {
	return RetryPolicy{
		Backoff: []time.Duration{
			0,
			10 * time.Second,
			time.Minute,
			5 * time.Minute,
			30 * time.Minute,
			2 * time.Hour,
			6 * time.Hour,
		},
		JitterFraction: 0.2,
		Timeout:        10 * time.Second,
	}
}

// Attempts is the total number of delivery attempts the policy allows.
func (p RetryPolicy) Attempts() int { return len(p.Backoff) }

// Validate rejects a policy that would either never give up or hammer a
// destination. Both ceilings exist because the failure they prevent is a
// customer's endpoint being kept down by our retries.
func (p RetryPolicy) Validate() error {
	if len(p.Backoff) == 0 {
		return errors.New("retry policy must allow at least one attempt")
	}
	if len(p.Backoff) > 20 {
		return errors.New("retry policy must not exceed 20 attempts")
	}
	if p.JitterFraction < 0 || p.JitterFraction > 1 {
		return errors.New("jitter fraction must be between 0 and 1")
	}
	if p.Timeout <= 0 || p.Timeout > time.Minute {
		return errors.New("per-attempt timeout must be positive and at most one minute")
	}
	for i, d := range p.Backoff {
		if d < 0 {
			return fmt.Errorf("backoff step %d is negative", i)
		}
	}
	return nil
}

// Destination is one of the customer's endpoints we forward to. A tenant may
// have several — a ledger and an analytics sink, each with its own filter,
// retry state and dead-letter queue (§3.2 C4).
type Destination struct {
	ID       string
	TenantID string
	Name     string
	URL      string

	SigningSecretRef string

	Filter      Filter
	RetryPolicy RetryPolicy

	// IncludeRaw attaches the provider's original bytes to the forwarded
	// payload. Off by default: most handlers do not want it, and raw bodies
	// are the most sensitive thing we hold (§8.4).
	IncludeRaw bool

	// SchemaVersion pins the payload shape this destination receives. Empty
	// means the destination predates versioning and gets the original shape —
	// never the newest, because silently moving an existing handler onto a
	// new shape is the failure versioning exists to prevent.
	SchemaVersion string

	Enabled   bool
	CreatedAt time.Time
}

// Filter decides which canonical events a destination receives. Empty means
// everything, which is the common case and should not require configuration.
type Filter struct {
	Providers  []string    `json:"providers,omitempty"`
	EventTypes []EventType `json:"event_types,omitempty"`
	Statuses   []Status    `json:"statuses,omitempty"`

	// MinAmountMinor lets an analytics sink ignore the long tail. Zero means
	// no floor; a filter that excluded zero-amount events by default would
	// silently drop chargeback notifications.
	MinAmountMinor int64 `json:"min_amount_minor,omitempty"`
}

// Matches reports whether the event should be delivered to this destination.
// Every clause is an allowlist: an empty list matches everything, a populated
// one matches only what it names.
func (f Filter) Matches(e *CanonicalEvent) bool {
	if len(f.Providers) > 0 && !containsFold(f.Providers, e.Provider) {
		return false
	}
	if len(f.EventTypes) > 0 && !contains(f.EventTypes, e.EventType) {
		return false
	}
	if len(f.Statuses) > 0 && !contains(f.Statuses, e.Status) {
		return false
	}
	if f.MinAmountMinor > 0 && e.AmountMinor < f.MinAmountMinor {
		return false
	}
	return true
}

// Validate rejects filter clauses naming values that do not exist, which is
// otherwise a filter that silently matches nothing and a customer wondering
// where their events went.
func (f Filter) Validate() error {
	for _, t := range f.EventTypes {
		if !t.Valid() {
			return fmt.Errorf("%w: %q", ErrBadEventType, t)
		}
	}
	for _, s := range f.Statuses {
		if !s.Valid() {
			return fmt.Errorf("%w: %q", ErrBadStatus, s)
		}
	}
	if f.MinAmountMinor < 0 {
		return errors.New("minimum amount cannot be negative")
	}
	return nil
}

// ValidateDestinationURL enforces the transport rules a forwarding target
// must satisfy before it is even stored (§10, SSRF). This is the registration
// check only — the delivery-time check re-resolves DNS, because a hostname
// that resolved publicly at registration can resolve to 169.254.169.254 by
// the time we deliver, and validating once is exactly the hole that
// rebinding attacks walk through.
func ValidateDestinationURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("destination URL is not a URL: %w", err)
	}
	if u.Scheme != "https" {
		return errors.New("destination URL must be https")
	}
	if u.Host == "" {
		return errors.New("destination URL has no host")
	}
	if u.User != nil {
		return errors.New("destination URL must not embed credentials")
	}
	if strings.ContainsAny(raw, "\r\n") {
		return errors.New("destination URL contains a line break")
	}
	return nil
}

func contains[T comparable](xs []T, v T) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

func containsFold(xs []string, v string) bool {
	for _, x := range xs {
		if strings.EqualFold(x, v) {
			return true
		}
	}
	return false
}
