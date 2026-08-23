// Package alert routes the conditions from §11.4 to somewhere a person will
// see them.
//
// §11.4 defines eight alert conditions and assumes a Prometheus and an
// on-call rotation. Most fintechs at the size that buys this do not have
// either, and an alert nobody receives is the same as no alert. So the
// conditions are also delivered to a channel the tenant already reads.
//
// The design problem is not delivery, it is trust. An alerting system that
// pages on warnings trains people to ignore pages, and the first thing they
// stop reading is the one that matters. So: pages go through immediately and
// individually, warnings are batched into a digest, and a condition that is
// already firing does not re-notify until it clears.
package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// Severity decides how an alert is delivered.
type Severity string

const (
	// SeverityPage means somebody should look now. Delivered immediately.
	SeverityPage Severity = "page"

	// SeverityWarn means somebody should look today. Batched into a digest,
	// because a warning that interrupts is a warning that gets muted.
	SeverityWarn Severity = "warn"
)

// Condition names one of the §11.4 alerts.
type Condition string

const (
	ConditionReceiverLatency   Condition = "receiver_latency"
	ConditionSignatureFailures Condition = "signature_failure_spike"
	ConditionNormalisation     Condition = "normalisation_failures"
	ConditionUnknownStatus     Condition = "new_unknown_status"
	ConditionDeadLetters       Condition = "dead_letters_growing"
	ConditionShardStalled      Condition = "shard_stalled"
	ConditionQueueDepth        Condition = "queue_depth"
	ConditionAuditChain        Condition = "audit_chain_broken"
	ConditionEndpointSilent    Condition = "endpoint_silent"
	ConditionBreakerOpen       Condition = "destination_unreachable"
)

// severities are fixed rather than configurable.
//
// Deliberately. A tenant who can downgrade "audit chain broken" to a digest
// entry will, on the day it is noisy for an unrelated reason, and then it is
// a warning nobody reads on the day it means what it says.
var severities = map[Condition]Severity{
	ConditionReceiverLatency:   SeverityPage,
	ConditionSignatureFailures: SeverityPage,
	ConditionDeadLetters:       SeverityPage,
	ConditionShardStalled:      SeverityPage,
	ConditionAuditChain:        SeverityPage,
	ConditionEndpointSilent:    SeverityPage,
	ConditionNormalisation:     SeverityWarn,
	ConditionUnknownStatus:     SeverityWarn,
	ConditionQueueDepth:        SeverityWarn,
	ConditionBreakerOpen:       SeverityWarn,
}

// SeverityOf returns a condition's fixed severity.
func SeverityOf(c Condition) Severity {
	if s, ok := severities[c]; ok {
		return s
	}
	return SeverityWarn
}

// Alert is one firing condition.
type Alert struct {
	Condition Condition `json:"condition"`
	Severity  Severity  `json:"severity"`
	TenantID  string    `json:"tenant_id"`

	// Subject is what is affected — an endpoint, a destination, a shard — so
	// two instances of the same condition about different things are
	// separate alerts rather than one flapping.
	Subject string `json:"subject,omitempty"`

	Summary string `json:"summary"`

	// FirstAction is the §11.4 column that makes an alert usable. An alert
	// without one is a notification, and the difference is whether the person
	// woken up knows what to do.
	FirstAction string `json:"first_action"`

	Detail  map[string]any `json:"detail,omitempty"`
	FiredAt time.Time      `json:"fired_at"`
}

// Key identifies a firing condition for deduplication.
func (a Alert) Key() string {
	return string(a.Condition) + "|" + a.TenantID + "|" + a.Subject
}

// firstActions are the §11.4 first-action column, verbatim, because the value
// of that column is that somebody wrote it down calmly in advance.
var firstActions = map[Condition]string{
	ConditionReceiverLatency:   "Providers will begin retrying. Check store write latency.",
	ConditionSignatureFailures: "Possible forgery attempt, or a provider rotated a secret without notice. Check the endpoint's signature-failure view for the source.",
	ConditionNormalisation:     "The provider changed their payload. Runbook 11.5: the raw bytes are safe, correct the adapter and replay the window.",
	ConditionUnknownStatus:     "Map it before it becomes a support ticket. GET /v1/unknown-statuses shows the value and a sample event.",
	ConditionDeadLetters:       "The customer's endpoint is down and this is customer-impacting. Check the dead-letter view for the response body.",
	ConditionShardStalled:      "Head-of-line blocking. Runbook 11.6: find the blocking transaction reference and decide whether the destination is failing for that event or generally.",
	ConditionQueueDepth:        "Scale the dispatcher.",
	ConditionAuditChain:        "Security incident. Do not restart anything; preserve state and escalate.",
	ConditionEndpointSilent:    "Check that the receiver URL is still set in the provider's dashboard. Nothing has arrived where traffic is normally expected.",
	ConditionBreakerOpen:       "Deliveries are parked, not failing, and will resume when the destination answers. Confirm the customer knows their endpoint is down.",
}

// New builds an alert with its fixed severity and first action.
func New(c Condition, tenantID, subject, summary string, detail map[string]any, at time.Time) Alert {
	return Alert{
		Condition: c, Severity: SeverityOf(c), TenantID: tenantID, Subject: subject,
		Summary: summary, FirstAction: firstActions[c], Detail: detail, FiredAt: at,
	}
}

// Sink delivers alerts.
type Sink interface {
	Name() string
	Deliver(ctx context.Context, alerts []Alert) error
}

// Router decides what is delivered, when, and to whom.
type Router struct {
	mu sync.Mutex

	sinks []Sink

	// firing tracks conditions already notified, so a condition that stays
	// true does not re-notify every evaluation. Re-notifying is how an
	// alerting system teaches people to filter it into a folder.
	firing map[string]time.Time

	// pending holds warnings until the digest goes out.
	pending []Alert

	// renotifyAfter is how long a still-firing page waits before repeating.
	// Long, because a repeat is only useful if the first one was missed.
	renotifyAfter time.Duration

	digestEvery  time.Duration
	lastDigestAt time.Time

	now func() time.Time
}

// RouterOptions configure a Router.
type RouterOptions struct {
	Sinks         []Sink
	RenotifyAfter time.Duration
	DigestEvery   time.Duration
	Now           func() time.Time
}

// NewRouter builds a Router.
func NewRouter(o RouterOptions) *Router {
	r := &Router{
		sinks: o.Sinks, firing: map[string]time.Time{},
		renotifyAfter: o.RenotifyAfter, digestEvery: o.DigestEvery, now: o.Now,
	}
	if r.renotifyAfter <= 0 {
		r.renotifyAfter = 4 * time.Hour
	}
	if r.digestEvery <= 0 {
		r.digestEvery = time.Hour
	}
	if r.now == nil {
		r.now = func() time.Time { return time.Now().UTC() }
	}
	return r
}

// Fire routes one alert. Pages go immediately; warnings are batched.
func (r *Router) Fire(ctx context.Context, a Alert) error {
	r.mu.Lock()
	now := r.now()
	if a.FiredAt.IsZero() {
		a.FiredAt = now
	}

	key := a.Key()
	last, alreadyFiring := r.firing[key]
	if alreadyFiring && now.Sub(last) < r.renotifyAfter {
		r.mu.Unlock()
		return nil
	}
	r.firing[key] = now

	if a.Severity == SeverityWarn {
		r.pending = append(r.pending, a)
		r.mu.Unlock()
		return nil
	}
	r.mu.Unlock()

	return r.deliver(ctx, []Alert{a})
}

// Clear marks a condition resolved, so the next occurrence notifies again
// rather than being suppressed as a repeat.
func (r *Router) Clear(condition Condition, tenantID, subject string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.firing, string(condition)+"|"+tenantID+"|"+subject)
}

// FlushDigest delivers batched warnings if the interval has elapsed.
func (r *Router) FlushDigest(ctx context.Context) error {
	r.mu.Lock()
	now := r.now()
	if len(r.pending) == 0 {
		r.lastDigestAt = now
		r.mu.Unlock()
		return nil
	}
	if !r.lastDigestAt.IsZero() && now.Sub(r.lastDigestAt) < r.digestEvery {
		r.mu.Unlock()
		return nil
	}
	batch := r.pending
	r.pending = nil
	r.lastDigestAt = now
	r.mu.Unlock()

	// Grouped by condition, so a digest with forty unknown statuses reads as
	// one problem rather than forty.
	sort.Slice(batch, func(i, j int) bool {
		if batch[i].Condition != batch[j].Condition {
			return batch[i].Condition < batch[j].Condition
		}
		return batch[i].Subject < batch[j].Subject
	})
	return r.deliver(ctx, batch)
}

// Pending is how many warnings are waiting.
func (r *Router) Pending() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.pending)
}

func (r *Router) deliver(ctx context.Context, alerts []Alert) error {
	var failures []string
	for _, s := range r.sinks {
		if err := s.Deliver(ctx, alerts); err != nil {
			// One sink failing must not stop the others. An alert that
			// reached Slack but not email is far better than one that reached
			// neither because email was down.
			failures = append(failures, fmt.Sprintf("%s: %v", s.Name(), err))
		}
	}
	if len(failures) == len(r.sinks) && len(r.sinks) > 0 {
		return fmt.Errorf("every alert sink failed: %s", strings.Join(failures, "; "))
	}
	return nil
}

// Format renders alerts as text, used by every sink and by the CLI.
func Format(alerts []Alert) string {
	var b strings.Builder
	if len(alerts) == 1 {
		a := alerts[0]
		fmt.Fprintf(&b, "[%s] %s\n\n%s\n\nFirst action: %s\n",
			strings.ToUpper(string(a.Severity)), a.Condition, a.Summary, a.FirstAction)
		if a.Subject != "" {
			fmt.Fprintf(&b, "Affected: %s\n", a.Subject)
		}
		return b.String()
	}

	fmt.Fprintf(&b, "StatusHub digest — %d conditions\n\n", len(alerts))
	current := Condition("")
	for _, a := range alerts {
		if a.Condition != current {
			current = a.Condition
			fmt.Fprintf(&b, "%s\n  %s\n", a.Condition, a.FirstAction)
		}
		fmt.Fprintf(&b, "    · %s\n", a.Summary)
	}
	return b.String()
}

// WebhookSink posts alerts as JSON. It covers Slack, Teams and anything with
// an incoming webhook, which between them is most of what a fintech this size
// actually uses.
type WebhookSink struct {
	URL    string
	Client *http.Client

	// SlackFormat sends {"text": …} rather than the structured payload, which
	// is what Slack's incoming webhooks expect.
	SlackFormat bool
}

// Name identifies the sink.
func (s *WebhookSink) Name() string { return "webhook" }

// Deliver posts the alerts.
func (s *WebhookSink) Deliver(ctx context.Context, alerts []Alert) error {
	var payload any
	if s.SlackFormat {
		payload = map[string]string{"text": Format(alerts)}
	} else {
		payload = map[string]any{
			"alerts": alerts,
			"text":   Format(alerts),
		}
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	client := s.Client
	if client == nil {
		// Short, because an alert that takes thirty seconds to deliver is an
		// alert that arrives after somebody has already noticed.
		client = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("alert webhook returned %d", resp.StatusCode)
	}
	return nil
}

// LogSink writes alerts to the log. Always present, so an alert is recorded
// even when every external sink is unreachable — which, during the kind of
// incident that fires a page, is a real possibility.
type LogSink struct {
	Write func(severity Severity, text string)
}

// Name identifies the sink.
func (s *LogSink) Name() string { return "log" }

// Deliver writes the alerts.
func (s *LogSink) Deliver(_ context.Context, alerts []Alert) error {
	if s.Write == nil {
		return nil
	}
	severity := SeverityWarn
	for _, a := range alerts {
		if a.Severity == SeverityPage {
			severity = SeverityPage
			break
		}
	}
	s.Write(severity, Format(alerts))
	return nil
}
