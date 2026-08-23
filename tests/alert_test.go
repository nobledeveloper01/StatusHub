package tests

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nobledeveloper01/StatusHub/internal/alert"
)

type capturingSink struct {
	mu       sync.Mutex
	name     string
	batches  [][]alert.Alert
	failWith error
}

func (s *capturingSink) Name() string { return s.name }

func (s *capturingSink) Deliver(_ context.Context, alerts []alert.Alert) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failWith != nil {
		return s.failWith
	}
	s.batches = append(s.batches, append([]alert.Alert(nil), alerts...))
	return nil
}

func (s *capturingSink) all() [][]alert.Alert {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([][]alert.Alert(nil), s.batches...)
}

func TestAlertPagesGoImmediatelyAndWarningsAreBatched(t *testing.T) {
	// An alerting system that pages on warnings trains people to ignore
	// pages, and the first thing they stop reading is the one that matters.
	clock := &testClock{t: time.Date(2026, 8, 11, 9, 0, 0, 0, time.UTC)}
	sink := &capturingSink{name: "test"}
	r := alert.NewRouter(alert.RouterOptions{
		Sinks: []alert.Sink{sink}, DigestEvery: time.Hour, Now: clock.now,
	})
	ctx := context.Background()

	mustNoErr(t, r.Fire(ctx, alert.New(alert.ConditionUnknownStatus, tenantA, "paystack:part_settled",
		"paystack sent part_settled, which has no mapping", nil, clock.now())), "firing a warning")
	if len(sink.all()) != 0 {
		t.Fatal("a warning was delivered immediately instead of being batched")
	}
	if r.Pending() != 1 {
		t.Errorf("%d pending", r.Pending())
	}

	mustNoErr(t, r.Fire(ctx, alert.New(alert.ConditionAuditChain, tenantA, "",
		"the nightly chain walk failed", nil, clock.now())), "firing a page")
	batches := sink.all()
	if len(batches) != 1 || len(batches[0]) != 1 {
		t.Fatalf("a page was not delivered immediately: %+v", batches)
	}
	if batches[0][0].Severity != alert.SeverityPage {
		t.Errorf("severity = %q", batches[0][0].Severity)
	}
}

func TestAlertSeveritiesAreNotConfigurable(t *testing.T) {
	// A tenant who can downgrade "audit chain broken" to a digest entry will,
	// on the day it is noisy for an unrelated reason — and then it is a
	// warning nobody reads on the day it means what it says.
	for _, c := range []alert.Condition{
		alert.ConditionAuditChain, alert.ConditionSignatureFailures,
		alert.ConditionDeadLetters, alert.ConditionShardStalled,
		alert.ConditionReceiverLatency, alert.ConditionEndpointSilent,
	} {
		if alert.SeverityOf(c) != alert.SeverityPage {
			t.Errorf("%s should page, got %q", c, alert.SeverityOf(c))
		}
	}
	for _, c := range []alert.Condition{
		alert.ConditionUnknownStatus, alert.ConditionQueueDepth, alert.ConditionNormalisation,
	} {
		if alert.SeverityOf(c) != alert.SeverityWarn {
			t.Errorf("%s should warn, got %q", c, alert.SeverityOf(c))
		}
	}
}

func TestAlertDoesNotRenotifyWhileStillFiring(t *testing.T) {
	// Re-notifying every evaluation is how an alerting system teaches people
	// to filter it into a folder.
	clock := &testClock{t: time.Date(2026, 8, 11, 9, 0, 0, 0, time.UTC)}
	sink := &capturingSink{name: "test"}
	r := alert.NewRouter(alert.RouterOptions{
		Sinks: []alert.Sink{sink}, RenotifyAfter: 4 * time.Hour, Now: clock.now,
	})
	ctx := context.Background()

	fire := func() {
		mustNoErr(t, r.Fire(ctx, alert.New(alert.ConditionDeadLetters, tenantA, "dst_1",
			"dead letters are growing", nil, clock.now())), "firing")
	}

	fire()
	for i := 0; i < 20; i++ {
		clock.advance(5 * time.Minute)
		fire()
	}
	if n := len(sink.all()); n != 1 {
		t.Fatalf("delivered %d times for one continuously-firing condition", n)
	}

	// A repeat is only useful if the first was missed, so it waits hours.
	clock.advance(5 * time.Hour)
	fire()
	if n := len(sink.all()); n != 2 {
		t.Errorf("a long-firing condition never repeated: %d deliveries", n)
	}

	// And once cleared, the next occurrence notifies again.
	r.Clear(alert.ConditionDeadLetters, tenantA, "dst_1")
	fire()
	if n := len(sink.all()); n != 3 {
		t.Errorf("a resolved-then-recurring condition did not re-notify: %d", n)
	}
}

func TestAlertSameConditionDifferentSubjectsAreSeparate(t *testing.T) {
	// Two destinations failing is two problems, and collapsing them would
	// hide the second one entirely.
	clock := &testClock{t: time.Date(2026, 8, 11, 9, 0, 0, 0, time.UTC)}
	sink := &capturingSink{name: "test"}
	r := alert.NewRouter(alert.RouterOptions{Sinks: []alert.Sink{sink}, Now: clock.now})
	ctx := context.Background()

	for _, dest := range []string{"dst_1", "dst_2"} {
		mustNoErr(t, r.Fire(ctx, alert.New(alert.ConditionDeadLetters, tenantA, dest,
			"dead letters growing for "+dest, nil, clock.now())), "firing")
	}
	if n := len(sink.all()); n != 2 {
		t.Fatalf("%d deliveries for two distinct subjects", n)
	}
}

func TestAlertDigestGroupsByCondition(t *testing.T) {
	// Forty unknown statuses should read as one problem, not forty.
	clock := &testClock{t: time.Date(2026, 8, 11, 9, 0, 0, 0, time.UTC)}
	sink := &capturingSink{name: "test"}
	r := alert.NewRouter(alert.RouterOptions{
		Sinks: []alert.Sink{sink}, DigestEvery: time.Hour, Now: clock.now,
	})
	ctx := context.Background()

	for _, v := range []string{"part_settled", "settling", "on_hold"} {
		mustNoErr(t, r.Fire(ctx, alert.New(alert.ConditionUnknownStatus, tenantA, "paystack:"+v,
			"paystack sent "+v, nil, clock.now())), "firing")
	}
	mustNoErr(t, r.Fire(ctx, alert.New(alert.ConditionQueueDepth, tenantA, "shard-3",
		"shard 3 is deep", nil, clock.now())), "firing")

	clock.advance(2 * time.Hour)
	mustNoErr(t, r.FlushDigest(ctx), "flushing")

	batches := sink.all()
	if len(batches) != 1 {
		t.Fatalf("%d digests delivered", len(batches))
	}
	if len(batches[0]) != 4 {
		t.Fatalf("%d alerts in the digest, want 4", len(batches[0]))
	}
	text := alert.Format(batches[0])
	// Each condition's first action appears once, above its instances.
	if strings.Count(text, "Map it before it becomes a support ticket") != 1 {
		t.Errorf("the first action was repeated per instance:\n%s", text)
	}
	if !strings.Contains(text, "4 conditions") {
		t.Errorf("digest header = %q", text[:40])
	}
}

func TestAlertDigestWaitsForItsInterval(t *testing.T) {
	clock := &testClock{t: time.Date(2026, 8, 11, 9, 0, 0, 0, time.UTC)}
	sink := &capturingSink{name: "test"}
	r := alert.NewRouter(alert.RouterOptions{
		Sinks: []alert.Sink{sink}, DigestEvery: time.Hour, Now: clock.now,
	})
	ctx := context.Background()

	// An empty first flush establishes the interval.
	mustNoErr(t, r.FlushDigest(ctx), "priming")
	mustNoErr(t, r.Fire(ctx, alert.New(alert.ConditionUnknownStatus, tenantA, "x", "x", nil, clock.now())), "firing")

	clock.advance(30 * time.Minute)
	mustNoErr(t, r.FlushDigest(ctx), "early flush")
	if len(sink.all()) != 0 {
		t.Fatal("the digest went out before its interval elapsed")
	}

	clock.advance(31 * time.Minute)
	mustNoErr(t, r.FlushDigest(ctx), "flush")
	if len(sink.all()) != 1 {
		t.Fatal("the digest did not go out after its interval")
	}
}

func TestAlertEverySinkGetsItEvenIfOneFails(t *testing.T) {
	// An alert that reached Slack but not email is far better than one that
	// reached neither because email was down.
	clock := &testClock{t: time.Date(2026, 8, 11, 9, 0, 0, 0, time.UTC)}
	good := &capturingSink{name: "good"}
	bad := &capturingSink{name: "bad", failWith: context.DeadlineExceeded}
	r := alert.NewRouter(alert.RouterOptions{Sinks: []alert.Sink{bad, good}, Now: clock.now})

	mustNoErr(t, r.Fire(context.Background(), alert.New(alert.ConditionAuditChain, tenantA, "",
		"chain broken", nil, clock.now())), "one sink failing must not fail the alert")
	if len(good.all()) != 1 {
		t.Fatal("the working sink did not receive the alert")
	}
}

func TestAlertCarriesItsFirstAction(t *testing.T) {
	// An alert without a first action is a notification. The difference is
	// whether the person woken up knows what to do.
	for _, c := range []alert.Condition{
		alert.ConditionAuditChain, alert.ConditionShardStalled, alert.ConditionSignatureFailures,
		alert.ConditionEndpointSilent, alert.ConditionDeadLetters, alert.ConditionNormalisation,
	} {
		a := alert.New(c, tenantA, "", "something happened", nil, time.Now())
		if a.FirstAction == "" {
			t.Errorf("%s carries no first action", c)
		}
	}

	// And the runbooks are named where they exist.
	stalled := alert.New(alert.ConditionShardStalled, tenantA, "shard-3", "stalled", nil, time.Now())
	if !strings.Contains(stalled.FirstAction, "11.6") {
		t.Errorf("the shard-stalled action does not point at its runbook: %q", stalled.FirstAction)
	}
	normalisation := alert.New(alert.ConditionNormalisation, tenantA, "paystack", "failing", nil, time.Now())
	if !strings.Contains(normalisation.FirstAction, "raw bytes are safe") {
		t.Errorf("the normalisation action does not reassure first: %q", normalisation.FirstAction)
	}
}

func TestAlertWebhookSinkPostsSlackShape(t *testing.T) {
	var received map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&received)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink := &alert.WebhookSink{URL: srv.URL, Client: srv.Client(), SlackFormat: true}
	mustNoErr(t, sink.Deliver(context.Background(), []alert.Alert{
		alert.New(alert.ConditionAuditChain, tenantA, "", "the nightly chain walk failed", nil, time.Now()),
	}), "delivering")

	text, _ := received["text"].(string)
	if !strings.Contains(text, "audit_chain_broken") || !strings.Contains(text, "First action:") {
		t.Fatalf("the Slack payload is not usable: %q", text)
	}
}

func TestAlertWebhookSinkReportsAFailedPost(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	sink := &alert.WebhookSink{URL: srv.URL, Client: srv.Client()}
	if err := sink.Deliver(context.Background(), []alert.Alert{
		alert.New(alert.ConditionQueueDepth, tenantA, "", "deep", nil, time.Now()),
	}); err == nil {
		t.Fatal("a 500 from the alert webhook was reported as success")
	}
}

func TestAlertLogSinkAlwaysRecords(t *testing.T) {
	// During the kind of incident that fires a page, every external sink
	// being unreachable is a real possibility.
	var got string
	sink := &alert.LogSink{Write: func(_ alert.Severity, text string) { got = text }}
	mustNoErr(t, sink.Deliver(context.Background(), []alert.Alert{
		alert.New(alert.ConditionShardStalled, tenantA, "shard-3", "stalled for 20m", nil, time.Now()),
	}), "delivering")
	if !strings.Contains(got, "stalled for 20m") {
		t.Errorf("log sink wrote %q", got)
	}
}
