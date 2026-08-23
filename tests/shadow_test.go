package tests

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nobledeveloper01/StatusHub/internal/dispatch"
	"github.com/nobledeveloper01/StatusHub/internal/domain"
)

type handlerStub struct {
	mu      sync.Mutex
	server  *httptest.Server
	bodies  [][]byte
	headers []http.Header
	respond func(n int) int
	delay   time.Duration
}

func newHandlerStub(t *testing.T) *handlerStub {
	t.Helper()
	h := &handlerStub{respond: func(int) int { return http.StatusOK }}
	h.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 4096)
		n, _ := r.Body.Read(buf)

		h.mu.Lock()
		attempt := len(h.bodies)
		h.bodies = append(h.bodies, buf[:n])
		h.headers = append(h.headers, r.Header.Clone())
		respond, delay := h.respond, h.delay
		h.mu.Unlock()

		if delay > 0 {
			time.Sleep(delay)
		}
		w.WriteHeader(respond(attempt))
	}))
	t.Cleanup(h.server.Close)
	return h
}

func (h *handlerStub) set(f func(int) int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.respond = f
}

func (h *handlerStub) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.bodies)
}

func shadowEvent(ref string) domain.CanonicalEvent {
	return domain.CanonicalEvent{
		ID: domain.NewID(domain.PrefixEvent), TenantID: tenantA, Provider: "paystack",
		EventType: domain.EventPaymentCompleted, TransactionRef: ref,
		Status: domain.StatusSuccess, AmountMinor: 5000000, Currency: "NGN",
		OccurredAt: time.Now().UTC(), ReceivedAt: time.Now().UTC(), MappingComplete: true,
	}
}

func TestShadowSendsEachHandlerItsOwnShape(t *testing.T) {
	// The control must see exactly what it sees today, or the comparison is
	// measuring our transformation rather than the customer's two handlers.
	control, candidate := newHandlerStub(t), newHandlerStub(t)
	s := dispatch.NewShadower(dispatch.ShadowOptions{Client: control.server.Client()})

	rawBody := []byte(`{"event":"charge.success","data":{"reference":"TXN-1","status":"success"}}`)
	res := s.Compare(context.Background(), dispatch.ShadowConfig{
		Control: control.server.URL, Candidate: candidate.server.URL, Enabled: true,
	}, shadowEvent("TXN-1"), rawBody)

	if !res.Agreed {
		t.Fatalf("two healthy handlers disagreed: %+v", res.Divergence)
	}

	control.mu.Lock()
	got := string(control.bodies[0])
	shadowHeader := control.headers[0].Get("X-StatusHub-Shadow")
	control.mu.Unlock()
	if got != string(rawBody) {
		t.Fatalf("the control received a transformed payload:\n got: %s\nwant: %s", got, rawBody)
	}
	// Marked, so a customer can tell a shadow delivery from a real one in
	// their own logs.
	if shadowHeader != "true" {
		t.Errorf("shadow deliveries are not marked: %q", shadowHeader)
	}

	candidate.mu.Lock()
	canonical := string(candidate.bodies[0])
	candidate.mu.Unlock()
	if !strings.Contains(canonical, `"amount_minor":5000000`) {
		t.Errorf("the candidate did not receive the canonical shape: %s", canonical)
	}
}

func TestShadowFlagsTheRegressionCase(t *testing.T) {
	// The one divergence that is a reason not to switch.
	control, candidate := newHandlerStub(t), newHandlerStub(t)
	candidate.set(func(int) int { return http.StatusBadRequest })

	s := dispatch.NewShadower(dispatch.ShadowOptions{Client: control.server.Client()})
	res := s.Compare(context.Background(), dispatch.ShadowConfig{
		Control: control.server.URL, Candidate: candidate.server.URL,
	}, shadowEvent("TXN-1"), []byte(`{}`))

	if res.Agreed || res.Divergence == nil {
		t.Fatal("a candidate rejection was not flagged")
	}
	if res.Divergence.Kind != dispatch.DivergeCandidateRejected {
		t.Errorf("kind = %q", res.Divergence.Kind)
	}
	if !strings.Contains(res.Divergence.Detail, "investigate before switching") {
		t.Errorf("detail = %q", res.Divergence.Detail)
	}

	r := s.Report()
	if !strings.Contains(r.Verdict, "regression") {
		t.Errorf("the verdict does not name this as a regression: %q", r.Verdict)
	}
}

func TestShadowFindsBugsInTheExistingHandlerToo(t *testing.T) {
	// The conversation worth having before anybody blames the new handler.
	control, candidate := newHandlerStub(t), newHandlerStub(t)
	control.set(func(int) int { return http.StatusInternalServerError })

	s := dispatch.NewShadower(dispatch.ShadowOptions{Client: control.server.Client()})
	res := s.Compare(context.Background(), dispatch.ShadowConfig{
		Control: control.server.URL, Candidate: candidate.server.URL,
	}, shadowEvent("TXN-1"), []byte(`{}`))

	if res.Divergence == nil || res.Divergence.Kind != dispatch.DivergeControlRejected {
		t.Fatalf("divergence = %+v", res.Divergence)
	}
	if !strings.Contains(res.Divergence.Detail, "dropping events like this today") {
		t.Errorf("detail = %q", res.Divergence.Detail)
	}

	// And this must not read as a reason to delay: it is a reason to switch
	// sooner.
	r := s.Report()
	if !strings.Contains(r.Verdict, "no regressions") {
		t.Errorf("the verdict treats an existing-handler bug as a blocker: %q", r.Verdict)
	}
}

func TestShadowDoesNotBlameTheCandidateWhenBothFail(t *testing.T) {
	control, candidate := newHandlerStub(t), newHandlerStub(t)
	control.set(func(int) int { return http.StatusBadRequest })
	candidate.set(func(int) int { return http.StatusBadRequest })

	s := dispatch.NewShadower(dispatch.ShadowOptions{Client: control.server.Client()})
	res := s.Compare(context.Background(), dispatch.ShadowConfig{
		Control: control.server.URL, Candidate: candidate.server.URL,
	}, shadowEvent("TXN-1"), []byte(`{}`))

	if res.Divergence == nil || res.Divergence.Kind != dispatch.DivergeBothRejected {
		t.Fatalf("divergence = %+v", res.Divergence)
	}
	if !strings.Contains(res.Divergence.Detail, "unusual rather than") {
		t.Errorf("detail = %q", res.Divergence.Detail)
	}
	// A both-failed case must not appear as a regression in the verdict.
	if strings.Contains(s.Report().Verdict, "regression") {
		t.Error("both handlers failing was reported as a candidate regression")
	}
}

func TestShadowIgnoresIrrelevantLatencyDifferences(t *testing.T) {
	// A candidate taking 6ms where the control takes 2ms is three times
	// slower and completely irrelevant. Reporting it would bury the case
	// where the candidate takes four seconds.
	control, candidate := newHandlerStub(t), newHandlerStub(t)
	candidate.mu.Lock()
	candidate.delay = 30 * time.Millisecond
	candidate.mu.Unlock()

	s := dispatch.NewShadower(dispatch.ShadowOptions{Client: control.server.Client()})
	res := s.Compare(context.Background(), dispatch.ShadowConfig{
		Control: control.server.URL, Candidate: candidate.server.URL,
	}, shadowEvent("TXN-1"), []byte(`{}`))

	if !res.Agreed {
		t.Fatalf("a 30ms difference was reported as a divergence: %+v", res.Divergence)
	}
}

func TestShadowRunsBothConcurrently(t *testing.T) {
	// Sequentially, the second handler always looks slower by the first one's
	// latency, which makes every latency comparison meaningless — and latency
	// is one of the two things the customer is deciding on.
	control, candidate := newHandlerStub(t), newHandlerStub(t)
	for _, h := range []*handlerStub{control, candidate} {
		h.mu.Lock()
		h.delay = 200 * time.Millisecond
		h.mu.Unlock()
	}

	s := dispatch.NewShadower(dispatch.ShadowOptions{Client: control.server.Client()})
	start := time.Now()
	s.Compare(context.Background(), dispatch.ShadowConfig{
		Control: control.server.URL, Candidate: candidate.server.URL,
	}, shadowEvent("TXN-1"), []byte(`{}`))
	elapsed := time.Since(start)

	if elapsed > 350*time.Millisecond {
		t.Fatalf("the two handlers took %s in total; they should run concurrently", elapsed)
	}
	if control.count() != 1 || candidate.count() != 1 {
		t.Errorf("control %d, candidate %d", control.count(), candidate.count())
	}
}

func TestShadowReportIsTheGoNoGoDocument(t *testing.T) {
	control, candidate := newHandlerStub(t), newHandlerStub(t)
	s := dispatch.NewShadower(dispatch.ShadowOptions{Client: control.server.Client()})
	ctx := context.Background()
	cfg := dispatch.ShadowConfig{Control: control.server.URL, Candidate: candidate.server.URL}

	for i := 0; i < 10; i++ {
		s.Compare(ctx, cfg, shadowEvent("TXN"), []byte(`{}`))
	}

	r := s.Report()
	if r.Compared != 10 || r.Agreed != 10 {
		t.Fatalf("report = %+v", r)
	}
	if r.AgreementRate != 1 {
		t.Errorf("agreement rate = %v", r.AgreementRate)
	}
	// A small clean sample is a good sign and not yet a decision.
	if !strings.Contains(r.Verdict, "not yet a large sample") {
		t.Errorf("the verdict oversells ten events: %q", r.Verdict)
	}

	text := r.Text()
	if !strings.Contains(text, "compared 10 events") {
		t.Errorf("the rendered report is not readable: %q", text)
	}
}

func TestShadowBoundsWhatItRetains(t *testing.T) {
	// A fortnight on a busy tenant would otherwise accumulate a divergence
	// list nobody can read and this process cannot hold.
	control, candidate := newHandlerStub(t), newHandlerStub(t)
	candidate.set(func(int) int { return http.StatusBadRequest })

	s := dispatch.NewShadower(dispatch.ShadowOptions{
		Client: control.server.Client(), MaxRetained: 5,
	})
	ctx := context.Background()
	cfg := dispatch.ShadowConfig{Control: control.server.URL, Candidate: candidate.server.URL}
	for i := 0; i < 20; i++ {
		s.Compare(ctx, cfg, shadowEvent("TXN"), []byte(`{}`))
	}

	r := s.Report()
	if r.Compared != 20 {
		t.Errorf("compared = %d", r.Compared)
	}
	if len(r.Divergences) != 5 {
		t.Fatalf("retained %d divergences, want the 5 cap", len(r.Divergences))
	}
	// And it says so, rather than quietly presenting five as the total.
	if !r.Truncated {
		t.Error("truncation was not reported")
	}
	if !strings.Contains(r.Text(), "only the first 5") {
		t.Errorf("the rendered report does not admit truncation:\n%s", r.Text())
	}
}
