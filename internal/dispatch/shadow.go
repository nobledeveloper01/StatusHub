package dispatch

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/nobledeveloper01/StatusHub/internal/domain"
)

// Shadow mode forwards each event to the customer's existing handler *and*
// their new canonical one, then reports where the two disagree.
//
// The objection that actually blocks these deals is not price or features.
// It is "I cannot risk switching my webhook handler" — which is entirely
// reasonable, because the handler is load-bearing and the failure mode is
// silent. Shadow mode turns the decision from a cutover into an observation
// period: run both for a fortnight, look at the divergence report, and switch
// when the report is boring.
//
// It also finds real bugs in the *old* handler, which is a conversation worth
// having before anybody blames the new one.

// ShadowConfig describes a comparison run.
type ShadowConfig struct {
	// Control is the customer's existing per-provider handler, which keeps
	// receiving the provider's raw payload exactly as it does today.
	Control string

	// Candidate is their new handler, receiving the canonical shape.
	Candidate string

	// Enabled turns comparison on. Off by default: shadow mode doubles the
	// requests a customer's infrastructure receives, and that is their
	// decision to make explicitly.
	Enabled bool
}

// Divergence is one disagreement between the two handlers.
type Divergence struct {
	EventID        string    `json:"event_id"`
	Provider       string    `json:"provider"`
	TransactionRef string    `json:"transaction_ref"`
	ObservedAt     time.Time `json:"observed_at"`

	ControlStatus   int `json:"control_status"`
	CandidateStatus int `json:"candidate_status"`

	ControlDuration   time.Duration `json:"control_duration"`
	CandidateDuration time.Duration `json:"candidate_duration"`

	// Kind names what disagreed, so a report can be grouped rather than read
	// line by line.
	Kind string `json:"kind"`

	// Detail is the sentence somebody reads during the go/no-go meeting.
	Detail string `json:"detail"`
}

// Divergence kinds.
const (
	DivergeCandidateRejected = "candidate_rejected"
	DivergeControlRejected   = "control_rejected"
	DivergeBothRejected      = "both_rejected"
	DivergeCandidateSlower   = "candidate_slower"
)

// slowerBy is the factor at which a latency difference is worth reporting.
//
// Three times, and only above a floor. A candidate that takes 6 ms where the
// control takes 2 ms is three times slower and completely irrelevant;
// reporting it would bury the case where the candidate takes four seconds.
const (
	slowerBy     = 3
	slowestFloor = 250 * time.Millisecond
)

// ShadowResult is one event compared.
type ShadowResult struct {
	EventID      string
	Agreed       bool
	Divergence   *Divergence
	ControlErr   error
	CandidateErr error
}

// Shadower runs both handlers and compares them.
type Shadower struct {
	client *http.Client

	mu          sync.Mutex
	compared    int64
	agreed      int64
	divergences []Divergence

	// maxRetained bounds the report. A run over a fortnight on a busy tenant
	// could otherwise accumulate a divergence list nobody can read and this
	// process cannot hold.
	maxRetained int

	now func() time.Time
}

// ShadowOptions configure a Shadower.
type ShadowOptions struct {
	Client      *http.Client
	MaxRetained int
	Now         func() time.Time
}

// NewShadower builds a Shadower.
func NewShadower(o ShadowOptions) *Shadower {
	s := &Shadower{client: o.Client, maxRetained: o.MaxRetained, now: o.Now}
	if s.client == nil {
		s.client = &http.Client{Timeout: 15 * time.Second}
	}
	if s.maxRetained <= 0 {
		s.maxRetained = 500
	}
	if s.now == nil {
		s.now = func() time.Time { return time.Now().UTC() }
	}
	return s
}

// Compare posts to both handlers and records any disagreement.
//
// The two requests go out concurrently. Sequentially, the second handler
// would always look slower by the first one's latency, which would make every
// latency comparison meaningless — and latency is one of the two things a
// customer is actually deciding on.
func (s *Shadower) Compare(ctx context.Context, cfg ShadowConfig, e domain.CanonicalEvent, rawBody []byte) ShadowResult {
	res := ShadowResult{EventID: e.ID, Agreed: true}

	canonical, err := json.Marshal(BuildPayload(e, nil))
	if err != nil {
		res.CandidateErr = err
		return res
	}

	type outcome struct {
		status   int
		duration time.Duration
		err      error
	}
	var (
		wg                 sync.WaitGroup
		control, candidate outcome
	)

	post := func(url string, body []byte, dst *outcome) {
		defer wg.Done()
		start := s.now()
		status, err := s.post(ctx, url, body)
		dst.status, dst.duration, dst.err = status, s.now().Sub(start), err
	}

	wg.Add(2)
	// The control receives the provider's raw payload, unchanged: it is the
	// handler that exists today and it must see exactly what it sees today,
	// or the comparison is measuring our transformation rather than their
	// two handlers.
	go post(cfg.Control, rawBody, &control)
	go post(cfg.Candidate, canonical, &candidate)
	wg.Wait()

	res.ControlErr, res.CandidateErr = control.err, candidate.err

	d := Divergence{
		EventID: e.ID, Provider: e.Provider, TransactionRef: e.TransactionRef,
		ObservedAt:      s.now(),
		ControlStatus:   control.status,
		CandidateStatus: candidate.status,
		ControlDuration: control.duration, CandidateDuration: candidate.duration,
	}

	controlOK := control.err == nil && domain.IsSuccess(control.status)
	candidateOK := candidate.err == nil && domain.IsSuccess(candidate.status)

	switch {
	case !controlOK && !candidateOK:
		// Both failing usually means the event itself is unusual, or both
		// handlers are down. Worth reporting, and worth not blaming the
		// candidate for.
		d.Kind = DivergeBothRejected
		d.Detail = fmt.Sprintf("both handlers rejected this event (control %d, candidate %d), "+
			"which usually means the event is unusual rather than that either handler is wrong",
			control.status, candidate.status)

	case controlOK && !candidateOK:
		// The case the customer is watching for.
		d.Kind = DivergeCandidateRejected
		d.Detail = fmt.Sprintf("your existing handler accepted this event and the new one returned %d. "+
			"This is the case to investigate before switching.", candidate.status)

	case !controlOK && candidateOK:
		// The conversation worth having before anybody blames the new
		// handler: shadow mode finds bugs in the old one too.
		d.Kind = DivergeControlRejected
		d.Detail = fmt.Sprintf("the new handler accepted this event and your existing one returned %d. "+
			"Your current handler is dropping events like this today.", control.status)

	case candidate.duration > slowestFloor && candidate.duration > control.duration*slowerBy:
		d.Kind = DivergeCandidateSlower
		d.Detail = fmt.Sprintf("the new handler took %s against the existing one's %s",
			candidate.duration.Round(time.Millisecond), control.duration.Round(time.Millisecond))

	default:
		s.record(true, nil)
		return res
	}

	res.Agreed = false
	res.Divergence = &d
	s.record(false, &d)
	return res
}

func (s *Shadower) post(ctx context.Context, url string, body []byte) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	// Marked, so a customer can tell a shadow delivery from a real one in
	// their own logs — and so a handler that wants to no-op during the
	// comparison can.
	req.Header.Set("X-StatusHub-Shadow", "true")

	resp, err := s.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	return resp.StatusCode, nil
}

func (s *Shadower) record(agreed bool, d *Divergence) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.compared++
	if agreed {
		s.agreed++
		return
	}
	if len(s.divergences) < s.maxRetained {
		s.divergences = append(s.divergences, *d)
	}
}

// Report is what a customer reads at the go/no-go meeting.
type Report struct {
	Compared int64 `json:"compared"`
	Agreed   int64 `json:"agreed"`

	// AgreementRate is the number somebody will quote in the meeting, so it
	// is computed here rather than left to be derived — and rounded the same
	// way every time.
	AgreementRate float64 `json:"agreement_rate"`

	ByKind      map[string]int `json:"by_kind"`
	Divergences []Divergence   `json:"divergences,omitempty"`
	Truncated   bool           `json:"truncated"`

	// Verdict is a sentence, not a score. The decision is "do we switch", and
	// a percentage on its own does not answer it.
	Verdict string `json:"verdict"`
}

// Report summarises the run.
func (s *Shadower) Report() Report {
	s.mu.Lock()
	defer s.mu.Unlock()

	r := Report{
		Compared: s.compared, Agreed: s.agreed,
		ByKind:      map[string]int{},
		Divergences: append([]Divergence(nil), s.divergences...),
		Truncated:   int64(len(s.divergences)) < s.compared-s.agreed,
	}
	if s.compared > 0 {
		r.AgreementRate = float64(s.agreed) / float64(s.compared)
	}
	for _, d := range s.divergences {
		r.ByKind[d.Kind]++
	}
	sort.Slice(r.Divergences, func(i, j int) bool {
		return r.Divergences[i].ObservedAt.Before(r.Divergences[j].ObservedAt)
	})
	r.Verdict = verdict(r)
	return r
}

// verdict turns the numbers into the sentence somebody needs.
//
// The distinction that matters is *which* divergences occurred, not how many.
// A hundred cases where the old handler rejected an event the new one
// accepted is a reason to switch sooner. One case the other way is a reason
// to wait.
func verdict(r Report) string {
	switch {
	case r.Compared == 0:
		return "no events compared yet. Leave shadow mode running until you have seen a normal week, " +
			"including whatever your month-end looks like."

	case r.ByKind[DivergeCandidateRejected] > 0:
		return fmt.Sprintf("%d event(s) your existing handler accepted were rejected by the new one. "+
			"Investigate those before switching — they are the only divergences that represent a "+
			"regression.", r.ByKind[DivergeCandidateRejected])

	case r.ByKind[DivergeControlRejected] > 0:
		return fmt.Sprintf("no regressions. %d event(s) went the other way: your existing handler "+
			"rejected events the new one accepted, which means those are being dropped today.",
			r.ByKind[DivergeControlRejected])

	case r.ByKind[DivergeCandidateSlower] > 0:
		return fmt.Sprintf("no correctness divergences. %d event(s) were materially slower against the "+
			"new handler; check whether that matters at your volume.", r.ByKind[DivergeCandidateSlower])

	case r.Compared < 100:
		return fmt.Sprintf("no divergences across %d events, which is a good sign and not yet a large "+
			"sample. Keep it running.", r.Compared)

	default:
		return fmt.Sprintf("no divergences across %d events. The new handler agrees with your existing "+
			"one on everything seen so far.", r.Compared)
	}
}

// Text renders the report for a terminal.
func (r Report) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "compared %d events, %d agreed (%.2f%%)\n\n",
		r.Compared, r.Agreed, r.AgreementRate*100)

	if len(r.ByKind) > 0 {
		for _, kind := range []string{
			DivergeCandidateRejected, DivergeControlRejected, DivergeBothRejected, DivergeCandidateSlower,
		} {
			if n := r.ByKind[kind]; n > 0 {
				fmt.Fprintf(&b, "  %-22s %d\n", kind, n)
			}
		}
		fmt.Fprintln(&b)
	}
	if r.Truncated {
		fmt.Fprintf(&b, "  (only the first %d divergences are retained)\n\n", len(r.Divergences))
	}
	fmt.Fprintln(&b, r.Verdict)
	return b.String()
}
