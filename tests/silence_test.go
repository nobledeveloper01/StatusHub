package tests

import (
	"testing"
	"time"

	"github.com/nobledeveloper01/StatusHub/internal/silence"
)

// tuesday14 is a busy hour; sunday04 is a quiet one. The distinction is the
// whole reason the baseline is per hour of week.
var (
	tuesday14 = time.Date(2026, 8, 11, 14, 0, 0, 0, time.UTC)
	sunday04  = time.Date(2026, 8, 9, 4, 0, 0, 0, time.UTC)
)

func newDetector(now time.Time) (*silence.Detector, *testClock) {
	clock := &testClock{t: now}
	return silence.New(silence.Options{
		Sensitivity:        0.25,
		GraceAfterCreation: 7 * 24 * time.Hour,
		Now:                clock.now,
	}), clock
}

// train records `weeks` weeks of the given count at the given hour of week.
func train(d *silence.Detector, at time.Time, weeks int, count int64) {
	for w := weeks; w > 0; w-- {
		d.Observe("ep_1", tenantA, "paystack", at.AddDate(0, 0, -7*w), count)
	}
}

func TestSilenceDetectsAnEndpointThatWentQuiet(t *testing.T) {
	// The failure nobody catches: a provider stops sending and every counter
	// simply flattens. No error is logged, because from our side nothing went
	// wrong.
	d, _ := newDetector(tuesday14)
	train(d, tuesday14, 4, 400)

	// A long-established endpoint receiving nothing in a normally-busy hour.
	v := d.Check("ep_1", 0, tuesday14.AddDate(0, -6, 0))
	if !v.Silent {
		t.Fatalf("an endpoint that normally sees 400 events received 0 and was not flagged: %+v", v)
	}
	// The reason has to tell an operator what to actually check.
	if v.Reason == "" || !containsAll(v.Reason, "receiver URL", "provider's dashboard") {
		t.Errorf("the alert does not say what to check: %q", v.Reason)
	}
}

func TestSilenceIgnoresAnHourThatIsNormallyQuiet(t *testing.T) {
	// A baseline that averaged Sunday 04:00 with Tuesday 14:00 would either
	// alert every weekend or never alert at all.
	d, _ := newDetector(sunday04)
	train(d, sunday04, 4, 0)

	v := d.Check("ep_1", 0, sunday04.AddDate(0, -6, 0))
	if v.Silent {
		t.Fatalf("a normally-quiet hour was flagged as silent: %+v", v)
	}
}

func TestSilenceDoesNotAlertOnAnOrdinaryDip(t *testing.T) {
	// Alerting on any below-average hour would alert on half of them. The
	// floor is the quietest comparable hour, not the mean.
	d, _ := newDetector(tuesday14)
	for i, count := range []int64{400, 380, 420, 300, 450} {
		d.Observe("ep_1", tenantA, "paystack", tuesday14.AddDate(0, 0, -7*(5-i)), count)
	}

	// 200 is well below average and well above the quietest hour's floor.
	v := d.Check("ep_1", 200, tuesday14.AddDate(0, -6, 0))
	if v.Silent {
		t.Fatalf("a quiet-but-normal hour was flagged: %+v (floor %.0f)", v, v.Expected)
	}

	// 10 is not.
	v = d.Check("ep_1", 10, tuesday14.AddDate(0, -6, 0))
	if !v.Silent {
		t.Fatalf("a genuine collapse was not flagged: %+v (floor %.0f)", v, v.Expected)
	}
}

func TestSilenceSaysItIsStillLearning(t *testing.T) {
	// Claiming to watch something you cannot yet judge is worse than saying
	// you are not watching it.
	d, _ := newDetector(tuesday14)
	train(d, tuesday14, 2, 400)

	v := d.Check("ep_1", 0, tuesday14.AddDate(0, -6, 0))
	if v.Silent {
		t.Fatal("alerted on two weeks of history")
	}
	if !v.Learning {
		t.Fatalf("did not report that it is still learning: %+v", v)
	}
	if v.Reason == "" {
		t.Error("no explanation of why it cannot judge yet")
	}
}

func TestSilenceExemptsANewEndpoint(t *testing.T) {
	// Alerting before the provider has even been pointed at the URL is noise
	// at exactly the moment an operator cannot tell noise from signal.
	d, _ := newDetector(tuesday14)
	train(d, tuesday14, 6, 400)

	v := d.Check("ep_1", 0, tuesday14.Add(-2*24*time.Hour))
	if v.Silent {
		t.Fatalf("a two-day-old endpoint was flagged: %+v", v)
	}
	if !v.Learning {
		t.Errorf("verdict = %+v", v)
	}
}

func TestSilenceSurvivesOneAnomalousWeek(t *testing.T) {
	// One near-zero week — a genuine outage, say — must not permanently
	// suppress the alert by dragging the floor to nothing.
	d, _ := newDetector(tuesday14)
	for i, count := range []int64{400, 380, 1, 420, 450, 410} {
		d.Observe("ep_1", tenantA, "paystack", tuesday14.AddDate(0, 0, -7*(6-i)), count)
	}

	v := d.Check("ep_1", 0, tuesday14.AddDate(0, -6, 0))
	if !v.Silent {
		t.Fatalf("one bad week suppressed the alert permanently: %+v (floor %.0f)", v, v.Expected)
	}
}

func TestSilenceReportsCoverageHonestly(t *testing.T) {
	// "Watching 2% of the week" is a useful thing for a dashboard to admit.
	// Implying full coverage from the first hour is not.
	d, _ := newDetector(tuesday14)
	if c := d.Confidence("ep_1"); c != 0 {
		t.Errorf("confidence with no history = %v", c)
	}
	train(d, tuesday14, 4, 400)

	c := d.Confidence("ep_1")
	if c <= 0 || c > 0.02 {
		t.Errorf("confidence after training one hour of the week = %v; want a small non-zero fraction", c)
	}
}

func TestSilenceIsPerEndpoint(t *testing.T) {
	d, _ := newDetector(tuesday14)
	train(d, tuesday14, 4, 400)
	for w := 4; w > 0; w-- {
		d.Observe("ep_2", tenantA, "stripe", tuesday14.AddDate(0, 0, -7*w), 5)
	}

	// Five events is a collapse for the busy endpoint and completely normal
	// for the quiet one.
	if v := d.Check("ep_1", 5, tuesday14.AddDate(0, -6, 0)); !v.Silent {
		t.Errorf("the busy endpoint at 5 events was not flagged: %+v", v)
	}
	if v := d.Check("ep_2", 5, tuesday14.AddDate(0, -6, 0)); v.Silent {
		t.Errorf("the quiet endpoint at its normal 5 events was flagged: %+v", v)
	}
}

func TestSilenceForgetsDeletedEndpoints(t *testing.T) {
	d, _ := newDetector(tuesday14)
	train(d, tuesday14, 4, 400)
	if d.Tracked() != 1 {
		t.Fatalf("tracking %d", d.Tracked())
	}
	d.Forget("ep_1")
	if d.Tracked() != 0 {
		t.Fatal("a deleted endpoint is still tracked, and will alert forever")
	}
}

func containsAll(s string, parts ...string) bool {
	for _, p := range parts {
		if indexOf(s, p) < 0 {
			return false
		}
	}
	return true
}
