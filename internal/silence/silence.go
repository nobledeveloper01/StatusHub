// Package silence detects an endpoint that has stopped receiving.
//
// Every alert in §11.4 fires on something happening: a latency spike, a
// signature failure, a dead letter. The failure none of them catches is
// *nothing* happening — a provider stops sending, or somebody overwrites the
// receiver URL in their dashboard during an unrelated change, and every
// counter simply flattens. No error is logged anywhere, because from our side
// nothing went wrong.
//
// That failure is both the most damaging and the hardest to notice. A fintech
// can go a full day before someone asks why settlements look light, and by
// then the provider's retries are long exhausted and the events are
// genuinely gone.
//
// Detection has to be against each endpoint's own history rather than a fixed
// threshold, because "quiet" means something different for a provider
// handling four hundred events an hour and one handling four.
package silence

import (
	"fmt"
	"math"
	"sort"
	"sync"
	"time"
)

// Buckets is how the week is divided.
//
// Hour of week, not hour of day. Nigerian payment volume on a Sunday at 04:00
// has nothing in common with a Tuesday at 14:00, and a baseline that averaged
// them would either alert every weekend or never alert at all.
const Buckets = 7 * 24

// MinObservations is how many weeks of history a bucket needs before it is
// trusted.
//
// Three. With one week a single unusual day becomes the baseline; with three
// an outlier is visibly an outlier. Until then the endpoint is reported as
// still learning rather than as healthy, because claiming to watch something
// you cannot yet judge is worse than saying you are not watching it.
const MinObservations = 3

// Baseline is one endpoint's learned volume.
type Baseline struct {
	EndpointID string
	Provider   string
	TenantID   string

	// counts[bucket] is the observed count per week for that hour of week.
	counts map[int][]float64

	lastSeen time.Time
	total    int64
}

// Detector holds every endpoint's baseline.
type Detector struct {
	mu        sync.Mutex
	baselines map[string]*Baseline

	// sensitivity is how far below the expected floor an endpoint must fall.
	// Expressed as a fraction of the historical minimum rather than of the
	// mean: a quiet hour that is normally quiet must not alert, and the
	// minimum is what encodes that.
	sensitivity float64

	// graceAfterCreation is how long a new endpoint is exempt. Without it
	// every endpoint alerts the moment it is created and before the provider
	// has been pointed at it — which is exactly when an operator is least able
	// to distinguish a real alert from noise.
	graceAfterCreation time.Duration

	now func() time.Time
}

// Options configure a Detector.
type Options struct {
	Sensitivity        float64
	GraceAfterCreation time.Duration
	Now                func() time.Time
}

// New builds a Detector.
func New(o Options) *Detector {
	d := &Detector{
		baselines:          map[string]*Baseline{},
		sensitivity:        o.Sensitivity,
		graceAfterCreation: o.GraceAfterCreation,
		now:                o.Now,
	}
	if d.sensitivity <= 0 {
		d.sensitivity = 0.25
	}
	if d.graceAfterCreation <= 0 {
		d.graceAfterCreation = 7 * 24 * time.Hour
	}
	if d.now == nil {
		d.now = func() time.Time { return time.Now().UTC() }
	}
	return d
}

// bucketOf returns the hour-of-week index for a time.
func bucketOf(t time.Time) int {
	u := t.UTC()
	return int(u.Weekday())*24 + u.Hour()
}

// Observe records an hour's count for an endpoint. Called by a job that rolls
// up the previous hour, not per event: per-event bookkeeping on the receiver's
// hot path would spend part of a 50 ms budget on something that only needs
// hourly resolution.
func (d *Detector) Observe(endpointID, tenantID, provider string, at time.Time, count int64) {
	d.mu.Lock()
	defer d.mu.Unlock()

	b, ok := d.baselines[endpointID]
	if !ok {
		b = &Baseline{
			EndpointID: endpointID, TenantID: tenantID, Provider: provider,
			counts: map[int][]float64{},
		}
		d.baselines[endpointID] = b
	}

	bucket := bucketOf(at)
	b.counts[bucket] = append(b.counts[bucket], float64(count))
	// Keep eight weeks. Enough to survive a month-end spike being treated as
	// normal, and bounded so the map does not grow forever.
	if len(b.counts[bucket]) > 8 {
		b.counts[bucket] = b.counts[bucket][1:]
	}
	if count > 0 {
		b.lastSeen = at
		b.total += count
	}
}

// Verdict is what the detector concluded about one endpoint.
type Verdict struct {
	EndpointID string    `json:"endpoint_id"`
	TenantID   string    `json:"tenant_id"`
	Provider   string    `json:"provider"`
	Silent     bool      `json:"silent"`
	Learning   bool      `json:"learning"`
	Observed   int64     `json:"observed"`
	Expected   float64   `json:"expected_floor"`
	LastSeen   time.Time `json:"last_seen,omitempty"`
	QuietFor   string    `json:"quiet_for,omitempty"`
	Reason     string    `json:"reason"`
}

// Check judges one endpoint's current hour against its baseline.
func (d *Detector) Check(endpointID string, observed int64, createdAt time.Time) Verdict {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := d.now()
	v := Verdict{EndpointID: endpointID, Observed: observed}

	b, ok := d.baselines[endpointID]
	if !ok {
		v.Learning = true
		v.Reason = "no history yet"
		return v
	}
	v.TenantID, v.Provider, v.LastSeen = b.TenantID, b.Provider, b.lastSeen

	if now.Sub(createdAt) < d.graceAfterCreation {
		// A brand-new endpoint alerting before the provider has even been
		// pointed at it is noise at exactly the moment an operator is least
		// able to tell noise from signal.
		v.Learning = true
		v.Reason = fmt.Sprintf("endpoint is less than %s old", d.graceAfterCreation)
		return v
	}

	samples := b.counts[bucketOf(now)]
	if len(samples) < MinObservations {
		v.Learning = true
		v.Reason = fmt.Sprintf("only %d of %d observations for this hour of the week", len(samples), MinObservations)
		return v
	}

	floor := quietFloor(samples) * d.sensitivity
	v.Expected = floor

	// An hour that is normally silent must not alert for being silent. This
	// is what makes the baseline hour-of-week rather than a single number.
	if floor <= 0 {
		v.Reason = "this hour is normally quiet"
		return v
	}
	if float64(observed) >= floor {
		v.Reason = "within the expected range"
		return v
	}

	v.Silent = true
	if !b.lastSeen.IsZero() {
		v.QuietFor = now.Sub(b.lastSeen).Round(time.Minute).String()
	}
	v.Reason = fmt.Sprintf(
		"received %d events this hour; this endpoint's quietest comparable hour over %d weeks was %.0f. "+
			"Check that the receiver URL is still set in the provider's dashboard.",
		observed, len(samples), quietFloor(samples))
	return v
}

// quietFloor is the lowest count seen for this hour across the retained
// weeks.
//
// The minimum rather than the mean, deliberately. A mean-based floor alerts
// on any below-average hour, which is half of them. The minimum answers the
// question that matters: has this endpoint gone quieter than it has ever been
// at this time of week?
func quietFloor(samples []float64) float64 {
	if len(samples) == 0 {
		return 0
	}
	sorted := append([]float64(nil), samples...)
	sort.Float64s(sorted)

	// The second-lowest when there are enough samples, so one anomalous
	// near-zero week does not permanently suppress the alert.
	if len(sorted) >= 5 {
		return sorted[1]
	}
	return sorted[0]
}

// CheckAll judges every endpoint the detector knows about.
func (d *Detector) CheckAll(observed map[string]int64, createdAt map[string]time.Time) []Verdict {
	d.mu.Lock()
	ids := make([]string, 0, len(d.baselines))
	for id := range d.baselines {
		ids = append(ids, id)
	}
	d.mu.Unlock()

	sort.Strings(ids)
	out := make([]Verdict, 0, len(ids))
	for _, id := range ids {
		created, ok := createdAt[id]
		if !ok {
			// Unknown creation time is treated as old rather than new: an
			// endpoint we have a baseline for but no record of is far more
			// likely to be long-lived than brand new.
			created = time.Time{}
		}
		out = append(out, d.Check(id, observed[id], created))
	}
	return out
}

// Forget drops an endpoint's baseline, for when one is deleted.
func (d *Detector) Forget(endpointID string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.baselines, endpointID)
}

// Tracked is how many endpoints have a baseline.
func (d *Detector) Tracked() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.baselines)
}

// Confidence reports how much of an endpoint's week has enough history to be
// judged, so the dashboard can say "watching 84% of the week" rather than
// implying full coverage from the first hour.
func (d *Detector) Confidence(endpointID string) float64 {
	d.mu.Lock()
	defer d.mu.Unlock()

	b, ok := d.baselines[endpointID]
	if !ok {
		return 0
	}
	var ready int
	for _, samples := range b.counts {
		if len(samples) >= MinObservations {
			ready++
		}
	}
	return math.Round(float64(ready)/float64(Buckets)*100) / 100
}
