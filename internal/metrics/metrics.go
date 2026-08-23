// Package metrics is the Prometheus surface from §11.2.
//
// Hand-rolled rather than pulled from a client library: this needs labelled
// counters, three histograms and a handful of gauges, and every dependency in
// a fintech's supply chain is one their security team has to approve. The
// exposition format is stable and small enough that implementing it is
// cheaper than justifying the import.
//
// The most valuable series here is statushub_status_unknown_total{raw_value}.
// It is a live feed of exactly which provider status values are not yet
// mapped, which means the product tells you what to build next instead of
// waiting for a customer to notice.
package metrics

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Registry holds every series. The zero value is not usable; call New.
type Registry struct {
	mu         sync.RWMutex
	counters   map[string]*counterVec
	gauges     map[string]*gaugeVec
	histograms map[string]*histogramVec
	order      []string
}

// New returns a registry with every series from §11.2 declared.
//
// Declaring them up front rather than creating them on first use means a
// dashboard panel shows zero instead of "no data" before the first event —
// and "no data" during an incident is indistinguishable from a broken
// exporter, which costs minutes at exactly the wrong moment.
func New() *Registry {
	r := &Registry{
		counters:   map[string]*counterVec{},
		gauges:     map[string]*gaugeVec{},
		histograms: map[string]*histogramVec{},
	}

	r.counter("statushub_webhooks_received_total", "Provider webhooks received, before normalisation.")
	r.counter("statushub_signature_failures_total", "Requests whose signature did not verify. A spike is a forgery attempt or an unannounced secret rotation.")
	r.counter("statushub_normalisation_failures_total", "Raw events an adapter could not parse. The raw bytes are safe; the adapter needs a fix.")
	r.counter("statushub_mapping_incomplete_total", "Events normalised with a field the adapter could not fill.")
	r.counter("statushub_status_unknown_total", "Provider status values with no mapping. This is the to-do list.")
	r.counter("statushub_deliveries_total", "Delivery attempts by outcome.")
	r.counter("statushub_dead_letter_total", "Deliveries that exhausted their retry budget.")
	r.counter("statushub_replay_total", "Events replayed on request.")
	r.counter("statushub_duplicates_rejected_total", "Provider redeliveries recognised and answered without creating a second event.")
	r.counter("statushub_payload_rejected_total", "Requests refused before storage: oversized, or carrying data we will not hold.")

	// The receive histogram's buckets are clustered under 50 ms because that
	// is the SLO (§11.3). Buckets spread evenly to ten seconds would put the
	// entire distribution in one bucket and measure nothing that matters.
	r.histogram("statushub_receive_duration_seconds", "Time from request arrival to the 200 being written.",
		[]float64{0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5})
	// Separated from the total, because in an edge region the write is the
	// cross-region hop and everything else is not. One histogram covering
	// both would make a network problem look like a code problem.
	r.histogram("statushub_store_write_duration_seconds", "Time for the receiver's single durable write.",
		[]float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.15, 0.25, 0.5, 1})
	r.counter("statushub_store_write_over_budget_total", "Durable writes that exceeded the region's write budget. Providers are about to start retrying.")
	r.histogram("statushub_normalisation_duration_seconds", "Time to map a raw event onto the canonical schema.",
		[]float64{0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1})
	r.histogram("statushub_delivery_duration_seconds", "Time for one delivery attempt, including the destination's response.",
		[]float64{0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30})

	// The gauge for the failure nobody else catches: an endpoint that has
	// gone quiet against its own learned baseline.
	r.gauge("statushub_endpoint_silent", "1 when an endpoint is receiving far below its historical floor for this hour of the week.")
	r.gauge("statushub_endpoint_silence_confidence", "Fraction of the week for which an endpoint has enough history to be judged.")
	r.gauge("statushub_receiver_in_flight", "Requests the receiver is handling right now, against its explicit ceiling.")
	r.gauge("statushub_delivery_queue_depth", "Deliveries not yet terminal, by shard.")
	r.gauge("statushub_shard_oldest_pending_seconds", "Age of the oldest pending delivery in a shard. Head-of-line blocking shows up here first.")
	r.gauge("statushub_destination_breaker_open", "1 when a destination's circuit breaker is not closed. Deliveries to it are parked, not failing.")
	r.gauge("statushub_build_info", "Always 1. Labels carry the version, commit and region.")
	r.gauge("statushub_replica_lag_seconds", "How far a replica is behind the primary. Read before promoting, never after.")
	r.gauge("statushub_audit_chain_intact", "1 when the nightly walk of a tenant's audit chain verified, 0 when it did not.")

	return r
}

// Labels are a metric's dimensions.
type Labels map[string]string

// Inc adds one to a counter.
func (r *Registry) Inc(name string, l Labels) { r.Add(name, l, 1) }

// Add increases a counter.
func (r *Registry) Add(name string, l Labels, v float64) {
	r.mu.RLock()
	c, ok := r.counters[name]
	r.mu.RUnlock()
	if !ok {
		return
	}
	c.add(l, v)
}

// Set writes a gauge.
func (r *Registry) Set(name string, l Labels, v float64) {
	r.mu.RLock()
	g, ok := r.gauges[name]
	r.mu.RUnlock()
	if !ok {
		return
	}
	g.set(l, v)
}

// Observe records a duration.
func (r *Registry) Observe(name string, l Labels, d time.Duration) {
	r.mu.RLock()
	h, ok := r.histograms[name]
	r.mu.RUnlock()
	if !ok {
		return
	}
	h.observe(l, d.Seconds())
}

// Write renders the registry in Prometheus text exposition format.
func (r *Registry) Write(w io.Writer) error {
	r.mu.RLock()
	names := append([]string(nil), r.order...)
	r.mu.RUnlock()
	sort.Strings(names)

	for _, name := range names {
		r.mu.RLock()
		c, isCounter := r.counters[name]
		g, isGauge := r.gauges[name]
		h, isHist := r.histograms[name]
		r.mu.RUnlock()

		switch {
		case isCounter:
			if err := c.write(w, name); err != nil {
				return err
			}
		case isGauge:
			if err := g.write(w, name); err != nil {
				return err
			}
		case isHist:
			if err := h.write(w, name); err != nil {
				return err
			}
		}
	}
	return nil
}

func (r *Registry) counter(name, help string) {
	r.counters[name] = &counterVec{help: help, values: map[string]*seriesValue{}}
	r.order = append(r.order, name)
}

func (r *Registry) gauge(name, help string) {
	r.gauges[name] = &gaugeVec{help: help, values: map[string]*seriesValue{}}
	r.order = append(r.order, name)
}

func (r *Registry) histogram(name, help string, buckets []float64) {
	r.histograms[name] = &histogramVec{help: help, buckets: buckets, values: map[string]*histogramValue{}}
	r.order = append(r.order, name)
}

type seriesValue struct {
	labels Labels
	value  float64
}

type counterVec struct {
	mu     sync.Mutex
	help   string
	values map[string]*seriesValue
}

func (c *counterVec) add(l Labels, v float64) {
	key := labelKey(l)
	c.mu.Lock()
	defer c.mu.Unlock()
	// The cardinality ceiling is not optional. Several of these series are
	// labelled with values a provider controls — raw_value on unknown
	// statuses most of all — and an unbounded label is how a scrape endpoint
	// grows until it takes the process down with it.
	if _, ok := c.values[key]; !ok && len(c.values) >= maxSeriesPerMetric {
		key = overflowKey
		l = Labels{"overflow": "true"}
	}
	s, ok := c.values[key]
	if !ok {
		s = &seriesValue{labels: l}
		c.values[key] = s
	}
	s.value += v
}

func (c *counterVec) write(w io.Writer, name string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return writeSeries(w, name, c.help, "counter", c.values)
}

type gaugeVec struct {
	mu     sync.Mutex
	help   string
	values map[string]*seriesValue
}

func (g *gaugeVec) set(l Labels, v float64) {
	key := labelKey(l)
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, ok := g.values[key]; !ok && len(g.values) >= maxSeriesPerMetric {
		return
	}
	g.values[key] = &seriesValue{labels: l, value: v}
}

func (g *gaugeVec) write(w io.Writer, name string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	return writeSeries(w, name, g.help, "gauge", g.values)
}

type histogramValue struct {
	labels Labels
	counts []uint64
	sum    float64
	count  uint64
}

type histogramVec struct {
	mu      sync.Mutex
	help    string
	buckets []float64
	values  map[string]*histogramValue
}

func (h *histogramVec) observe(l Labels, v float64) {
	key := labelKey(l)
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.values[key]; !ok && len(h.values) >= maxSeriesPerMetric {
		return
	}
	hv, ok := h.values[key]
	if !ok {
		hv = &histogramValue{labels: l, counts: make([]uint64, len(h.buckets))}
		h.values[key] = hv
	}
	for i, b := range h.buckets {
		if v <= b {
			hv.counts[i]++
		}
	}
	hv.sum += v
	hv.count++
}

func (h *histogramVec) write(w io.Writer, name string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, err := fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s histogram\n", name, h.help, name); err != nil {
		return err
	}
	keys := sortedKeys(h.values)
	for _, k := range keys {
		hv := h.values[k]
		// counts[i] is already cumulative: observe increments every bucket
		// whose upper bound the value falls under, which is what a
		// Prometheus histogram bucket means.
		for i, b := range h.buckets {
			if _, err := fmt.Fprintf(w, "%s_bucket%s %d\n", name,
				renderLabels(hv.labels, "le", strconv.FormatFloat(b, 'g', -1, 64)), hv.counts[i]); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintf(w, "%s_bucket%s %d\n", name, renderLabels(hv.labels, "le", "+Inf"), hv.count); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "%s_sum%s %g\n%s_count%s %d\n",
			name, renderLabels(hv.labels), hv.sum, name, renderLabels(hv.labels), hv.count); err != nil {
			return err
		}
	}
	return nil
}

const (
	maxSeriesPerMetric = 2000
	overflowKey        = "\x00overflow"
)

func writeSeries(w io.Writer, name, help, kind string, values map[string]*seriesValue) error {
	if _, err := fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, kind); err != nil {
		return err
	}
	if len(values) == 0 {
		// A declared metric with no observations still emits a zero, so a
		// dashboard shows a flat line rather than a gap.
		_, err := fmt.Fprintf(w, "%s 0\n", name)
		return err
	}
	for _, k := range sortedKeys(values) {
		s := values[k]
		if _, err := fmt.Fprintf(w, "%s%s %g\n", name, renderLabels(s.labels), s.value); err != nil {
			return err
		}
	}
	return nil
}

func sortedKeys[T any](m map[string]T) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func labelKey(l Labels) string {
	if len(l) == 0 {
		return ""
	}
	keys := make([]string, 0, len(l))
	for k := range l {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(l[k])
		b.WriteByte(',')
	}
	return b.String()
}

func renderLabels(l Labels, extra ...string) string {
	if len(l) == 0 && len(extra) == 0 {
		return ""
	}
	keys := make([]string, 0, len(l))
	for k := range l {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	b.WriteByte('{')
	first := true
	for _, k := range keys {
		if !first {
			b.WriteByte(',')
		}
		first = false
		fmt.Fprintf(&b, "%s=%q", k, escape(l[k]))
	}
	for i := 0; i+1 < len(extra); i += 2 {
		if !first {
			b.WriteByte(',')
		}
		first = false
		fmt.Fprintf(&b, "%s=%q", extra[i], escape(extra[i+1]))
	}
	b.WriteByte('}')
	return b.String()
}

// escape bounds a provider-controlled label value. Quoting is left to %q,
// which already escapes backslashes, quotes and newlines the way the
// exposition format requires — doing it here as well would double every
// backslash. What %q will not do is stop an unbounded value: a provider
// status echoed into a label is attacker-influenced text, and a megabyte of
// it would be served on every scrape until the collector gave up.
func escape(v string) string {
	if len(v) > 128 {
		return v[:128]
	}
	return v
}
