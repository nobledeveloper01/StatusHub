// Package usage produces the billing metric, and produces it so a customer
// can check it.
//
// §2.4 chooses "events received" as the billing metric specifically because
// the customer can reconcile it against their provider dashboards. That
// promise only holds if the number we bill is derived from the same rows the
// event explorer shows — a separate counter, however carefully maintained,
// drifts, and a billing figure that disagrees with the customer's own view of
// the same data is worse than no auditable metric at all.
//
// So every figure here is a query over raw_events. It is slower than reading
// a counter, and it is run daily rather than per request, and it is correct
// by construction: if the customer can see the event, it was billed, and if
// they cannot, it was not.
package usage

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Day is one tenant's usage for one provider on one day.
type Day struct {
	Date     string `json:"date"`
	Provider string `json:"provider"`

	// Received is everything that arrived, including forgeries.
	//
	// Billing on Received rather than on what was forwarded is the honest
	// choice: the work of receiving, verifying and storing an event happened
	// whether or not its signature checked out. It is also the number the
	// customer can reconcile, because their provider dashboard counts
	// deliveries attempted, not deliveries we liked.
	Received int64 `json:"received"`

	// Rejected is the subset whose signature failed. Billed, and broken out,
	// because a customer seeing a bill larger than their provider dashboard
	// deserves to know that the difference is forgery attempts rather than
	// our arithmetic.
	Rejected int64 `json:"signature_failures"`

	Normalised int64 `json:"normalised"`
	Delivered  int64 `json:"delivered"`
	Bytes      int64 `json:"bytes_received"`
}

// Report is a billing period.
type Report struct {
	TenantID string `json:"tenant_id"`
	From     string `json:"from"`
	To       string `json:"to"`

	Days  []Day `json:"days"`
	Total Day   `json:"total"`

	// GeneratedAt and Method are here so a finance team can tell two exports
	// apart and an auditor can see what was counted.
	GeneratedAt time.Time `json:"generated_at"`
	Method      string    `json:"method"`
}

// Meter reads usage from the store.
type Meter struct {
	pool *pgxpool.Pool
	now  func() time.Time
}

// New builds a Meter.
func New(pool *pgxpool.Pool, now func() time.Time) *Meter {
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Meter{pool: pool, now: now}
}

// Usage returns a tenant's usage over a period, by day and provider.
//
// The range is half-open — from inclusive, to exclusive — because a closed
// range on timestamps either double-counts the boundary second between
// consecutive months or misses it, and both show up as an unexplainable
// one-event discrepancy on exactly the invoice somebody is querying.
func (m *Meter) Usage(ctx context.Context, tenantID string, from, to time.Time) (Report, error) {
	r := Report{
		TenantID:    tenantID,
		From:        from.UTC().Format(time.RFC3339),
		To:          to.UTC().Format(time.RFC3339),
		GeneratedAt: m.now(),
		Method: "counted from raw_events, the same rows the event explorer shows. " +
			"Every event billed is one you can find and inspect.",
	}
	if !to.After(from) {
		return r, fmt.Errorf("the period must end after it starts")
	}

	rows, err := m.pool.Query(ctx,
		`SELECT to_char(date_trunc('day', r.received_at AT TIME ZONE 'UTC'), 'YYYY-MM-DD') AS day,
		        r.provider,
		        count(*),
		        count(*) FILTER (WHERE NOT r.signature_valid),
		        count(*) FILTER (WHERE r.normalised_at IS NOT NULL),
		        COALESCE(sum(length(r.body)), 0)
		   FROM raw_events r
		  WHERE r.tenant_id = $1 AND r.received_at >= $2 AND r.received_at < $3
		  GROUP BY 1, 2
		  ORDER BY 1, 2`, tenantID, from.UTC(), to.UTC())
	if err != nil {
		return r, err
	}
	defer rows.Close()

	for rows.Next() {
		var d Day
		if err := rows.Scan(&d.Date, &d.Provider, &d.Received, &d.Rejected, &d.Normalised, &d.Bytes); err != nil {
			return r, err
		}
		r.Days = append(r.Days, d)
	}
	if err := rows.Err(); err != nil {
		return r, err
	}

	// Deliveries are counted separately: they are per destination, so joining
	// them into the same query would multiply the received count by the
	// number of destinations — a fanned-out event is one event received and
	// several delivered, and billing must not confuse the two.
	delivered, err := m.deliveredByDay(ctx, tenantID, from, to)
	if err != nil {
		return r, err
	}
	for i := range r.Days {
		r.Days[i].Delivered = delivered[r.Days[i].Date+"|"+r.Days[i].Provider]
	}

	r.Total = total(r.Days)
	return r, nil
}

func (m *Meter) deliveredByDay(ctx context.Context, tenantID string, from, to time.Time) (map[string]int64, error) {
	rows, err := m.pool.Query(ctx,
		`SELECT to_char(date_trunc('day', d.created_at AT TIME ZONE 'UTC'), 'YYYY-MM-DD'),
		        e.provider, count(*)
		   FROM deliveries d
		   JOIN canonical_events e ON e.id = d.event_id
		  WHERE d.tenant_id = $1 AND d.created_at >= $2 AND d.created_at < $3
		    AND d.status = 'succeeded'
		  GROUP BY 1, 2`, tenantID, from.UTC(), to.UTC())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := map[string]int64{}
	for rows.Next() {
		var day, provider string
		var n int64
		if err := rows.Scan(&day, &provider, &n); err != nil {
			return nil, err
		}
		out[day+"|"+provider] = n
	}
	return out, rows.Err()
}

func total(days []Day) Day {
	t := Day{Date: "total", Provider: "all"}
	for _, d := range days {
		t.Received += d.Received
		t.Rejected += d.Rejected
		t.Normalised += d.Normalised
		t.Delivered += d.Delivered
		t.Bytes += d.Bytes
	}
	return t
}

// ByProvider collapses a report to per-provider totals, which is the shape a
// customer reconciles against their provider dashboards.
func (r Report) ByProvider() []Day {
	agg := map[string]*Day{}
	for _, d := range r.Days {
		p, ok := agg[d.Provider]
		if !ok {
			p = &Day{Date: r.From[:10] + " to " + r.To[:10], Provider: d.Provider}
			agg[d.Provider] = p
		}
		p.Received += d.Received
		p.Rejected += d.Rejected
		p.Normalised += d.Normalised
		p.Delivered += d.Delivered
		p.Bytes += d.Bytes
	}
	out := make([]Day, 0, len(agg))
	for _, d := range agg {
		out = append(out, *d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Provider < out[j].Provider })
	return out
}

// WriteCSV renders a report for a finance team.
func (r Report) WriteCSV(w io.Writer) error {
	c := csv.NewWriter(w)
	defer c.Flush()

	if err := c.Write([]string{
		"date", "provider", "events_received", "signature_failures",
		"normalised", "delivered", "bytes_received",
	}); err != nil {
		return err
	}
	for _, d := range append(append([]Day{}, r.Days...), r.Total) {
		if err := c.Write([]string{
			// Every field is defused against spreadsheet formula injection.
			// Provider names are ours, but a declarative adapter's name is
			// customer-supplied, and a CSV that executes on open is a real
			// finding in a real penetration test.
			defuse(d.Date), defuse(d.Provider),
			strconv.FormatInt(d.Received, 10),
			strconv.FormatInt(d.Rejected, 10),
			strconv.FormatInt(d.Normalised, 10),
			strconv.FormatInt(d.Delivered, 10),
			strconv.FormatInt(d.Bytes, 10),
		}); err != nil {
			return err
		}
	}
	return c.Error()
}

// defuse prefixes a value that a spreadsheet would treat as a formula.
func defuse(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}
	return s
}

// WriteJSON renders a report.
func (r Report) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// Reconciliation is the sentence a customer needs beside the number.
func (r Report) Reconciliation() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d events received between %s and %s.\n\n", r.Total.Received, r.From[:10], r.To[:10])
	fmt.Fprintf(&b, "Reconcile this against each provider's own dashboard: they count deliveries "+
		"attempted, which is what this counts too.\n")
	if r.Total.Rejected > 0 {
		fmt.Fprintf(&b, "\n%d of these failed signature verification. They are included in the count "+
			"because receiving, verifying and storing them happened — and they are broken out here so a "+
			"figure larger than your provider's is explainable rather than mysterious.\n", r.Total.Rejected)
	}
	if gap := r.Total.Received - r.Total.Normalised; gap > 0 {
		fmt.Fprintf(&b, "\n%d were received but not normalised. Some are the signature failures above; "+
			"the rest are payloads an adapter could not read, which are visible under "+
			"mapping_complete=false and are recoverable by replay.\n", gap)
	}
	return b.String()
}
