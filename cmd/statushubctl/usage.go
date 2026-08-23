package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/nobledeveloper01/StatusHub/internal/usage"
)

// cmdUsage exports the billing metric in a form a customer can reconcile.
func cmdUsage(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("usage", flag.ExitOnError)
	slug := fs.String("tenant", "", "tenant slug")
	from := fs.String("from", "", "RFC 3339 or YYYY-MM-DD; defaults to the start of last month")
	to := fs.String("to", "", "RFC 3339 or YYYY-MM-DD, exclusive; defaults to the start of this month")
	format := fs.String("format", "text", "text, csv or json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *slug == "" {
		return fmt.Errorf("--tenant is required")
	}

	// Default to the previous complete month, because that is the period an
	// invoice covers and typing two dates to get it every time is friction
	// nobody needs.
	now := time.Now().UTC()
	thisMonth := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	fromT, toT := thisMonth.AddDate(0, -1, 0), thisMonth

	var err error
	if *from != "" {
		if fromT, err = parseDay(*from); err != nil {
			return err
		}
	}
	if *to != "" {
		if toT, err = parseDay(*to); err != nil {
			return err
		}
	}

	s, err := openStore(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = s.Close() }()

	tenant, err := s.GetTenantBySlug(ctx, *slug)
	if err != nil {
		return fmt.Errorf("tenant %q: %w", *slug, err)
	}

	m := usage.New(s.Pool(), nil)
	report, err := m.Usage(ctx, tenant.ID, fromT, toT)
	if err != nil {
		return err
	}

	switch *format {
	case "csv":
		return report.WriteCSV(os.Stdout)
	case "json":
		return report.WriteJSON(os.Stdout)
	default:
		fmt.Printf("%s — %s to %s\n\n", tenant.Slug, report.From[:10], report.To[:10])
		fmt.Printf("  %-14s %12s %12s %12s %12s\n", "provider", "received", "rejected", "normalised", "delivered")
		for _, p := range report.ByProvider() {
			fmt.Printf("  %-14s %12d %12d %12d %12d\n",
				p.Provider, p.Received, p.Rejected, p.Normalised, p.Delivered)
		}
		fmt.Printf("  %-14s %12d %12d %12d %12d\n\n", "total",
			report.Total.Received, report.Total.Rejected, report.Total.Normalised, report.Total.Delivered)
		fmt.Println(report.Reconciliation())
		return nil
	}
}

func parseDay(s string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339, "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("%q is not YYYY-MM-DD or RFC 3339", s)
}
