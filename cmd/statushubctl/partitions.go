package main

import (
	"context"
	"flag"
	"fmt"
	"time"

	"github.com/nobledeveloper01/StatusHub/internal/retention"
)

// cmdPartitions provisions monthly partitions and enforces retention.
//
// Run it daily. It provisions three months ahead, so it can be broken for two
// of them without harm — and it recovers rows that landed in the catch-all
// while it was, which is what stops a missed run becoming permanent.
func cmdPartitions(ctx context.Context, args []string) error {
	sub := "status"
	if len(args) > 0 && args[0][0] != '-' {
		sub, args = args[0], args[1:]
	}

	fs := flag.NewFlagSet("partitions "+sub, flag.ExitOnError)
	retainDays := fs.Int("retain-days", 30, "how long raw events are kept; §11.7 defaults to 30")
	dryRun := fs.Bool("dry-run", false, "report what would be dropped without dropping it")
	if err := fs.Parse(args); err != nil {
		return err
	}

	pool, err := openPool(ctx)
	if err != nil {
		return err
	}
	defer pool.Close()
	m := retention.New(pool, nil)

	switch sub {
	case "status":
		parts, err := m.List(ctx)
		if err != nil {
			return err
		}
		var total int64
		for _, p := range parts {
			total += p.Bytes
			rangeText := "default (catch-all)"
			if !p.From.IsZero() {
				rangeText = fmt.Sprintf("%s to %s", p.From.Format("2006-01-02"), p.To.Format("2006-01-02"))
			}
			fmt.Printf("  %-24s %-26s %10s\n", p.Name, rangeText, humanBytes(p.Bytes))
		}
		fmt.Printf("\n  %-24s %-26s %10s\n", "total", "", humanBytes(total))

		stranded, err := m.DefaultPartitionRows(ctx)
		if err != nil {
			return err
		}
		if stranded > 0 {
			// Not a statistic. Rows here cannot be dropped by retention and
			// will accumulate until somebody notices the disk.
			fmt.Printf("\n  WARNING: %d rows are in the default partition. Run `statushubctl partitions run`\n", stranded)
			fmt.Printf("           to move the recoverable ones into their proper months.\n")
		}
		return nil

	case "run":
		report, err := m.Run(ctx, time.Duration(*retainDays)*24*time.Hour, *dryRun)
		if err != nil {
			return err
		}
		for _, name := range report.Created {
			fmt.Printf("  created  %s\n", name)
		}
		for _, p := range report.Dropped {
			verb := "dropped"
			if *dryRun {
				verb = "would drop"
			}
			fmt.Printf("  %-9s %s (%s, entirely older than %d days)\n",
				verb, p.Name, humanBytes(p.Bytes), *retainDays)
		}
		if len(report.Created) == 0 && len(report.Dropped) == 0 {
			fmt.Println("  nothing to do")
		}
		if report.Warning != "" {
			fmt.Printf("\n  WARNING: %s\n", report.Warning)
		}
		return nil

	default:
		return fmt.Errorf("unknown subcommand %q; use status or run", sub)
	}
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
