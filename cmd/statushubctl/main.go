// Command statushubctl is the admin CLI.
//
// It exists because the first ten minutes of an evaluation should not require
// reading an API reference, and because the incident runbooks (§11.5, §11.6)
// are written as commands somebody can paste at three in the morning.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"

	"github.com/nobledeveloper01/StatusHub/internal/server"
)

type command struct {
	name    string
	summary string
	run     func(ctx context.Context, args []string) error
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	commands := []command{
		{"init", "create a tenant, its first endpoint and an owner key", cmdInit},
		{"migrate", "apply, roll back or inspect database migrations", cmdMigrate},
		{"tenants", "list and create tenants", cmdTenants},
		{"endpoints", "list, create and rotate receiver URLs", cmdEndpoints},
		{"destinations", "list and create forwarding targets", cmdDestinations},
		{"adapters", "list built-in adapters and test declarative ones", cmdAdapters},
		{"infer", "draft a declarative adapter from captured payloads", cmdInfer},
		{"events", "search events and replay them", cmdEvents},
		{"keys", "issue and revoke API keys", cmdKeys},
		{"listen", "stream live events to a handler on your own machine", cmdListen},
		{"simulate", "post a correctly-signed sample webhook at a receiver URL", cmdSimulate},
		{"partitions", "provision monthly partitions and enforce retention; run daily", cmdPartitions},
		{"usage", "export the billing metric in a form the customer can reconcile", cmdUsage},
		{"secrets", "generate the secrets a deployment needs, with what each one does", cmdSecrets},
		{"doctor", "check the things that fail silently", cmdDoctor},
		{"version", "print the version", cmdVersion},
	}

	if len(os.Args) < 2 {
		printUsage(commands)
		os.Exit(2)
	}

	name := os.Args[1]
	for _, c := range commands {
		if c.name == name {
			if err := c.run(ctx, os.Args[2:]); err != nil {
				fmt.Fprintf(os.Stderr, "statushubctl %s: %v\n", name, err)
				os.Exit(1)
			}
			return
		}
	}

	fmt.Fprintf(os.Stderr, "statushubctl: unknown command %q\n\n", name)
	printUsage(commands)
	os.Exit(2)
}

func printUsage(commands []command) {
	fmt.Fprintf(os.Stderr, `statushubctl %s — administer a StatusHub deployment.

Usage:
  statushubctl <command> [flags]

Commands:
`, server.Version)
	sort.Slice(commands, func(i, j int) bool { return commands[i].name < commands[j].name })
	for _, c := range commands {
		fmt.Fprintf(os.Stderr, "  %-14s %s\n", c.name, c.summary)
	}
	fmt.Fprintf(os.Stderr, `
The database is read from STATUSHUB_DATABASE_URL.

Getting a first event flowing:
  statushubctl init --slug acme --name "Acme Payments"
  statushubctl endpoints create --tenant acme --provider paystack --env live --secret-ref env://PAYSTACK_LIVE
  statushubctl destinations create --tenant acme --url https://acme.io/hooks/statushub --secret-ref env://ACME_SIGNING
  # paste the printed receiver URL into Paystack's dashboard, and you are done

Developing against live webhooks without a public URL:
  statushubctl listen --forward http://localhost:3000/hooks --key sh_test_...

Proving it works before a real transaction exists:
  statushubctl simulate --provider paystack --event charge.success --url <receiver URL> --secret <secret>

When a provider changes their payload (runbook 11.5):
  statushubctl events list --tenant acme --provider paystack --mapping-complete=false
  statushubctl adapters test --config adapter.json --sample captured.json
  statushubctl events replay --tenant acme --provider paystack --from 2026-08-11T00:00:00Z
`)
}

func cmdVersion(context.Context, []string) error {
	fmt.Printf("statushubctl %s (%s)\n", server.Version, server.Commit)
	return nil
}

// databaseURL is read from one place so every subcommand fails the same way
// when it is missing.
func databaseURL() (string, error) {
	dsn := strings.TrimSpace(os.Getenv("STATUSHUB_DATABASE_URL"))
	if dsn == "" {
		return "", fmt.Errorf("STATUSHUB_DATABASE_URL is not set")
	}
	return dsn, nil
}
