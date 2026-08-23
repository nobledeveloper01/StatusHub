package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/nobledeveloper01/StatusHub/internal/migrate"
	"github.com/nobledeveloper01/StatusHub/internal/secret"
)

// cmdDoctor is a preflight for the failure modes that are silent (§6.3).
//
// Every check here corresponds to a way an evaluation quietly fails: the
// database is reachable but unmigrated, the secret reference resolves to
// nothing, egress is blocked so deliveries will time out, or — the one that
// wastes the most time — the clock is skewed, which breaks HMAC timestamp
// windows in both directions and produces an error message that tells the
// operator nothing.
func cmdDoctor(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	secretRefs := multiFlag{}
	fs.Var(&secretRefs, "secret-ref", "a secret reference to resolve; repeat for several")
	egress := fs.String("egress", "https://api.paystack.co", "a URL to prove outbound HTTPS works")
	skipEgress := fs.Bool("skip-egress", false, "do not attempt an outbound request")
	if err := fs.Parse(args); err != nil {
		return err
	}

	var failed bool
	check := func(name string, fn func() (string, error)) {
		detail, err := fn()
		if err != nil {
			failed = true
			fmt.Printf("  FAILED  %-22s %v\n", name, err)
			return
		}
		fmt.Printf("  ok      %-22s %s\n", name, detail)
	}

	check("database", func() (string, error) {
		pool, err := openPool(ctx)
		if err != nil {
			return "", err
		}
		defer pool.Close()
		start := time.Now()
		if err := pool.Ping(ctx); err != nil {
			return "", err
		}
		return fmt.Sprintf("reachable in %s", time.Since(start).Round(time.Millisecond)), nil
	})

	check("migrations", func() (string, error) {
		pool, err := openPool(ctx)
		if err != nil {
			return "", err
		}
		defer pool.Close()
		pending, err := migrate.Pending(ctx, pool)
		if err != nil {
			return "", err
		}
		if len(pending) > 0 {
			// Named, because "the database is behind" without saying which
			// migration sends someone reading a directory listing.
			return "", fmt.Errorf("%d pending: %s — run `statushubctl migrate up`",
				len(pending), strings.Join(pending, ", "))
		}
		return "up to date", nil
	})

	check("clock skew", func() (string, error) {
		offset, err := clockOffset(ctx)
		if err != nil {
			return "", err
		}
		abs := offset
		if abs < 0 {
			abs = -abs
		}
		switch {
		case abs > 5*time.Minute:
			// Beyond the signature window in both directions: every Stripe
			// webhook will be rejected as replayed, and every outbound
			// signature we produce will be rejected by the customer.
			return "", fmt.Errorf("this host is %s from network time, which is outside the five-minute signature window in both directions", abs.Round(time.Second))
		case abs > 30*time.Second:
			return "", fmt.Errorf("this host is %s from network time; signature windows will start failing intermittently", abs.Round(time.Second))
		default:
			return fmt.Sprintf("within %s of network time", abs.Round(time.Millisecond)), nil
		}
	})

	for _, ref := range secretRefs {
		ref := ref
		check("secret "+ref, func() (string, error) {
			r := secret.NewMulti(map[string]secret.Resolver{
				"env":    secret.NewEnv(),
				"static": secret.NewStatic(),
			})
			values, err := r.ResolveAll(ctx, ref)
			if err != nil {
				return "", err
			}
			// The value is never printed. Reporting how many are valid is the
			// useful part anyway: two means a rotation is in progress.
			if len(values) > 1 {
				return fmt.Sprintf("resolves; %d values valid, so a rotation overlap is in place", len(values)), nil
			}
			return "resolves", nil
		})
	}

	if !*skipEgress {
		check("outbound https", func() (string, error) {
			client := &http.Client{
				Timeout: 10 * time.Second,
				Transport: &http.Transport{
					DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
				},
			}
			req, err := http.NewRequestWithContext(ctx, http.MethodHead, *egress, nil)
			if err != nil {
				return "", err
			}
			resp, err := client.Do(req)
			if err != nil {
				var dnsErr *net.DNSError
				if errors.As(err, &dnsErr) {
					return "", fmt.Errorf("DNS resolution failed: %w — deliveries will never leave this host", err)
				}
				return "", fmt.Errorf("%w — check egress rules; every delivery will time out", err)
			}
			defer func() { _ = resp.Body.Close() }()
			return fmt.Sprintf("reached %s", *egress), nil
		})
	}

	fmt.Println()
	if failed {
		return fmt.Errorf("one or more checks failed")
	}
	fmt.Println("Everything checks out.")
	return nil
}

// clockOffset measures this host against an HTTP Date header.
//
// Not NTP: a container that cannot reach an NTP server can usually still make
// an HTTPS request, and the question being answered is "will signature
// windows work", which is about agreement with the internet rather than with
// a stratum-1 clock. A second of precision is ample for a five-minute window.
func clockOffset(ctx context.Context) (time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, "https://www.cloudflare.com", nil)
	if err != nil {
		return 0, err
	}
	client := &http.Client{Timeout: 10 * time.Second}

	before := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("could not reach a time reference: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	after := time.Now()

	remote, err := http.ParseTime(resp.Header.Get("Date"))
	if err != nil {
		return 0, fmt.Errorf("the time reference sent no usable Date header: %w", err)
	}
	// Compare against the midpoint of the request, so the round trip is not
	// counted as skew.
	local := before.Add(after.Sub(before) / 2)
	return local.Sub(remote), nil
}
