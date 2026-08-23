package main

import (
	"context"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/nobledeveloper01/StatusHub/internal/simulate"
)

// cmdSimulate posts a correctly-signed sample webhook at a receiver URL.
//
// It is the shortest path from "I have pasted a URL into a provider's
// dashboard" to "I have seen an event arrive", and it removes the worst part
// of a webhook integration: waiting for a real transaction to find out
// whether it works.
func cmdSimulate(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("simulate", flag.ExitOnError)
	url := fs.String("url", "", "the receiver URL to post at")
	provider := fs.String("provider", "", "paystack, flutterwave, nibss, monnify, interswitch or stripe")
	sample := fs.String("event", "", "which sample to send; omit to list what is available")
	secret := fs.String("secret", "", "the endpoint's signing secret, so the request verifies")
	all := fs.Bool("all", false, "send every sample for the provider, including the failure cases")
	list := fs.Bool("list", false, "list the available samples and exit")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *list || (*url == "" && *sample == "") {
		return listSamples(*provider)
	}
	if *provider == "" {
		return fmt.Errorf("--provider is required")
	}
	if *url == "" {
		return fmt.Errorf("--url is required; get it from `statushubctl endpoints list`")
	}
	if *secret == "" {
		return fmt.Errorf("--secret is required: the simulator signs exactly as the provider would, " +
			"so an unsigned request would be stored and flagged rather than accepted")
	}

	samples, err := simulate.List(*provider)
	if err != nil {
		return err
	}
	if !*all {
		s, err := simulate.Get(*provider, *sample)
		if err != nil {
			return err
		}
		samples = []simulate.Sample{s}
	}

	now := time.Now().UTC()
	var failures int
	for _, s := range samples {
		res, err := simulate.Send(ctx, nil, *url, s, *secret, now)
		if err != nil {
			failures++
			fmt.Printf("  %-28s could not send: %v\n", s.Name, err)
			continue
		}
		if res.StatusCode < 200 || res.StatusCode >= 300 {
			failures++
		}
		fmt.Printf("  %-28s %d in %s\n", s.Name, res.StatusCode, res.Duration.Round(time.Millisecond))
		fmt.Printf("  %-28s %s\n", "", res.Explain())
		if res.Body != "" {
			fmt.Printf("  %-28s %s\n", "", truncateLine(res.Body, 120))
		}
		fmt.Println()
	}

	if failures > 0 {
		return fmt.Errorf("%d of %d simulated events were not accepted", failures, len(samples))
	}
	fmt.Println("All accepted. Check `statushubctl events list --tenant <slug>` in a second or two.")
	return nil
}

func listSamples(provider string) error {
	samples, err := simulate.List(provider)
	if err != nil {
		return err
	}
	current := ""
	for _, s := range samples {
		if s.Provider != current {
			current = s.Provider
			fmt.Printf("\n%s\n", current)
		}
		fmt.Printf("  %-28s %d bytes\n", s.Name, len(s.Body))
	}
	fmt.Printf(`
These are the same captured payloads the adapter test suite runs against, so a
sample the simulator sends is a sample the adapter is proven to read.

  statushubctl simulate --provider paystack --event charge.success \
    --url https://hooks.statushub.dev/v1/hooks/acme/paystack/test/tok_… \
    --secret sk_test_…

Send --all to include the failure and unmapped-status cases, which are the
ones worth putting through your handler before you rely on it.
`)
	return nil
}

func truncateLine(s string, n int) string {
	s = strings.ReplaceAll(strings.TrimSpace(s), "\n", " ")
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
