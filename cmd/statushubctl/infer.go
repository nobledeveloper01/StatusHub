package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/nobledeveloper01/StatusHub/internal/adapters/declarative"
)

// cmdInfer drafts an adapter from captured payloads.
func cmdInfer(_ context.Context, args []string) error {
	fs := flag.NewFlagSet("infer", flag.ExitOnError)
	name := fs.String("name", "", "adapter name; lower-case letters, digits and hyphens")
	out := fs.String("out", "", "write the draft configuration here instead of standard output")
	samplePaths := multiFlag{}
	fs.Var(&samplePaths, "sample", "path to a captured payload; repeat for several")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" {
		return fmt.Errorf("--name is required")
	}
	if len(samplePaths) < 2 {
		return fmt.Errorf("at least two --sample payloads are needed; three or four covering success, " +
			"failure and pending gives a much better draft")
	}

	samples := make([]declarative.Sample, 0, len(samplePaths))
	for _, path := range samplePaths {
		// #nosec G304 -- the path is an argument the operator typed. This is a
		// CLI reading a file its user named; refusing to would make the
		// command useless, and the operator already has whatever access
		// the process has.
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		samples = append(samples, declarative.Sample{Name: path, Body: string(body)})
	}

	proposal, err := declarative.Infer(*name, samples)
	if err != nil {
		return err
	}

	// The reasoning goes to stderr and the configuration to stdout, so the
	// draft can be piped straight to a file while the engineer still reads
	// what was guessed and why.
	fmt.Fprintf(os.Stderr, "%s\n\n", proposal.Summary())
	for _, g := range proposal.Guesses {
		marker := " "
		if g.Confidence != "high" {
			marker = "!"
		}
		fmt.Fprintf(os.Stderr, "%s %-22s %-28s %s\n", marker, g.Field, g.Path, g.Confidence)
		fmt.Fprintf(os.Stderr, "  %-22s %s\n", "", wrap(g.Why, 72, 25))
	}
	if len(proposal.Warnings) > 0 {
		fmt.Fprintln(os.Stderr, "\nBefore activating this:")
		for _, w := range proposal.Warnings {
			fmt.Fprintf(os.Stderr, "  - %s\n", wrap(w, 72, 4))
		}
	}

	// Dry-run against the same samples, so the engineer sees whether the
	// draft actually reads them rather than only that it compiles.
	result := declarative.Test(proposal.Config, declarative.TestRequest{Payloads: samples})
	fmt.Fprintln(os.Stderr)
	for _, sr := range result.Samples {
		status := "parsed"
		if !sr.Parsed {
			status = "DID NOT PARSE: " + sr.Error
		}
		fmt.Fprintf(os.Stderr, "  %-40s %s\n", sr.Name, status)
		if len(sr.MissingFields) > 0 {
			fmt.Fprintf(os.Stderr, "  %-40s missing: %s\n", "", strings.Join(sr.MissingFields, ", "))
		}
	}

	body, err := json.MarshalIndent(proposal.Config, "", "  ")
	if err != nil {
		return err
	}
	if *out != "" {
		if err := os.WriteFile(*out, append(body, '\n'), 0o600); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "\nwrote %s\n", *out)
		fmt.Fprintf(os.Stderr, "Next: statushubctl adapters test --config %s %s\n",
			*out, "--sample "+strings.Join(samplePaths, " --sample "))
		return nil
	}
	fmt.Println(string(body))
	return nil
}
