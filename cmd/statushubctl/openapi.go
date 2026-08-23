package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/nobledeveloper01/StatusHub/internal/api"
	"github.com/nobledeveloper01/StatusHub/internal/server"
)

// cmdOpenAPI prints the specification, generated from the router.
//
// Generated rather than maintained, because a specification written beside
// the code drifts — silently, starting the first time somebody adds a route
// in a hurry — and a drifted specification is worse than none: a generated
// client calls endpoints that do not exist, omits ones that do, and is
// trusted because it looks authoritative.
func cmdOpenAPI(_ context.Context, args []string) error {
	fs := flag.NewFlagSet("openapi", flag.ExitOnError)
	out := fs.String("out", "", "write here instead of standard output")
	version := fs.String("version", server.Version, "the version to stamp into the document")
	if err := fs.Parse(args); err != nil {
		return err
	}

	doc := api.OpenAPIDocument(*version)
	if *out == "" {
		fmt.Print(doc)
		return nil
	}
	if err := os.WriteFile(*out, []byte(doc), 0o600); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote %s\n", *out)
	return nil
}
