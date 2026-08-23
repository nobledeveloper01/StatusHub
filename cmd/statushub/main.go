// Command statushub is the server. One binary, two logical workloads
// selected by --mode (§11.1).
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/nobledeveloper01/StatusHub/internal/server"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "statushub: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg := server.FromEnv()

	fs := flag.NewFlagSet("statushub", flag.ExitOnError)
	mode := fs.String("mode", cfg.Mode.String(),
		"receiver, dispatcher, api, or all. Receiver and dispatcher are deployed separately in production so they scale on different signals and fail independently.")
	addr := fs.String("listen", cfg.ListenAddr, "address the receiver listens on")
	apiAddr := fs.String("api-listen", cfg.APIListenAddr, "address the management API listens on")
	storeKind := fs.String("store", cfg.StoreKind, "postgres or memory. Memory is for evaluation only and is refused in the live environment.")
	baseURL := fs.String("base-url", cfg.BaseURL, "public origin providers POST to; it appears in every receiver URL")
	showVersion := fs.Bool("version", false, "print the version and exit")

	fs.Usage = func() {
		_, _ = fmt.Fprintf(fs.Output(), `StatusHub %s — one webhook receiver in front of every payment provider.

Usage:
  statushub serve [flags]
  statushub --version

Every flag can also be set as an environment variable with a STATUSHUB_
prefix, which is how they arrive in a container: STATUSHUB_MODE,
STATUSHUB_DATABASE_URL, STATUSHUB_LISTEN_ADDR, and so on.

Flags:
`, server.Version)
		fs.PrintDefaults()
	}

	args := os.Args[1:]
	if len(args) > 0 && args[0] == "serve" {
		args = args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *showVersion {
		fmt.Printf("statushub %s (%s)\n", server.Version, server.Commit)
		return nil
	}

	cfg.Mode = server.Mode(*mode)
	cfg.ListenAddr = *addr
	cfg.APIListenAddr = *apiAddr
	cfg.StoreKind = *storeKind
	cfg.BaseURL = *baseURL

	// SIGTERM is what a container orchestrator sends. Cancelling the context
	// on it starts the drain; the second signal is not caught, so an operator
	// who is out of patience can still kill the process (§8.6).
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	srv, err := server.New(ctx, cfg)
	if err != nil {
		return err
	}
	return srv.Run(ctx)
}
