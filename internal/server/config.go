// Package server wires the components together and runs them.
//
// One binary, two logical workloads (§11.1). The receiver is latency-critical
// and must stay available when the dispatcher is entirely down; the
// dispatcher is throughput-oriented and scales on queue depth. They are
// separate modes rather than separate binaries so there is one artefact to
// build, sign and scan — but they are never coupled at runtime.
package server

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Mode is which workload this process runs.
type Mode string

const (
	ModeReceiver   Mode = "receiver"
	ModeDispatcher Mode = "dispatcher"
	ModeAPI        Mode = "api"

	// ModeAll runs everything in one process. Correct for evaluation, for a
	// single-tenant self-hosted install, and for local development —
	// and wrong for anything with real volume, because the two workloads then
	// share a fate they are designed not to share.
	ModeAll Mode = "all"
)

// Valid reports whether m is a known mode.
func (m Mode) Valid() bool {
	switch m {
	case ModeReceiver, ModeDispatcher, ModeAPI, ModeAll:
		return true
	}
	return false
}

func (m Mode) String() string { return string(m) }

// RunsReceiver reports whether this mode serves provider webhooks.
func (m Mode) RunsReceiver() bool { return m == ModeReceiver || m == ModeAll }

// RunsDispatcher reports whether this mode delivers events.
func (m Mode) RunsDispatcher() bool { return m == ModeDispatcher || m == ModeAll }

// RunsAPI reports whether this mode serves the management API.
func (m Mode) RunsAPI() bool { return m == ModeAPI || m == ModeAll }

// RunsNormaliser reports whether this mode maps raw events.
//
// Normalisation runs with the dispatcher rather than with the receiver. It is
// off the request path by design, and putting it beside the receiver would
// put a variable-cost workload next to the one with a 50 ms budget.
func (m Mode) RunsNormaliser() bool { return m.RunsDispatcher() }

// Config is everything the server needs.
type Config struct {
	Mode Mode

	DatabaseURL string

	// StoreKind is "postgres" or "memory". The memory store is refused in the
	// live environment: it does not survive a restart, and a webhook receiver
	// that loses events on deploy is the one thing this product exists not to
	// be.
	StoreKind string

	Environment string

	ListenAddr    string
	APIListenAddr string

	// BaseURL is the public origin providers POST to. It appears in every
	// receiver URL the API hands out, so a wrong value produces URLs nobody
	// can use.
	BaseURL string

	Shards int

	TrustProxyHeaders bool

	SecretBackend string

	// BlockedCIDRs are ranges destinations may never resolve to, beyond the
	// universal private ones. A VPC range is publicly routable and still
	// inside the perimeter.
	BlockedCIDRs []string

	// AllowPrivateDestinations opens the SSRF guard. For development only,
	// and refused in the live environment.
	AllowPrivateDestinations bool

	NormaliseInterval time.Duration
	DispatchInterval  time.Duration
	DeliveryLease     time.Duration

	ShutdownGrace time.Duration

	LogFormat string
	LogLevel  string
}

// Defaults returns a usable configuration for local evaluation.
func Defaults() Config {
	return Config{
		Mode:              ModeAll,
		StoreKind:         "postgres",
		Environment:       "test",
		ListenAddr:        ":8080",
		APIListenAddr:     ":8081",
		BaseURL:           "http://localhost:8080",
		Shards:            64,
		SecretBackend:     "env",
		NormaliseInterval: 2 * time.Second,
		DispatchInterval:  time.Second,
		DeliveryLease:     2 * time.Minute,
		// Longer than the longest delivery attempt, so a rolling deploy
		// drains rather than severing a request the customer's endpoint is
		// still answering. terminationGracePeriodSeconds must exceed this
		// (§8.6).
		ShutdownGrace: 30 * time.Second,
		LogFormat:     "json",
		LogLevel:      "info",
	}
}

// FromEnv layers environment variables over the defaults. Every name is
// prefixed STATUSHUB_ so a shared environment cannot collide with us, and
// nothing here reads a bare name.
func FromEnv() Config {
	c := Defaults()

	str := func(name string, dst *string) {
		if v, ok := os.LookupEnv("STATUSHUB_" + name); ok && v != "" {
			*dst = v
		}
	}
	boolean := func(name string, dst *bool) {
		if v, ok := os.LookupEnv("STATUSHUB_" + name); ok {
			if b, err := strconv.ParseBool(v); err == nil {
				*dst = b
			}
		}
	}
	dur := func(name string, dst *time.Duration) {
		if v, ok := os.LookupEnv("STATUSHUB_" + name); ok {
			if d, err := time.ParseDuration(v); err == nil {
				*dst = d
			}
		}
	}

	var mode string
	str("MODE", &mode)
	if mode != "" {
		c.Mode = Mode(mode)
	}
	str("DATABASE_URL", &c.DatabaseURL)
	str("STORE", &c.StoreKind)
	str("ENVIRONMENT", &c.Environment)
	str("LISTEN_ADDR", &c.ListenAddr)
	str("API_LISTEN_ADDR", &c.APIListenAddr)
	str("BASE_URL", &c.BaseURL)
	str("SECRET_BACKEND", &c.SecretBackend)
	str("LOG_FORMAT", &c.LogFormat)
	str("LOG_LEVEL", &c.LogLevel)
	boolean("TRUST_PROXY_HEADERS", &c.TrustProxyHeaders)
	boolean("ALLOW_PRIVATE_DESTINATIONS", &c.AllowPrivateDestinations)
	dur("NORMALISE_INTERVAL", &c.NormaliseInterval)
	dur("DISPATCH_INTERVAL", &c.DispatchInterval)
	dur("DELIVERY_LEASE", &c.DeliveryLease)
	dur("SHUTDOWN_GRACE", &c.ShutdownGrace)

	if v := os.Getenv("STATUSHUB_SHARDS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			c.Shards = n
		}
	}
	if v := os.Getenv("STATUSHUB_BLOCKED_CIDRS"); v != "" {
		for _, part := range strings.Split(v, ",") {
			if p := strings.TrimSpace(part); p != "" {
				c.BlockedCIDRs = append(c.BlockedCIDRs, p)
			}
		}
	}
	return c
}

// Validate refuses a configuration that would be unsafe or unusable.
//
// Everything here fails at start-up rather than at the first request. A
// misconfiguration that only appears under traffic is a misconfiguration
// discovered by a customer.
func (c Config) Validate() error {
	if !c.Mode.Valid() {
		return fmt.Errorf("mode %q is not receiver, dispatcher, api or all", c.Mode)
	}

	live := c.Environment == "live" || c.Environment == "production"

	switch c.StoreKind {
	case "postgres":
		if c.DatabaseURL == "" {
			return errors.New("STATUSHUB_DATABASE_URL is required for the postgres store")
		}
	case "memory":
		if live {
			// The in-memory store does not survive a restart. A webhook
			// receiver that loses events on deploy is the one thing this
			// product exists not to be, so this is refused rather than warned
			// about.
			return errors.New("the memory store cannot be used in the live environment: it loses every event on restart")
		}
	default:
		return fmt.Errorf("store %q is not postgres or memory", c.StoreKind)
	}

	if c.AllowPrivateDestinations && live {
		// Opening the SSRF guard in production turns every destination into a
		// way to reach the cloud metadata service.
		return errors.New("private destinations cannot be allowed in the live environment")
	}
	if live && strings.HasPrefix(c.BaseURL, "http://") {
		// Receiver URLs are pasted into providers' dashboards. A plaintext
		// one would carry the token, and the payload, over the open internet.
		return errors.New("BASE_URL must be https in the live environment")
	}
	if c.Shards <= 0 || c.Shards > 4096 {
		return fmt.Errorf("shards must be between 1 and 4096, got %d", c.Shards)
	}
	if c.ShutdownGrace <= 0 {
		return errors.New("shutdown grace must be positive")
	}
	return nil
}
