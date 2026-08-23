package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/nobledeveloper01/StatusHub/internal/adapters"
	"github.com/nobledeveloper01/StatusHub/internal/api"
	"github.com/nobledeveloper01/StatusHub/internal/auth"
	"github.com/nobledeveloper01/StatusHub/internal/dispatch"
	"github.com/nobledeveloper01/StatusHub/internal/metrics"
	"github.com/nobledeveloper01/StatusHub/internal/migrate"
	"github.com/nobledeveloper01/StatusHub/internal/normalise"
	"github.com/nobledeveloper01/StatusHub/internal/receive"
	"github.com/nobledeveloper01/StatusHub/internal/secret"
	"github.com/nobledeveloper01/StatusHub/internal/store"
)

// Server owns the process's components and lifecycle.
type Server struct {
	cfg     Config
	log     *slog.Logger
	metrics *metrics.Registry

	store    store.Store
	keys     auth.KeyStore
	registry *adapters.Registry
	secrets  secret.Resolver
	guard    *dispatch.Guard

	dispatcher *dispatch.Dispatcher
	normaliser *normalise.Normaliser

	receiverHTTP *http.Server
	apiHTTP      *http.Server

	normWorker *normalise.Worker
	dispWorker *dispatch.Worker
}

// New builds everything the configured mode needs, and nothing it does not.
func New(ctx context.Context, cfg Config) (*Server, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	log := newLogger(cfg)
	s := &Server{cfg: cfg, log: log, metrics: metrics.New(), registry: adapters.New()}

	s.metrics.Set("statushub_build_info", metrics.Labels{
		"version": Version, "commit": Commit, "mode": cfg.Mode.String(),
	}, 1)

	st, err := openStore(ctx, cfg, log)
	if err != nil {
		return nil, err
	}
	s.store = st

	s.secrets = openSecrets(cfg)
	s.keys = auth.NewMemoryKeyStore()

	guard, err := dispatch.NewGuard(dispatch.GuardOptions{
		BlockedCIDRs: cfg.BlockedCIDRs,
		AllowPrivate: cfg.AllowPrivateDestinations,
	})
	if err != nil {
		return nil, fmt.Errorf("building the destination guard: %w", err)
	}
	s.guard = guard

	if cfg.Mode.RunsDispatcher() {
		d, err := dispatch.New(dispatch.Options{
			Store: s.store, Secrets: s.secrets, Metrics: s.metrics,
			Logger: log.With("component", "dispatcher"), Guard: guard, Shards: cfg.Shards,
		})
		if err != nil {
			return nil, err
		}
		s.dispatcher = d
		s.dispWorker = dispatch.NewWorker(dispatch.WorkerOptions{
			Dispatcher: d, Interval: cfg.DispatchInterval, Lease: cfg.DeliveryLease,
		})
	}

	if cfg.Mode.RunsNormaliser() {
		s.normaliser = normalise.New(normalise.Options{
			Store: s.store, Registry: s.registry, Secrets: s.secrets, Metrics: s.metrics,
			Logger: log.With("component", "normaliser"),
			// nil when this process does not run the dispatcher, which is
			// fine: the events are stored and the dispatcher's own sweep
			// picks up anything that was never queued.
			Enqueuer: enqueuerOrNil(s.dispatcher),
		})
		s.normWorker = normalise.NewWorker(normalise.WorkerOptions{
			Normaliser: s.normaliser,
			Logger:     log.With("component", "normaliser"),
			Interval:   cfg.NormaliseInterval,
		})
	}

	if cfg.Mode.RunsReceiver() {
		r := receive.New(receive.Options{
			Store: s.store, Registry: s.registry, Secrets: s.secrets, Metrics: s.metrics,
			Logger:            log.With("component", "receiver"),
			Notifier:          notifierOrNil(s.normWorker),
			TrustProxyHeaders: cfg.TrustProxyHeaders,
		})
		s.receiverHTTP = &http.Server{
			Addr:    cfg.ListenAddr,
			Handler: r.Handler(),
			// Tight, because every one of these is a way for a slow or
			// malicious caller to hold a connection the receiver needs for
			// somebody's payment notification.
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       15 * time.Second,
			WriteTimeout:      15 * time.Second,
			IdleTimeout:       60 * time.Second,
			MaxHeaderBytes:    32 << 10,
			ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
		}
	}

	if cfg.Mode.RunsAPI() {
		apiSrv := api.New(api.Options{
			Store: s.store, Keys: s.keys, Registry: s.registry, Dispatcher: s.dispatcher,
			Secrets: s.secrets, Guard: guard, Metrics: s.metrics,
			Logger: log.With("component", "api"), BaseURL: cfg.BaseURL,
		})
		if err := api.LoadTenantAdapters(ctx, apiSrv); err != nil {
			return nil, fmt.Errorf("loading tenant adapters: %w", err)
		}
		addr := cfg.APIListenAddr
		if cfg.Mode == ModeAPI {
			// Running the API alone, the primary listen address is the one
			// the operator configured.
			addr = cfg.ListenAddr
		}
		s.apiHTTP = &http.Server{
			Addr:              addr,
			Handler:           apiSrv.Handler(),
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       90 * time.Second,
			MaxHeaderBytes:    32 << 10,
			ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
		}
	}

	return s, nil
}

// Run serves until the context is cancelled, then drains.
func (s *Server) Run(ctx context.Context) error {
	var (
		wg     sync.WaitGroup
		errsMu sync.Mutex
		errs   []error
	)
	fail := func(err error) {
		errsMu.Lock()
		errs = append(errs, err)
		errsMu.Unlock()
	}

	if s.receiverHTTP != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.log.Info("receiver listening", "addr", s.receiverHTTP.Addr)
			if err := s.receiverHTTP.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				fail(fmt.Errorf("receiver: %w", err))
			}
		}()
	}
	if s.apiHTTP != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.log.Info("management API listening", "addr", s.apiHTTP.Addr)
			if err := s.apiHTTP.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				fail(fmt.Errorf("api: %w", err))
			}
		}()
	}
	if s.normWorker != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.log.Info("normaliser running", "interval", s.cfg.NormaliseInterval)
			s.normWorker.Run(ctx)
		}()
	}
	if s.dispWorker != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.log.Info("dispatcher running", "interval", s.cfg.DispatchInterval, "shards", s.cfg.Shards)
			s.dispWorker.Run(ctx)
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.reclaimLoop(ctx)
		}()
	}

	<-ctx.Done()
	s.log.Info("shutting down", "grace", s.cfg.ShutdownGrace)

	// Graceful shutdown, in this order (§8.6): stop accepting, drain
	// in-flight, then stop the workers. Stopping the receiver first means a
	// provider mid-request still gets its 200, and a provider that has not
	// connected yet is refused at the load balancer rather than dropped
	// mid-body.
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.cfg.ShutdownGrace)
	defer cancel()

	if s.receiverHTTP != nil {
		if err := s.receiverHTTP.Shutdown(shutdownCtx); err != nil {
			fail(fmt.Errorf("receiver shutdown: %w", err))
		}
	}
	if s.apiHTTP != nil {
		if err := s.apiHTTP.Shutdown(shutdownCtx); err != nil {
			fail(fmt.Errorf("api shutdown: %w", err))
		}
	}
	if s.normWorker != nil {
		s.normWorker.Stop()
	}
	if s.dispWorker != nil {
		s.dispWorker.Stop()
	}

	wg.Wait()
	if err := s.store.Close(); err != nil {
		fail(fmt.Errorf("closing the store: %w", err))
	}

	errsMu.Lock()
	defer errsMu.Unlock()
	return errors.Join(errs...)
}

// reclaimLoop returns deliveries abandoned by a dispatcher that died
// mid-attempt.
//
// Without it a killed replica leaves deliveries in_flight forever, and since
// in-flight blocks its transaction reference, that key stalls permanently.
// The loop is what turns a crash into one lease interval of latency.
func (s *Server) reclaimLoop(ctx context.Context) {
	pg, ok := s.store.(*store.Postgres)
	if !ok {
		return
	}
	ticker := time.NewTicker(s.cfg.DeliveryLease / 2)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			n, err := pg.ReclaimExpiredLeases(ctx, time.Now().UTC())
			if err != nil {
				s.log.ErrorContext(ctx, "could not reclaim expired delivery leases", "error", err)
				continue
			}
			if n > 0 {
				s.log.WarnContext(ctx, "reclaimed deliveries abandoned by a dispatcher that stopped mid-attempt",
					"count", n)
			}
		}
	}
}

// Store exposes the store, for the CLI and for tests.
func (s *Server) Store() store.Store { return s.store }

// Keys exposes the key store.
func (s *Server) Keys() auth.KeyStore { return s.keys }

func openStore(ctx context.Context, cfg Config, log *slog.Logger) (store.Store, error) {
	if cfg.StoreKind == "memory" {
		log.Warn("using the in-memory store: nothing survives a restart")
		return store.NewMemory(), nil
	}

	pg, err := store.NewPostgres(ctx, cfg.DatabaseURL)
	if err != nil {
		return nil, err
	}
	// A binary running against an older schema fails in ways that look like
	// data corruption, so it refuses to serve instead. Migrations are applied
	// as a separate, reviewable step before the new binary rolls out (§11.8).
	pending, err := migrate.Pending(ctx, pg.Pool())
	if err != nil {
		_ = pg.Close()
		return nil, fmt.Errorf("checking for pending migrations: %w", err)
	}
	if len(pending) > 0 {
		_ = pg.Close()
		return nil, fmt.Errorf(
			"the database is %d migration(s) behind this binary (%s); run `statushubctl migrate up` first",
			len(pending), strings.Join(pending, ", "))
	}
	return pg, nil
}

func openSecrets(cfg Config) secret.Resolver {
	env := secret.NewEnv()
	static := secret.NewStatic()
	multi := secret.NewMulti(map[string]secret.Resolver{
		"env":    env,
		"static": static,
	})
	// Cached, because the receiver resolves a secret on every request and a
	// secret-manager round trip per webhook would spend the whole 50 ms
	// budget. Thirty seconds bounds how long a revoked secret stays usable.
	return secret.NewCached(multi, 30*time.Second)
}

func enqueuerOrNil(d *dispatch.Dispatcher) normalise.Enqueuer {
	if d == nil {
		return nil
	}
	return d
}

func notifierOrNil(w *normalise.Worker) receive.Notifier {
	if w == nil {
		return nil
	}
	return w
}

func newLogger(cfg Config) *slog.Logger {
	level := slog.LevelInfo
	switch strings.ToLower(cfg.LogLevel) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	opts := &slog.HandlerOptions{Level: level}

	var h slog.Handler = slog.NewJSONHandler(os.Stdout, opts)
	if strings.EqualFold(cfg.LogFormat, "text") {
		h = slog.NewTextHandler(os.Stdout, opts)
	}
	return slog.New(h).With("service", "statushub", "mode", cfg.Mode.String())
}

// Version and Commit are set at build time with -ldflags.
var (
	Version = "dev"
	Commit  = "unknown"
)
