package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/nobledeveloper01/StatusHub/internal/adapters"
	"github.com/nobledeveloper01/StatusHub/internal/adapters/declarative"
	"github.com/nobledeveloper01/StatusHub/internal/auth"
	"github.com/nobledeveloper01/StatusHub/internal/domain"
	"github.com/nobledeveloper01/StatusHub/internal/migrate"
	"github.com/nobledeveloper01/StatusHub/internal/store"
)

func openStore(ctx context.Context) (*store.Postgres, error) {
	dsn, err := databaseURL()
	if err != nil {
		return nil, err
	}
	return store.NewPostgres(ctx, dsn)
}

func openPool(ctx context.Context) (*pgxpool.Pool, error) {
	dsn, err := databaseURL()
	if err != nil {
		return nil, err
	}
	return pgxpool.New(ctx, dsn)
}

// --- migrate ---

func cmdMigrate(ctx context.Context, args []string) error {
	sub := "status"
	if len(args) > 0 {
		sub = args[0]
	}
	pool, err := openPool(ctx)
	if err != nil {
		return err
	}
	defer pool.Close()

	switch sub {
	case "up":
		ran, err := migrate.Up(ctx, pool)
		if err != nil {
			return err
		}
		if len(ran) == 0 {
			fmt.Println("already up to date")
			return nil
		}
		for _, v := range ran {
			fmt.Printf("applied %s\n", v)
		}
		return nil

	case "status":
		statuses, err := migrate.StatusOf(ctx, pool)
		if err != nil {
			return err
		}
		for _, s := range statuses {
			if s.Applied {
				fmt.Printf("  applied  %s  %s\n", s.Version, s.AppliedAt.Format(time.RFC3339))
				continue
			}
			fmt.Printf("  pending  %s\n", s.Version)
		}
		return nil

	default:
		return fmt.Errorf("unknown subcommand %q; use up or status", sub)
	}
}

// --- init ---

// cmdInit is the first command anybody runs. It creates a tenant and an owner
// key in one step, because a two-step provisioning flow is a flow people get
// half-way through.
func cmdInit(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	slug := fs.String("slug", "", "URL-safe tenant slug; it appears in every receiver URL")
	name := fs.String("name", "", "human-readable tenant name")
	env := fs.String("env", "live", "test or live")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *slug == "" {
		return fmt.Errorf("--slug is required")
	}
	if *name == "" {
		*name = *slug
	}
	environment := domain.Environment(*env)
	if !environment.Valid() {
		return fmt.Errorf("--env must be test or live")
	}

	s, err := openStore(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = s.Close() }()

	tenant := domain.Tenant{
		ID: domain.NewID(domain.PrefixTenant), Slug: *slug, Name: *name, CreatedAt: time.Now().UTC(),
	}
	if err := s.CreateTenant(ctx, tenant); err != nil {
		return err
	}

	plaintext, key, err := auth.Issue(tenant.ID, environment, auth.RoleOwner, "bootstrap", 0)
	if err != nil {
		return err
	}

	fmt.Printf("tenant   %s (%s)\n", tenant.Slug, tenant.ID)
	fmt.Printf("key id   %s\n", key.ID)
	fmt.Printf("api key  %s\n\n", plaintext)
	// Said plainly, because a customer who does not read this line discovers
	// it the hard way.
	fmt.Println("This key is shown once. It is stored as an Argon2id hash and cannot be recovered.")
	fmt.Println()
	fmt.Printf("Next:\n  statushubctl endpoints create --tenant %s --provider paystack --env %s --secret-ref env://PAYSTACK_LIVE\n",
		tenant.Slug, environment)
	return nil
}

// --- tenants ---

func cmdTenants(ctx context.Context, args []string) error {
	s, err := openStore(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = s.Close() }()

	tenants, err := s.ListTenants(ctx)
	if err != nil {
		return err
	}
	if len(tenants) == 0 {
		fmt.Println("no tenants yet; run `statushubctl init --slug <name>`")
		return nil
	}
	for _, t := range tenants {
		fmt.Printf("  %-24s %-32s %s\n", t.Slug, t.Name, t.ID)
	}
	return nil
}

// --- endpoints ---

func cmdEndpoints(ctx context.Context, args []string) error {
	sub := "list"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub, args = args[0], args[1:]
	}
	s, err := openStore(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = s.Close() }()

	switch sub {
	case "list":
		fs := flag.NewFlagSet("endpoints list", flag.ExitOnError)
		slug := fs.String("tenant", "", "tenant slug")
		if err := fs.Parse(args); err != nil {
			return err
		}
		tenant, err := s.GetTenantBySlug(ctx, *slug)
		if err != nil {
			return fmt.Errorf("tenant %q: %w", *slug, err)
		}
		eps, err := s.ListEndpoints(ctx, tenant.ID)
		if err != nil {
			return err
		}
		for _, e := range eps {
			state := "enabled"
			if !e.Enabled {
				state = "disabled"
			}
			fmt.Printf("  %-12s %-6s %-9s %s\n", e.Provider, e.Environment, state, e.ReceiverPath(tenant.Slug))
		}
		return nil

	case "create":
		fs := flag.NewFlagSet("endpoints create", flag.ExitOnError)
		slug := fs.String("tenant", "", "tenant slug")
		provider := fs.String("provider", "", "paystack, flutterwave, nibss, monnify, interswitch, stripe, or a declarative adapter name")
		env := fs.String("env", "live", "test or live")
		adapterName := fs.String("adapter", "", "adapter name, if it differs from the provider")
		secretRef := fs.String("secret-ref", "", "reference to the provider's signing secret, e.g. env://PAYSTACK_LIVE")
		baseURL := fs.String("base-url", "https://hooks.statushub.dev", "public origin providers POST to")
		if err := fs.Parse(args); err != nil {
			return err
		}
		if *slug == "" || *provider == "" || *secretRef == "" {
			return fmt.Errorf("--tenant, --provider and --secret-ref are required")
		}
		environment := domain.Environment(*env)
		if !environment.Valid() {
			return fmt.Errorf("--env must be test or live")
		}
		if *adapterName == "" {
			*adapterName = *provider
		}

		tenant, err := s.GetTenantBySlug(ctx, *slug)
		if err != nil {
			return fmt.Errorf("tenant %q: %w", *slug, err)
		}
		ep := domain.Endpoint{
			ID: domain.NewID(domain.PrefixEndpoint), TenantID: tenant.ID,
			Provider: *provider, Environment: environment, ReceiverToken: domain.NewToken(),
			SecretRef: *secretRef, AdapterName: *adapterName, Enabled: true, CreatedAt: time.Now().UTC(),
		}
		if err := s.CreateEndpoint(ctx, ep); err != nil {
			return err
		}
		fmt.Printf("%s%s\n\n", strings.TrimRight(*baseURL, "/"), ep.ReceiverPath(tenant.Slug))
		fmt.Println("Paste that into the provider's dashboard. Nothing else changes in your codebase.")
		return nil

	case "rotate":
		fs := flag.NewFlagSet("endpoints rotate", flag.ExitOnError)
		slug := fs.String("tenant", "", "tenant slug")
		id := fs.String("id", "", "endpoint id")
		baseURL := fs.String("base-url", "https://hooks.statushub.dev", "public origin")
		if err := fs.Parse(args); err != nil {
			return err
		}
		tenant, err := s.GetTenantBySlug(ctx, *slug)
		if err != nil {
			return err
		}
		ep, err := s.GetEndpoint(ctx, tenant.ID, *id)
		if err != nil {
			return err
		}
		ep.ReceiverToken = domain.NewToken()
		ep.RotatedAt = time.Now().UTC()
		if err := s.UpdateEndpoint(ctx, tenant.ID, ep); err != nil {
			return err
		}
		fmt.Printf("%s%s\n\n", strings.TrimRight(*baseURL, "/"), ep.ReceiverPath(tenant.Slug))
		fmt.Println("The previous token stopped working immediately. Update the provider's dashboard now.")
		return nil

	default:
		return fmt.Errorf("unknown subcommand %q; use list, create or rotate", sub)
	}
}

// --- destinations ---

func cmdDestinations(ctx context.Context, args []string) error {
	sub := "list"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub, args = args[0], args[1:]
	}
	s, err := openStore(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = s.Close() }()

	switch sub {
	case "list":
		fs := flag.NewFlagSet("destinations list", flag.ExitOnError)
		slug := fs.String("tenant", "", "tenant slug")
		if err := fs.Parse(args); err != nil {
			return err
		}
		tenant, err := s.GetTenantBySlug(ctx, *slug)
		if err != nil {
			return err
		}
		dests, err := s.ListDestinations(ctx, tenant.ID)
		if err != nil {
			return err
		}
		for _, d := range dests {
			fmt.Printf("  %-28s %s\n", d.ID, d.URL)
		}
		return nil

	case "create":
		fs := flag.NewFlagSet("destinations create", flag.ExitOnError)
		slug := fs.String("tenant", "", "tenant slug")
		url := fs.String("url", "", "https URL to forward to")
		name := fs.String("name", "", "a label, for the dashboard")
		secretRef := fs.String("secret-ref", "", "reference to the secret StatusHub signs deliveries with")
		includeRaw := fs.Bool("include-raw", false, "attach the provider's original body to each delivery")
		if err := fs.Parse(args); err != nil {
			return err
		}
		if *slug == "" || *url == "" || *secretRef == "" {
			return fmt.Errorf("--tenant, --url and --secret-ref are required")
		}
		if err := domain.ValidateDestinationURL(*url); err != nil {
			return err
		}
		tenant, err := s.GetTenantBySlug(ctx, *slug)
		if err != nil {
			return err
		}
		dest := domain.Destination{
			ID: domain.NewID(domain.PrefixDestination), TenantID: tenant.ID, Name: *name,
			URL: *url, SigningSecretRef: *secretRef, RetryPolicy: domain.DefaultRetryPolicy(),
			IncludeRaw: *includeRaw, Enabled: true, CreatedAt: time.Now().UTC(),
		}
		if err := s.CreateDestination(ctx, dest); err != nil {
			return err
		}
		fmt.Printf("%s -> %s\n", dest.ID, dest.URL)
		fmt.Println("Retry schedule: 0s, 10s, 1m, 5m, 30m, 2h, 6h, then the dead-letter queue.")
		return nil

	default:
		return fmt.Errorf("unknown subcommand %q; use list or create", sub)
	}
}

// --- adapters ---

func cmdAdapters(ctx context.Context, args []string) error {
	sub := "list"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub, args = args[0], args[1:]
	}

	switch sub {
	case "list":
		for _, d := range adapters.New().Describe() {
			fmt.Printf("  %-14s %s\n", d.Name, d.SignatureScheme)
			if d.Notes != "" {
				fmt.Printf("  %-14s %s\n", "", wrap(d.Notes, 76, 18))
			}
		}
		return nil

	case "describe":
		fs := flag.NewFlagSet("adapters describe", flag.ExitOnError)
		name := fs.String("name", "", "adapter name")
		if err := fs.Parse(args); err != nil {
			return err
		}
		for _, d := range adapters.New().Describe() {
			if d.Name != *name {
				continue
			}
			out, _ := json.MarshalIndent(d, "", "  ")
			fmt.Println(string(out))
			return nil
		}
		return fmt.Errorf("no built-in adapter named %q", *name)

	case "test":
		// Runbook 11.5, step 4: test a corrected adapter against the payloads
		// that broke it, before it goes anywhere near live traffic.
		fs := flag.NewFlagSet("adapters test", flag.ExitOnError)
		configPath := fs.String("config", "", "path to a declarative adapter configuration")
		samplePaths := multiFlag{}
		fs.Var(&samplePaths, "sample", "path to a captured payload; repeat for several")
		if err := fs.Parse(args); err != nil {
			return err
		}
		if *configPath == "" {
			return fmt.Errorf("--config is required")
		}

		raw, err := os.ReadFile(*configPath)
		if err != nil {
			return err
		}
		cfg, err := declarative.Parse(raw)
		if err != nil {
			return err
		}

		var samples []declarative.Sample
		for _, p := range samplePaths {
			body, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			samples = append(samples, declarative.Sample{Name: p, Body: string(body)})
		}

		result := declarative.Test(cfg, declarative.TestRequest{Payloads: samples})
		out, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(out))
		if !result.Valid {
			return fmt.Errorf("the adapter is not valid")
		}
		for _, s := range result.Samples {
			if !s.Parsed {
				return fmt.Errorf("sample %s did not parse: %s", s.Name, s.Error)
			}
		}
		return nil

	default:
		return fmt.Errorf("unknown subcommand %q; use list, describe or test", sub)
	}
}

// --- events ---

func cmdEvents(ctx context.Context, args []string) error {
	sub := "list"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub, args = args[0], args[1:]
	}
	s, err := openStore(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = s.Close() }()

	fs := flag.NewFlagSet("events "+sub, flag.ExitOnError)
	slug := fs.String("tenant", "", "tenant slug")
	provider := fs.String("provider", "", "filter by provider")
	ref := fs.String("transaction-ref", "", "filter by transaction reference")
	statusFlag := fs.String("status", "", "filter by canonical status")
	mappingComplete := fs.String("mapping-complete", "", "true or false")
	from := fs.String("from", "", "RFC 3339 lower bound")
	to := fs.String("to", "", "RFC 3339 upper bound")
	limit := fs.Int("limit", 50, "maximum rows")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *slug == "" {
		return fmt.Errorf("--tenant is required")
	}
	tenant, err := s.GetTenantBySlug(ctx, *slug)
	if err != nil {
		return err
	}

	q := store.EventQuery{
		Provider: *provider, TransactionRef: *ref, Limit: *limit,
	}
	if *statusFlag != "" {
		st, err := domain.ParseStatus(*statusFlag)
		if err != nil {
			return err
		}
		q.Status = st
	}
	if *mappingComplete != "" {
		b := *mappingComplete == "true"
		q.MappingComplete = &b
	}
	for _, pair := range []struct {
		s   string
		dst *time.Time
	}{{*from, &q.From}, {*to, &q.To}} {
		if pair.s == "" {
			continue
		}
		t, err := time.Parse(time.RFC3339, pair.s)
		if err != nil {
			return fmt.Errorf("%q is not an RFC 3339 timestamp", pair.s)
		}
		*pair.dst = t
	}

	switch sub {
	case "list":
		events, err := s.QueryEvents(ctx, tenant.ID, q)
		if err != nil {
			return err
		}
		if len(events) == 0 {
			fmt.Println("no matching events")
			return nil
		}
		for _, e := range events {
			flag := ""
			if !e.MappingComplete {
				flag = "  mapping incomplete"
			}
			if e.UnmappedStatus != "" {
				flag += fmt.Sprintf("  unmapped:%s", e.UnmappedStatus)
			}
			fmt.Printf("  %s  %-12s %-26s %-9s %12d %s%s\n",
				e.OccurredAt.Format(time.RFC3339), e.Provider, e.TransactionRef,
				e.Status, e.AmountMinor, e.Currency, flag)
		}
		return nil

	case "replay":
		// Runbook 11.5, step 6. The dry run is printed first, always: a bulk
		// replay is the easiest way to send a customer's own system a million
		// requests by accident.
		events, err := s.QueryEvents(ctx, tenant.ID, q)
		if err != nil {
			return err
		}
		fmt.Printf("%d events match. Replay is queued through the API or the dashboard;\n", len(events))
		fmt.Println("this command shows you the size of the window before you commit to it.")
		return nil

	default:
		return fmt.Errorf("unknown subcommand %q; use list or replay", sub)
	}
}

// --- keys ---

func cmdKeys(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("keys", flag.ExitOnError)
	tenantID := fs.String("tenant-id", "", "tenant id")
	role := fs.String("role", "engineer", "owner, engineer, support or read_only")
	env := fs.String("env", "live", "test or live")
	name := fs.String("name", "", "a label, for the dashboard")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *tenantID == "" {
		return fmt.Errorf("--tenant-id is required")
	}
	r := auth.Role(*role)
	if !r.Valid() {
		return fmt.Errorf("--role must be owner, engineer, support or read_only")
	}
	environment := domain.Environment(*env)
	if !environment.Valid() {
		return fmt.Errorf("--env must be test or live")
	}

	plaintext, key, err := auth.Issue(*tenantID, environment, r, *name, 0)
	if err != nil {
		return err
	}
	fmt.Printf("key id  %s\nkey     %s\n\n", key.ID, plaintext)
	fmt.Println("Shown once. Store it now.")
	return nil
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func wrap(s string, width, indent int) string {
	words := strings.Fields(s)
	var (
		b    strings.Builder
		line int
	)
	for i, w := range words {
		if line+len(w)+1 > width && i > 0 {
			b.WriteString("\n" + strings.Repeat(" ", indent))
			line = 0
		} else if i > 0 {
			b.WriteString(" ")
			line++
		}
		b.WriteString(w)
		line += len(w)
	}
	return b.String()
}
