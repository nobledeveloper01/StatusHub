package declarative

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/nobledeveloper01/StatusHub/internal/adapter"
	"github.com/nobledeveloper01/StatusHub/internal/domain"
	"github.com/nobledeveloper01/StatusHub/internal/jsonpath"
)

// Adapter is a compiled declarative configuration.
//
// Compiling once and reusing is not only a performance choice. A path that
// compiles at upload time cannot fail to compile at event time, which means
// there is no class of adapter error that first appears in production at
// three in the morning.
type Adapter struct {
	cfg Config
	loc *time.Location

	txnRef    jsonpath.Path
	eventID   *jsonpath.Path
	statusAt  jsonpath.Path
	occurred  *jsonpath.Path
	amount    *jsonpath.Path
	currency  *jsonpath.Path
	customer  *jsonpath.Path
	signed    []jsonpath.Path
	extras    map[string]jsonpath.Path
	statusMap map[string]domain.Status
	claimed   map[string]struct{}

	now func() time.Time
}

// Compile validates a configuration and turns it into a runnable adapter.
func Compile(cfg Config) (*Adapter, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	a := &Adapter{
		cfg:       cfg,
		statusMap: make(map[string]domain.Status, len(cfg.Mapping.Status.Values)),
		extras:    make(map[string]jsonpath.Path, len(cfg.Mapping.ExtraFields)),
		claimed:   map[string]struct{}{},
		now:       func() time.Time { return time.Now().UTC() },
	}

	loc, err := adapter.LoadLocation(cfg.Mapping.OccurredAt.Timezone)
	if err != nil {
		return nil, err
	}
	if cfg.Mapping.OccurredAt.Timezone == "" {
		// No configured zone means naive timestamps are an error rather than
		// being read as UTC. Validate has already rejected a format that
		// needs one, so this only affects the format-free guessing path.
		loc = nil
	}
	a.loc = loc

	if a.txnRef, err = jsonpath.Compile(cfg.Mapping.TransactionRef); err != nil {
		return nil, err
	}
	a.claim(a.txnRef)

	if a.statusAt, err = jsonpath.Compile(cfg.Mapping.Status.Path); err != nil {
		return nil, err
	}
	a.claim(a.statusAt)

	for _, opt := range []struct {
		src string
		dst **jsonpath.Path
	}{
		{cfg.Mapping.ProviderEventID, &a.eventID},
		{cfg.Mapping.OccurredAt.Path, &a.occurred},
		{cfg.Mapping.Amount.Path, &a.amount},
		{cfg.Mapping.Amount.CurrencyPath, &a.currency},
		{cfg.Mapping.CustomerRef, &a.customer},
	} {
		if opt.src == "" {
			continue
		}
		p, err := jsonpath.Compile(opt.src)
		if err != nil {
			return nil, err
		}
		*opt.dst = &p
		a.claim(p)
	}

	for name, path := range cfg.Mapping.ExtraFields {
		p, err := jsonpath.Compile(path)
		if err != nil {
			return nil, err
		}
		a.extras[name] = p
	}

	for _, f := range cfg.Verification.Fields {
		p, err := jsonpath.Compile(f)
		if err != nil {
			return nil, err
		}
		a.signed = append(a.signed, p)
	}

	for raw, mapped := range cfg.Mapping.Status.Values {
		key := raw
		if !cfg.Mapping.Status.CaseSensitive {
			key = strings.ToLower(strings.TrimSpace(raw))
		}
		a.statusMap[key] = domain.Status(mapped)
	}
	return a, nil
}

// WithClock returns a copy using the supplied clock, for testing timestamp
// windows without sleeping.
func (a *Adapter) WithClock(now func() time.Time) *Adapter {
	c := *a
	if now != nil {
		c.now = now
	}
	return &c
}

func (a *Adapter) claim(p jsonpath.Path) {
	a.claimed[strings.TrimPrefix(strings.TrimPrefix(p.String(), "$"), ".")] = struct{}{}
}

// Config returns the configuration this adapter was compiled from, so the
// dashboard's editor can round-trip it.
func (a *Adapter) Config() Config { return a.cfg }

func (a *Adapter) Name() string { return a.cfg.Name }

// Verify applies the configured scheme.
func (a *Adapter) Verify(headers http.Header, rawBody []byte, secret string) error {
	v := a.cfg.Verification

	switch v.Type {
	case "source_only":
		// The source check itself runs in the receiver, which is the only
		// place that knows the connection's address. Here there is nothing
		// to verify, and saying so plainly beats returning a success that
		// implies a check happened.
		return nil

	case "shared_secret":
		presented := adapter.FirstHeader(headers, v.Header)
		if presented == "" {
			return adapter.ErrNoSignature
		}
		if secret == "" {
			return adapter.Failf(adapter.ErrBadSignature, "endpoint has no configured secret")
		}
		if !adapter.Equal(presented, secret, adapter.Hex) {
			return adapter.ErrBadSignature
		}
		return nil

	case "hmac":
		presented := adapter.FirstHeader(headers, v.Header)
		if presented == "" {
			return adapter.ErrNoSignature
		}

		if v.TimestampHeader != "" {
			ts := adapter.FirstHeader(headers, v.TimestampHeader)
			if ts == "" {
				return adapter.Failf(adapter.ErrMalformedHeader, "timestamp header %s is absent", v.TimestampHeader)
			}
			signedAt, err := adapter.ParseTime(ts, time.UTC)
			if err != nil {
				return adapter.Failf(adapter.ErrMalformedHeader, "timestamp header is not a timestamp")
			}
			// Checked before the digest: a captured request replayed later
			// carries a genuine signature, so only the window stops it.
			if err := adapter.CheckTimestamp(signedAt, a.now(), v.Tolerance()); err != nil {
				return err
			}
		}

		payload, err := a.signedPayload(rawBody)
		if err != nil {
			return err
		}
		alg := adapter.Algorithm(v.Algorithm)
		enc := adapter.Encoding(v.Encoding)
		if enc == "" {
			enc = adapter.Hex
		}
		return adapter.VerifyHMAC(alg, enc, secret, payload, presented)

	default:
		return adapter.Failf(adapter.ErrBadSignature, "adapter has no usable verification type")
	}
}

// signedPayload builds the bytes the signature covers.
func (a *Adapter) signedPayload(rawBody []byte) ([]byte, error) {
	if a.cfg.Verification.Source != "fields" {
		return rawBody, nil
	}
	doc, err := jsonpath.Decode(rawBody)
	if err != nil {
		return nil, adapter.Failf(adapter.ErrMalformedHeader, "payload is not JSON, so the signed fields cannot be read")
	}
	var b strings.Builder
	for _, p := range a.signed {
		s, err := jsonpath.StringAt(doc, p)
		if err != nil {
			return nil, adapter.Failf(adapter.ErrBadSignature, "signed field %s is absent", p)
		}
		b.WriteString(s)
	}
	return []byte(b.String()), nil
}

// Parse maps a payload using the configured mapping.
func (a *Adapter) Parse(rawBody []byte) (domain.CanonicalEvent, error) {
	doc, err := jsonpath.Decode(rawBody)
	if err != nil {
		return domain.CanonicalEvent{}, fmt.Errorf("%w: %w", adapter.ErrUnparseable, err)
	}

	ev := domain.CanonicalEvent{
		Provider:        a.cfg.Name,
		ProviderExtra:   map[string]any{},
		MappingComplete: true,
	}

	ref, err := jsonpath.StringAt(doc, a.txnRef)
	if err != nil || ref == "" {
		return domain.CanonicalEvent{}, fmt.Errorf("%w: %s did not resolve", adapter.ErrNoTransaction, a.txnRef)
	}
	ev.TransactionRef = ref

	if a.eventID != nil {
		if id, err := jsonpath.StringAt(doc, *a.eventID); err == nil && id != "" {
			ev.ProviderEventID = id
		}
	}

	rawStatus, err := jsonpath.StringAt(doc, a.statusAt)
	if err != nil {
		ev.Status = domain.StatusUnknown
		ev.MappingComplete = false
	} else {
		key := rawStatus
		if !a.cfg.Mapping.Status.CaseSensitive {
			key = strings.ToLower(strings.TrimSpace(rawStatus))
		}
		if s, ok := a.statusMap[key]; ok {
			ev.Status = s
		} else {
			// The default is guaranteed to be unknown; Validate refuses
			// anything else.
			ev.Status = domain.StatusUnknown
			ev.UnmappedStatus = rawStatus
			ev.MappingComplete = false
		}
	}

	family := a.cfg.Mapping.EventFamily
	if family == "" {
		family = "payment"
	}
	ev.EventType = domain.EventTypeFor(family, ev.Status)

	currency := domain.NormaliseCurrency(a.cfg.Mapping.Amount.DefaultCurrency)
	if a.currency != nil {
		if c, err := jsonpath.StringAt(doc, *a.currency); err == nil && c != "" {
			currency = domain.NormaliseCurrency(c)
		} else if currency == "" {
			ev.MappingComplete = false
		}
	}
	ev.Currency = currency

	if a.amount != nil {
		if v, err := a.amount.Eval(doc); err == nil {
			if s, ok := jsonpath.String(v); ok {
				var (
					minor int64
					cerr  error
				)
				if a.cfg.Mapping.Amount.Unit == "major" {
					minor, cerr = domain.MajorToMinor(s, currency)
				} else {
					minor, cerr = domain.ParseMinor(s)
				}
				if cerr == nil {
					ev.AmountMinor = minor
				} else {
					ev.MappingComplete = false
				}
			} else {
				ev.MappingComplete = false
			}
		} else {
			ev.MappingComplete = false
		}
	}

	if a.occurred != nil {
		if s, err := jsonpath.StringAt(doc, *a.occurred); err == nil && s != "" {
			t, perr := adapter.ParseTimeLayout(s, a.cfg.Mapping.OccurredAt.Format, a.loc)
			if perr == nil {
				ev.OccurredAt = t
			} else {
				ev.MappingComplete = false
			}
		} else {
			ev.MappingComplete = false
		}
	}

	if a.customer != nil {
		if s, err := jsonpath.StringAt(doc, *a.customer); err == nil && s != "" {
			ev.CustomerRefHash = s
		}
	}

	// Named extras first, then everything unclaimed. Nothing the provider
	// sent is dropped (§3.2 B4).
	for name, p := range a.extras {
		if v, err := p.Eval(doc); err == nil {
			ev.ProviderExtra[name] = v
		}
	}
	for k, v := range jsonpath.Flatten(doc) {
		if _, taken := a.claimed[k]; taken {
			continue
		}
		if _, named := ev.ProviderExtra[k]; named {
			continue
		}
		ev.ProviderExtra[k] = v
	}
	return ev, nil
}

// DedupeKey reads the configured provider event ID.
func (a *Adapter) DedupeKey(rawBody []byte) (string, bool) {
	if a.eventID == nil {
		return "", false
	}
	doc, err := jsonpath.Decode(rawBody)
	if err != nil {
		return "", false
	}
	id, err := jsonpath.StringAt(doc, *a.eventID)
	if err != nil || id == "" {
		return "", false
	}
	return id, true
}

// AllowedSources implements adapter.SourceRestricted for source_only
// adapters.
func (a *Adapter) AllowedSources() []string { return a.cfg.Verification.AllowedSourceCIDRs }

// WhySourceCheckIsWeaker is shown wherever a source_only adapter is used.
func (a *Adapter) WhySourceCheckIsWeaker() string {
	return "This adapter authenticates on source address alone, with no signature. An address can be " +
		"spoofed on a network path StatusHub does not control, and a provider's published ranges change " +
		"without notice. Treat events from this endpoint as authenticated more weakly than the others, " +
		"and ask the provider for a signing secret."
}

// Describe documents a customer's own adapter the same way the built-in ones
// are documented.
func (a *Adapter) Describe() adapter.Description {
	known := make(map[string]string, len(a.statusMap))
	for k, v := range a.statusMap {
		known[k] = v.String()
	}
	display := a.cfg.DisplayName
	if display == "" {
		display = a.cfg.Name
	}
	scheme := a.cfg.Verification.Type
	switch a.cfg.Verification.Type {
	case "hmac":
		alg := a.cfg.Verification.Algorithm
		if alg == "" {
			alg = "sha256"
		}
		src := a.cfg.Verification.Source
		if src == "" {
			src = "raw_body"
		}
		scheme = fmt.Sprintf("HMAC-%s over %s", strings.ToUpper(alg), src)
	case "shared_secret":
		scheme = "Shared secret echoed in a header — does not cover the request body"
	case "source_only":
		scheme = "Source address only — no signature"
	}
	unit := a.cfg.Mapping.Amount.Unit
	if unit == "" {
		unit = "minor"
	}
	return adapter.Description{
		Name:             a.cfg.Name,
		DisplayName:      display,
		SignatureScheme:  scheme,
		SignatureHeader:  a.cfg.Verification.Header,
		KnownStatuses:    known,
		SuppliesEventID:  a.eventID != nil,
		SuppliesCurrency: a.currency != nil,
		AmountUnit:       unit,
		Notes:            a.cfg.Notes,
	}
}
