// Package declarative implements the configuration-driven adapter (§4.4).
//
// This is what separates a platform from a service: a customer can support a
// provider StatusHub has never heard of without opening a support ticket or
// waiting for a release. It is also the largest attack surface in the
// product, because the configuration is data an authenticated customer
// uploads and it then runs on the normalisation path for every event that
// endpoint receives.
//
// The whole design follows from that. Adapters are declarative data with no
// scripting of any kind, every expression is a bounded JSONPath subset, and
// every list, string and mapping table has an explicit ceiling. There is no
// construct here that can loop, recurse, or be made to backtrack.
package declarative

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nobledeveloper01/StatusHub/internal/adapter"
	"github.com/nobledeveloper01/StatusHub/internal/domain"
	"github.com/nobledeveloper01/StatusHub/internal/jsonpath"
)

// Ceilings on an uploaded adapter. Each one is here because the alternative
// is a configuration form that can be turned into a denial of service.
const (
	MaxStatusValues = 200
	MaxExtraFields  = 50
	MaxNameLength   = 64
	MaxConfigBytes  = 64 * 1024
	MaxSignedFields = 8
	MaxSourceCIDRs  = 64
)

// Config is an uploaded adapter definition.
type Config struct {
	Name    string `json:"name" yaml:"name"`
	Version int    `json:"version" yaml:"version"`

	// DisplayName and Notes appear in the dashboard beside the built-in
	// adapters, so a customer's own adapter is documented the same way ours
	// are.
	DisplayName string `json:"display_name,omitempty" yaml:"display_name"`
	Notes       string `json:"notes,omitempty" yaml:"notes"`

	Verification Verification `json:"verification" yaml:"verification"`
	Mapping      Mapping      `json:"mapping" yaml:"mapping"`
}

// Verification describes the provider's signature scheme.
type Verification struct {
	// Type is "hmac", "shared_secret" or "source_only".
	Type string `json:"type" yaml:"type"`

	Algorithm string `json:"algorithm,omitempty" yaml:"algorithm"` // sha256 | sha512
	Encoding  string `json:"encoding,omitempty" yaml:"encoding"`   // hex | base64
	Header    string `json:"header" yaml:"header"`

	// Source is "raw_body" or "fields". Signing the raw body is stronger and
	// is what the validator recommends; signing named fields is what several
	// real providers do, so it has to be supported.
	Source string `json:"source,omitempty" yaml:"source"`

	// Fields are the paths concatenated to form the signed payload when
	// Source is "fields", in order.
	Fields []string `json:"fields,omitempty" yaml:"fields"`

	// TimestampHeader and Tolerance add replay protection where the provider
	// signs a timestamp.
	TimestampHeader string `json:"timestamp_header,omitempty" yaml:"timestamp_header"`
	ToleranceSecs   int    `json:"tolerance_seconds,omitempty" yaml:"tolerance_seconds"`

	// AllowedSourceCIDRs applies to every type, and is the only control when
	// the type is "source_only".
	AllowedSourceCIDRs []string `json:"allowed_source_cidrs,omitempty" yaml:"allowed_source_cidrs"`
}

// Mapping describes how to read the payload.
type Mapping struct {
	ProviderEventID string      `json:"provider_event_id,omitempty" yaml:"provider_event_id"`
	TransactionRef  string      `json:"transaction_ref" yaml:"transaction_ref"`
	EventFamily     string      `json:"event_family,omitempty" yaml:"event_family"`
	OccurredAt      TimeMapping `json:"occurred_at,omitempty" yaml:"occurred_at"`
	Amount          AmountMap   `json:"amount,omitempty" yaml:"amount"`
	Status          StatusMap   `json:"status" yaml:"status"`
	CustomerRef     string      `json:"customer_ref,omitempty" yaml:"customer_ref"`

	// ExtraFields names paths to lift into provider_extra under friendly
	// names. Everything unclaimed is carried anyway; this is for the handful
	// of fields worth naming.
	ExtraFields map[string]string `json:"extra_fields,omitempty" yaml:"extra_fields"`
}

// TimeMapping reads a timestamp.
type TimeMapping struct {
	Path   string `json:"path,omitempty" yaml:"path"`
	Format string `json:"format,omitempty" yaml:"format"`

	// Timezone is stated explicitly and never inferred (§4.4). A naive
	// timestamp read in the wrong zone places an event an hour from where it
	// belongs, which reorders it against every other event on the same
	// transaction.
	Timezone string `json:"timezone,omitempty" yaml:"timezone"`
}

// AmountMap reads an amount.
type AmountMap struct {
	Path string `json:"path,omitempty" yaml:"path"`

	// Unit is "minor" or "major". There is no default: guessing is a
	// hundredfold error in someone's ledger, so the validator requires it
	// whenever a path is set.
	Unit string `json:"unit,omitempty" yaml:"unit"`

	CurrencyPath    string `json:"currency_path,omitempty" yaml:"currency_path"`
	DefaultCurrency string `json:"default_currency,omitempty" yaml:"default_currency"`
}

// StatusMap reads and maps the status.
type StatusMap struct {
	Path   string            `json:"path" yaml:"path"`
	Values map[string]string `json:"values" yaml:"values"`

	// Default is what an unlisted value becomes. It may only be "unknown":
	// see Validate.
	Default string `json:"default,omitempty" yaml:"default"`

	// CaseSensitive is off by default, because providers are inconsistent
	// about casing within a single account.
	CaseSensitive bool `json:"case_sensitive,omitempty" yaml:"case_sensitive"`
}

// Validation errors, kept distinct so the adapter editor can point at the
// field that is wrong.
var (
	ErrNoName           = errors.New("adapter needs a name")
	ErrBadName          = errors.New("adapter name must be lower-case letters, digits and hyphens")
	ErrTooLarge         = errors.New("adapter configuration is too large")
	ErrNoTransactionRef = errors.New("adapter must map a transaction reference")
	ErrNoStatus         = errors.New("adapter must map a status")
	ErrUnsafeDefault    = errors.New("an unmapped status may only default to unknown")
	ErrNoAmountUnit     = errors.New("an amount mapping must state whether the provider sends major or minor units")
	ErrNoTimezone       = errors.New("a timestamp format with no zone must state a timezone")
	ErrTooManyValues    = errors.New("status mapping has too many entries")
	ErrBadVerification  = errors.New("verification configuration is not usable")
)

// Parse reads a configuration from JSON.
func Parse(b []byte) (Config, error) {
	if len(b) > MaxConfigBytes {
		return Config{}, fmt.Errorf("%w: %d bytes, limit %d", ErrTooLarge, len(b), MaxConfigBytes)
	}
	var c Config
	dec := json.NewDecoder(strings.NewReader(string(b)))
	// Unknown fields are an error, not a shrug. A customer who typed
	// "transactionRef" instead of "transaction_ref" should be told, not have
	// their adapter silently ignore the mapping and flag every event
	// incomplete.
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return Config{}, fmt.Errorf("adapter configuration is not valid JSON: %w", err)
	}
	return c, nil
}

// Validate checks a configuration before it is ever run.
//
// Every rule here corresponds to a way an adapter can be wrong that would
// otherwise only show up as corrupted events days later.
func (c Config) Validate() error {
	if strings.TrimSpace(c.Name) == "" {
		return ErrNoName
	}
	if len(c.Name) > MaxNameLength {
		return fmt.Errorf("%w: name is %d characters", ErrTooLarge, len(c.Name))
	}
	if !validName(c.Name) {
		return fmt.Errorf("%w: %q", ErrBadName, c.Name)
	}

	if err := c.Verification.validate(); err != nil {
		return err
	}

	if strings.TrimSpace(c.Mapping.TransactionRef) == "" {
		return ErrNoTransactionRef
	}
	if _, err := jsonpath.Compile(c.Mapping.TransactionRef); err != nil {
		return fmt.Errorf("transaction_ref path: %w", err)
	}

	for name, path := range map[string]string{
		"provider_event_id":    c.Mapping.ProviderEventID,
		"customer_ref":         c.Mapping.CustomerRef,
		"occurred_at.path":     c.Mapping.OccurredAt.Path,
		"amount.path":          c.Mapping.Amount.Path,
		"amount.currency_path": c.Mapping.Amount.CurrencyPath,
	} {
		if path == "" {
			continue
		}
		if _, err := jsonpath.Compile(path); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}

	if c.Mapping.Amount.Path != "" {
		switch c.Mapping.Amount.Unit {
		case "minor", "major":
		default:
			// No default. Assuming minor units for a provider that sends
			// major ones divides every amount by a hundred; assuming the
			// reverse multiplies it. Both are worse than refusing to load.
			return fmt.Errorf("%w: unit is %q", ErrNoAmountUnit, c.Mapping.Amount.Unit)
		}
		if c.Mapping.Amount.DefaultCurrency != "" && !domain.ValidCurrency(c.Mapping.Amount.DefaultCurrency) {
			return fmt.Errorf("default_currency %q is not a three-letter code", c.Mapping.Amount.DefaultCurrency)
		}
	}

	if err := c.Mapping.OccurredAt.validate(); err != nil {
		return err
	}

	if strings.TrimSpace(c.Mapping.Status.Path) == "" {
		return ErrNoStatus
	}
	if _, err := jsonpath.Compile(c.Mapping.Status.Path); err != nil {
		return fmt.Errorf("status.path: %w", err)
	}
	if len(c.Mapping.Status.Values) > MaxStatusValues {
		return fmt.Errorf("%w: %d entries, limit %d", ErrTooManyValues, len(c.Mapping.Status.Values), MaxStatusValues)
	}
	for raw, mapped := range c.Mapping.Status.Values {
		s := domain.Status(mapped)
		if !s.Valid() {
			return fmt.Errorf("status value %q maps to %q, which is not one of the canonical statuses", raw, mapped)
		}
	}
	if d := c.Mapping.Status.Default; d != "" && d != string(domain.StatusUnknown) {
		// The single most important rule in this file. An adapter that
		// defaults an unrecognised provider status to "failed" will, sooner
		// or later, cause a fintech to reverse a payment that succeeded. The
		// product's answer is that we do not guess, and that answer cannot be
		// configurable.
		return fmt.Errorf("%w: %q", ErrUnsafeDefault, d)
	}

	if len(c.Mapping.ExtraFields) > MaxExtraFields {
		return fmt.Errorf("%w: %d extra fields, limit %d", ErrTooLarge, len(c.Mapping.ExtraFields), MaxExtraFields)
	}
	for name, path := range c.Mapping.ExtraFields {
		if _, err := jsonpath.Compile(path); err != nil {
			return fmt.Errorf("extra_fields[%s]: %w", name, err)
		}
	}

	if c.Mapping.EventFamily != "" {
		switch c.Mapping.EventFamily {
		case "payment", "transfer", "refund", "chargeback":
		default:
			return fmt.Errorf("event_family %q is not one of payment, transfer, refund, chargeback", c.Mapping.EventFamily)
		}
	}
	return nil
}

func (v Verification) validate() error {
	switch v.Type {
	case "hmac":
		if v.Header == "" {
			return fmt.Errorf("%w: hmac verification needs a header", ErrBadVerification)
		}
		switch v.Algorithm {
		case "", "sha256", "sha512":
		default:
			return fmt.Errorf("%w: algorithm %q is not sha256 or sha512", ErrBadVerification, v.Algorithm)
		}
		switch v.Encoding {
		case "", "hex", "base64":
		default:
			return fmt.Errorf("%w: encoding %q is not hex or base64", ErrBadVerification, v.Encoding)
		}
		switch v.Source {
		case "", "raw_body":
		case "fields":
			if len(v.Fields) == 0 {
				return fmt.Errorf("%w: source is fields but none are listed", ErrBadVerification)
			}
			if len(v.Fields) > MaxSignedFields {
				return fmt.Errorf("%w: %d signed fields, limit %d", ErrBadVerification, len(v.Fields), MaxSignedFields)
			}
			for _, f := range v.Fields {
				if _, err := jsonpath.Compile(f); err != nil {
					return fmt.Errorf("signed field %q: %w", f, err)
				}
			}
		default:
			return fmt.Errorf("%w: source %q is not raw_body or fields", ErrBadVerification, v.Source)
		}
	case "shared_secret":
		if v.Header == "" {
			return fmt.Errorf("%w: shared_secret verification needs a header", ErrBadVerification)
		}
	case "source_only":
		if len(v.AllowedSourceCIDRs) == 0 {
			// source_only with no ranges accepts everything, which looks like
			// a control and is not one.
			return fmt.Errorf("%w: source_only verification needs at least one allowed CIDR", ErrBadVerification)
		}
	default:
		return fmt.Errorf("%w: type %q is not hmac, shared_secret or source_only", ErrBadVerification, v.Type)
	}

	if len(v.AllowedSourceCIDRs) > MaxSourceCIDRs {
		return fmt.Errorf("%w: %d CIDRs, limit %d", ErrTooLarge, len(v.AllowedSourceCIDRs), MaxSourceCIDRs)
	}
	if v.ToleranceSecs < 0 || v.ToleranceSecs > 3600 {
		return fmt.Errorf("%w: tolerance must be between 0 and 3600 seconds", ErrBadVerification)
	}
	return nil
}

func (t TimeMapping) validate() error {
	if t.Path == "" {
		return nil
	}
	if _, err := jsonpath.Compile(t.Path); err != nil {
		return fmt.Errorf("occurred_at.path: %w", err)
	}
	if t.Timezone != "" {
		if _, err := adapter.LoadLocation(t.Timezone); err != nil {
			// Caught at upload rather than on the first event, so a host
			// without the named zone's tzdata fails with a clear message
			// instead of flagging every event incomplete.
			return fmt.Errorf("occurred_at.timezone: %w", err)
		}
	}
	if t.Format != "" && !formatCarriesZone(t.Format) && t.Timezone == "" {
		return fmt.Errorf("%w: format %q has no offset, so a timezone must be stated", ErrNoTimezone, t.Format)
	}
	return nil
}

// formatCarriesZone reports whether a Go time layout includes a zone.
func formatCarriesZone(layout string) bool {
	for _, marker := range []string{"Z07", "-07", "MST", "Z0700", "-0700"} {
		if strings.Contains(layout, marker) {
			return true
		}
	}
	return false
}

func validName(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-':
		default:
			return false
		}
	}
	return s[0] != '-' && s[len(s)-1] != '-'
}

// Tolerance returns the configured timestamp window, or the default.
func (v Verification) Tolerance() time.Duration {
	if v.ToleranceSecs > 0 {
		return time.Duration(v.ToleranceSecs) * time.Second
	}
	return adapter.DefaultTimestampTolerance
}
