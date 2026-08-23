// Package statushub is the Go client library.
//
// It is deliberately small. The integration StatusHub sells is a URL change,
// so the SDK's job is not to be a framework — it is to make the one piece of
// code the customer *does* have to write impossible to get wrong.
//
// That piece is signature verification. It is the most commonly botched part
// of any webhook integration: somebody compares two hex strings with ==,
// which leaks the position of the first differing byte through timing, and an
// attacker who can measure that can forge a signature a byte at a time.
// Nobody notices, because the handler works perfectly.
//
// This package is Apache-2.0 rather than BUSL, so integrating needs no
// lawyer.
package statushub

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// SignatureHeader carries the signature StatusHub signs deliveries with.
const SignatureHeader = "X-StatusHub-Signature"

// Headers StatusHub sets on every delivery.
const (
	EventIDHeader        = "X-StatusHub-Event-Id"
	ReplayHeader         = "X-StatusHub-Replay"
	AttemptHeader        = "X-StatusHub-Attempt"
	SchemaVersionHeader  = "X-StatusHub-Schema-Version"
	IdempotencyKeyHeader = "Idempotency-Key"
)

// DefaultTolerance is how far a delivery's timestamp may be from now.
//
// Five minutes each way. Symmetric, because clocks drift in both directions
// and a receiver that only tolerates the past rejects every delivery from a
// sender running slightly fast.
const DefaultTolerance = 5 * time.Minute

// Verification failures. They are distinguished so a handler can log
// something useful; the response to the caller should be a bare 401 either
// way.
var (
	ErrNoSignature  = errors.New("statushub: no signature header")
	ErrMalformed    = errors.New("statushub: signature header is malformed")
	ErrStale        = errors.New("statushub: signature timestamp is outside the accepted window")
	ErrBadSignature = errors.New("statushub: signature does not match the body")
)

// Verify checks a delivery's signature.
//
// Pass the raw request body, before any JSON parsing. A round trip through a
// decoder changes the bytes — reordered keys, different whitespace, numbers
// reformatted — and the signature covers the bytes that were sent.
func Verify(body []byte, header, secret string) error {
	return VerifyAt(body, header, secret, time.Now(), DefaultTolerance)
}

// VerifyAt is Verify with an explicit clock and window, for tests.
func VerifyAt(body []byte, header, secret string, now time.Time, tolerance time.Duration) error {
	if strings.TrimSpace(header) == "" {
		return ErrNoSignature
	}
	if tolerance <= 0 {
		tolerance = DefaultTolerance
	}

	var (
		ts   int64
		sigs []string
	)
	for _, part := range strings.Split(header, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		switch k {
		case "t":
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				return fmt.Errorf("%w: timestamp %q is not an integer", ErrMalformed, v)
			}
			ts = n
		case "v1":
			if v != "" {
				sigs = append(sigs, v)
			}
		}
		// Unknown elements are ignored rather than rejected. StatusHub may
		// add one, and a handler that refuses an unfamiliar element stops
		// working the day it does.
	}
	if ts == 0 {
		return fmt.Errorf("%w: no timestamp", ErrMalformed)
	}
	if len(sigs) == 0 {
		return fmt.Errorf("%w: no v1 signature", ErrMalformed)
	}

	// Checked before the digest. A captured delivery replayed tomorrow
	// carries a genuine signature; only the window stops it.
	age := now.UTC().Sub(time.Unix(ts, 0).UTC())
	if age < 0 {
		age = -age
	}
	if age > tolerance {
		return fmt.Errorf("%w: %s old", ErrStale, age.Round(time.Second))
	}

	signed := make([]byte, 0, len(body)+16)
	signed = append(signed, strconv.FormatInt(ts, 10)...)
	// The separator matters: without it, timestamp 1754903662 with body "x"
	// and timestamp 175490366 with body "2x" sign identically.
	signed = append(signed, '.')
	signed = append(signed, body...)

	m := hmac.New(sha256.New, []byte(secret))
	_, _ = m.Write(signed)
	expected := m.Sum(nil)

	// Several v1 values appear during a secret rotation, and any one matching
	// is enough — that is what lets you rotate on your own schedule.
	for _, s := range sigs {
		presented, err := hex.DecodeString(strings.ToLower(strings.TrimSpace(s)))
		if err != nil {
			continue
		}
		// Constant time. This is the line the whole package exists for.
		if subtle.ConstantTimeCompare(presented, expected) == 1 {
			return nil
		}
	}
	return ErrBadSignature
}

// Event is the canonical shape (§7.2). One struct, whichever provider sent it.
type Event struct {
	EventID         string `json:"event_id"`
	EventType       string `json:"event_type"`
	Provider        string `json:"provider"`
	ProviderEventID string `json:"provider_event_id,omitempty"`
	TransactionRef  string `json:"transaction_ref"`
	Status          Status `json:"status"`

	// AmountMinor is always integer minor units, in the currency's own
	// exponent — kobo for NGN, cents for USD, yen for JPY. Never a float,
	// never a decimal string, never a unit you have to look up.
	AmountMinor int64  `json:"amount_minor"`
	Currency    string `json:"currency,omitempty"`

	OccurredAt time.Time `json:"occurred_at"`
	ReceivedAt time.Time `json:"received_at"`

	Customer *Customer `json:"customer,omitempty"`

	// ProviderExtra carries every field StatusHub did not map, so you are
	// never blocked waiting for them to add one.
	ProviderExtra map[string]any `json:"provider_extra,omitempty"`

	// MappingComplete is false when StatusHub was unsure about a field.
	// Worth branching on: it is the difference between "this is what
	// happened" and "this is our best reading of what happened".
	MappingComplete bool `json:"mapping_complete"`

	// UnmappedStatus is the provider's own string when Status is Unknown.
	UnmappedStatus string `json:"unmapped_status,omitempty"`

	Redacted bool            `json:"redacted,omitempty"`
	Raw      json.RawMessage `json:"raw,omitempty"`
}

// Customer is the pseudonymised identity. There is no name, email or phone
// here and there never will be: the hash is enough to correlate two events as
// one person without StatusHub holding who that person is.
type Customer struct {
	RefHash string `json:"ref_hash"`
}

// Status is the canonical outcome. A closed set of six.
type Status string

const (
	StatusPending   Status = "pending"
	StatusSuccess   Status = "success"
	StatusFailed    Status = "failed"
	StatusReversed  Status = "reversed"
	StatusAbandoned Status = "abandoned"

	// StatusUnknown means StatusHub did not recognise the provider's value
	// and refused to guess.
	//
	// Handle it explicitly. The tempting shortcut is to treat it as a
	// failure, which is exactly the mistake the value exists to prevent: an
	// unmapped SUCCESS treated as a failure reverses a payment that
	// completed. UnmappedStatus carries the provider's own string.
	StatusUnknown Status = "unknown"
)

// IsTerminal reports whether the transaction can still change. Unknown is not
// terminal, because not knowing what something is includes not knowing
// whether it is finished.
func (s Status) IsTerminal() bool {
	return s != StatusPending && s != StatusUnknown
}

// Parse reads a delivery body into an Event.
func Parse(body []byte) (Event, error) {
	var e Event
	if err := json.Unmarshal(body, &e); err != nil {
		return Event{}, fmt.Errorf("statushub: %w", err)
	}
	return e, nil
}

// Handler wraps your own handler with verification, so the security-critical
// part is not something you have to remember.
//
//	http.Handle("/hooks/statushub", statushub.Handler(secret, func(w http.ResponseWriter, e statushub.Event) {
//	    // one schema, forever
//	    w.WriteHeader(http.StatusOK)
//	}))
func Handler(secret string, next func(http.ResponseWriter, Event)) http.Handler {
	return HandlerWithOptions(HandlerOptions{Secret: secret, Handle: next})
}

// HandlerOptions configure Handler.
type HandlerOptions struct {
	Secret string
	Handle func(http.ResponseWriter, Event)

	// Tolerance overrides the timestamp window.
	Tolerance time.Duration

	// MaxBody bounds the request. Defaults to 2 MB, comfortably above
	// StatusHub's own 1 MB receive ceiling.
	MaxBody int64

	// OnError is called when verification or parsing fails, for your logs.
	// The response is always a bare 401 or 400 regardless: telling a caller
	// which part of their signature was wrong turns your endpoint into an
	// oracle.
	OnError func(*http.Request, error)
}

// HandlerWithOptions is Handler with the knobs.
func HandlerWithOptions(o HandlerOptions) http.Handler {
	if o.MaxBody <= 0 {
		o.MaxBody = 2 << 20
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fail := func(status int, err error) {
			if o.OnError != nil {
				o.OnError(r, err)
			}
			w.WriteHeader(status)
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, o.MaxBody))
		if err != nil {
			fail(http.StatusBadRequest, err)
			return
		}
		if err := VerifyAt(body, r.Header.Get(SignatureHeader), o.Secret, time.Now(), o.Tolerance); err != nil {
			fail(http.StatusUnauthorized, err)
			return
		}
		event, err := Parse(body)
		if err != nil {
			fail(http.StatusBadRequest, err)
			return
		}
		o.Handle(w, event)
	})
}

// IsReplay reports whether a request is a replayed delivery rather than a
// first attempt. The idempotency key is the same either way, so a handler
// that deduplicates on it needs no special case — this is for logging and for
// the rare handler that genuinely wants to know.
func IsReplay(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get(ReplayHeader), "true")
}

// IdempotencyKey returns the key StatusHub sent, which is the canonical event
// ID. Deduplicating on it turns StatusHub's at-least-once into your
// exactly-once.
func IdempotencyKey(r *http.Request) string {
	return r.Header.Get(IdempotencyKeyHeader)
}

// Sign produces a signature header. Exported for your own tests: it is how
// you build a request your handler will accept, without needing StatusHub
// running.
func Sign(body []byte, secret string, at time.Time) string {
	ts := at.UTC().Unix()
	signed := make([]byte, 0, len(body)+16)
	signed = append(signed, strconv.FormatInt(ts, 10)...)
	signed = append(signed, '.')
	signed = append(signed, body...)

	m := hmac.New(sha256.New, []byte(secret))
	_, _ = m.Write(signed)
	return fmt.Sprintf("t=%d,v1=%s", ts, hex.EncodeToString(m.Sum(nil)))
}
