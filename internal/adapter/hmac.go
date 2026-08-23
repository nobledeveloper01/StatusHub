package adapter

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"hash"
	"strings"
	"time"
)

// Algorithm names the digest a provider signs with. Six providers use four
// combinations between them, which is the whole reason this package exists.
type Algorithm string

const (
	SHA256 Algorithm = "sha256"
	SHA512 Algorithm = "sha512"
)

// New returns the hash constructor, defaulting to SHA-256. The default is
// safe: a declarative adapter that omits the algorithm gets the stronger of
// the two common choices rather than a nil function.
func (a Algorithm) New() func() hash.Hash {
	if a == SHA512 {
		return sha512.New
	}
	return sha256.New
}

// Encoding is how the digest is rendered in the header.
type Encoding string

const (
	Hex    Encoding = "hex"
	Base64 Encoding = "base64"
)

// Sign computes the provider's expected signature over payload.
func Sign(alg Algorithm, enc Encoding, secret string, payload []byte) string {
	m := hmac.New(alg.New(), []byte(secret))
	_, _ = m.Write(payload)
	sum := m.Sum(nil)
	if enc == Base64 {
		return base64.StdEncoding.EncodeToString(sum)
	}
	return hex.EncodeToString(sum)
}

// Equal compares a presented signature against the expected one in constant
// time.
//
// The reason this is a shared function rather than a line in each adapter is
// that it is the single most commonly got-wrong line in webhook handling.
// A `==` on two hex strings leaks the position of the first differing byte
// through timing, and an attacker who can measure that can build a valid
// signature a byte at a time. Doing it once, here, means six adapters cannot
// each get it wrong independently.
//
// The comparison is on the decoded bytes rather than the hex text, so a
// signature presented in the wrong case still matches — providers are
// inconsistent about this and a case mismatch rejecting a genuine event is a
// worse outcome than accepting an unusually-cased valid one.
func Equal(presented, expected string, enc Encoding) bool {
	p, err1 := decode(strings.TrimSpace(presented), enc)
	e, err2 := decode(strings.TrimSpace(expected), enc)
	if err1 != nil || err2 != nil {
		// Fall back to comparing the raw text, still in constant time. An
		// undecodable signature will not match a well-formed expected value,
		// but it must not shortcut out early either.
		return subtle.ConstantTimeCompare([]byte(presented), []byte(expected)) == 1
	}
	return subtle.ConstantTimeCompare(p, e) == 1
}

func decode(s string, enc Encoding) ([]byte, error) {
	if enc == Base64 {
		if b, err := base64.StdEncoding.DecodeString(s); err == nil {
			return b, nil
		}
		return base64.RawStdEncoding.DecodeString(s)
	}
	return hex.DecodeString(strings.ToLower(s))
}

// VerifyHMAC is the whole of the common case: compute the digest over the raw
// body and compare it in constant time.
func VerifyHMAC(alg Algorithm, enc Encoding, secret string, body []byte, presented string) error {
	if presented == "" {
		return ErrNoSignature
	}
	if !Equal(presented, Sign(alg, enc, secret, body), enc) {
		return ErrBadSignature
	}
	return nil
}

// DefaultTimestampTolerance is how far a signed timestamp may be from now.
//
// Five minutes each way. Too tight and a provider retrying after a network
// stall gets rejected for a delay that was not their fault; too loose and a
// captured request stays replayable for as long as the window. Five minutes
// is the value Stripe chose and providers' own retry behaviour has grown up
// around it.
//
// The tolerance is symmetric because clocks drift in both directions, and a
// receiver that only tolerates the past rejects every event from a provider
// whose clock runs thirty seconds fast. `statushubctl doctor` checks our own
// skew explicitly for this reason (§6.3).
const DefaultTimestampTolerance = 5 * time.Minute

// CheckTimestamp rejects a signature whose timestamp is outside the window.
// Providers that sign a timestamp get replay protection from it; providers
// that do not fall back to event-ID and body-hash deduplication (§10).
func CheckTimestamp(signed, now time.Time, tolerance time.Duration) error {
	if tolerance <= 0 {
		tolerance = DefaultTimestampTolerance
	}
	d := now.Sub(signed)
	if d < 0 {
		d = -d
	}
	if d > tolerance {
		return Failf(ErrTimestampOutside, "signed at %s, now %s", signed.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
	}
	return nil
}

// FirstHeader returns the first non-empty value among names, so an adapter
// can accept a provider's old and new header spellings without branching.
// Providers rename these without a version bump more often than they should.
func FirstHeader(h map[string][]string, names ...string) string {
	for _, n := range names {
		for k, vs := range h {
			if strings.EqualFold(k, n) {
				for _, v := range vs {
					if strings.TrimSpace(v) != "" {
						return strings.TrimSpace(v)
					}
				}
			}
		}
	}
	return ""
}
