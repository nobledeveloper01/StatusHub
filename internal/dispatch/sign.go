package dispatch

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// SignatureHeader is the header StatusHub signs its outbound deliveries with.
const SignatureHeader = "X-StatusHub-Signature"

// Sign produces the header value for a delivery: `t=<unix>,v1=<hex>`.
//
// This is Stripe's scheme, deliberately (§8.2). Copying a well-documented,
// widely-implemented design means a customer's engineer has probably already
// written this verification once, most language ecosystems already have a
// library for it, and nobody has to review a novel cryptographic construction
// written by a webhook vendor. The one thing that would be worse than using
// somebody else's scheme is inventing our own.
//
// The signed payload is `{timestamp}.{body}`. The timestamp is inside the
// signature rather than beside it, which is what makes it replay protection:
// an attacker who captures a delivery cannot move it forward in time without
// invalidating the digest.
func Sign(secret string, body []byte, at time.Time) string {
	ts := at.UTC().Unix()
	signed := make([]byte, 0, len(body)+16)
	signed = append(signed, strconv.FormatInt(ts, 10)...)
	// The separator is not decoration. Without it, timestamp 1754903662 with
	// body "x" and timestamp 175490366 with body "2x" sign identically.
	signed = append(signed, '.')
	signed = append(signed, body...)

	m := hmac.New(sha256.New, []byte(secret))
	_, _ = m.Write(signed)
	return fmt.Sprintf("t=%d,v1=%s", ts, hex.EncodeToString(m.Sum(nil)))
}

// SignWith produces a header carrying several signatures, one per secret.
//
// Rotation is why. During an overlap window the customer may have configured
// either the old or the new secret; sending both means the rotation happens
// on their schedule rather than requiring a synchronised cutover that will
// inevitably drop a delivery (§8.2).
func SignWith(secrets []string, body []byte, at time.Time) string {
	if len(secrets) == 0 {
		return ""
	}
	ts := at.UTC().Unix()
	signed := make([]byte, 0, len(body)+16)
	signed = append(signed, strconv.FormatInt(ts, 10)...)
	signed = append(signed, '.')
	signed = append(signed, body...)

	var b strings.Builder
	fmt.Fprintf(&b, "t=%d", ts)
	for _, s := range secrets {
		m := hmac.New(sha256.New, []byte(s))
		_, _ = m.Write(signed)
		fmt.Fprintf(&b, ",v1=%s", hex.EncodeToString(m.Sum(nil)))
	}
	return b.String()
}

// Verify checks a StatusHub signature. It lives here, in the server, so the
// server's tests and the three client libraries all check the same thing —
// and so the reference implementation of the verification a customer must
// write is one they can read.
func Verify(secret string, body []byte, header string, now time.Time, tolerance time.Duration) error {
	if tolerance <= 0 {
		tolerance = 5 * time.Minute
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
				return fmt.Errorf("signature timestamp %q is not an integer", v)
			}
			ts = n
		case "v1":
			if v != "" {
				sigs = append(sigs, v)
			}
		}
	}
	if ts == 0 {
		return fmt.Errorf("signature header carries no timestamp")
	}
	if len(sigs) == 0 {
		return fmt.Errorf("signature header carries no v1 signature")
	}

	// Checked before the digest, and symmetric, because clocks drift both
	// ways and a receiver that only tolerates the past rejects everything
	// from a sender running slightly fast.
	age := now.UTC().Sub(time.Unix(ts, 0).UTC())
	if age < 0 {
		age = -age
	}
	if age > tolerance {
		return fmt.Errorf("signature timestamp is %s away from now, outside the %s window", age, tolerance)
	}

	signed := make([]byte, 0, len(body)+16)
	signed = append(signed, strconv.FormatInt(ts, 10)...)
	signed = append(signed, '.')
	signed = append(signed, body...)

	m := hmac.New(sha256.New, []byte(secret))
	_, _ = m.Write(signed)
	expected := hex.EncodeToString(m.Sum(nil))

	for _, s := range sigs {
		// Constant time, on the decoded bytes where possible. This is the
		// line customers most often get wrong in their own handlers, which is
		// why the client libraries exist and why this is the first thing in
		// the documentation.
		presented, err := hex.DecodeString(strings.ToLower(strings.TrimSpace(s)))
		want, werr := hex.DecodeString(expected)
		if err == nil && werr == nil {
			if subtle.ConstantTimeCompare(presented, want) == 1 {
				return nil
			}
			continue
		}
		if subtle.ConstantTimeCompare([]byte(s), []byte(expected)) == 1 {
			return nil
		}
	}
	return fmt.Errorf("no signature in the header matched the body")
}
