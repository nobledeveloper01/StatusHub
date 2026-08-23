// Package redact removes card data from provider payloads before they are
// stored (§8.4).
//
// StatusHub is out of PCI-DSS scope by design, and that claim only holds if
// it is enforced rather than asserted. A provider that puts a full PAN in a
// webhook — which happens, usually by accident, usually in a "description"
// field — would otherwise drag every backup, every replica and every log
// index into scope with it.
//
// §8.4 describes rejecting such a payload outright; §10 describes redacting
// before storage. This implements redaction, and the reason is ADR-002: a
// rejected webhook is an event permanently lost, because the provider will
// not resend once its retries are exhausted, and losing a real payment to
// protect against a field the provider should not have sent trades an
// unrecoverable failure for a recoverable one. The redaction is recorded, the
// event survives, and the customer is told.
package redact

import (
	"bytes"
	"fmt"
)

// Result reports what was removed.
type Result struct {
	// Body is the payload as it should be stored. When nothing was found it
	// is the original slice, unchanged and not copied.
	Body []byte

	// PANsFound is how many card-number-shaped values were replaced.
	PANsFound int

	// Redacted is true when Body differs from the input.
	Redacted bool
}

// Placeholder replaces a detected PAN. It is a fixed length regardless of the
// original, so the stored payload does not leak how long the card number was.
const Placeholder = "[redacted:pan]"

// Scan finds and replaces card-number-shaped values.
//
// The test is deliberately two-part: a run of 13 to 19 digits, optionally
// separated by single spaces or hyphens, that also passes a Luhn check. The
// digit-length test alone would eat transaction references, session IDs and
// account numbers — NIP session IDs are 30 digits and Monnify references are
// numeric — and redacting those would destroy the very fields the product
// exists to correlate on. Luhn is what makes the test specific enough to be
// safe to apply automatically.
func Scan(body []byte) Result {
	if len(body) < 13 {
		return Result{Body: body}
	}

	var (
		out   *bytes.Buffer
		last  int
		found int
	)

	for i := 0; i < len(body); i++ {
		if !isDigit(body[i]) {
			continue
		}
		// Do not start mid-number, or "1234" inside a longer run would be
		// tested on its own and a 30-digit session ID would yield a passing
		// 16-digit window. A preceding separator only disqualifies the
		// position when it is itself preceded by a digit — otherwise the
		// space in "card 4111..." would stop the match from ever starting.
		if i > 0 && isDigit(body[i-1]) {
			continue
		}
		if i > 1 && isSeparator(body[i-1]) && isDigit(body[i-2]) {
			continue
		}

		end, digits := scanCandidate(body, i)
		if len(digits) < 13 || len(digits) > 19 || !luhn(digits) {
			continue
		}

		if out == nil {
			out = bytes.NewBuffer(make([]byte, 0, len(body)))
		}
		out.Write(body[last:i])
		out.WriteString(Placeholder)
		last = end
		found++
		i = end - 1
	}

	if out == nil {
		return Result{Body: body}
	}
	out.Write(body[last:])
	return Result{Body: out.Bytes(), PANsFound: found, Redacted: true}
}

// scanCandidate reads a run of digits from i, tolerating single spaces and
// hyphens between them — the two ways a card number gets written into a free
// text field.
func scanCandidate(body []byte, i int) (end int, digits []byte) {
	digits = make([]byte, 0, 19)
	j := i
	for j < len(body) {
		switch {
		case isDigit(body[j]):
			digits = append(digits, body[j])
			if len(digits) > 19 {
				// Longer than any card number. A 30-digit NIP session ID
				// lands here and is left alone.
				return i, nil
			}
			j++
		case isSeparator(body[j]) && j+1 < len(body) && isDigit(body[j+1]) && len(digits) > 0:
			j++
		default:
			return j, digits
		}
	}
	return j, digits
}

func isDigit(b byte) bool     { return b >= '0' && b <= '9' }
func isSeparator(b byte) bool { return b == ' ' || b == '-' }

// luhn is the check digit algorithm every card scheme uses. A random 16-digit
// string passes it one time in ten, which is why the redaction is a
// replacement rather than a rejection: a false positive costs one mangled
// field in provider_extra, not a lost event.
func luhn(digits []byte) bool {
	sum, alt := 0, false
	for i := len(digits) - 1; i >= 0; i-- {
		d := int(digits[i] - '0')
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	return sum%10 == 0
}

// Describe renders a short, loggable summary. It never includes any part of
// what was found, not even a masked prefix: a first-six and last-four is
// still card data under most interpretations, and there is no diagnostic
// question that needs it.
func (r Result) Describe() string {
	if !r.Redacted {
		return "no card data found"
	}
	return fmt.Sprintf("%d card-number-shaped value(s) replaced before storage", r.PANsFound)
}
