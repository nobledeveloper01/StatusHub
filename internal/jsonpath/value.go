package jsonpath

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// The helpers below all take the same view: a provider's JSON types are not
// stable, so a field that is a number today may be a string tomorrow, and an
// adapter that only handles one of the two breaks on a Tuesday. Each helper
// accepts every JSON encoding that could plausibly carry the value, and fails
// on the ones that could not.

// String reads a value as text. Numbers and booleans are accepted and
// rendered, because providers send `"amount": 5000` and `"amount": "5000"`
// interchangeably — sometimes within one payload.
func String(v any) (string, bool) {
	switch t := v.(type) {
	case string:
		return t, true
	case json.Number:
		return t.String(), true
	case float64:
		// A float64 that is integral must not render as 5e+06: that is the
		// difference between a transaction reference that matches and one
		// that does not.
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10), true
		}
		return strconv.FormatFloat(t, 'f', -1, 64), true
	case bool:
		return strconv.FormatBool(t), true
	case nil:
		return "", false
	default:
		return "", false
	}
}

// StringAt evaluates a path and reads the result as text.
func StringAt(doc any, p Path) (string, error) {
	v, err := p.Eval(doc)
	if err != nil {
		return "", err
	}
	s, ok := String(v)
	if !ok {
		return "", fmt.Errorf("%w: %s is not a scalar", ErrWrongShape, p)
	}
	return s, nil
}

// Int reads a value as a whole number. Decimal strings are accepted only when
// their fractional part is zero: silently truncating 5000.7 kobo is exactly
// the kind of quiet rounding that shows up in a reconciliation three months
// later.
func Int(v any) (int64, bool) {
	switch t := v.(type) {
	case float64:
		if t != float64(int64(t)) {
			return 0, false
		}
		return int64(t), true
	case json.Number:
		n, err := t.Int64()
		return n, err == nil
	case string:
		s := strings.TrimSpace(t)
		if i := strings.IndexByte(s, '.'); i >= 0 {
			if strings.Trim(s[i+1:], "0") != "" {
				return 0, false
			}
			s = s[:i]
		}
		n, err := strconv.ParseInt(s, 10, 64)
		return n, err == nil
	default:
		return 0, false
	}
}

// Bool reads a value as a boolean, accepting the string spellings providers
// use for flags.
func Bool(v any) (bool, bool) {
	switch t := v.(type) {
	case bool:
		return t, true
	case string:
		b, err := strconv.ParseBool(strings.TrimSpace(t))
		return b, err == nil
	case float64:
		return t != 0, true
	default:
		return false, false
	}
}

// Decode unmarshals a provider body with numbers preserved as text.
//
// encoding/json's default is float64, and float64 cannot hold every int64.
// A transaction amount of 9007199254740993 kobo — larger than any real
// payment, but not larger than a malformed or malicious one — comes back as
// 9007199254740992. json.Number defers the decision to whoever reads the
// field, which is the only way to be sure the amount we store is the amount
// that was sent.
func Decode(body []byte) (any, error) {
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return nil, err
	}
	return doc, nil
}

// Flatten renders a document as dotted paths to scalar values. The normaliser
// uses it to work out what a mapping did not claim, so unknown fields end up
// in provider_extra with a metric rather than being dropped (§3.2 B4).
//
// It is bounded in both breadth and depth: a payload can be adversarial, and
// walking one should not be the way a receiver runs out of memory.
func Flatten(doc any) map[string]any {
	out := make(map[string]any, 32)
	flatten("", doc, out, 0)
	return out
}

const (
	maxFlattenDepth = 12
	maxFlattenKeys  = 512
)

func flatten(prefix string, v any, out map[string]any, depth int) {
	if depth > maxFlattenDepth || len(out) >= maxFlattenKeys {
		return
	}
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			key := k
			if prefix != "" {
				key = prefix + "." + k
			}
			flatten(key, child, out, depth+1)
		}
	case []any:
		for i, child := range t {
			flatten(fmt.Sprintf("%s[%d]", prefix, i), child, out, depth+1)
		}
	default:
		if prefix != "" {
			out[prefix] = v
		}
	}
}
