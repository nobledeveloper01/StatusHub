package tests

import (
	"errors"
	"strings"
	"testing"

	"github.com/nobledeveloper01/StatusHub/internal/jsonpath"
)

const sample = `{
  "event": "charge.success",
  "data": {
    "reference": "TXN-1",
    "amount": 5000000,
    "big": 9007199254740993,
    "customer": {"email": "t@example.com"},
    "odd.key": "dotted",
    "items": [{"sku": "A"}, {"sku": "B"}, {"sku": "C"}],
    "nothing": null
  }
}`

func doc(t *testing.T) any {
	t.Helper()
	d, err := jsonpath.Decode([]byte(sample))
	mustNoErr(t, err, "decoding the sample")
	return d
}

func TestJSONPathEvaluation(t *testing.T) {
	d := doc(t)
	for _, c := range []struct{ path, want string }{
		{"$.event", "charge.success"},
		{"$.data.reference", "TXN-1"},
		{"data.reference", "TXN-1"}, // the $ prefix is optional
		{"$.data.customer.email", "t@example.com"},
		{"$.data.items[0].sku", "A"},
		{"$.data.items[2].sku", "C"},
		{"$.data.items[-1].sku", "C"}, // negative indices count from the end
		{"$.data['odd.key']", "dotted"},
	} {
		got, err := jsonpath.StringAt(d, jsonpath.MustCompile(c.path))
		if err != nil {
			t.Errorf("%s: %v", c.path, err)
			continue
		}
		if got != c.want {
			t.Errorf("%s = %q, want %q", c.path, got, c.want)
		}
	}
}

func TestJSONPathLargeIntegersSurvive(t *testing.T) {
	// Decoding into float64 would return 9007199254740992 here — one less
	// than the value that was sent. For an amount field that is a silent,
	// unrecoverable corruption, so decoding uses json.Number throughout.
	got, err := jsonpath.StringAt(doc(t), jsonpath.MustCompile("$.data.big"))
	mustNoErr(t, err, "reading a large integer")
	if got != "9007199254740993" {
		t.Fatalf("large integer came back as %q — precision was lost in decoding", got)
	}
}

func TestJSONPathAmountsDoNotBecomeScientificNotation(t *testing.T) {
	// A reference or an amount rendered as 5e+06 is a value that no longer
	// matches anything.
	got, err := jsonpath.StringAt(doc(t), jsonpath.MustCompile("$.data.amount"))
	mustNoErr(t, err, "reading an amount")
	if strings.ContainsAny(got, "eE") {
		t.Fatalf("amount rendered as %q", got)
	}
}

func TestJSONPathMissingIsDistinctFromNull(t *testing.T) {
	d := doc(t)
	// "the provider stopped sending this field" is a mapping problem;
	// "the provider sent null" is information. Collapsing them loses the
	// difference at the moment it matters.
	_, err := jsonpath.MustCompile("$.data.absent").Eval(d)
	if !errors.Is(err, jsonpath.ErrNotFound) {
		t.Errorf("a missing field should be ErrNotFound, got %v", err)
	}
	v, err := jsonpath.MustCompile("$.data.nothing").Eval(d)
	if err != nil {
		t.Errorf("an explicit null should evaluate, got %v", err)
	}
	if v != nil {
		t.Errorf("an explicit null should be nil, got %v", v)
	}
}

func TestJSONPathRefusesUnboundedExpressions(t *testing.T) {
	// A declarative adapter is data a customer uploads. Every construct that
	// can be made to backtrack or recurse is a way to burn CPU on the
	// normalisation path, delivered through a configuration form (§10).
	for _, bad := range []string{
		"$..reference",              // recursive descent
		"$.data.items[*].sku",       // wildcard
		"$.data[?(@.x)]",            // filter
		"$.a.b.c.d.e.f.g.h.i.j.k.l", // deeper than MaxDepth
		strings.Repeat("$.a", 200),  // longer than MaxPathLength
		"",
		"$.data[",   // unclosed bracket
		"$.data[x]", // not an index
	} {
		if _, err := jsonpath.Compile(bad); err == nil {
			t.Errorf("Compile(%q) was accepted; it should be refused", bad)
		}
	}
}

func TestJSONPathWrongShapeIsNamed(t *testing.T) {
	d := doc(t)
	// Indexing an object, or walking into a scalar, is a mapping bug and
	// should say so rather than come back as "not found".
	if _, err := jsonpath.MustCompile("$.data[0]").Eval(d); !errors.Is(err, jsonpath.ErrWrongShape) {
		t.Errorf("indexing an object: %v", err)
	}
	if _, err := jsonpath.MustCompile("$.event.nested").Eval(d); !errors.Is(err, jsonpath.ErrWrongShape) {
		t.Errorf("walking into a string: %v", err)
	}
	if _, err := jsonpath.MustCompile("$.data.items[9]").Eval(d); !errors.Is(err, jsonpath.ErrNotFound) {
		t.Errorf("out-of-range index: %v", err)
	}
}

func TestJSONPathFlattenKeepsEverything(t *testing.T) {
	flat := jsonpath.Flatten(doc(t))
	for _, key := range []string{
		"event", "data.reference", "data.customer.email",
		"data.items[0].sku", "data.items[2].sku", "data.odd.key",
	} {
		if _, ok := flat[key]; !ok {
			t.Errorf("Flatten dropped %s", key)
		}
	}
}
