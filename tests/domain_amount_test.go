package tests

import (
	"errors"
	"testing"

	"github.com/nobledeveloper01/StatusHub/internal/domain"
)

func TestAmountMajorToMinor(t *testing.T) {
	cases := []struct {
		amount   string
		currency string
		want     int64
	}{
		// The case the whole function exists for: 8134.55 is not
		// representable in binary floating point, and 8134.55 * 100 in
		// float64 is 813454.9999999999.
		{"8134.55", "NGN", 813455},
		{"0.01", "NGN", 1},
		{"0.1", "NGN", 10},
		{"1", "NGN", 100},
		{"1.5", "NGN", 150},
		{"1.50", "NGN", 150},
		{"0", "NGN", 0},
		{"0.00", "NGN", 0},
		{"-25.30", "NGN", -2530},
		{"1234567890.12", "NGN", 123456789012},

		// Zero-decimal currencies. Multiplying these by 100 would inflate
		// every Japanese or West African transaction a hundredfold.
		{"5000", "JPY", 5000},
		{"5000", "XOF", 5000},
		{"1200", "RWF", 1200},

		// Three-decimal currencies go the other way.
		{"1.234", "KWD", 1234},
		{"10", "BHD", 10000},

		// Case and whitespace on the currency code must not change the
		// exponent, because providers send all three spellings.
		{"12.34", "ngn", 1234},
		{"12.34", " NGN ", 1234},
	}

	for _, c := range cases {
		got, err := domain.MajorToMinor(c.amount, c.currency)
		if err != nil {
			t.Errorf("MajorToMinor(%q, %q): %v", c.amount, c.currency, err)
			continue
		}
		if got != c.want {
			t.Errorf("MajorToMinor(%q, %q) = %d, want %d", c.amount, c.currency, got, c.want)
		}
	}
}

func TestAmountRefusesToRoundSilently(t *testing.T) {
	// More precision than the currency has means either we identified the
	// currency wrongly or the provider is sending sub-minor amounts. Both
	// deserve an error: quietly rounding inside a payment system is how a
	// discrepancy appears in a reconciliation three months later with no
	// trace of where it came from.
	for _, bad := range []string{"1.234", "0.005", "99.999"} {
		if _, err := domain.MajorToMinor(bad, "NGN"); !errors.Is(err, domain.ErrAmountUnrepresentable) {
			t.Errorf("MajorToMinor(%q, NGN) should refuse to round, got %v", bad, err)
		}
	}
	// Trailing zeros are not extra precision and must still be accepted.
	if v, err := domain.MajorToMinor("1.2300", "NGN"); err != nil || v != 123 {
		t.Errorf("MajorToMinor(1.2300, NGN) = %d, %v; want 123", v, err)
	}
}

func TestAmountRefusesFormattedText(t *testing.T) {
	// A thousands separator or a currency symbol means guessing which number
	// in the string is the amount. There is no safe guess.
	for _, bad := range []string{"8,134.55", "₦8134.55", "NGN 8134", "1e5", "", "  ", "abc", "1.2.3"} {
		if _, err := domain.MajorToMinor(bad, "NGN"); err == nil {
			t.Errorf("MajorToMinor(%q) was accepted; it should not be", bad)
		}
	}
}

func TestAmountUnknownCurrencyIsFlaggedNotGuessed(t *testing.T) {
	exp, known := domain.MinorUnitExponent("ZZZ")
	if known {
		t.Fatal("ZZZ should not be a known currency")
	}
	// Two is the right guess for almost everything, but the caller is told it
	// was a guess so the event can be flagged rather than quietly converted.
	if exp != 2 {
		t.Errorf("fallback exponent = %d, want 2", exp)
	}
}

func TestAmountParseMinor(t *testing.T) {
	for _, c := range []struct {
		in   string
		want int64
	}{{"5000000", 5000000}, {"5000000.00", 5000000}, {"0", 0}, {"-100", -100}} {
		got, err := domain.ParseMinor(c.in)
		if err != nil || got != c.want {
			t.Errorf("ParseMinor(%q) = %d, %v; want %d", c.in, got, err, c.want)
		}
	}
	// A "minor unit" amount with a real fractional part is a contradiction,
	// and accepting it would mean silently deciding what a fraction of a kobo
	// is worth.
	if _, err := domain.ParseMinor("5000.55"); err == nil {
		t.Error("ParseMinor accepted a fractional minor-unit amount")
	}
}

func TestAmountRoundTrip(t *testing.T) {
	for _, c := range []struct {
		minor    int64
		currency string
		want     string
	}{
		{813455, "NGN", "8134.55"},
		{1, "NGN", "0.01"},
		{0, "NGN", "0.00"},
		{-2530, "NGN", "-25.30"},
		{5000, "JPY", "5000"},
		{1234, "KWD", "1.234"},
	} {
		if got := domain.MinorToMajor(c.minor, c.currency); got != c.want {
			t.Errorf("MinorToMajor(%d, %s) = %q, want %q", c.minor, c.currency, got, c.want)
		}
	}
}

func TestCurrencyValidation(t *testing.T) {
	for _, good := range []string{"NGN", "ngn", " USD "} {
		if !domain.ValidCurrency(good) {
			t.Errorf("ValidCurrency(%q) = false", good)
		}
	}
	for _, bad := range []string{"", "NG", "NGNN", "N1N", "12"} {
		if domain.ValidCurrency(bad) {
			t.Errorf("ValidCurrency(%q) = true", bad)
		}
	}
}
