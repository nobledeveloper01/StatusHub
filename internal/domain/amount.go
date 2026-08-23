package domain

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// ErrAmountUnrepresentable is returned when a provider's amount cannot be
// converted to integer minor units without losing money.
var ErrAmountUnrepresentable = errors.New("amount cannot be represented in integer minor units")

// minorUnitExponent is the ISO 4217 exponent — how many decimal places the
// currency has. It matters more than it looks: multiplying a major-unit
// amount by 100 is right for NGN and USD, wrong for JPY, and wrong in the
// other direction for the three-decimal Gulf currencies. Getting this wrong
// is a hundredfold error in someone's ledger.
var minorUnitExponent = map[string]int{
	"NGN": 2, "USD": 2, "EUR": 2, "GBP": 2, "GHS": 2, "KES": 2, "ZAR": 2,
	"TZS": 2, "UGX": 0, "RWF": 0, "XOF": 0, "XAF": 0, "EGP": 2, "MAD": 2,
	"ZMW": 2, "CAD": 2, "AUD": 2, "CHF": 2, "CNY": 2, "INR": 2, "BRL": 2,
	"JPY": 0, "KRW": 0, "VND": 0, "CLP": 0, "ISK": 0, "PYG": 0,
	"BHD": 3, "IQD": 3, "JOD": 3, "KWD": 3, "LYD": 3, "OMR": 3, "TND": 3,
}

// MinorUnitExponent returns the number of decimal places for an ISO 4217
// code. Unknown codes get 2, which is right for the overwhelming majority —
// but the caller is told it was a guess so the event can be flagged rather
// than quietly converted.
func MinorUnitExponent(currency string) (exp int, known bool) {
	e, ok := minorUnitExponent[NormaliseCurrency(currency)]
	if !ok {
		return 2, false
	}
	return e, true
}

// NormaliseCurrency upper-cases and trims a currency code. It does not
// validate: an adapter that received something that is not a currency should
// surface that, not have it silently corrected here.
func NormaliseCurrency(c string) string {
	return strings.ToUpper(strings.TrimSpace(c))
}

// ValidCurrency reports whether c is three ASCII letters. Providers have been
// observed sending "NGN ", "ngn", and once an empty string on a refund.
func ValidCurrency(c string) bool {
	c = NormaliseCurrency(c)
	if len(c) != 3 {
		return false
	}
	for i := 0; i < 3; i++ {
		if c[i] < 'A' || c[i] > 'Z' {
			return false
		}
	}
	return true
}

// MajorToMinor converts a major-unit amount, given as the string the provider
// actually sent, into integer minor units.
//
// It works on the decimal text rather than on a float64 because a float
// cannot hold 8134.55 exactly, and 8134.55 * 100 in float64 is 813454.99...,
// which truncates to a kobo less than the customer paid. Parsing the digits
// either side of the point avoids the question entirely.
func MajorToMinor(amount string, currency string) (int64, error) {
	exp, _ := MinorUnitExponent(currency)
	return decimalToMinor(amount, exp)
}

// MinorToMajor renders integer minor units as a decimal string. Used for
// display and for adapters that must hand an amount back to a provider.
func MinorToMajor(minor int64, currency string) string {
	exp, _ := MinorUnitExponent(currency)
	if exp == 0 {
		return strconv.FormatInt(minor, 10)
	}
	neg := minor < 0
	if neg {
		minor = -minor
	}
	scale := int64(math.Pow10(exp))
	whole, frac := minor/scale, minor%scale
	s := fmt.Sprintf("%d.%0*d", whole, exp, frac)
	if neg {
		s = "-" + s
	}
	return s
}

// decimalToMinor is the digit-level conversion. It accepts an optional sign,
// digits, an optional fractional part, and nothing else — no exponents, no
// thousands separators, no currency symbols. A provider that sends "₦8,134.55"
// gets an error rather than an amount, because the alternative is guessing
// which of the two numbers in that string is the amount.
func decimalToMinor(amount string, exp int) (int64, error) {
	s := strings.TrimSpace(amount)
	if s == "" {
		return 0, fmt.Errorf("%w: empty", ErrAmountUnrepresentable)
	}

	neg := false
	switch s[0] {
	case '-':
		neg, s = true, s[1:]
	case '+':
		s = s[1:]
	}

	intPart, fracPart, hasFrac := strings.Cut(s, ".")
	if intPart == "" && !hasFrac {
		return 0, fmt.Errorf("%w: %q", ErrAmountUnrepresentable, amount)
	}
	if !allDigits(intPart) || (hasFrac && !allDigits(fracPart)) {
		return 0, fmt.Errorf("%w: %q is not a plain decimal", ErrAmountUnrepresentable, amount)
	}

	// A provider sending more decimal places than the currency has is either
	// using a currency we mis-identified or sending sub-minor precision we
	// would have to round. Both are worth an error rather than a rounding
	// decision made silently inside a payment system.
	if len(fracPart) > exp {
		trimmed := strings.TrimRight(fracPart, "0")
		if len(trimmed) > exp {
			return 0, fmt.Errorf("%w: %q has more precision than the currency's %d decimal places",
				ErrAmountUnrepresentable, amount, exp)
		}
		fracPart = fracPart[:exp]
	}
	for len(fracPart) < exp {
		fracPart += "0"
	}

	digits := intPart + fracPart
	digits = strings.TrimLeft(digits, "0")
	if digits == "" {
		return 0, nil
	}
	v, err := strconv.ParseInt(digits, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%w: %q overflows int64 minor units", ErrAmountUnrepresentable, amount)
	}
	if neg {
		v = -v
	}
	return v, nil
}

// ParseMinor reads an amount already expressed in minor units. Providers send
// these as integers, as decimal strings ending in .00, and as floats in JSON —
// all three mean the same kobo count and all three arrive in production.
func ParseMinor(amount string) (int64, error) {
	s := strings.TrimSpace(amount)
	if s == "" {
		return 0, fmt.Errorf("%w: empty", ErrAmountUnrepresentable)
	}
	if i := strings.IndexByte(s, '.'); i >= 0 {
		if strings.Trim(s[i+1:], "0") != "" {
			return 0, fmt.Errorf("%w: %q claims minor units but has a fractional part",
				ErrAmountUnrepresentable, amount)
		}
		s = s[:i]
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%w: %q", ErrAmountUnrepresentable, amount)
	}
	return v, nil
}

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
