package adapter

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ErrNoTimezone is returned when a timestamp carries no zone and the caller
// supplied none. It is an error rather than a default because "2026-08-11
// 09:14:22" read as UTC when it was written in Lagos is an event that appears
// to have happened an hour before it did — which reorders it against every
// other event in the same transaction.
var ErrNoTimezone = fmt.Errorf("timestamp has no timezone and none was configured")

// zonedLayouts carry their own offset, so they need no help.
var zonedLayouts = []string{
	time.RFC3339Nano,
	time.RFC3339,
	"2006-01-02T15:04:05.999999999Z0700",
	"2006-01-02T15:04:05Z0700",
	"2006-01-02T15:04:05.999999999-07:00",
	"2006-01-02 15:04:05Z07:00",
	"2006-01-02 15:04:05 -0700",
	"Mon, 02 Jan 2006 15:04:05 -0700",
	"Mon, 02 Jan 2006 15:04:05 MST",
}

// naiveLayouts have no offset. Every one of these needs a zone supplied from
// configuration, which is why the declarative adapter's `timezone` field is
// stated explicitly and never inferred (§4.4).
var naiveLayouts = []string{
	"2006-01-02T15:04:05.999999999",
	"2006-01-02T15:04:05",
	"2006-01-02 15:04:05.999999999",
	"2006-01-02 15:04:05",
	"2006-01-02T15:04",
	"2006-01-02 15:04",
	"02/01/2006 15:04:05",
	"2006-01-02",
}

// ParseTime reads a provider timestamp and returns it in UTC.
//
// Order matters. A Unix timestamp is tried first because it is unambiguous;
// then layouts that carry an offset; then, only if a zone was configured,
// layouts that do not. A naive timestamp with no configured zone is an error,
// not a guess.
func ParseTime(value string, loc *time.Location) (time.Time, error) {
	s := strings.TrimSpace(value)
	if s == "" {
		return time.Time{}, fmt.Errorf("%w: empty timestamp", ErrUnparseable)
	}

	if t, ok := parseUnix(s); ok {
		return t.UTC(), nil
	}
	for _, layout := range zonedLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	for _, layout := range naiveLayouts {
		if _, err := time.Parse(layout, s); err != nil {
			continue
		}
		if loc == nil {
			return time.Time{}, fmt.Errorf("%w: %q", ErrNoTimezone, s)
		}
		t, err := time.ParseInLocation(layout, s, loc)
		if err != nil {
			continue
		}
		return t.UTC(), nil
	}
	return time.Time{}, fmt.Errorf("%w: %q is not a recognised timestamp", ErrUnparseable, s)
}

// ParseTimeLayout reads a timestamp against one stated layout, which is what
// a declarative adapter configures. Being explicit beats the guessing above
// whenever the customer knows the format.
func ParseTimeLayout(value, layout string, loc *time.Location) (time.Time, error) {
	s := strings.TrimSpace(value)
	if layout == "" {
		return ParseTime(s, loc)
	}
	if loc != nil {
		t, err := time.ParseInLocation(layout, s, loc)
		if err != nil {
			return time.Time{}, fmt.Errorf("%w: %q against layout %q: %w", ErrUnparseable, s, layout, err)
		}
		return t.UTC(), nil
	}
	t, err := time.Parse(layout, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: %q against layout %q: %w", ErrUnparseable, s, layout, err)
	}
	return t.UTC(), nil
}

// parseUnix reads a bare epoch value, in seconds, milliseconds, microseconds
// or nanoseconds.
//
// The unit is inferred from magnitude, which is the one inference in this
// file that is safe to make: the ranges do not overlap for any timestamp in
// the century either side of now. A ten-digit value is seconds — anything
// else would place the event in 1970 or in the year 33658.
func parseUnix(s string) (time.Time, bool) {
	if len(s) < 9 || len(s) > 19 {
		return time.Time{}, false
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 {
		return time.Time{}, false
	}
	switch {
	case n < 1e11: // seconds, through the year 5138
		return time.Unix(n, 0), true
	case n < 1e14: // milliseconds
		return time.UnixMilli(n), true
	case n < 1e17: // microseconds
		return time.UnixMicro(n), true
	default: // nanoseconds
		return time.Unix(0, n), true
	}
}

// LoadLocation resolves a configured IANA zone name. It is separated out so
// an adapter upload naming a zone the host has no tzdata for fails at upload
// time, with a clear message, rather than on the first event.
func LoadLocation(name string) (*time.Location, error) {
	n := strings.TrimSpace(name)
	if n == "" || strings.EqualFold(n, "UTC") {
		return time.UTC, nil
	}
	loc, err := time.LoadLocation(n)
	if err != nil {
		return nil, fmt.Errorf("unknown timezone %q: %w", name, err)
	}
	return loc, nil
}
