package domain

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// ID prefixes. A bare opaque identifier in a log line or a support ticket is
// unhelpfully anonymous; a prefixed one says what it is before anyone has to
// look it up, and makes pasting the wrong kind of ID into an endpoint a
// validation error rather than a 404 someone spends an hour on.
const (
	PrefixTenant      = "tnt"
	PrefixEndpoint    = "ep"
	PrefixDestination = "dst"
	PrefixRawEvent    = "sh_raw"
	PrefixEvent       = "sh_evt"
	PrefixAudit       = "aud"
	PrefixAdapter     = "adp"
	PrefixAPIKey      = "sh"
)

// Crockford base32, which excludes I, L, O and U so an identifier read aloud
// down a phone line during an incident survives the journey.
var idAlphabet = base32.NewEncoding("0123456789ABCDEFGHJKMNPQRSTVWXYZ").WithPadding(base32.NoPadding)

// NewID returns a prefixed, lexicographically sortable identifier: 48 bits of
// millisecond timestamp followed by 80 bits of randomness, in the ULID layout.
//
// Sortability is not cosmetic here. raw_events is range-partitioned by time
// and is the largest table in the system; primary keys that sort with insert
// order keep the index appends at the right-hand edge instead of scattering
// writes across every page of a B-tree that will not fit in memory.
func NewID(prefix string) string {
	var b [16]byte
	binary.BigEndian.PutUint64(b[:8], uint64(time.Now().UTC().UnixMilli())<<16)
	// Reclaim the two bytes the shift left empty, then fill the rest.
	if _, err := rand.Read(b[6:]); err != nil {
		// crypto/rand does not fail on any platform we support, and a
		// non-random ID would be a collision and a guessability problem at
		// once. There is no sensible degraded mode.
		panic(fmt.Sprintf("statushub: entropy source unavailable: %v", err))
	}
	return prefix + "_" + idAlphabet.EncodeToString(b[:])
}

// HasPrefix reports whether id carries the given kind's prefix. Handlers use
// it to reject an endpoint ID passed where a destination ID belongs, before
// the query runs and returns an honest but confusing empty result.
func HasPrefix(id, prefix string) bool {
	return strings.HasPrefix(id, prefix+"_") && len(id) > len(prefix)+1
}

// NewToken returns an unguessable receiver path segment (§8.2). 160 bits: the
// token is in a URL that will be pasted into a provider's dashboard, and may
// end up in that provider's logs, so it is treated as obscurity rather than
// as a secret — but obscurity worth having is obscurity nobody can enumerate.
func NewToken() string {
	var b [20]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Sprintf("statushub: entropy source unavailable: %v", err))
	}
	return "tok_" + idAlphabet.EncodeToString(b[:])
}
