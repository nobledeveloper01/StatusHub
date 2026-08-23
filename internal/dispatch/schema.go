package dispatch

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/nobledeveloper01/StatusHub/internal/domain"
)

// SchemaVersion is the shape of the payload a destination receives.
//
// The product's promise is that a customer writes one handler and never
// touches it again when a provider is added. That promise breaks the first
// time the canonical schema gains a field their parser rejects — a strict
// decoder in Go, Java or Rust will refuse an unknown key, and there are more
// of those in fintech than in most places.
//
// So the version is pinned per destination. A schema change ships as a new
// version, existing destinations keep receiving the one they were built
// against, and moving is something the customer does on a day they chose.
type SchemaVersion string

const (
	// SchemaV1 is the shape in §7.2.
	SchemaV1 SchemaVersion = "2026-08-01"

	// SchemaLatest is what a new destination gets. It is a distinct constant
	// rather than an alias so that adding a version is a one-line change here
	// and cannot be forgotten at a call site.
	SchemaLatest = SchemaV1
)

// schemaVersions is every version, with the date it stops being served.
//
// A retirement date is set when a version is deprecated, never at the moment
// it is introduced, and it is communicated before it is enforced. A schema
// version that disappears on a deploy is the failure this whole mechanism
// exists to prevent — doing it accidentally would be worse than not having
// versions at all.
var schemaVersions = map[SchemaVersion]*schemaInfo{
	SchemaV1: {
		Introduced: time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC),
		Notes:      "The initial canonical schema.",
	},
}

type schemaInfo struct {
	Introduced time.Time
	RetiresAt  time.Time
	Notes      string
}

// ValidSchemaVersion reports whether a version is served.
func ValidSchemaVersion(v SchemaVersion) bool {
	_, ok := schemaVersions[v]
	return ok
}

// SchemaVersions lists what is served, oldest first, for the dashboard and
// the docs.
type SchemaDescription struct {
	Version    SchemaVersion `json:"version"`
	Introduced time.Time     `json:"introduced"`
	RetiresAt  *time.Time    `json:"retires_at,omitempty"`
	Latest     bool          `json:"latest"`
	Notes      string        `json:"notes,omitempty"`
}

// SchemaVersions returns every served version.
func SchemaVersions() []SchemaDescription {
	out := make([]SchemaDescription, 0, len(schemaVersions))
	for v, info := range schemaVersions {
		d := SchemaDescription{
			Version: v, Introduced: info.Introduced,
			Latest: v == SchemaLatest, Notes: info.Notes,
		}
		if !info.RetiresAt.IsZero() {
			t := info.RetiresAt
			d.RetiresAt = &t
		}
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Introduced.Before(out[j].Introduced) })
	return out
}

// ResolveSchema returns the version a destination should receive.
//
// An unset version means the destination predates versioning, and it gets v1
// rather than latest. Defaulting an existing destination to "whatever is
// newest" would silently move every handler onto a new shape on the day a
// version ships, which is exactly the outcome this prevents.
func ResolveSchema(configured SchemaVersion) SchemaVersion {
	if configured == "" {
		return SchemaV1
	}
	if !ValidSchemaVersion(configured) {
		// A retired or unknown version falls back to v1 and is served rather
		// than refused. Refusing would stop delivering to a customer whose
		// only mistake was not reading a deprecation notice, and a payload
		// they can parse beats no payload at all.
		return SchemaV1
	}
	return configured
}

// RenderPayload produces the body for a destination's schema version.
//
// Every version is rendered from the same stored event. Nothing is written
// per version, so adding a version costs a function here and no migration —
// and an event stored two years ago can still be replayed in whichever shape
// its destination expects.
func RenderPayload(v SchemaVersion, e domain.CanonicalEvent, raw []byte) ([]byte, error) {
	switch ResolveSchema(v) {
	case SchemaV1:
		return json.Marshal(BuildPayload(e, raw))
	default:
		return nil, fmt.Errorf("no renderer for schema version %q", v)
	}
}

// SchemaHeader tells the customer which shape they are receiving, on every
// delivery.
//
// It is not optional. A handler that receives an unexpected shape and has no
// way to know which version it is cannot log anything useful, and the support
// conversation starts with "what did you send us" rather than with the answer.
const SchemaHeader = "X-StatusHub-Schema-Version"
