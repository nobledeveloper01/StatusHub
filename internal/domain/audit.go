package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// AuditEventType names a state change worth recording. The list is closed
// because "we log everything" and "we can prove what happened" are different
// claims, and only the second one survives an auditor asking which events are
// guaranteed to be present.
type AuditEventType string

const (
	AuditEventReceived      AuditEventType = "event.received"
	AuditEventNormalised    AuditEventType = "event.normalised"
	AuditEventForwarded     AuditEventType = "event.forwarded"
	AuditEventDeadLettered  AuditEventType = "event.dead_lettered"
	AuditEventReplayed      AuditEventType = "event.replayed"
	AuditSignatureFailed    AuditEventType = "signature.failed"
	AuditEndpointCreated    AuditEventType = "endpoint.created"
	AuditEndpointUpdated    AuditEventType = "endpoint.updated"
	AuditEndpointDeleted    AuditEventType = "endpoint.deleted"
	AuditTokenRotated       AuditEventType = "endpoint.token_rotated"
	AuditDestinationCreated AuditEventType = "destination.created"
	AuditDestinationUpdated AuditEventType = "destination.updated"
	AuditDestinationDeleted AuditEventType = "destination.deleted"
	AuditAdapterUploaded    AuditEventType = "adapter.uploaded"
	AuditAdapterActivated   AuditEventType = "adapter.activated"
	AuditAdapterDeleted     AuditEventType = "adapter.deleted"
	AuditAPIKeyCreated      AuditEventType = "api_key.created"
	AuditAPIKeyRevoked      AuditEventType = "api_key.revoked"
	AuditRawPayloadRead     AuditEventType = "raw_payload.read"
	AuditCorrection         AuditEventType = "record.corrected"
)

// ActorType distinguishes who caused a change. "system" is a real answer and
// not a shrug — normalisation and delivery genuinely have no human actor, and
// recording them as if they did would be a lie in the evidence.
type ActorType string

const (
	ActorSystem ActorType = "system"
	ActorUser   ActorType = "user"
	ActorAPIKey ActorType = "api_key"
)

// Actor is who did it.
type Actor struct {
	Type ActorType `json:"type"`
	ID   string    `json:"id,omitempty"`
	IP   string    `json:"ip,omitempty"`
}

// Subject is what it was done to.
type Subject struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// AuditRecord is one immutable entry (§8.3).
type AuditRecord struct {
	ID         string         `json:"id"`
	TenantID   string         `json:"tenant_id"`
	EventType  AuditEventType `json:"event_type"`
	OccurredAt time.Time      `json:"occurred_at"`
	RecordedAt time.Time      `json:"recorded_at"`
	Actor      Actor          `json:"actor"`
	Subject    Subject        `json:"subject"`
	Payload    map[string]any `json:"payload,omitempty"`

	// Corrects points at a record this one supersedes. Corrections are
	// appended, never applied: the original stays, wrong, with a later record
	// explaining it. An audit trail you can edit to fix a mistake is one you
	// can edit to hide one.
	Corrects string `json:"corrects,omitempty"`

	PrevHash string `json:"prev_hash"`
	Hash     string `json:"hash"`
}

// ComputeHash derives the record's hash from its content and its
// predecessor's, forming the per-tenant chain. Tampering with any record
// invalidates every record after it, which is what makes the trail evidence
// rather than a log.
//
// The hashed form is built field by field rather than by marshalling the
// struct, because Go's map iteration order is randomised and a hash that
// depends on it would fail verification at random.
func (r *AuditRecord) ComputeHash() (string, error) {
	payload, err := canonicalJSON(r.Payload)
	if err != nil {
		return "", fmt.Errorf("audit payload is not hashable: %w", err)
	}
	h := sha256.New()
	for _, part := range []string{
		r.ID,
		r.TenantID,
		string(r.EventType),
		r.OccurredAt.UTC().Format(time.RFC3339Nano),
		string(r.Actor.Type), r.Actor.ID, r.Actor.IP,
		r.Subject.Type, r.Subject.ID,
		payload,
		r.Corrects,
		r.PrevHash,
	} {
		// The length prefix stops two different records hashing identically
		// by shifting content across a boundary — an actor ID of "ab" with a
		// subject of "c" must not collide with "a" and "bc".
		fmt.Fprintf(h, "%d:%s|", len(part), part)
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

// Seal computes and sets the record's hash. Called once, by the store, inside
// the same transaction that inserts it.
func (r *AuditRecord) Seal(prevHash string) error {
	if r.RecordedAt.IsZero() {
		r.RecordedAt = time.Now().UTC()
	}
	if r.OccurredAt.IsZero() {
		r.OccurredAt = r.RecordedAt
	}
	r.PrevHash = prevHash
	h, err := r.ComputeHash()
	if err != nil {
		return err
	}
	r.Hash = h
	return nil
}

// GenesisHash starts a tenant's chain. A fixed, non-empty value so that an
// empty PrevHash is always a bug rather than a legitimate first record.
const GenesisHash = "sha256:genesis"

// ChainProof is the result of walking a tenant's chain, returned by
// GET /v1/audit/verify so a customer's auditor can check it without asking us
// (§8.3).
type ChainProof struct {
	TenantID string    `json:"tenant_id"`
	Records  int64     `json:"records"`
	From     time.Time `json:"from"`
	To       time.Time `json:"to"`
	Head     string    `json:"head_hash"`
	Intact   bool      `json:"intact"`

	// BrokenAt names the first record whose hash does not follow from its
	// predecessor. Naming the first break rather than counting all of them is
	// deliberate: everything after a break is expected to fail, and listing
	// it buries the one record that matters.
	BrokenAt string `json:"broken_at,omitempty"`
	Reason   string `json:"reason,omitempty"`

	VerifiedAt time.Time `json:"verified_at"`
}

// canonicalJSON marshals with sorted keys. encoding/json sorts map keys
// already; this wrapper exists to make that guarantee explicit at the one
// place where relying on it silently would be a correctness bug.
func canonicalJSON(v map[string]any) (string, error) {
	if len(v) == 0 {
		return "{}", nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
