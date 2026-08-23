package tests

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/nobledeveloper01/StatusHub/internal/dispatch"
	"github.com/nobledeveloper01/StatusHub/internal/domain"
)

func TestSchemaExistingDestinationsNeverMoveOnTheirOwn(t *testing.T) {
	// The whole mechanism in one assertion. A destination created before
	// versioning existed must keep the original shape — defaulting it to
	// "whatever is newest" would silently move every handler onto a new
	// payload on the day a version ships, which is exactly what this
	// prevents.
	if got := dispatch.ResolveSchema(""); got != dispatch.SchemaV1 {
		t.Fatalf("an unset version resolved to %q, want the original shape", got)
	}
	if got := dispatch.ResolveSchema(dispatch.SchemaV1); got != dispatch.SchemaV1 {
		t.Errorf("an explicit v1 resolved to %q", got)
	}
}

func TestSchemaUnknownVersionIsServedNotRefused(t *testing.T) {
	// Refusing would stop delivering to a customer whose only mistake was not
	// reading a deprecation notice. A payload they can parse beats no payload.
	if got := dispatch.ResolveSchema("1999-01-01"); got != dispatch.SchemaV1 {
		t.Fatalf("an unknown version resolved to %q rather than falling back", got)
	}
	if dispatch.ValidSchemaVersion("1999-01-01") {
		t.Error("an unknown version reported as served")
	}
}

func TestSchemaEveryVersionRendersFromTheSameStoredEvent(t *testing.T) {
	// Nothing is written per version, so an event stored two years ago can
	// still be replayed in whichever shape its destination expects.
	ev := domain.CanonicalEvent{
		ID: "sh_evt_1", TenantID: tenantA, Provider: "paystack",
		EventType: domain.EventPaymentCompleted, TransactionRef: "TXN-1",
		Status: domain.StatusSuccess, AmountMinor: 5000000, Currency: "NGN",
		OccurredAt:      time.Date(2026, 8, 11, 9, 14, 31, 0, time.UTC),
		ReceivedAt:      time.Date(2026, 8, 11, 9, 14, 31, 0, time.UTC),
		MappingComplete: true,
	}

	for _, d := range dispatch.SchemaVersions() {
		body, err := dispatch.RenderPayload(d.Version, ev, nil)
		mustNoErr(t, err, "rendering "+string(d.Version))

		var out map[string]any
		mustNoErr(t, json.Unmarshal(body, &out), "decoding "+string(d.Version))
		// Whatever else changes between versions, these are the fields the
		// product is about.
		if out["event_id"] != "sh_evt_1" || out["transaction_ref"] != "TXN-1" {
			t.Errorf("%s dropped an identifying field: %v", d.Version, out)
		}
		if out["status"] != "success" {
			t.Errorf("%s rendered status as %v", d.Version, out["status"])
		}
	}
}

func TestSchemaVersionsArePublished(t *testing.T) {
	// A customer should be able to see what shapes exist and when one
	// retires, rather than discovering a version change from a broken
	// handler.
	versions := dispatch.SchemaVersions()
	if len(versions) == 0 {
		t.Fatal("no schema versions published")
	}
	var latest int
	for _, v := range versions {
		if v.Version == "" || v.Introduced.IsZero() {
			t.Errorf("version is not documented: %+v", v)
		}
		if v.Latest {
			latest++
		}
		// A retirement date is set when a version is deprecated, never when
		// it is introduced.
		if v.RetiresAt != nil && !v.RetiresAt.After(v.Introduced) {
			t.Errorf("%s retires before it was introduced", v.Version)
		}
	}
	if latest != 1 {
		t.Errorf("%d versions marked latest, want exactly 1", latest)
	}
}

func TestSchemaVersionIsOnEveryDelivery(t *testing.T) {
	// A handler that receives an unexpected shape and cannot say which
	// version it was makes the support conversation start with "what did you
	// send us" rather than with the answer.
	h := newDispatchHarness(t, domain.DefaultRetryPolicy())
	ctx := context.Background()
	ev := h.event(t, "TXN-SCHEMA", domain.StatusSuccess, h.clock.now())
	mustNoErr(t, h.d.Enqueue(ctx, ev), "enqueuing")
	h.drain(t, 3)

	if h.sink.count() != 1 {
		t.Fatalf("%d deliveries", h.sink.count())
	}
	h.sink.mu.Lock()
	got := h.sink.headers[0].Get(dispatch.SchemaHeader)
	h.sink.mu.Unlock()

	if got == "" {
		t.Fatal("no schema version header on the delivery")
	}
	if !dispatch.ValidSchemaVersion(dispatch.SchemaVersion(got)) {
		t.Errorf("the delivered version %q is not one we serve", got)
	}
}

func TestSchemaAPIRefusesAnUnservedVersionAtCreation(t *testing.T) {
	// Caught at creation, where the customer can fix it, rather than at
	// delivery, where they cannot.
	h := newAPIHarness(t)
	resp, body := h.do(t, h.ownerA, http.MethodPost, "/v1/destinations", map[string]any{
		"url": destinationURL, "signing_secret_ref": signingRef, "schema_version": "1999-01-01",
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("an unserved schema version was accepted: %d %v", resp.StatusCode, body)
	}

	// And a new destination with none specified gets the newest, which is
	// safe because it has no existing handler to break.
	resp, created := h.do(t, h.ownerA, http.MethodPost, "/v1/destinations", map[string]any{
		"url": destinationURL, "signing_secret_ref": signingRef,
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("creating = %d: %v", resp.StatusCode, created)
	}
	if created["schema_version"] != string(dispatch.SchemaLatest) {
		t.Errorf("a new destination got %v, want the latest", created["schema_version"])
	}
}

func TestSchemaAPIPublishesTheVersionList(t *testing.T) {
	h := newAPIHarness(t)
	resp, body := h.do(t, h.readerA, http.MethodGet, "/v1/schema-versions", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	versions, _ := body["versions"].([]any)
	if len(versions) == 0 {
		t.Fatal("no versions published")
	}
	if body["latest"] != string(dispatch.SchemaLatest) {
		t.Errorf("latest = %v", body["latest"])
	}
	note, _ := body["note"].(string)
	if note == "" {
		t.Error("no note explaining the pinning behaviour")
	}
}
