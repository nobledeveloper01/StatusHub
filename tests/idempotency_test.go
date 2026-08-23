package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"testing"
)

// doWithKey posts with an Idempotency-Key.
func (h *apiHarness) doWithKey(t *testing.T, key, idemKey, method, path string, body any) (apiResponse, map[string]any) {
	t.Helper()
	b, err := json.Marshal(body)
	mustNoErr(t, err, "marshalling")
	req, err := http.NewRequestWithContext(context.Background(), method, h.server.URL+path, bytes.NewReader(b))
	mustNoErr(t, err, "building")
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/json")
	if idemKey != "" {
		req.Header.Set("Idempotency-Key", idemKey)
	}
	resp, err := h.server.Client().Do(req)
	mustNoErr(t, err, "sending")

	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	_ = resp.Body.Close()
	return apiResponse{StatusCode: resp.StatusCode, Header: resp.Header}, out
}

// TestIdempotentCreateDoesNotIssueASecondReceiverToken is the failure this
// whole feature exists to prevent.
//
// Without it, a retried create during a network blip leaves the operator with
// two receiver URLs and no way to tell which one the provider is calling.
func TestIdempotentCreateDoesNotIssueASecondReceiverToken(t *testing.T) {
	h := newAPIHarness(t)
	body := map[string]any{
		"provider": "paystack", "environment": "live", "secret_ref": testSecretRef,
	}

	resp, first := h.doWithKey(t, h.ownerA, "key-1", http.MethodPost, "/v1/endpoints", body)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("first create = %d: %v", resp.StatusCode, first)
	}

	resp, second := h.doWithKey(t, h.ownerA, "key-1", http.MethodPost, "/v1/endpoints", body)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("the retry = %d, want the original 201", resp.StatusCode)
	}
	// A caller that cannot tell a replay from a fresh execution cannot tell
	// whether their retry did anything.
	if resp.Header.Get("Idempotency-Replayed") != "true" {
		t.Error("the replay was not marked as one")
	}
	if first["id"] != second["id"] {
		t.Fatalf("the retry created a second endpoint: %v then %v", first["id"], second["id"])
	}
	if first["receiver_url"] != second["receiver_url"] {
		t.Fatalf("the retry issued a second receiver token:\n  %v\n  %v", first["receiver_url"], second["receiver_url"])
	}

	// And exactly one endpoint exists.
	_, list := h.do(t, h.ownerA, http.MethodGet, "/v1/endpoints", nil)
	eps, _ := list["endpoints"].([]any)
	if len(eps) != 1 {
		t.Fatalf("%d endpoints exist after one create and one retry", len(eps))
	}
}

func TestIdempotencyKeyReusedWithADifferentBodyIsAConflict(t *testing.T) {
	// Returning the first response would answer a question this caller did
	// not ask. Executing this one makes the key meaningless. A 409 tells them
	// their client has a bug, which it does.
	h := newAPIHarness(t)

	resp, _ := h.doWithKey(t, h.ownerA, "key-2", http.MethodPost, "/v1/endpoints", map[string]any{
		"provider": "paystack", "environment": "live", "secret_ref": testSecretRef,
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("first = %d", resp.StatusCode)
	}

	resp, body := h.doWithKey(t, h.ownerA, "key-2", http.MethodPost, "/v1/endpoints", map[string]any{
		"provider": "stripe", "environment": "live", "secret_ref": testSecretRef,
	})
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("reusing a key with a different body = %d, want 409: %v", resp.StatusCode, body)
	}
}

func TestIdempotencyToleratesKeyReordering(t *testing.T) {
	// A client whose JSON serialiser reorders map keys between retries must
	// not be told its own retry is a different request.
	h := newAPIHarness(t)

	first := `{"provider":"paystack","environment":"live","secret_ref":"` + testSecretRef + `"}`
	reordered := `{"secret_ref":"` + testSecretRef + `","environment":"live","provider":"paystack"}`

	post := func(raw string) (apiResponse, map[string]any) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
			h.server.URL+"/v1/endpoints", bytes.NewReader([]byte(raw)))
		mustNoErr(t, err, "building")
		req.Header.Set("Authorization", "Bearer "+h.ownerA)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", "key-reorder")
		resp, err := h.server.Client().Do(req)
		mustNoErr(t, err, "sending")
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		_ = resp.Body.Close()
		return apiResponse{StatusCode: resp.StatusCode, Header: resp.Header}, out
	}

	resp, a := post(first)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("first = %d: %v", resp.StatusCode, a)
	}
	resp, b := post(reordered)
	if resp.StatusCode == http.StatusConflict {
		t.Fatal("reordered keys were treated as a different request")
	}
	if a["id"] != b["id"] {
		t.Fatalf("reordered retry created a second resource: %v then %v", a["id"], b["id"])
	}
}

func TestIdempotencyIsPerTenant(t *testing.T) {
	// Two tenants using the same key — "create-endpoint", say — must not
	// collide, or one tenant's write returns another's response.
	h := newAPIHarness(t)
	body := map[string]any{"provider": "paystack", "environment": "live", "secret_ref": testSecretRef}

	respA, a := h.doWithKey(t, h.ownerA, "shared-key", http.MethodPost, "/v1/endpoints", body)
	respB, b := h.doWithKey(t, h.ownerB, "shared-key", http.MethodPost, "/v1/endpoints", body)

	if respA.StatusCode != http.StatusCreated || respB.StatusCode != http.StatusCreated {
		t.Fatalf("statuses = %d, %d", respA.StatusCode, respB.StatusCode)
	}
	if a["id"] == b["id"] {
		t.Fatal("two tenants sharing a key got the same resource")
	}
	if respB.Header.Get("Idempotency-Replayed") == "true" {
		t.Fatal("tenant B was served tenant A's recorded response")
	}
}

func TestIdempotencyDoesNotRecordFailures(t *testing.T) {
	// Replaying a 400 would keep answering a request the caller has since
	// corrected, which is a worse outcome than making them retry.
	h := newAPIHarness(t)

	resp, _ := h.doWithKey(t, h.ownerA, "key-fail", http.MethodPost, "/v1/endpoints", map[string]any{
		"provider": "paystack", "environment": "live", "secret_ref": "static://does-not-resolve",
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected a 400, got %d", resp.StatusCode)
	}

	// The same key, now with a request that works.
	resp, body := h.doWithKey(t, h.ownerA, "key-fail", http.MethodPost, "/v1/endpoints", map[string]any{
		"provider": "paystack", "environment": "live", "secret_ref": testSecretRef,
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("the corrected request = %d, want 201: %v", resp.StatusCode, body)
	}
}

func TestWritesWithoutAKeyStillWork(t *testing.T) {
	// Idempotency is opt-in per request. Forcing every caller to generate a
	// key would break every curl command in the documentation for a guarantee
	// most of them do not need.
	h := newAPIHarness(t)
	resp, _ := h.do(t, h.ownerA, http.MethodPost, "/v1/endpoints", map[string]any{
		"provider": "paystack", "environment": "live", "secret_ref": testSecretRef,
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("a write with no idempotency key = %d", resp.StatusCode)
	}
}

func TestIdempotentConcurrentRetriesExecuteOnce(t *testing.T) {
	// Two retries racing is the ordinary case, not the exotic one: a client
	// timeout fires while the original is still in flight.
	h := newAPIHarness(t)
	body := map[string]any{"provider": "paystack", "environment": "live", "secret_ref": testSecretRef}

	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		created []string
		codes   []int
	)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, out := h.doWithKey(t, h.ownerA, "race-key", http.MethodPost, "/v1/endpoints", body)
			mu.Lock()
			defer mu.Unlock()
			codes = append(codes, resp.StatusCode)
			if id, ok := out["id"].(string); ok && id != "" {
				created = append(created, id)
			}
		}()
	}
	wg.Wait()

	// Every response that carries a resource must carry the same one.
	for _, id := range created {
		if id != created[0] {
			t.Fatalf("concurrent retries produced different resources: %v", created)
		}
	}
	_, list := h.do(t, h.ownerA, http.MethodGet, "/v1/endpoints", nil)
	eps, _ := list["endpoints"].([]any)
	if len(eps) != 1 {
		t.Fatalf("%d endpoints after 8 concurrent retries of one request", len(eps))
	}
}
