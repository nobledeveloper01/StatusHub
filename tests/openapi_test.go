package tests

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nobledeveloper01/StatusHub/internal/api"
)

// TestOpenAPIMatchesTheCommittedDocument is the gate that keeps the
// specification honest.
//
// A specification maintained beside the code drifts, and a drifted one is
// worse than none: a generated client calls endpoints that do not exist,
// omits ones that do, and is trusted because it looks authoritative.
func TestOpenAPIMatchesTheCommittedDocument(t *testing.T) {
	path := filepath.Join("..", "docs", "openapi.yaml")
	committed, err := os.ReadFile(path)
	mustNoErr(t, err, "reading the committed document")

	// The version is stamped at generation, so it is normalised out of the
	// comparison — otherwise every release would fail this.
	generated := api.OpenAPIDocument(versionOf(string(committed)))
	if generated != string(committed) {
		t.Fatalf("docs/openapi.yaml is out of date with the routes.\n"+
			"Regenerate it:\n  go run ./cmd/statushubctl openapi --out docs/openapi.yaml\n"+
			"(generated %d bytes, committed %d)", len(generated), len(committed))
	}
}

func versionOf(doc string) string {
	for _, line := range strings.Split(doc, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "version:"); ok {
			return strings.Trim(strings.TrimSpace(v), `"`)
		}
	}
	return "dev"
}

// TestOpenAPIRouteTableIsComplete checks the half a generator cannot.
//
// The document and the mux are built from one loop over one table, so they
// cannot list different routes. What that does not prove is that the table is
// filled in — a route with a nil handler, or no summary, would generate a
// document entry for something nobody can call or understand.
func TestOpenAPIRouteTableIsComplete(t *testing.T) {
	doc := api.OpenAPIDocument("test")

	paths := documentedPaths(doc)
	if len(paths) < 25 {
		t.Fatalf("only %d paths documented; the table looks truncated", len(paths))
	}

	// Every documented path must be reachable through the real mux. Probing
	// with OPTIONS rather than GET, because several paths are POST-only and a
	// GET on them would fall through to a different route entirely.
	h := newAPIHarness(t)
	for _, path := range paths {
		// Only the versioned API is probed. The health routes sit on the
		// outer mux alongside the dashboard's catch-all, so an unmatched
		// method there is answered by the file server — correctly, and not
		// in a way this assertion can read.
		if !strings.HasPrefix(path, "/v1/") {
			continue
		}
		concrete := strings.NewReplacer("{id}", "probe", "{name}", "probe").Replace(path)
		req, err := http.NewRequestWithContext(t.Context(), http.MethodOptions, h.server.URL+concrete, nil)
		mustNoErr(t, err, "building")
		req.Header.Set("Authorization", "Bearer "+h.ownerA)

		resp, err := h.server.Client().Do(req)
		mustNoErr(t, err, "sending")
		code := resp.StatusCode
		_ = resp.Body.Close()

		// 405 is the healthy answer: the mux knows the path and OPTIONS is
		// not one of its methods. A 404 would mean the document promises a
		// path nothing serves — which, for the dashboard's catch-all route,
		// cannot happen, so this also confirms the catch-all is not
		// swallowing API paths.
		if code != http.StatusMethodNotAllowed {
			t.Errorf("OPTIONS %s = %d; the documented path does not route as an API path", path, code)
		}
	}
}

// TestOpenAPIStatesTheThingsAGeneratedClientCannotInfer checks the prose that
// makes the document worth reading.
//
// A schema says `status` is a string. Only a sentence says that `unknown`
// means StatusHub refused to guess, and that treating it as a failure will
// reverse payments that succeeded. That sentence is the difference between a
// specification and a type listing.
func TestOpenAPIStatesTheThingsAGeneratedClientCannotInfer(t *testing.T) {
	// Whitespace collapsed, because these sentences wrap across lines in YAML
	// and an assertion that depends on where the wrap falls breaks every time
	// somebody edits the prose around it.
	doc := strings.Join(strings.Fields(api.OpenAPIDocument("test")), " ")
	for _, want := range []string{
		"refused to guess",                    // why unknown exists
		"reverses a payment that completed",   // what happens if you ignore it
		"404, never 403",                      // the tenancy rule
		"which of their stolen keys are real", // why 401s are opaque
		"Idempotency-Replayed",                // how a caller detects a replay
		"integer minor units",                 // the amount contract
		"there never will be",                 // the pseudonymisation promise
		"never diverted",                      // that listening does not break production
		"dead letter is preserved",            // why a retry does not overwrite
		"dry_run",                             // the bulk-replay safety step
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("the document does not explain %q", want)
		}
	}
}

func TestOpenAPIMarksRolesAndUnauthenticatedRoutes(t *testing.T) {
	doc := api.OpenAPIDocument("test")

	// An unauthenticated route says so explicitly, rather than leaving a
	// reader to infer it from a missing key.
	if !strings.Contains(doc, "security: []") {
		t.Error("public routes are not marked as unauthenticated")
	}
	// And every authenticated one carries the role it needs, so a reader can
	// see which key to use without trying.
	for _, role := range []string{"owner", "engineer", "support", "read_only"} {
		if !strings.Contains(doc, "x-statushub-minimum-role: "+role) {
			t.Errorf("no route documents the %s role", role)
		}
	}
}

func TestOpenAPIGenerationIsDeterministic(t *testing.T) {
	// A generator whose output moves between runs turns the drift gate into
	// one that fails at random and is therefore deleted.
	first := api.OpenAPIDocument("test")
	for i := 0; i < 20; i++ {
		if api.OpenAPIDocument("test") != first {
			t.Fatal("the document changed between identical generations")
		}
	}
}

// documentedPaths lists the paths the specification declares.
func documentedPaths(doc string) []string {
	var (
		out   []string
		inMap bool
	)
	for _, line := range strings.Split(doc, "\n") {
		if strings.HasPrefix(line, "paths:") {
			inMap = true
			continue
		}
		if inMap && strings.HasPrefix(line, "components:") {
			break
		}
		if !inMap || !strings.HasPrefix(line, "  /") {
			continue
		}
		out = append(out, strings.TrimSuffix(strings.TrimSpace(line), ":"))
	}
	return out
}
