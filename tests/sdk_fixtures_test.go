package tests

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nobledeveloper01/StatusHub/internal/dispatch"
)

// TestGenerateSDKFixtures writes the vectors the Node and Python libraries
// verify against.
//
// One source of truth, produced by the server that will actually be signing
// in production. Three independent implementations agreeing with each other
// but not with the server is a failure mode worth designing out, and this is
// how: the fixtures are generated here, and the other two suites read them.
//
// Run with -run GenerateSDKFixtures to regenerate after a signing change.
func TestGenerateSDKFixtures(t *testing.T) {
	dir := filepath.Join("..", "sdk", "fixtures")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("creating the fixture directory: %v", err)
	}

	at := time.Date(2026, 8, 11, 9, 14, 31, 0, time.UTC)
	const secret = "whsec_fixture_secret_do_not_use_in_production"

	body, err := json.Marshal(dispatch.BuildPayload(shadowEvent("TXN-2026-08-11-8842"), nil))
	mustNoErr(t, err, "marshalling the canonical payload")

	type vector struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Secret      string `json:"secret"`
		Body        string `json:"body"`
		Header      string `json:"signature_header"`
		NowUnix     int64  `json:"now_unix"`
		ToleranceS  int    `json:"tolerance_seconds"`
		ShouldPass  bool   `json:"should_pass"`
	}

	valid := dispatch.Sign(secret, body, at)
	vectors := []vector{
		{
			Name: "genuine", Description: "a real delivery, verified within the window",
			Secret: secret, Body: string(body), Header: valid,
			NowUnix: at.Unix(), ToleranceS: 300, ShouldPass: true,
		},
		{
			Name:        "rotation",
			Description: "two v1 signatures during a secret rotation; either matching is enough",
			Secret:      secret, Body: string(body),
			Header:  dispatch.SignWith([]string{"an-old-secret", secret}, body, at),
			NowUnix: at.Unix(), ToleranceS: 300, ShouldPass: true,
		},
		{
			Name:        "unknown_header_element",
			Description: "an element the library has never seen must be ignored, not rejected",
			Secret:      secret, Body: string(body), Header: valid + ",v2=future,scheme=whatever",
			NowUnix: at.Unix(), ToleranceS: 300, ShouldPass: true,
		},
		{
			Name:        "clock_drift_forward",
			Description: "a sender running two minutes fast is inside a symmetric window",
			Secret:      secret, Body: string(body), Header: valid,
			NowUnix: at.Add(-2 * time.Minute).Unix(), ToleranceS: 300, ShouldPass: true,
		},
		{
			Name:        "replayed",
			Description: "the digest is genuine; only the timestamp window stops this",
			Secret:      secret, Body: string(body), Header: valid,
			NowUnix: at.Add(time.Hour).Unix(), ToleranceS: 300, ShouldPass: false,
		},
		{
			Name:        "tampered_body",
			Description: "the amount was changed after signing",
			Secret:      secret, Body: `{"event_id":"sh_evt_1","amount_minor":1}`, Header: valid,
			NowUnix: at.Unix(), ToleranceS: 300, ShouldPass: false,
		},
		{
			Name:        "wrong_secret",
			Description: "signed with a secret this endpoint does not hold",
			Secret:      "a-different-secret", Body: string(body), Header: valid,
			NowUnix: at.Unix(), ToleranceS: 300, ShouldPass: false,
		},
		{
			Name:        "no_timestamp",
			Description: "a header with a signature but no timestamp is malformed",
			Secret:      secret, Body: string(body), Header: "v1=deadbeef",
			NowUnix: at.Unix(), ToleranceS: 300, ShouldPass: false,
		},
		{
			Name:        "no_signature",
			Description: "a header with a timestamp but no signature is malformed",
			Secret:      secret, Body: string(body), Header: "t=1786511671",
			NowUnix: at.Unix(), ToleranceS: 300, ShouldPass: false,
		},
		{
			Name:        "empty_header",
			Description: "no signature at all",
			Secret:      secret, Body: string(body), Header: "",
			NowUnix: at.Unix(), ToleranceS: 300, ShouldPass: false,
		},
	}

	out, err := json.MarshalIndent(map[string]any{
		"generated_by": "go test ./tests -run GenerateSDKFixtures",
		"note": "One source of truth for every client library. Three implementations agreeing with " +
			"each other but not with the server is the failure this file exists to prevent, so these " +
			"vectors are produced by the server's own signing code.",
		"vectors": vectors,
	}, "", "  ")
	mustNoErr(t, err, "marshalling the fixtures")

	path := filepath.Join(dir, "signature_vectors.json")
	mustNoErr(t, os.WriteFile(path, append(out, '\n'), 0o600), "writing the fixtures")

	// The Go library must pass its own fixtures, or the other two are
	// verifying against something nothing agrees with.
	for _, v := range vectors {
		err := dispatch.Verify(v.Secret, []byte(v.Body), v.Header,
			time.Unix(v.NowUnix, 0).UTC(), time.Duration(v.ToleranceS)*time.Second)
		if (err == nil) != v.ShouldPass {
			t.Errorf("vector %q: got %v, should_pass=%v", v.Name, err, v.ShouldPass)
		}
	}
}
