// Package openapi generates the OpenAPI 3.1 document from the router.
//
// §7.3 promises a specification at docs/openapi.yaml from which the client
// libraries are generated. The obvious way to produce one is to write it by
// hand beside the code — and a hand-written specification drifts, silently,
// starting the first time somebody adds a route in a hurry. A drifted
// specification is worse than none: generated clients call endpoints that do
// not exist and omit ones that do, and the customer trusts it because it
// looks authoritative.
//
// So the route table is the source of truth. Paths, methods and required
// roles come from the same declarations the server actually serves, and CI
// fails when the committed document and the router disagree. What is still
// written by hand is prose — descriptions and schemas — because nothing can
// generate an explanation of why an unmapped status becomes `unknown`.
package openapi

import (
	"fmt"
	"sort"
	"strings"
)

// Route is one endpoint, as the router declares it.
type Route struct {
	Method string
	Path   string

	// Role is the minimum role, or "" for an unauthenticated route.
	Role string

	Summary     string
	Description string

	// Idempotent marks a write that accepts an Idempotency-Key.
	Idempotent bool

	// RequestExample and ResponseExample are rendered into the document.
	// Examples matter more than schemas for an API somebody integrates
	// against once: the schema says a field is a string, the example says
	// what a real one looks like.
	RequestExample  string
	ResponseExample string

	// Params are query or path parameters.
	Params []Param
}

// Param is one parameter.
type Param struct {
	Name        string
	In          string // query | path
	Required    bool
	Schema      string // string | integer | boolean
	Description string
}

// Document is the whole specification.
type Document struct {
	Version string
	Routes  []Route
}

// Generate renders the document as YAML.
//
// Written directly rather than through a YAML library: the output has to be
// stable byte-for-byte across runs, because CI compares it against the
// committed copy. A marshaller that reorders a map turns that gate into one
// that fails at random and is therefore deleted.
func (d Document) Generate() string {
	var b strings.Builder

	routes := append([]Route(nil), d.Routes...)
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].Path != routes[j].Path {
			return routes[i].Path < routes[j].Path
		}
		return routes[i].Method < routes[j].Method
	})

	b.WriteString(header(d.Version))

	// Grouped by path, because OpenAPI nests methods under paths and a
	// generator that emits the same path twice produces a document most
	// tooling silently truncates.
	b.WriteString("paths:\n")
	var currentPath string
	for _, r := range routes {
		if r.Path != currentPath {
			currentPath = r.Path
			fmt.Fprintf(&b, "  %s:\n", openAPIPath(r.Path))
			writePathParams(&b, r.Path)
		}
		writeOperation(&b, r)
	}

	b.WriteString(components())
	return b.String()
}

// openAPIPath converts Go 1.22 wildcards to OpenAPI's braces. They are
// already the same shape, which is a small mercy.
func openAPIPath(p string) string { return p }

func writePathParams(b *strings.Builder, path string) {
	names := pathWildcards(path)
	if len(names) == 0 {
		return
	}
	b.WriteString("    parameters:\n")
	for _, n := range names {
		fmt.Fprintf(b, "      - name: %s\n        in: path\n        required: true\n"+
			"        schema: { type: string }\n", n)
	}
}

// pathWildcards extracts {name} segments.
func pathWildcards(path string) []string {
	var out []string
	for _, seg := range strings.Split(path, "/") {
		if strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}") {
			out = append(out, strings.Trim(seg, "{}"))
		}
	}
	return out
}

func writeOperation(b *strings.Builder, r Route) {
	fmt.Fprintf(b, "    %s:\n", strings.ToLower(r.Method))
	fmt.Fprintf(b, "      summary: %s\n", quote(r.Summary))
	if r.Description != "" {
		fmt.Fprintf(b, "      description: |\n%s\n", indent(r.Description, 8))
	}
	fmt.Fprintf(b, "      operationId: %s\n", operationID(r))

	if r.Role == "" {
		// Stated explicitly rather than by omission. A reader should not have
		// to infer that a route is unauthenticated from a missing key.
		b.WriteString("      security: []\n")
	} else {
		b.WriteString("      security:\n        - apiKey: []\n")
		fmt.Fprintf(b, "      x-statushub-minimum-role: %s\n", r.Role)
	}

	var params []Param
	if r.Idempotent {
		params = append(params, Param{
			Name: "Idempotency-Key", In: "header", Schema: "string",
			Description: "Optional. A retry carrying the same key returns the original result rather " +
				"than creating a second resource. Reusing a key with a different body is a 409.",
		})
	}
	params = append(params, r.Params...)

	if len(params) > 0 {
		b.WriteString("      parameters:\n")
		for _, p := range params {
			fmt.Fprintf(b, "        - name: %s\n          in: %s\n", p.Name, p.In)
			if p.Required {
				b.WriteString("          required: true\n")
			}
			schema := p.Schema
			if schema == "" {
				schema = "string"
			}
			fmt.Fprintf(b, "          schema: { type: %s }\n", schema)
			if p.Description != "" {
				fmt.Fprintf(b, "          description: %s\n", quote(p.Description))
			}
		}
	}

	if r.RequestExample != "" {
		b.WriteString("      requestBody:\n        required: true\n        content:\n" +
			"          application/json:\n            example:\n")
		b.WriteString(indent(r.RequestExample, 14) + "\n")
	}

	b.WriteString("      responses:\n")
	writeSuccessResponse(b, r)

	if r.Role != "" {
		// Every authenticated route can return these, and saying so once per
		// route beats a note somewhere the generated client will not read.
		b.WriteString("        '401':\n          $ref: '#/components/responses/Unauthorised'\n")
		b.WriteString("        '403':\n          $ref: '#/components/responses/Forbidden'\n")
		b.WriteString("        '404':\n          $ref: '#/components/responses/NotFound'\n")
	}
}

func writeSuccessResponse(b *strings.Builder, r Route) {
	code := "200"
	switch {
	case r.Method == "POST" && strings.Contains(r.Summary, "reate"):
		code = "201"
	case r.Method == "DELETE":
		code = "204"
	case r.Method == "POST" && (strings.Contains(r.Summary, "eplay") || strings.Contains(r.Summary, "etry")):
		code = "202"
	}

	fmt.Fprintf(b, "        '%s':\n          description: %s\n", code, quote(successText(code)))
	if code == "204" {
		return
	}
	b.WriteString("          content:\n            application/json:\n")
	if r.ResponseExample != "" {
		b.WriteString("              example:\n")
		b.WriteString(indent(r.ResponseExample, 16) + "\n")
		return
	}
	b.WriteString("              schema: { type: object }\n")
}

func successText(code string) string {
	switch code {
	case "201":
		return "Created."
	case "202":
		return "Accepted and queued."
	case "204":
		return "Deleted."
	default:
		return "Success."
	}
}

// operationID is derived deterministically, so a generated client's method
// names do not change when a route is added above another.
func operationID(r Route) string {
	parts := []string{strings.ToLower(r.Method)}
	for _, seg := range strings.Split(strings.TrimPrefix(r.Path, "/"), "/") {
		if seg == "" || seg == "v1" {
			continue
		}
		seg = strings.Trim(seg, "{}")
		seg = strings.ReplaceAll(seg, "-", " ")
		parts = append(parts, strings.ReplaceAll(strings.Title(seg), " ", "")) //nolint:staticcheck // ASCII segment names only
	}
	return strings.Join(parts, "")
}

func quote(s string) string {
	if s == "" {
		return `""`
	}
	return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
}

func indent(s string, n int) string {
	pad := strings.Repeat(" ", n)
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, l := range lines {
		if l == "" {
			continue
		}
		lines[i] = pad + l
	}
	return strings.Join(lines, "\n")
}
