// Package jsonpath evaluates a deliberately small subset of JSONPath against
// decoded JSON.
//
// The subset is the point. A declarative adapter is data uploaded by a
// customer (§4.4), and the moment a customer-supplied expression can
// backtrack, recurse or filter, it can also be made to burn CPU on the
// normalisation path — a denial of service delivered through a configuration
// upload (§10). What is supported is object member access, array indexing
// including negative indices, and nothing else. No wildcards, no descent, no
// filters, no scripting.
//
// Everything below has an explicit ceiling, because an expression that a
// customer can make arbitrarily long is an expression that must be bounded
// somewhere.
package jsonpath

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Limits on what an expression may be and do.
const (
	// MaxDepth is the number of path steps. Ten is deeper than any real
	// provider payload; Interswitch's is the deepest we have seen at five.
	MaxDepth = 10

	// MaxPathLength bounds the expression text itself, so parsing cost is
	// bounded before evaluation cost is considered.
	MaxPathLength = 256
)

var (
	ErrEmptyPath  = errors.New("path is empty")
	ErrTooDeep    = errors.New("path exceeds the maximum depth")
	ErrTooLong    = errors.New("path exceeds the maximum length")
	ErrMalformed  = errors.New("path is malformed")
	ErrUnbracket  = errors.New("path has an unclosed bracket")
	ErrNotFound   = errors.New("path does not exist in the document")
	ErrWrongShape = errors.New("path traverses a value of the wrong kind")
)

// Path is a compiled expression. Compiling once and evaluating many times
// matters: an adapter config is parsed at load and then used on every event
// that endpoint receives.
type Path struct {
	raw   string
	steps []step
}

type step struct {
	key     string
	index   int
	isIndex bool
}

// String returns the original expression.
func (p Path) String() string { return p.raw }

// Depth returns how many steps the path takes.
func (p Path) Depth() int { return len(p.steps) }

// Compile parses an expression such as `$.data.customer.email` or
// `$.events[0].status` or `$.items[-1].amount`.
//
// A leading `$.` or `$` is optional, because half the world writes paths with
// it and half without, and rejecting one spelling only produces a confusing
// error in an adapter editor.
func Compile(expr string) (Path, error) {
	raw := strings.TrimSpace(expr)
	if raw == "" {
		return Path{}, ErrEmptyPath
	}
	if len(raw) > MaxPathLength {
		return Path{}, fmt.Errorf("%w: %d characters", ErrTooLong, len(raw))
	}

	s := raw
	s = strings.TrimPrefix(s, "$")
	s = strings.TrimPrefix(s, ".")
	if s == "" {
		// "$" alone is the whole document, which is a legitimate thing for a
		// mapping to want: some providers put the payload at the top level.
		return Path{raw: raw}, nil
	}

	var steps []step
	for s != "" {
		if len(steps) > MaxDepth {
			return Path{}, fmt.Errorf("%w: more than %d steps", ErrTooDeep, MaxDepth)
		}
		switch s[0] {
		case '[':
			end := strings.IndexByte(s, ']')
			if end < 0 {
				return Path{}, fmt.Errorf("%w: %q", ErrUnbracket, raw)
			}
			inner := s[1:end]
			s = s[end+1:]
			s = strings.TrimPrefix(s, ".")

			// Bracketed member access, `['odd.key']`, is how a path reaches a
			// field whose name contains a dot — which providers do produce.
			if len(inner) >= 2 && (inner[0] == '\'' || inner[0] == '"') && inner[len(inner)-1] == inner[0] {
				steps = append(steps, step{key: inner[1 : len(inner)-1]})
				continue
			}
			n, err := strconv.Atoi(inner)
			if err != nil {
				return Path{}, fmt.Errorf("%w: %q is not an array index", ErrMalformed, inner)
			}
			steps = append(steps, step{index: n, isIndex: true})
		default:
			var name string
			if i := strings.IndexAny(s, ".["); i >= 0 {
				name, s = s[:i], s[i:]
				s = strings.TrimPrefix(s, ".")
			} else {
				name, s = s, ""
			}
			if name == "" {
				return Path{}, fmt.Errorf("%w: empty step in %q", ErrMalformed, raw)
			}
			if strings.ContainsAny(name, "*?") {
				return Path{}, fmt.Errorf("%w: wildcards are not supported (%q)", ErrMalformed, raw)
			}
			steps = append(steps, step{key: name})
		}
	}
	if len(steps) > MaxDepth {
		return Path{}, fmt.Errorf("%w: more than %d steps", ErrTooDeep, MaxDepth)
	}
	return Path{raw: raw, steps: steps}, nil
}

// MustCompile is for paths written in this repository, where a bad path is a
// bug rather than bad input. It is never reachable from a customer upload.
func MustCompile(expr string) Path {
	p, err := Compile(expr)
	if err != nil {
		panic("jsonpath: " + err.Error())
	}
	return p
}

// Eval walks the path. A missing step returns ErrNotFound rather than nil, so
// "the provider stopped sending this field" is distinguishable from "the
// provider sent null" — the first is a mapping problem and the second is
// information.
func (p Path) Eval(doc any) (any, error) {
	cur := doc
	for i, st := range p.steps {
		switch {
		case st.isIndex:
			arr, ok := cur.([]any)
			if !ok {
				return nil, fmt.Errorf("%w: step %d of %s expected an array", ErrWrongShape, i+1, p.raw)
			}
			idx := st.index
			if idx < 0 {
				idx += len(arr)
			}
			if idx < 0 || idx >= len(arr) {
				return nil, fmt.Errorf("%w: index %d of %s is out of range", ErrNotFound, st.index, p.raw)
			}
			cur = arr[idx]
		default:
			obj, ok := cur.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("%w: step %d of %s expected an object", ErrWrongShape, i+1, p.raw)
			}
			v, ok := obj[st.key]
			if !ok {
				return nil, fmt.Errorf("%w: %q in %s", ErrNotFound, st.key, p.raw)
			}
			cur = v
		}
	}
	return cur, nil
}

// Keys returns the object member names the path visits, used by the
// normaliser to work out which fields a mapping has claimed so the rest can
// go to provider_extra without being lost (§3.2 B4).
func (p Path) Keys() []string {
	out := make([]string, 0, len(p.steps))
	for _, s := range p.steps {
		if !s.isIndex {
			out = append(out, s.key)
		}
	}
	return out
}

// Root returns the first member name in the path, or "" for a path that
// starts with an index or is the whole document.
func (p Path) Root() string {
	if len(p.steps) == 0 || p.steps[0].isIndex {
		return ""
	}
	return p.steps[0].key
}
