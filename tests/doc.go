// Package tests holds the whole test suite.
//
// Tests live here rather than beside each package, so they exercise only the
// exported API — the same surface a caller gets. The one thing that buys us
// that matters: an adapter cannot be tested through an internal shortcut that
// the receiver does not itself take.
package tests
