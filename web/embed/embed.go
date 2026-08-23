// Package embed carries the built dashboard into the binary.
//
// `web/embed/dist` is committed, deliberately. The alternative — building the
// dashboard as part of the Go build — puts a Node toolchain in the path of
// anybody who wants to compile the server, including a customer's build
// pipeline and a security team reproducing a release. `go build` needs Go and
// nothing else, and the cost is remembering `make web` after changing
// anything under web/src. CI enforces that.
package embed

import (
	"embed"
	"io/fs"
)

//go:embed dist
var files embed.FS

// FS returns the dashboard's files, rooted at dist.
func FS() fs.FS {
	sub, err := fs.Sub(files, "dist")
	if err != nil {
		// Unreachable: the directory is embedded at compile time, so a
		// failure here means the binary was built wrong.
		panic("statushub: dashboard assets are missing from the binary: " + err.Error())
	}
	return sub
}
