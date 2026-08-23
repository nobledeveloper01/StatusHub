// Package embed carries the dashboard into the binary.
//
// The files are plain HTML, CSS and JavaScript with no build step and no
// dependencies. That is a deliberate trade: a bundler would buy component
// reuse and cost every operator a Node toolchain in their build, every
// security team a dependency tree to review, and this repository a
// lockfile-shaped supply-chain surface. The dashboard is eight screens of
// tables and forms, which is not enough to justify any of that.
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
