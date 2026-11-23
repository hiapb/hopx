//go:build !webdist

package web

import (
	"io/fs"
	"os"
)

func assets() fs.FS {
	if _, err := os.Stat("web/dist/index.html"); err == nil {
		return os.DirFS("web/dist")
	}
	return fallback
}
