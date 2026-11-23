//go:build webdist

package web

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var distribution embed.FS

func assets() fs.FS {
	sub, err := fs.Sub(distribution, "dist")
	if err != nil {
		panic(err)
	}
	return sub
}
