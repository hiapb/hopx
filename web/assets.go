package web

import (
	"embed"
	"io/fs"
)

//go:embed index.html
var fallback embed.FS

func Assets() fs.FS { return assets() }
