package panel

import (
	"net/http"
	"os"
	"regexp"
	"strings"
)

var releaseVersion = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

func releaseFileAllowed(name string) bool {
	switch name {
	case "node-install.sh", "node-runner.sh", "release.pem", "install-amd64.txt", "install-arm64.txt", "manifest.json":
		return true
	}
	version, file, ok := strings.Cut(name, "/")
	if !ok || strings.HasPrefix(version, ".") || !releaseVersion.MatchString(version) {
		return false
	}
	switch file {
	case "node-amd64", "node-arm64", "verify-amd64", "verify-arm64", "install-amd64.txt", "install-arm64.txt":
		return true
	default:
		return false
	}
}

func (s *Server) releaseFile(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("file")
	if !releaseFileAllowed(name) {
		http.NotFound(w, r)
		return
	}
	if !strings.Contains(name, "/") {
		w.Header().Set("Cache-Control", "no-store")
	}
	root, err := os.OpenRoot(s.releaseDir)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer root.Close()
	if directory, _, nested := strings.Cut(name, "/"); nested {
		info, err := root.Lstat(directory)
		if err != nil || !info.IsDir() {
			http.NotFound(w, r)
			return
		}
	}
	info, err := root.Lstat(name)
	if err != nil || !info.Mode().IsRegular() {
		http.NotFound(w, r)
		return
	}
	file, err := root.Open(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer file.Close()
	info, err = file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		http.NotFound(w, r)
		return
	}
	http.ServeContent(w, r, info.Name(), info.ModTime(), file)
}
