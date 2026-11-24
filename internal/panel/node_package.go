package panel

import (
	"archive/zip"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

func (s *Server) nodePackage(w http.ResponseWriter, r *http.Request, u User) {
	arch := r.PathValue("arch")
	if s.releaseDir == "" || (arch != "arm64" && arch != "amd64") || (!u.Admin && !u.AllowDevice && s.setting("personalTunnels", "false") != "true") {
		fail(w, 404, "离线节点发行包不可用")
		return
	}
	bootstrap := "install-" + arch + ".txt"
	raw, err := os.ReadFile(filepath.Join(s.releaseDir, bootstrap))
	if err != nil {
		fail(w, 404, "未找到已发布的节点版本")
		return
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 4 {
		fail(w, 503, "节点发行信息无效")
		return
	}
	artifact := filepath.Join(lines[0], "node-"+arch)
	if !filepath.IsLocal(artifact) || "/releases/"+artifact != lines[1] {
		fail(w, 503, "节点发行信息无效")
		return
	}
	files := []string{"node-install.sh", "node-runner.sh", "release.pem", artifact}
	for _, name := range []string{"verify-" + arch, "haproxy-source.tar.gz"} {
		optional := filepath.Join(lines[0], name)
		if info, err := os.Stat(filepath.Join(s.releaseDir, optional)); err == nil && info.Mode().IsRegular() {
			files = append(files, optional)
		}
	}
	opened := make([]*os.File, 0, len(files))
	defer func() {
		for _, file := range opened {
			_ = file.Close()
		}
	}()
	for _, name := range files {
		file, err := os.Open(filepath.Join(s.releaseDir, name))
		if err != nil {
			fail(w, 503, "发行包缺少文件")
			return
		}
		opened = append(opened, file)
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="hopx-node-linux-`+arch+`.zip"`)
	archive := zip.NewWriter(w)
	defer archive.Close()
	for i, name := range files {
		entry, err := archive.Create(name)
		if err != nil {
			return
		}
		if _, err = io.Copy(entry, opened[i]); err != nil {
			return
		}
	}
	entry, err := archive.Create(bootstrap)
	if err == nil {
		_, _ = entry.Write(raw)
	}
}
