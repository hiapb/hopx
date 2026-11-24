package node

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"hopx/internal/release"
	"hopx/internal/wire"
)

func stageUpgrade(ctx context.Context, client *http.Client, s Settings, r wire.Release) error {
	pub, e := os.ReadFile(s.PublicKey)
	if e != nil {
		return e
	}
	if e = release.Verify(pub, r.Version, runtime.GOOS+"-"+runtime.GOARCH, r.SHA256, r.Signature); e != nil {
		return e
	}
	if r.Version == "" || strings.ContainsAny(r.Version, "/\\\r\n") {
		return errors.New("invalid release version")
	}
	base, e := url.Parse(strings.TrimRight(s.Panel, "/") + "/")
	if e != nil {
		return e
	}
	piece, e := url.Parse(r.URL)
	if e != nil {
		return e
	}
	target := base.ResolveReference(piece)
	if target.Host != base.Host || target.Scheme != base.Scheme {
		return errors.New("release URL must use the panel origin")
	}
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if e != nil {
		return e
	}
	resp, e := client.Do(req)
	if e != nil {
		return e
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("release download returned %d", resp.StatusCode)
	}
	staged, e := os.CreateTemp(filepath.Dir(s.Executable), ".hopx-upgrade-*")
	if e != nil {
		return e
	}
	defer os.Remove(staged.Name())
	hasher := sha256.New()
	_, e = io.Copy(io.MultiWriter(staged, hasher), io.LimitReader(resp.Body, 128<<20))
	if e == nil && !strings.EqualFold(hex.EncodeToString(hasher.Sum(nil)), r.SHA256) {
		e = errors.New("release hash mismatch")
	}
	if e == nil {
		e = staged.Chmod(0755)
	}
	if e == nil {
		e = staged.Sync()
	}
	closeErr := staged.Close()
	if e == nil {
		e = closeErr
	}
	if e != nil {
		return e
	}
	if e = os.Rename(staged.Name(), s.Executable+".candidate"); e != nil {
		return e
	}
	return atomicFile(filepath.Join(s.Directory, "update.pending"), []byte(r.Version+"\n"), 0600)
}

func pendingUpgrade(s Settings) (bool, error) {
	if s.Executable == "" {
		return false, nil
	}
	pending := localMessage(s.Directory, "update.pending")
	if pending == "" {
		return false, nil
	}
	if pending != s.Version {
		if _, err := os.Stat(filepath.Join(s.Directory, "update.attempted")); err == nil {
			return false, errors.New("candidate binary reported a different version")
		}
		return false, nil
	}
	return true, nil
}

func recordUpgradeFailure(dir string, err error) {
	if errors.Is(err, ErrRestart) || localMessage(dir, "update.pending") == "" {
		return
	}
	if _, statErr := os.Stat(filepath.Join(dir, "update.attempted")); statErr != nil {
		return
	}
	message := strings.Join(strings.Fields(err.Error()), " ")
	_ = atomicFile(filepath.Join(dir, "update.check"), []byte(message+"\n"), 0600)
}

func confirmUpgrade(s Settings) error {
	if err := os.Remove(filepath.Join(s.Directory, "update.pending")); err != nil {
		return err
	}
	_ = os.Remove(filepath.Join(s.Directory, "update.attempted"))
	_ = os.Remove(filepath.Join(s.Directory, "update.error"))
	_ = os.Remove(filepath.Join(s.Directory, "update.check"))
	return nil
}
