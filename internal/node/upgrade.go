package node

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"hopx/internal/wire"
)

func releaseMessage(r wire.Release) []byte {
	return []byte(r.Version + "\n" + runtime.GOOS + "-" + runtime.GOARCH + "\n" + strings.ToLower(r.SHA256) + "\n")
}

func stageUpgrade(ctx context.Context, client *http.Client, s Settings, r wire.Release) error {
	pub, e := os.ReadFile(s.PublicKey)
	if e != nil {
		return e
	}
	block, _ := pem.Decode(pub)
	if block == nil {
		return errors.New("invalid release public key")
	}
	parsed, e := x509.ParsePKIXPublicKey(block.Bytes)
	if e != nil {
		return e
	}
	key, ok := parsed.(ed25519.PublicKey)
	sig, e := base64.StdEncoding.DecodeString(r.Signature)
	if !ok || e != nil || !ed25519.Verify(key, releaseMessage(r), sig) {
		return errors.New("release signature invalid")
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

func confirmUpgrade(s Settings) error {
	if err := os.Remove(filepath.Join(s.Directory, "update.pending")); err != nil {
		return err
	}
	_ = os.Remove(filepath.Join(s.Directory, "update.attempted"))
	_ = os.Remove(filepath.Join(s.Directory, "update.error"))
	_ = os.Remove(filepath.Join(s.Directory, "update.check"))
	return nil
}

func (e *Engine) checkUpgradeRoutes(ctx context.Context, config wire.Config) error {
	for _, network := range []string{"tcp", "udp"} {
		for _, rule := range config.Rules {
			if !rule.Enabled || rule.TLSShared || (rule.Protocol != network && rule.Protocol != "both") {
				continue
			}
			e.mu.Lock()
			active := e.activeRules[rule.ID]
			e.mu.Unlock()
			if active == nil {
				return fmt.Errorf("规则 #%d 尚未加载", rule.ID)
			}
			if network == "udp" && !active.rule.UDPProbe && len(active.rule.Path) == 0 && len(active.rule.BackupPath) == 0 {
				continue
			}
			links := probeRuleLinks(ctx, active, wire.DiagnosticTask{ProbeSamples: 1})
			if rejectedByTargetPolicy(links, network) {
				continue
			}
			if !upgradeLinkHealthy(links, network) {
				return fmt.Errorf("规则 #%d 的 %s 代表性链路未通过检查", rule.ID, strings.ToUpper(network))
			}
			break
		}
	}
	return ctx.Err()
}

func rejectedByTargetPolicy(links []wire.LinkProbe, network string) bool {
	for _, link := range links {
		if link.Network != network {
			continue
		}
		for _, trace := range link.Traces {
			if len(trace.Steps) == 1 && trace.Steps[0].Phase == "target_policy" {
				return true
			}
		}
	}
	return false
}

func upgradeLinkHealthy(links []wire.LinkProbe, network string) bool {
	for _, link := range links {
		if link.Network != network {
			continue
		}
		for _, trace := range link.Traces {
			if len(trace.Steps) == 0 {
				continue
			}
			healthy := true
			for i, step := range trace.Steps {
				if step.Status != "ok" && !(i == len(trace.Steps)-1 && !link.MeasuresTarget && step.Status == "unknown") {
					healthy = false
					break
				}
			}
			if healthy {
				return true
			}
		}
	}
	return false
}
