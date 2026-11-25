package node

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"hopx/internal/wire"
)

func TestUpgradeConfirmsWithUnreachableForwardTarget(t *testing.T) {
	t.Run("fresh config", func(t *testing.T) { testUpgradeConfirmation(t, false, false) })
	t.Run("cached config with stale apply error", func(t *testing.T) { testUpgradeConfirmation(t, true, false) })
	t.Run("current config replaces a cached listener conflict", func(t *testing.T) { testUpgradeConfirmation(t, true, true) })
}

func TestCandidateRecordsStartupFailure(t *testing.T) {
	stateDir := t.TempDir()
	if err := toFile(filepath.Join(stateDir, "identity.json"), localState{Identity: wire.Identity{ID: 1, Token: "test"}}); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		"update.pending": "candidate\n", "update.attempted": "", "active-routes.json": "{",
	} {
		if err := os.WriteFile(filepath.Join(stateDir, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	err := Run(t.Context(), Settings{
		Panel: "http://127.0.0.1:0", Directory: stateDir, Executable: filepath.Join(stateDir, "hopx-node"),
		Version: "candidate", MaxListeners: 8, MaxConnections: 16, Period: time.Second,
	})
	if err == nil || !strings.Contains(err.Error(), "unexpected end of JSON input") {
		t.Fatalf("want configuration load failure, got %v", err)
	}
	if got := localMessage(stateDir, "update.check"); got != err.Error() {
		t.Fatalf("rollback reason = %q, want %q", got, err)
	}
}

func testUpgradeConfirmation(t *testing.T, cached, conflict bool) {
	t.Helper()
	stateDir := t.TempDir()
	if err := toFile(filepath.Join(stateDir, "identity.json"), localState{Identity: wire.Identity{ID: 1, Token: "test"}}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "update.pending"), []byte("candidate\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "update.attempted"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	_, portText, _ := net.SplitHostPort(freeTCP(t))
	port, _ := strconv.Atoi(portText)
	config := wire.Config{Revision: "test-config", Rules: []wire.Forward{{
		Rule: wire.Rule{ID: 1, Enabled: true, Protocol: "tcp", Port: port, Targets: []string{"127.0.0.1:0"}},
	}}}
	if cached {
		previous := config
		if conflict {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			previous.Revision = "obsolete-config"
			previous.Rules = append([]wire.Forward(nil), config.Rules...)
			previous.Rules[0].Port = listener.Addr().(*net.TCPAddr).Port
		}
		if err := toFile(filepath.Join(stateDir, "active-routes.json"), previous); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(stateDir, "apply.error"), []byte("previous config failed\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	confirmed := make(chan wire.Heartbeat, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/node/sync", func(w http.ResponseWriter, r *http.Request) {
		var heartbeat wire.Heartbeat
		if err := json.NewDecoder(r.Body).Decode(&heartbeat); err != nil {
			http.Error(w, "invalid heartbeat", http.StatusBadRequest)
			return
		}
		var reply wire.Sync
		if heartbeat.Revision != config.Revision {
			reply.Config = &config
		}
		if !heartbeat.UpgradePending {
			confirmed <- heartbeat
			cancel()
		}
		_ = json.NewEncoder(w).Encode(reply)
	})
	panel := httptest.NewServer(mux)
	defer panel.Close()
	if err := Run(ctx, Settings{
		Panel: panel.URL, Directory: stateDir, Executable: filepath.Join(stateDir, "hopx-node"),
		Version: "candidate", Bind: "127.0.0.1", MaxListeners: 8, MaxConnections: 16, Period: 10 * time.Millisecond,
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case heartbeat := <-confirmed:
		if heartbeat.Revision != config.Revision || heartbeat.ApplyError != "" || heartbeat.Metrics.Listeners != 1 {
			t.Fatalf("candidate confirmed without loading its listener: %+v", heartbeat)
		}
	default:
		t.Fatal("candidate never confirmed its upgrade")
	}
}
