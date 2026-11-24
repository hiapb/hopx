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
	"testing"
	"time"

	"hopx/internal/wire"
)

func TestUpgradeConfirmsWithUnreachableForwardTarget(t *testing.T) {
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
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
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
