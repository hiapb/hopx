package panel

import (
	"context"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"hopx/internal/wire"
)

func TestRolloutPausesAfterRollbackAcrossPanelRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "panel.db")
	server, err := Open(Options{Database: path})
	if err != nil {
		t.Fatal(err)
	}
	release := &wire.Release{Version: "new"}
	config := wire.Config{Revision: "target"}
	first := wire.Device{ID: 1, Version: "old"}
	second := wire.Device{ID: 2, Version: "old"}
	if server.nodeRelease(first, release, config, false) == nil || server.nodeRelease(second, release, config, false) != nil {
		t.Fatal("expected exactly one node to receive the release")
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	server, err = Open(Options{Database: path})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if server.nodeRelease(second, release, config, false) != nil {
		t.Fatal("panel restart bypassed the active upgrade")
	}
	first.UpdateError = "new: previous binary restored"
	if server.nodeRelease(first, release, config, false) != nil || server.rollout.Phase != "paused" ||
		server.nodeRelease(second, release, config, false) != nil {
		t.Fatalf("rollback must pause the rollout: %+v", server.rollout)
	}
	updated := &wire.Release{Version: "fixed"}
	if server.nodeRelease(first, updated, config, false) == nil {
		t.Fatal("the previously failed node should receive the corrected release")
	}
}

func TestRolloutWaitsForCandidateConfiguration(t *testing.T) {
	release := wire.Release{Version: "new"}
	state := nodeRollout{Version: "new", Node: 1, Phase: "updating", Until: 500}
	first := wire.Device{ID: 1, Version: "new", Revision: "old"}
	state, _ = rolloutStep(state, first, release, "target", false, 100)
	if state.Phase != "checking" {
		t.Fatalf("stale configuration passed: %+v", state)
	}
	first.Revision = "target"
	state, _ = rolloutStep(state, first, release, "target", true, 101)
	if state.Phase != "checking" {
		t.Fatalf("unconfirmed candidate passed: %+v", state)
	}
	state, _ = rolloutStep(state, first, release, "target", false, 102)
	if state.Phase != "ready" {
		t.Fatalf("healthy candidate did not unlock the rollout: %+v", state)
	}
}

func TestManualDiagnosticReplacesBackgroundProbe(t *testing.T) {
	server := &Server{diagnostics: make(map[int64]probeCheck)}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	background := make(chan int, 1)
	manual := make(chan int, 1)
	go func() {
		_, code := server.waitNodeCheck(ctx, 1, wire.DiagnosticTask{ID: "periodic"}, true)
		background <- code
	}()
	waitForTask := func(id string) {
		t.Helper()
		for ctx.Err() == nil {
			if task := server.pollDiagnostic(1, nil); task != nil && task.ID == id {
				return
			}
			time.Sleep(time.Millisecond)
		}
		t.Fatalf("task %s was not dispatched", id)
	}
	waitForTask("periodic")
	go func() {
		_, code := server.waitDiagnostic(ctx, 1, wire.DiagnosticTask{ID: "manual"})
		manual <- code
	}()
	waitForTask("manual")
	server.pollDiagnostic(1, &wire.DiagnosticResult{ID: "periodic"})
	waitForTask("manual")
	server.pollDiagnostic(1, &wire.DiagnosticResult{ID: "manual"})
	if got := <-manual; got != http.StatusOK {
		t.Fatalf("manual probe status = %d", got)
	}
	if got := <-background; got != http.StatusTooManyRequests {
		t.Fatalf("displaced background probe status = %d", got)
	}
}
