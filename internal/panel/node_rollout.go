package panel

import (
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"hopx/internal/wire"
)

type nodeRollout struct {
	Version string  `json:"version"`
	Node    int64   `json:"node,omitempty"`
	Name    string  `json:"name,omitempty"`
	Phase   string  `json:"phase"`
	Reason  string  `json:"reason,omitempty"`
	Until   int64   `json:"until,omitempty"`
	Skipped []int64 `json:"skipped,omitempty"`
}

func (s *Server) loadRollout() error {
	var raw string
	err := s.db.QueryRow("SELECT state FROM node_rollout WHERE id=1").Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(raw), &s.rollout)
}

// The caller holds rolloutMu. A failed persistence operation must leave the gate closed.
func (s *Server) storeRollout(next nodeRollout) error {
	raw, err := json.Marshal(next)
	if err == nil {
		_, err = s.db.Exec("INSERT INTO node_rollout(id,state) VALUES(1,?) ON CONFLICT(id) DO UPDATE SET state=excluded.state", string(raw))
	}
	if err == nil {
		s.rollout = next
	}
	return err
}

func (s *Server) nodeRelease(d wire.Device, release *wire.Release, config wire.Config, pending bool) *wire.Release {
	if release == nil {
		return nil
	}
	s.rolloutMu.Lock()
	defer s.rolloutMu.Unlock()
	next, offered := rolloutStep(s.rollout, d, *release, config.Revision, pending, time.Now().Unix())
	if next.Version != s.rollout.Version || next.Node != s.rollout.Node || next.Phase != s.rollout.Phase {
		if err := s.storeRollout(next); err != nil {
			slog.Error("persist node rollout", "error", err)
			return nil
		}
	}
	if offered {
		return release
	}
	return nil
}

func rolloutStep(state nodeRollout, d wire.Device, release wire.Release, revision string, pending bool, now int64) (nodeRollout, bool) {
	if state.Phase == "updating" || state.Phase == "checking" {
		switch {
		case state.Node == d.ID && strings.HasPrefix(d.UpdateError, state.Version+":"):
			state.Phase, state.Reason = "paused", d.UpdateError
		case state.Until <= now:
			state.Phase, state.Reason = "paused", "节点升级超时，未收到健康检查结果"
		case state.Node != d.ID:
			return state, false
		case d.Version == state.Version:
			state.Phase = "checking"
			if !pending && revision != "" && revision == d.Revision && d.ApplyError == "" && d.RelayModeError == "" && d.NativeUDPError == "" {
				state.Phase, state.Until = "ready", 0
			}
			return state, false
		case state.Phase == "checking" && d.Version != state.Version:
			state.Phase, state.Reason = "paused", "节点已回到上一版本"
		default:
			return state, state.Version == release.Version && !pending
		}
		return state, false
	}
	if state.Version != release.Version {
		state = nodeRollout{Version: release.Version, Phase: "ready"}
	}
	if state.Phase == "paused" || pending || d.Version == release.Version || slices.Contains(state.Skipped, d.ID) ||
		strings.HasPrefix(d.UpdateError, release.Version+":") || revision == "" {
		return state, false
	}
	state.Node, state.Name, state.Phase, state.Until = d.ID, d.Name, "updating", now+180
	return state, true
}

func (s *Server) nodeRolloutStatus(w http.ResponseWriter, r *http.Request, _ User) {
	s.rolloutMu.Lock()
	state := s.rollout
	if (state.Phase == "updating" || state.Phase == "checking") && state.Until <= time.Now().Unix() {
		state.Phase, state.Reason = "paused", "节点升级超时，未收到健康检查结果"
		if err := s.storeRollout(state); err != nil {
			s.rolloutMu.Unlock()
			dbFailure(w, err)
			return
		}
	}
	s.rolloutMu.Unlock()
	respond(w, 200, state)
}

func (s *Server) resumeNodeRollout(w http.ResponseWriter, r *http.Request, _ User) {
	s.rolloutMu.Lock()
	defer s.rolloutMu.Unlock()
	if s.rollout.Phase != "paused" {
		fail(w, 409, "当前没有已暂停的节点发布")
		return
	}
	next := s.rollout
	next.Skipped = append(slices.Clone(next.Skipped), next.Node)
	next.Node, next.Name, next.Phase, next.Reason, next.Until = 0, "", "ready", "", 0
	if err := s.storeRollout(next); err != nil {
		dbFailure(w, err)
		return
	}
	respond(w, 200, next)
}
