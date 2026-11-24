package panel

import (
	"crypto/subtle"
	"math"
	"net/http"
	"strconv"
	"time"

	"hopx/internal/wire"
)

const bandwidthFreshness = 3 * time.Second

func (s *Server) clearNodeBandwidth(id int64) {
	if state := s.nodeBandwidth[id]; state != nil {
		*state = nodeBandwidth{viewers: state.viewers}
	}
}

type nodeBandwidth struct {
	viewers    int
	credential string
	at         time.Time
	metrics    wire.Bandwidth
}

type bandwidthEvent struct {
	ID        int64          `json:"id"`
	Bandwidth wire.Bandwidth `json:"bandwidth"`
}

// s.mu protects subscriptions and the samples shared by all status streams.
func (s *Server) changeBandwidthViewers(added, removed []int64) {
	if len(added)+len(removed) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, id := range removed {
		if state := s.nodeBandwidth[id]; state != nil {
			state.viewers--
			if state.viewers == 0 {
				delete(s.nodeBandwidth, id)
			}
		}
	}
	for _, id := range added {
		if s.nodeBandwidth == nil {
			s.nodeBandwidth = make(map[int64]*nodeBandwidth)
		}
		state := s.nodeBandwidth[id]
		if state == nil {
			state = &nodeBandwidth{}
			s.nodeBandwidth[id] = state
		}
		state.viewers++
	}
}

func (s *Server) updateNodeBandwidth(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.Header.Get("X-Node-ID"), 10, 64)
	token := bearer(r)
	if id <= 0 || token == "" || len(token) > 128 {
		fail(w, http.StatusUnauthorized, "节点凭据无效")
		return
	}
	rateKey := digest(token)
	now := time.Now()
	s.mu.RLock()
	status := s.bandwidthUploadStatus(id, rateKey, now)
	s.mu.RUnlock()
	if status != http.StatusNoContent {
		w.WriteHeader(status)
		return
	}
	var metrics wire.Bandwidth
	if !decodeLimit(w, r, &metrics, 512) {
		return
	}
	if !metrics.HasTotals || metrics.InBytes < 0 || metrics.OutBytes < 0 ||
		metrics.InMbps < 0 || metrics.OutMbps < 0 || math.IsInf(metrics.InMbps+metrics.OutMbps, 0) {
		fail(w, http.StatusBadRequest, "网卡流量数据无效")
		return
	}
	now = time.Now()
	s.mu.Lock()
	status = s.bandwidthUploadStatus(id, rateKey, now)
	if status == http.StatusNoContent {
		state := s.nodeBandwidth[id]
		state.metrics, state.at = metrics, now
	}
	s.mu.Unlock()
	w.WriteHeader(status)
}

// The caller holds s.mu. Recheck after reading the body in case access changed.
func (s *Server) bandwidthUploadStatus(id int64, credential string, now time.Time) int {
	state := s.nodeBandwidth[id]
	node, present := s.devices[id]
	switch {
	case !present || state == nil || now.Sub(node.LastSeen) >= 30*time.Second ||
		subtle.ConstantTimeCompare([]byte(state.credential), []byte(credential)) != 1:
		return http.StatusUnauthorized
	case now.Sub(state.at) < 700*time.Millisecond:
		return http.StatusTooManyRequests
	default:
		return http.StatusNoContent
	}
}

func (s *Server) bandwidthUpdates(previous map[int64]wire.Device) []bandwidthEvent {
	var changes []bandwidthEvent
	now := time.Now()
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.nodeBandwidth) == 0 {
		return nil
	}
	for id, node := range previous {
		if !node.Online {
			continue
		}
		state := s.nodeBandwidth[id]
		if state == nil || state.at.IsZero() || now.Sub(state.at) >= bandwidthFreshness {
			continue
		}
		latest, present := s.devices[id]
		if !present || node.GroupID != latest.GroupID ||
			now.Sub(latest.LastSeen) >= 30*time.Second || node.Metrics.Bandwidth == state.metrics {
			continue
		}
		node.Metrics.Bandwidth = state.metrics
		previous[id] = node
		changes = append(changes, bandwidthEvent{ID: id, Bandwidth: state.metrics})
	}
	return changes
}
