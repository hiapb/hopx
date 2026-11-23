package panel

import (
	"cmp"
	"slices"

	"hopx/internal/wire"
)

type entryRuntimeStatus struct {
	online, matched, failed int
	proxyReady              int
	reportedAt              int64
}

func (status *entryRuntimeStatus) add(node wire.Device, revision string) {
	if !node.LastSeen.IsZero() {
		status.reportedAt = max(status.reportedAt, node.LastSeen.Unix())
	}
	if !node.Online {
		return
	}
	status.online++
	if node.AcceptHAProxy {
		status.proxyReady++
	}
	if node.ApplyError != "" {
		status.failed++
	}
	if revision != "" && node.Revision == revision {
		status.matched++
	}
}

func (status entryRuntimeStatus) syncFailed() bool {
	return status.failed > 0 && status.matched == 0
}

func (s *Server) failedRuleEntries() ([]int64, error) {
	devices, err := s.deviceSnapshot(false)
	if err != nil {
		return nil, err
	}
	statuses := make(map[int64]entryRuntimeStatus)
	s.configMu.RLock()
	for _, node := range devices {
		status := statuses[node.GroupID]
		status.add(node, s.configs[node.GroupID].value.Revision)
		statuses[node.GroupID] = status
	}
	s.configMu.RUnlock()
	ids := []int64{}
	for id, status := range statuses {
		if status.syncFailed() {
			ids = append(ids, id)
		}
	}
	return ids, nil
}

func (s *Server) ruleRuntimeStatus(rows []ruleRow) error {
	if len(rows) == 0 {
		return nil
	}
	type groupStatus struct {
		current wire.Config
		entryRuntimeStatus
	}
	groupStatuses := make(map[int64]*groupStatus)
	s.configMu.RLock()
	for _, row := range rows {
		if row.Enabled && groupStatuses[row.Entry] == nil {
			groupStatuses[row.Entry] = &groupStatus{current: s.configs[row.Entry].value}
		}
	}
	s.configMu.RUnlock()
	if len(groupStatuses) != 0 {
		devices, err := s.deviceSnapshot(false)
		if err != nil {
			return err
		}
		for _, node := range devices {
			if status := groupStatuses[node.GroupID]; status != nil {
				status.add(node, status.current.Revision)
			}
		}
	}
	for i := range rows {
		row := &rows[i]
		row.Runtime = "paused"
		if !row.Enabled {
			continue
		}
		status := groupStatuses[row.Entry]
		row.ReportedAt = status.reportedAt
		index, compiled := slices.BinarySearchFunc(status.current.Rules, row.ID, func(rule wire.Forward, id int64) int {
			return cmp.Compare(rule.ID, id)
		})
		var forward wire.Forward
		if compiled {
			forward = status.current.Rules[index]
		}
		switch {
		case status.online == 0:
			row.Runtime = "offline"
		case row.UsesHAProxy() && status.proxyReady == 0:
			row.Runtime = "proxy_unavailable"
		case status.syncFailed():
			row.Runtime = "failed"
		case status.matched == 0:
			row.Runtime = "syncing"
		case !compiled:
			row.Runtime = "inactive"
		case len(forward.Path) != 0 && len(forward.Routes)+len(forward.Backup) == 0:
			row.Runtime = "waiting_exit"
		case status.matched < status.online || status.failed > 0:
			row.Runtime = "partial"
		default:
			row.Runtime = "running"
		}
	}
	return nil
}
