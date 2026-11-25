package panel

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"slices"
	"time"

	"hopx/internal/wire"
)

const ruleProbeEligibleSQL = `json_extract(r.json,'$.enabled')=1
	AND coalesce(json_extract(r.json,'$.tlsShared'),0)=0
	AND ` + ruleServiceActiveSQL + ` AND ` + ruleRouteReadySQL

const (
	maxBackgroundChecks = 16
	maxProbeTries       = 2
	probeLease          = 15 * time.Second
	probeRetention      = 7 * 24 * 3600
)

type ruleProbeKey struct {
	rule, at, interval int64
}

func probeKey(rule, interval int64, now time.Time) ruleProbeKey {
	return ruleProbeKey{rule, now.Unix() / interval * interval, interval}
}

func hasProbeTraces(links []wire.LinkProbe) bool {
	return slices.ContainsFunc(links, func(link wire.LinkProbe) bool { return len(link.Traces) != 0 })
}

func (s *Server) saveManualRuleProbe(ctx context.Context, key ruleProbeKey, entry int64, links []wire.LinkProbe) error {
	if !hasProbeTraces(links) {
		return nil
	}
	data, err := json.Marshal(links)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO rule_probe_slots(rule,at,interval,entry,due,status,sampled,links)
		SELECT r.id,?,?,r.entry,?,'sampled',unixepoch(),? FROM rules r JOIN users u ON u.id=r.owner
		WHERE r.id=? AND r.entry=? AND `+ruleProbeEligibleSQL+`
		ON CONFLICT(rule,at,interval) DO UPDATE SET status='sampled',sampled=excluded.sampled,links=excluded.links
		WHERE rule_probe_slots.sampled=0 AND rule_probe_slots.entry=excluded.entry`,
		key.at, key.interval, key.at, string(data), key.rule, entry)
	return err
}

func (s *Server) monitorRuleLinks(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	var nextPlan int64
	observedSince := time.Now().Unix()
	for {
		now := time.Now()
		if now.Unix() >= nextPlan {
			if err := s.planRuleProbes(ctx, now); err != nil {
				if ctx.Err() == nil {
					slog.Warn("plan rule probes", "error", err)
				}
			} else {
				nextPlan = (now.Unix()/10 + 1) * 10
			}
		}
		if err := s.probeRuleBatch(ctx, now, observedSince); err != nil && ctx.Err() == nil {
			slog.Warn("schedule rule probes", "error", err)
		}
		observedSince = now.Unix()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *Server) planRuleProbes(ctx context.Context, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `WITH eligible AS (
		SELECT r.id,r.entry,`+ruleProbeIntervalSQL+` AS interval FROM rules r
		JOIN users u ON u.id=r.owner WHERE `+ruleProbeEligibleSQL+`
	), slots AS (SELECT id,entry,interval,?/interval*interval AS at FROM eligible)
	INSERT OR IGNORE INTO rule_probe_slots(rule,at,interval,entry,due)
	SELECT id,at,interval,entry,at+((id%1009)*137+(at/interval)*(id%13+1))%(interval-20) FROM slots
	WHERE NOT EXISTS(SELECT 1 FROM rule_probe_slots p WHERE p.rule=slots.id AND p.at=slots.at AND p.interval=slots.interval)
	AND NOT EXISTS(SELECT 1 FROM rule_probe_samples p WHERE p.rule=slots.id AND p.sampled>=slots.at AND p.sampled<slots.at+slots.interval)`, now.Unix())
	return err
}

type scheduledRuleProbe struct {
	ruleProbeKey
	entry, lastNode, tries int64
}

func (s *Server) probeRuleBatch(ctx context.Context, now time.Time, observedSince int64) error {
	nodes := make(map[int64][]wire.Device)
	online := make(map[int64]bool)
	inFlight := make([]int64, 0, maxBackgroundChecks)
	free := maxBackgroundChecks
	s.mu.Lock()
	for nodeID, check := range s.diagnostics {
		if !check.expires.After(now) {
			delete(s.diagnostics, nodeID)
		} else if check.task.ProbeSamples > 0 {
			inFlight = append(inFlight, check.task.RuleID)
			if check.background {
				free--
			}
		}
	}
	for _, node := range s.devices {
		if node.Revoked || now.Sub(node.LastSeen) >= 20*time.Second {
			continue
		}
		online[node.GroupID] = true
		if !node.AcceptLinkProbe || node.ApplyError != "" || s.diagnostics[node.ID].expires.After(now) ||
			node.Metrics.CPU >= 85 ||
			(node.Metrics.ConnectionLimit > 0 && node.Metrics.Connections*10 >= int64(node.Metrics.ConnectionLimit)*9) {
			continue
		}
		nodes[node.GroupID] = append(nodes[node.GroupID], node)
	}
	s.mu.Unlock()

	onlineGroups := make([]int64, 0, len(online))
	for group := range online {
		onlineGroups = append(onlineGroups, group)
	}
	// A missed scheduler tick has no evidence about node availability at that time.
	observedSince = max(observedSince, now.Unix()-4)
	if now.Before(s.warmUntil.Add(5 * time.Second)) {
		observedSince = now.Unix()
	}
	onlineJSON, _ := json.Marshal(onlineGroups)
	_, err := s.db.ExecContext(ctx, `UPDATE rule_probe_slots AS p SET status=CASE
		WHEN p.evidence<>'' THEN p.evidence
		WHEN p.deadline<=? THEN 'unreported'
		WHEN p.entry IN (SELECT value FROM json_each(?)) THEN 'backlog'
		WHEN EXISTS(SELECT 1 FROM devices d WHERE d.group_id=p.entry) THEN 'offline'
		ELSE 'no_entry' END
		WHERE (p.rule,p.at,p.interval) IN (
			SELECT rule,at,interval FROM rule_probe_slots WHERE status='pending' AND deadline<=? ORDER BY deadline LIMIT 256)`,
		observedSince, string(onlineJSON), now.Unix())
	if err != nil || free <= 0 || len(nodes) == 0 {
		return err
	}

	configs := make(map[int64]wire.Config, len(nodes))
	groups := make([]int64, 0, len(nodes))
	s.configMu.RLock()
	for group, devices := range nodes {
		config := s.configs[group].value
		if config.Revision == "" {
			continue
		}
		devices = slices.DeleteFunc(devices, func(node wire.Device) bool { return node.Revision != config.Revision })
		if len(devices) == 0 {
			continue
		}
		slices.SortFunc(devices, func(a, b wire.Device) int { return cmp.Compare(a.ID, b.ID) })
		nodes[group] = devices
		configs[group] = config
		groups = append(groups, group)
	}
	s.configMu.RUnlock()
	if len(groups) == 0 {
		return nil
	}

	groupJSON, _ := json.Marshal(groups)
	inFlightJSON, _ := json.Marshal(inFlight)
	rows, err := s.db.QueryContext(ctx, `SELECT p.rule,p.at,p.interval,p.entry,p.last_node,p.tries
		FROM rule_probe_slots p JOIN rules r ON r.id=p.rule AND r.entry=p.entry JOIN users u ON u.id=r.owner
		WHERE p.status='pending' AND p.entry IN (SELECT value FROM json_each(?))
		AND p.due<=? AND p.at+p.interval>? AND p.tries<? AND `+ruleProbeEligibleSQL+`
		AND p.rule NOT IN (SELECT value FROM json_each(?))
		ORDER BY p.due,p.at,p.rule LIMIT 64`, string(groupJSON), now.Unix(), now.Unix(), maxProbeTries, string(inFlightJSON))
	if err != nil {
		return err
	}
	var pending []scheduledRuleProbe
	for rows.Next() {
		var item scheduledRuleProbe
		if err := rows.Scan(&item.rule, &item.at, &item.interval, &item.entry, &item.lastNode, &item.tries); err != nil {
			rows.Close()
			return err
		}
		pending = append(pending, item)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if err := rows.Err(); err != nil {
		return err
	}
	used := make(map[int64]bool)
	for _, item := range pending {
		config := configs[item.entry]
		if _, found := slices.BinarySearchFunc(config.Rules, item.rule, func(f wire.Forward, id int64) int {
			return cmp.Compare(f.ID, id)
		}); !found {
			_, err := s.db.ExecContext(ctx, `UPDATE rule_probe_slots SET due=?,evidence='not_ready'
				WHERE rule=? AND at=? AND interval=? AND status='pending' AND tries=0`,
				now.Unix()+8, item.rule, item.at, item.interval)
			if err != nil {
				return err
			}
			continue
		}
		devices := nodes[item.entry]
		var node int64
		offset := item.at / item.interval
		for index := range devices {
			candidate := devices[(int(offset%int64(len(devices)))+index)%len(devices)].ID
			if used[candidate] {
				continue
			}
			node = candidate
			if candidate != item.lastNode {
				break
			}
		}
		if node == 0 {
			continue
		}
		task := wire.DiagnosticTask{ID: token(), RuleID: item.rule, Revision: config.Revision, ProbeSamples: 1, ProbeOffset: offset}
		issued, err := s.issueRuleProbe(ctx, item, node, task, now)
		if err != nil {
			return err
		}
		used[node] = true
		if issued {
			free--
			if free == 0 {
				break
			}
		}
	}
	return nil
}

func (s *Server) issueRuleProbe(ctx context.Context, item scheduledRuleProbe, node int64, task wire.DiagnosticTask, now time.Time) (bool, error) {
	expiry := now.Add(probeLease)
	s.mu.Lock()
	if s.diagnostics[node].expires.After(now) || len(s.diagnostics) >= 32 ||
		s.devices[node].GroupID != item.entry {
		s.mu.Unlock()
		return false, nil
	}
	for _, check := range s.diagnostics {
		if check.expires.After(now) && check.task.RuleID == task.RuleID && check.task.ProbeSamples > 0 {
			s.mu.Unlock()
			return false, nil
		}
	}
	s.diagnostics[node] = probeCheck{task: task, expires: expiry, background: true}
	s.mu.Unlock()

	issued := false
	defer func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		check := s.diagnostics[node]
		if check.task.ID == task.ID {
			if issued {
				check.ready = true
				s.diagnostics[node] = check
			} else {
				delete(s.diagnostics, node)
			}
		}
	}()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	updated, err := tx.ExecContext(ctx, `UPDATE rule_probe_slots SET tries=tries+1,last_node=?,due=?,
		evidence=CASE WHEN evidence IN ('','not_ready') THEN 'unclaimed' ELSE evidence END
		WHERE rule=? AND at=? AND interval=? AND status='pending' AND tries=? AND due<=?
		AND EXISTS(SELECT 1 FROM devices d WHERE d.id=? AND d.group_id=entry)`,
		node, expiry.Unix(), item.rule, item.at, item.interval, item.tries, now.Unix(), node)
	if err != nil {
		return false, err
	}
	if count, err := updated.RowsAffected(); err != nil || count == 0 {
		return false, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO rule_probe_attempts(id,node,rule,at,interval,ordinal) VALUES(?,?,?,?,?,?)`,
		task.ID, node, item.rule, item.at, item.interval, item.tries+1); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	issued = true
	return true, nil
}

func (s *Server) receiveRuleProbe(ctx context.Context, node int64, credential string, result *wire.DiagnosticResult, now time.Time) error {
	if result == nil || result.ID == "" || len(result.ID) > 64 {
		return nil
	}
	// Manual route checks are resolved in memory. An absent or different task may
	// be a periodic result returning after its lease or after a panel restart.
	s.mu.RLock()
	check := s.diagnostics[node]
	s.mu.RUnlock()
	if check.task.ID == result.ID && !check.background {
		return nil
	}
	var key ruleProbeKey
	var ordinal int64
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	err = tx.QueryRowContext(ctx, `SELECT a.rule,a.at,a.interval,a.ordinal FROM rule_probe_attempts a
		JOIN rule_probe_slots p ON (p.rule,p.at,p.interval)=(a.rule,a.at,a.interval)
		JOIN rules r ON r.id=a.rule AND r.entry=p.entry JOIN users u ON u.id=r.owner
		JOIN devices d ON d.id=a.node AND d.group_id=p.entry
		WHERE a.id=? AND a.node=? AND d.token=? AND a.offered=1 AND a.returned=0
		AND p.sampled=0 AND a.at+a.interval>? AND `+ruleProbeEligibleSQL,
		result.ID, node, credential, now.Unix()-probeRetention).Scan(&key.rule, &key.at, &key.interval, &ordinal)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}

	links := boundedProbeLinks(result.Links, 1)
	if result.RuleStatus == "running" && hasProbeTraces(links) {
		data, err := json.Marshal(links)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE rule_probe_slots SET status='sampled',sampled=?,links=?
			WHERE rule=? AND at=? AND interval=?`, now.Unix(), string(data), key.rule, key.at, key.interval); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM rule_probe_attempts WHERE rule=? AND at=? AND interval=?`,
			key.rule, key.at, key.interval); err != nil {
			return err
		}
		return tx.Commit()
	}

	state := "unreported"
	switch result.RuleStatus {
	case "busy":
		state = "backlog"
	case "syncing", "inactive":
		state = "not_ready"
	case "running":
		if links != nil || len(result.Links) == 0 {
			state = "unmeasured"
		}
	}
	if _, err := tx.ExecContext(ctx, "UPDATE rule_probe_attempts SET returned=1 WHERE id=?", result.ID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE rule_probe_slots SET evidence=?,due=min(due,?),
		status=CASE WHEN deadline<=? THEN ? ELSE status END
		WHERE rule=? AND at=? AND interval=? AND tries=?`,
		state, now.Unix()+2, now.Unix(), state, key.rule, key.at, key.interval, ordinal); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Server) offerRuleProbe(ctx context.Context, node int64, credential, taskID string) (bool, error) {
	s.mu.RLock()
	check := s.diagnostics[node]
	s.mu.RUnlock()
	if check.task.ID != taskID {
		return false, nil
	}
	if !check.background || check.offered {
		return true, nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	updated, err := tx.ExecContext(ctx, `UPDATE rule_probe_attempts SET offered=1
		WHERE id=? AND node=? AND returned=0 AND EXISTS(SELECT 1 FROM devices WHERE id=? AND token=?)
		AND EXISTS(SELECT 1 FROM rule_probe_slots p JOIN rules r ON r.id=p.rule AND r.entry=p.entry
			JOIN users u ON u.id=r.owner WHERE (p.rule,p.at,p.interval)=(rule_probe_attempts.rule,rule_probe_attempts.at,rule_probe_attempts.interval)
			AND p.status='pending' AND `+ruleProbeEligibleSQL+`)`, taskID, node, node, credential)
	if err != nil {
		return false, err
	}
	if count, err := updated.RowsAffected(); err != nil || count == 0 {
		if err == nil {
			s.mu.Lock()
			if s.diagnostics[node].task.ID == taskID {
				delete(s.diagnostics, node)
			}
			s.mu.Unlock()
		}
		return false, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE rule_probe_slots SET evidence='timeout'
		WHERE (rule,at,interval)=(SELECT rule,at,interval FROM rule_probe_attempts WHERE id=?) AND status='pending'`, taskID); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if current := s.diagnostics[node]; current.task.ID == taskID {
		current.offered = true
		s.diagnostics[node] = current
		return true, nil
	}
	return false, nil
}
