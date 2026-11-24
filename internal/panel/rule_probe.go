package panel

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"hopx/internal/wire"
)

const ruleProbeIntervalSQL = `CASE json_extract(r.json,'$.probeInterval')
	WHEN 60 THEN 60 WHEN 300 THEN 300
	ELSE CASE (SELECT value FROM settings WHERE key='ruleProbeInterval') WHEN '60' THEN 60 ELSE 300 END END`

func boundedProbeLinks(links []wire.LinkProbe, attempts int) []wire.LinkProbe {
	if attempts == 0 || len(links) > 4 {
		return nil
	}
	seen := make(map[[2]string]bool, len(links))
	for _, link := range links {
		key := [2]string{link.Network, link.Lane}
		if (link.Network != "tcp" && link.Network != "udp") ||
			(link.Lane != "primary" && link.Lane != "backup") || seen[key] || len(link.Traces) > attempts {
			return nil
		}
		seen[key] = true
		for _, trace := range link.Traces {
			if trace.Hops < 0 || trace.Hops > 8 || len(trace.Steps) != trace.Hops+1 || len(trace.Target) > 300 {
				return nil
			}
			for _, step := range trace.Steps {
				if step.GroupID < 0 || step.LatencyMS < 0 || step.LatencyMS > 6000 ||
					len(step.Transport) > 12 || len(step.Phase) > 20 ||
					!slices.Contains([]string{"ok", "failed", "skipped", "unknown"}, step.Status) {
					return nil
				}
			}
		}
	}
	return links
}

func (s *Server) saveRuleProbe(ctx context.Context, ruleID int64, links []wire.LinkProbe) {
	if !slices.ContainsFunc(links, func(link wire.LinkProbe) bool { return len(link.Traces) != 0 }) {
		return
	}
	data, err := json.Marshal(links)
	if err != nil {
		return
	}
	at := time.Now().Unix()
	// Use minute keys for new rows. Cadence checks use sampled so they include rows
	// stored with five-minute keys by older panels and survive interval changes.
	_, err = s.db.ExecContext(ctx, `INSERT OR IGNORE INTO rule_probe_samples(rule,bucket,sampled,links)
		SELECT r.id,?,?,? FROM rules r JOIN users u ON u.id=r.owner
		WHERE r.id=? AND json_extract(r.json,'$.enabled')=1 AND `+ruleServiceActiveSQL+` AND `+ruleRouteReadySQL+`
		AND NOT EXISTS (SELECT 1 FROM rule_probe_samples p WHERE p.rule=r.id
			AND p.sampled>?-(`+ruleProbeIntervalSQL+`))`, at/60, at, string(data), ruleID, at)
	if err != nil && ctx.Err() == nil {
		slog.Warn("save rule probe", "rule", ruleID, "error", err)
	}
}

const maxBackgroundChecks = 16

func (s *Server) monitorRuleLinks(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	var cursor int64
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			next, err := s.probeRuleBatch(ctx, cursor)
			if err != nil && ctx.Err() == nil {
				slog.Warn("schedule rule probes", "error", err)
			}
			cursor = next
		}
	}
}

func (s *Server) probeRuleBatch(ctx context.Context, cursor int64) (int64, error) {
	now := time.Now()
	nodes := make(map[int64][]wire.Device)
	inFlight := make(map[int64]bool)
	free := maxBackgroundChecks
	s.mu.RLock()
	for _, check := range s.diagnostics {
		if check.background && now.Before(check.expires) {
			free--
			inFlight[check.task.RuleID] = true
		}
	}
	for _, node := range s.devices {
		if !node.AcceptLinkProbe || node.ApplyError != "" || now.Sub(node.LastSeen) >= 20*time.Second ||
			s.diagnostics[node.ID].expires.After(now) || node.Metrics.CPU >= 85 ||
			(node.Metrics.ConnectionLimit > 0 && node.Metrics.Connections*10 >= int64(node.Metrics.ConnectionLimit)*9) {
			continue
		}
		nodes[node.GroupID] = append(nodes[node.GroupID], node)
	}
	s.mu.RUnlock()
	if len(nodes) == 0 || free <= 0 {
		return cursor, nil
	}

	for _, devices := range nodes {
		slices.SortFunc(devices, func(a, b wire.Device) int { return cmp.Compare(a.ID, b.ID) })
	}
	groups := make([]string, 0, len(nodes))
	for group := range nodes {
		groups = append(groups, strconv.FormatInt(group, 10))
	}
	rows, err := s.db.QueryContext(ctx, `SELECT r.id,r.entry,`+ruleProbeIntervalSQL+` FROM rules r JOIN users u ON u.id=r.owner
		WHERE r.id>? AND r.entry IN (`+strings.Join(groups, ",")+`) AND json_extract(r.json,'$.enabled')=1
		AND `+ruleServiceActiveSQL+` AND `+ruleRouteReadySQL+`
		AND coalesce(json_extract(r.json,'$.tlsShared'),0)=0
		AND NOT EXISTS(SELECT 1 FROM rule_probe_samples p WHERE p.rule=r.id AND p.sampled>?-(`+ruleProbeIntervalSQL+`))
		ORDER BY r.id LIMIT 64`, cursor, now.Unix())
	if err != nil {
		return cursor, err
	}
	type candidate struct{ rule, group, interval int64 }
	pending := make([]candidate, 0, 64)
	for rows.Next() {
		var item candidate
		if err := rows.Scan(&item.rule, &item.group, &item.interval); err != nil {
			rows.Close()
			return cursor, err
		}
		pending = append(pending, item)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return cursor, err
	}
	if len(pending) == 0 {
		return 0, nil
	}

	used := make(map[int64]bool)
	count := 0
	for _, item := range pending {
		cursor = item.rule
		if inFlight[item.rule] {
			continue
		}
		devices := nodes[item.group]
		if len(devices) == 0 {
			continue
		}
		s.configMu.RLock()
		config := s.configs[item.group].value
		s.configMu.RUnlock()
		if config.Revision == "" {
			continue
		}
		if _, compiled := slices.BinarySearchFunc(config.Rules, item.rule, func(f wire.Forward, id int64) int {
			return cmp.Compare(f.ID, id)
		}); !compiled {
			continue
		}
		var node wire.Device
		bucket := now.Unix() / item.interval
		for i := range devices {
			device := devices[(int(bucket%int64(len(devices)))+i)%len(devices)]
			if !used[device.ID] && device.Revision == config.Revision {
				node = device
				break
			}
		}
		if node.ID == 0 {
			continue
		}
		used[node.ID] = true
		task := wire.DiagnosticTask{ID: token(), RuleID: item.rule, Revision: config.Revision, ProbeSamples: 1, ProbeOffset: bucket}
		go func() {
			result, status := s.waitNodeCheck(ctx, node.ID, task, true)
			if status == http.StatusOK {
				s.saveRuleProbe(ctx, task.RuleID, boundedProbeLinks(result.Links, task.ProbeSamples))
			}
		}()
		count++
		if count == free {
			break
		}
	}
	return cursor, nil
}

type probeStats struct {
	Attempts int   `json:"attempts"`
	Failed   int   `json:"failed"`
	TotalMS  int64 `json:"totalMs"`
	Samples  int   `json:"samples"`
}

func (s *probeStats) add(status string, latency int64) {
	switch status {
	case "ok":
		s.Attempts++
		s.TotalMS += latency
	case "failed":
		s.Attempts++
		s.Failed++
	}
}

type probeHistoryPoint struct {
	At int64 `json:"at"`
	probeStats
}

type probeHistorySegment struct {
	Index     int                 `json:"index"`
	GroupID   int64               `json:"groupId"`
	Transport string              `json:"transport"`
	Target    bool                `json:"target"`
	Points    []probeHistoryPoint `json:"points"`
	probeStats
}

type probeHistoryLane struct {
	Network  string                `json:"network"`
	Lane     string                `json:"lane"`
	Points   []probeHistoryPoint   `json:"points"`
	Segments []probeHistorySegment `json:"segments"`
	probeStats
}

func (s *Server) ruleProbeHistory(w http.ResponseWriter, r *http.Request, u User) {
	id := pathID(r)
	var entry, interval, latest int64
	var serviceBlock string
	var routeReady bool
	err := s.db.QueryRowContext(r.Context(), `SELECT r.entry,`+ruleProbeIntervalSQL+`,`+ruleServiceBlockSQL+`,`+ruleRouteReadySQL+`,
		coalesce((SELECT max(sampled) FROM rule_probe_samples WHERE rule=r.id AND sampled>=unixepoch()-604800),0)
		FROM rules r JOIN users u ON u.id=r.owner WHERE r.id=? AND (r.owner=? OR ?)`, id, u.ID, u.Admin).Scan(&entry, &interval, &serviceBlock, &routeReady, &latest)
	if errors.Is(err, sql.ErrNoRows) {
		fail(w, 404, "规则不存在")
		return
	}
	if err != nil {
		dbFailure(w, err)
		return
	}
	if serviceBlock != "" {
		fail(w, 403, serviceBlock)
		return
	}
	if !routeReady {
		fail(w, 409, ruleRouteRepairMessage)
		return
	}
	group, err := scanGroup(s.db.QueryRowContext(r.Context(), groupSelect+" WHERE id=?", entry))
	if err != nil || !canUse(u, group) {
		fail(w, 403, "当前账号无权使用此入口")
		return
	}
	duration, resolution := int64(3600), interval
	switch r.URL.Query().Get("range") {
	case "", "live":
	case "1d":
		duration, resolution = 86400, 1800
	case "3d":
		duration, resolution = 259200, 3600
	case "7d":
		duration, resolution = 604800, 7200
	default:
		fail(w, 400, "无效的历史时间范围")
		return
	}
	end := time.Now().Unix()
	start := end - duration
	rows, err := s.db.QueryContext(r.Context(), `SELECT sampled,links FROM rule_probe_samples
		WHERE rule=? AND sampled>=? ORDER BY sampled`, id, start)
	if err != nil {
		dbFailure(w, err)
		return
	}
	defer rows.Close()
	type storedSample struct {
		at    int64
		links string
	}
	var samples []storedSample
	for rows.Next() {
		var sample storedSample
		if err = rows.Scan(&sample.at, &sample.links); err != nil {
			dbFailure(w, err)
			return
		}
		samples = append(samples, sample)
	}
	if err := rows.Err(); err != nil {
		dbFailure(w, err)
		return
	}
	type segmentKey struct {
		index     int
		groupID   int64
		transport string
		target    bool
	}
	type segmentHistory struct {
		probeStats
		points map[int64]*probeStats
	}
	type history struct {
		probeHistoryLane
		points   map[int64]*probeStats
		segments map[segmentKey]*segmentHistory
	}
	lanes := make(map[[2]string]*history)
	coverage := make(map[int64]bool)
	firstCompleteBucket := (start + interval - 1) / interval
	for _, sample := range samples {
		var links []wire.LinkProbe
		if err = json.Unmarshal([]byte(sample.links), &links); err != nil {
			dbFailure(w, err)
			return
		}
		if bucket := sample.at / interval; bucket >= firstCompleteBucket && bucket < end/interval {
			coverage[bucket] = true
		}
		for _, link := range links {
			key := [2]string{link.Network, link.Lane}
			lane := lanes[key]
			if lane == nil {
				lane = &history{probeHistoryLane: probeHistoryLane{Network: key[0], Lane: key[1]},
					points: make(map[int64]*probeStats), segments: make(map[segmentKey]*segmentHistory)}
				lanes[key] = lane
			}
			bucket := sample.at - sample.at%resolution
			point := lane.points[bucket]
			if point == nil {
				point = &probeStats{}
				lane.points[bucket] = point
			}
			if len(link.Traces) > 0 {
				lane.Samples++
				point.Samples++
			}
			sampledSegments := make(map[segmentKey]bool)
			for _, trace := range link.Traces {
				status := "skipped"
				var latency int64
				for i, step := range trace.Steps {
					target := i == len(trace.Steps)-1
					groupKey := segmentKey{i, step.GroupID, step.Transport, target}
					stats := lane.segments[groupKey]
					if stats == nil {
						stats = &segmentHistory{points: make(map[int64]*probeStats)}
						lane.segments[groupKey] = stats
					}
					stats.add(step.Status, step.LatencyMS)
					segmentPoint := stats.points[bucket]
					if segmentPoint == nil {
						segmentPoint = &probeStats{}
						stats.points[bucket] = segmentPoint
					}
					segmentPoint.add(step.Status, step.LatencyMS)
					if !sampledSegments[groupKey] {
						stats.Samples++
						segmentPoint.Samples++
						sampledSegments[groupKey] = true
					}
					switch {
					case step.Status == "failed":
						status = "failed"
					case step.Status == "ok":
						latency += step.LatencyMS
						if target && status != "failed" {
							status = "ok"
						}
					}
				}
				if link.MeasuresTarget {
					lane.add(status, latency)
					point.add(status, latency)
				}
			}
		}
	}
	result := make([]probeHistoryLane, 0, len(lanes))
	series := func(points map[int64]*probeStats) []probeHistoryPoint {
		values := make([]probeHistoryPoint, 0, duration/resolution+1)
		for t := start - start%resolution; t <= end; t += resolution {
			value := probeHistoryPoint{At: t}
			if stats := points[t]; stats != nil {
				value.probeStats = *stats
			}
			values = append(values, value)
		}
		return values
	}
	for _, network := range []string{"tcp", "udp"} {
		for _, name := range []string{"primary", "backup"} {
			lane := lanes[[2]string{network, name}]
			if lane == nil {
				continue
			}
			lane.Points = series(lane.points)
			for key, value := range lane.segments {
				lane.Segments = append(lane.Segments, probeHistorySegment{
					Index: key.index, GroupID: key.groupID, Transport: key.transport, Target: key.target,
					Points: series(value.points), probeStats: value.probeStats,
				})
			}
			slices.SortFunc(lane.Segments, func(a, b probeHistorySegment) int {
				return cmp.Or(cmp.Compare(a.Index, b.Index), cmp.Compare(a.GroupID, b.GroupID), cmp.Compare(a.Transport, b.Transport))
			})
			result = append(result, lane.probeHistoryLane)
		}
	}
	respond(w, 200, map[string]any{"lanes": result, "latest": latest, "start": start, "end": end, "interval": interval,
		"sampledBuckets": len(coverage), "completeBuckets": max(0, end/interval-firstCompleteBucket)})
}
