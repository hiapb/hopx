package panel

import (
	"cmp"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
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
	probePeriod
}

type probePeriod struct {
	Expected int    `json:"expected"`
	Recorded int    `json:"recorded"`
	Status   string `json:"status"`
}

func (p *probePeriod) add(status string) {
	p.Expected++
	if status == "sampled" {
		p.Recorded++
	}
	if p.Status == "" {
		p.Status = status
	} else if p.Status != status {
		p.Status = "mixed"
	}
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
	var entry, interval int64
	var serviceBlock string
	var routeReady, enabled, sharedTLS bool
	err := s.db.QueryRowContext(r.Context(), `SELECT r.entry,`+ruleProbeIntervalSQL+`,`+ruleServiceBlockSQL+`,`+ruleRouteReadySQL+`,
		coalesce(json_extract(r.json,'$.enabled'),0),coalesce(json_extract(r.json,'$.tlsShared'),0)
		FROM rules r JOIN users u ON u.id=r.owner WHERE r.id=? AND (r.owner=? OR ?)`, id, u.ID, u.Admin).
		Scan(&entry, &interval, &serviceBlock, &routeReady, &enabled, &sharedTLS)
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
	now := time.Now().Unix()
	end := now / interval * interval
	start := end - duration
	rows, err := s.db.QueryContext(r.Context(), `SELECT at,interval,sampled,status,evidence,coalesce(links,'') FROM rule_probe_slots
		WHERE rule=? AND at>=? AND at<=? AND at+interval>?
		UNION ALL SELECT sampled,0,sampled,'sampled','',links FROM rule_probe_samples
		WHERE rule=? AND sampled>=? AND sampled<=?`, id, start-300, now, start, id, start, now)
	if err != nil {
		dbFailure(w, err)
		return
	}
	defer rows.Close()
	type storedSample struct {
		at, interval, sampled   int64
		status, evidence, links string
	}
	var samples []storedSample
	for rows.Next() {
		var sample storedSample
		if err = rows.Scan(&sample.at, &sample.interval, &sample.sampled, &sample.status, &sample.evidence, &sample.links); err != nil {
			dbFailure(w, err)
			return
		}
		if sample.status == "pending" {
			switch {
			case sample.at+sample.interval+16 <= now:
				sample.status = firstNonempty(sample.evidence, "unreported")
			case sample.at+sample.interval <= now:
				sample.status = "awaiting"
			}
		}
		samples = append(samples, sample)
	}
	bucketAt := func(at int64) int64 { return start + (at-start)/resolution*resolution }
	periods := make(map[int64]probePeriod, duration/resolution)
	known := make(map[int64]bool)
	legacy := make(map[int64]bool)
	expected, recorded := 0, 0
	addPeriod := func(at int64, status string) {
		expected++
		if status == "sampled" {
			recorded++
		}
		bucket := bucketAt(at)
		period := periods[bucket]
		period.add(status)
		periods[bucket] = period
	}
	current := "pending"
	var latest int64
	for _, sample := range samples {
		if sample.interval == 0 {
			continue
		}
		latest = max(latest, sample.sampled)
		if sample.at == end && sample.interval == interval {
			current = sample.status
		}
		for at := max(start, sample.at); at < min(end, sample.at+sample.interval); at += 60 {
			known[at] = true
		}
		if sample.at >= start && sample.at+sample.interval <= end {
			addPeriod(sample.at, sample.status)
		}
	}
	if current == "pending" {
		if !enabled {
			current = "paused"
		} else if sharedTLS {
			current = "unsupported"
		}
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
	for _, sample := range samples {
		if sample.interval == 0 {
			// Imported history only has a receipt time. Keep it unless a fixed
			// slot already accounts for that part of the timeline.
			if known[sample.at/60*60] {
				continue
			}
			latest = max(latest, sample.sampled)
			if sample.at >= end {
				if current == "pending" {
					current = "sampled"
				}
				continue
			}
			at := sample.at / interval * interval
			if !legacy[at] {
				addPeriod(at, "sampled")
				legacy[at] = true
			}
		} else if sample.at < start || sample.at+sample.interval > end || sample.links == "" {
			continue
		}
		var links []wire.LinkProbe
		if err = json.Unmarshal([]byte(sample.links), &links); err != nil {
			dbFailure(w, err)
			return
		}
		for _, link := range links {
			key := [2]string{link.Network, link.Lane}
			lane := lanes[key]
			if lane == nil {
				lane = &history{probeHistoryLane: probeHistoryLane{Network: key[0], Lane: key[1]},
					points: make(map[int64]*probeStats), segments: make(map[segmentKey]*segmentHistory)}
				lanes[key] = lane
			}
			bucket := bucketAt(sample.at)
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
	for at := start; at < end; at += interval {
		if legacy[at] {
			continue
		}
		covered := false
		for t := at; t < at+interval; t += 60 {
			covered = covered || known[t]
		}
		if !covered {
			addPeriod(at, "unreported")
		}
	}
	result := make([]probeHistoryLane, 0, len(lanes))
	series := func(points map[int64]*probeStats) []probeHistoryPoint {
		values := make([]probeHistoryPoint, 0, duration/resolution)
		for t := start; t < end; t += resolution {
			period := periods[t]
			if period.Expected == 0 {
				period.Status = "other_cadence"
			}
			value := probeHistoryPoint{At: t, probePeriod: period}
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
		"points": series(nil), "current": map[string]any{"at": end, "status": current},
		"sampledBuckets": recorded, "completeBuckets": expected})
}
