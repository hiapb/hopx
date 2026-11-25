package panel

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"hopx/internal/wire"
)

func (s *Server) probeNode(w http.ResponseWriter, r *http.Request, u User) (wire.Device, bool) {
	devices, e := s.visibleNodes(u)
	if e != nil {
		dbFailure(w, e)
		return wire.Device{}, false
	}
	for _, d := range devices {
		if d.ID == pathID(r) {
			return d, true
		}
	}
	fail(w, 404, "节点不可见或不存在")
	return wire.Device{}, false
}

func (s *Server) probeHistory(w http.ResponseWriter, r *http.Request, u User) {
	d, ok := s.probeNode(w, r, u)
	if !ok {
		return
	}
	rows, e := s.db.Query("SELECT bucket,cpu,ram,disk,inbound,outbound FROM probe_samples WHERE node=? AND bucket>=unixepoch()-3600 ORDER BY bucket", d.ID)
	if e != nil {
		dbFailure(w, e)
		return
	}
	defer rows.Close()
	type sample struct {
		Timestamp int64   `json:"timestamp"`
		CPU       float64 `json:"cpu"`
		RAM       float64 `json:"ram"`
		Disk      float64 `json:"disk"`
		In        float64 `json:"in"`
		Out       float64 `json:"out"`
	}
	list := []sample{}
	for rows.Next() {
		var a sample
		if e = rows.Scan(&a.Timestamp, &a.CPU, &a.RAM, &a.Disk, &a.In, &a.Out); e != nil {
			dbFailure(w, e)
			return
		}
		list = append(list, a)
	}
	if e = rows.Err(); e != nil {
		dbFailure(w, e)
		return
	}
	respond(w, 200, list)
}

func (s *Server) probeDiagnose(w http.ResponseWriter, r *http.Request, u User) {
	d, ok := s.probeNode(w, r, u)
	if !ok {
		return
	}
	var ago int64
	if !d.LastSeen.IsZero() {
		ago = max(0, int64(time.Since(d.LastSeen).Seconds()))
	}
	status := "在线"
	detail := "心跳正常"
	if !d.Online {
		status = "离线"
		detail = "未收到近期心跳"
	}
	if d.ApplyError != "" {
		detail = "配置应用失败：" + d.ApplyError
	}
	if d.UpdateError != "" {
		detail = "升级失败：" + d.UpdateError
	}
	respond(w, 200, map[string]any{"status": status, "detail": detail, "age": ago, "listeners": d.Metrics.Listeners, "connections": d.Metrics.Connections})
}

type probeCheck struct {
	task       wire.DiagnosticTask
	result     *wire.DiagnosticResult
	expires    time.Time
	done       chan struct{}
	background bool
	ready      bool
	offered    bool
}

func (s *Server) pollDiagnostic(id int64, result *wire.DiagnosticResult) *wire.DiagnosticTask {
	s.mu.Lock()
	defer s.mu.Unlock()
	check, ok := s.diagnostics[id]
	if !ok {
		return nil
	}
	if time.Now().After(check.expires) {
		delete(s.diagnostics, id)
		return nil
	}
	if check.background {
		if !check.ready {
			return nil
		}
		if result != nil && result.ID == check.task.ID {
			delete(s.diagnostics, id)
			return nil
		}
		return &check.task
	}
	if check.result == nil && result != nil && result.ID == check.task.ID {
		check.result = result
		s.diagnostics[id] = check
		close(check.done)
	}
	if check.result == nil {
		return &check.task
	}
	return nil
}

func connectivityRuleStatus(node wire.Device, group wire.DeviceGroup, rule wire.Rule, admin bool) (int, string) {
	switch {
	case len(rule.Targets) == 0 || !targetOK(rule.Targets[0]):
		return http.StatusBadRequest, "目标地址无效"
	case rule.RouteRepair != nil:
		return http.StatusConflict, ruleRouteRepairMessage
	case group.RuleNetwork(rule) == "udp" || rule.TLSShared:
		return http.StatusBadRequest, "请选择可以连接 TCP 目标的规则"
	case !node.AcceptRuleProbe && (!admin || len(rule.Path) > 0 || len(rule.BackupPath) > 0 || rule.TLSSharedPort != 0):
		return http.StatusConflict, "该节点版本尚不支持链路诊断"
	default:
		return http.StatusOK, ""
	}
}

func (s *Server) probeRuleOptions(w http.ResponseWriter, r *http.Request, u User) {
	node, ok := s.probeNode(w, r, u)
	if !ok {
		return
	}
	if !node.Online {
		fail(w, 409, "节点当前离线")
		return
	}
	group, err := scanGroup(s.db.QueryRowContext(r.Context(), groupSelect+" WHERE id=?", node.GroupID))
	if err != nil {
		dbFailure(w, err)
		return
	}
	query := `SELECT r.id,r.port,r.json FROM rules r JOIN users u ON u.id=r.owner
		WHERE r.entry=? AND json_extract(r.json,'$.enabled')=1 AND ` + ruleServiceActiveSQL + ` AND ` + ruleRouteReadySQL
	args := []any{node.GroupID}
	if search := strings.TrimSpace(r.URL.Query().Get("q")); search != "" {
		query += ` AND (instr(lower(json_extract(r.json,'$.name')),lower(?))>0 OR r.port=?)`
		args = append(args, search, search)
	}
	rows, err := s.db.QueryContext(r.Context(), query+" ORDER BY r.port", args...)
	if err != nil {
		dbFailure(w, err)
		return
	}
	defer rows.Close()
	type option struct {
		ID   int64  `json:"id"`
		Name string `json:"name"`
		Port int    `json:"port"`
	}
	const limit = 30
	options := make([]option, 0, limit)
	for len(options) < limit && rows.Next() {
		var item option
		var raw []byte
		var rule wire.Rule
		if err := rows.Scan(&item.ID, &item.Port, &raw); err != nil {
			dbFailure(w, err)
			return
		}
		if json.Unmarshal(raw, &rule) != nil {
			continue
		}
		if status, _ := connectivityRuleStatus(node, group, rule, u.Admin); status == http.StatusOK {
			item.Name = rule.Name
			options = append(options, item)
		}
	}
	if err := rows.Err(); err != nil {
		dbFailure(w, err)
		return
	}
	respond(w, 200, options)
}

func (s *Server) probeConnectivity(w http.ResponseWriter, r *http.Request, u User) {
	node, ok := s.probeNode(w, r, u)
	if !ok {
		return
	}
	if !node.Online {
		fail(w, 409, "节点当前离线")
		return
	}
	var input struct{ RuleID int64 }
	if !decode(w, r, &input) {
		return
	}
	var config, serviceBlock string
	err := s.db.QueryRowContext(r.Context(), `SELECT r.json,`+ruleServiceBlockSQL+`
		FROM rules r JOIN users u ON u.id=r.owner WHERE r.id=? AND r.entry=? AND (r.owner=? OR ?)
		AND json_extract(r.json,'$.enabled')=1`, input.RuleID, node.GroupID, u.ID, u.Admin).Scan(&config, &serviceBlock)
	if errors.Is(err, sql.ErrNoRows) {
		fail(w, 404, "该入口没有这条已启用规则")
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
	var rule wire.Rule
	if json.Unmarshal([]byte(config), &rule) != nil {
		fail(w, 400, "目标地址无效")
		return
	}
	group, err := scanGroup(s.db.QueryRowContext(r.Context(), groupSelect+" WHERE id=?", node.GroupID))
	if err != nil {
		dbFailure(w, err)
		return
	}
	if status, reason := connectivityRuleStatus(node, group, rule, u.Admin); status != http.StatusOK {
		fail(w, status, reason)
		return
	}
	task := wire.DiagnosticTask{ID: token(), Address: rule.Targets[0]}
	if node.AcceptRuleProbe {
		task.RuleID, task.Address = input.RuleID, ""
	}
	s.runDiagnostic(w, r, node.ID, task, false)
}

const ruleDiagnosticPageSize = 3

type entryDiagnostic struct {
	Number       int                   `json:"number"`
	ID           int64                 `json:"id,omitempty"`
	Name         string                `json:"name"`
	Region       string                `json:"region,omitempty"`
	CountryCode  string                `json:"countryCode,omitempty"`
	Online       bool                  `json:"online"`
	Status       string                `json:"status"`
	ApplyError   string                `json:"applyError,omitempty"`
	Primary      *wire.RouteDiagnostic `json:"primary,omitempty"`
	Backup       *wire.RouteDiagnostic `json:"backup,omitempty"`
	RecentRoutes []wire.RecentRoute    `json:"recentRoutes,omitempty"`
	Links        []wire.LinkProbe      `json:"links,omitempty"`
}

func (s *Server) diagnoseRule(w http.ResponseWriter, r *http.Request, u User) {
	id := pathID(r)
	var rule wire.Rule
	var raw, serviceBlock string
	var entryID, ownerID, interval int64
	err := s.db.QueryRowContext(r.Context(), `SELECT r.entry,r.owner,r.json,`+ruleServiceBlockSQL+`,`+ruleProbeIntervalSQL+`
		FROM rules r JOIN users u ON u.id=r.owner WHERE r.id=? AND (r.owner=? OR ?)`,
		id, u.ID, u.Admin).Scan(&entryID, &ownerID, &raw, &serviceBlock, &interval)
	if errors.Is(err, sql.ErrNoRows) {
		fail(w, 404, "规则不存在")
		return
	}
	if err == nil {
		err = json.Unmarshal([]byte(raw), &rule)
	}
	if err != nil {
		dbFailure(w, err)
		return
	}
	if serviceBlock != "" {
		fail(w, 403, serviceBlock)
		return
	}
	if rule.RouteRepair != nil {
		fail(w, 409, ruleRouteRepairMessage)
		return
	}
	group, err := scanGroup(s.db.QueryRowContext(r.Context(), groupSelect+" WHERE id=?", entryID))
	if err != nil {
		dbFailure(w, err)
		return
	}
	if !canUse(u, group) {
		fail(w, 403, "当前账号无权使用此入口")
		return
	}
	devices, err := s.deviceGroupSnapshot(false, entryID)
	if err != nil {
		dbFailure(w, err)
		return
	}
	// Read the most recent configuration sent by a heartbeat. Diagnostics must not
	// force the panel to recompile a large entry group on demand.
	s.configMu.RLock()
	config := s.configs[entryID].value
	s.configMu.RUnlock()
	index, compiled := slices.BinarySearchFunc(config.Rules, id, func(f wire.Forward, id int64) int {
		return cmp.Compare(f.ID, id)
	})
	if compiled {
		forward := config.Rules[index]
		compiled = rule.Enabled && ownerID == forward.Owner && slices.Equal(rule.Targets, forward.Targets) && slices.Equal(rule.Path, forward.Path)
		if compiled {
			rule.BackupPath = forward.BackupPath
		}
	}
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	page = min(max(page, 1), max(1, (len(devices)+ruleDiagnosticPageSize-1)/ruleDiagnosticPageSize))
	start := (page - 1) * ruleDiagnosticPageSize
	end := min(start+ruleDiagnosticPageSize, len(devices))
	results := make([]entryDiagnostic, end-start)
	showName := group.Routing.StatusVisibility != "none" && (u.Admin || group.Owner == u.ID ||
		(!group.HideStatus && group.Routing.StatusVisibility != "admin" && s.setting("showNodeStatus", "true") != "false"))
	var checks sync.WaitGroup
	query := r.URL.Query()
	detailed, statusOnly := query.Get("detail") == "1", query.Get("status") == "1"
	selected, _ := strconv.Atoi(query.Get("node"))
	for i, device := range devices[start:end] {
		number := start + i + 1
		out := &results[i]
		*out = entryDiagnostic{Number: number, Name: fmt.Sprintf("入口 %d", number), Online: device.Online && !device.Revoked}
		if showName {
			out.Name, out.ID, out.Region = device.Name, device.ID, device.Region
			out.CountryCode = s.nodeCountry(device.Registration)
		}
		out.Status = entryStatus(device, rule.Enabled, compiled, config.Revision)
		if out.Status == "failed" && u.Admin {
			out.ApplyError = device.ApplyError
		}
		if out.Status == "running" && !statusOnly && (!query.Has("node") || selected == number) {
			checks.Go(func() {
				s.diagnoseEntry(r.Context(), device, detailed, id, interval, config.Revision, out)
			})
		}
	}
	checks.Wait()
	respond(w, 200, map[string]any{
		"entry": group.Name, "nodes": results, "total": len(devices), "page": page, "pageSize": ruleDiagnosticPageSize,
		"enabled": rule.Enabled, "compiled": compiled, "primaryPath": rule.Path, "backupPath": rule.BackupPath,
		"tcp": group.RuleNetwork(rule) != "udp" && !rule.TLSShared,
	})
}

func entryStatus(device wire.Device, enabled, compiled bool, revision string) string {
	switch {
	case device.Revoked:
		return "revoked"
	case !device.Online:
		return "offline"
	case !enabled:
		return "paused"
	case device.ApplyError != "":
		return "failed"
	case revision == "" || device.Revision != revision:
		return "syncing"
	case !compiled:
		return "inactive"
	case !device.AcceptRouteProbe:
		return "upgrade"
	default:
		return "running"
	}
}

func (s *Server) diagnoseEntry(ctx context.Context, device wire.Device, detailed bool, ruleID, interval int64, revision string, out *entryDiagnostic) {
	now := time.Now()
	task := wire.DiagnosticTask{ID: token(), RuleID: ruleID, Revision: revision}
	if detailed && device.AcceptLinkProbe {
		task.ProbeSamples, task.ProbeOffset = 1, now.Unix()
	}
	result, status := s.waitDiagnostic(ctx, device.ID, task)
	switch status {
	case http.StatusOK:
		out.Status, out.Primary, out.Backup = result.RuleStatus, result.PrimaryRoute, result.BackupRoute
		out.RecentRoutes = result.RecentRoutes
		out.Links = boundedProbeLinks(result.Links, task.ProbeSamples)
		if task.ProbeSamples > 0 && result.RuleStatus == "running" {
			if err := s.saveManualRuleProbe(ctx, probeKey(ruleID, interval, now), device.GroupID, out.Links); err != nil && ctx.Err() == nil {
				slog.Warn("save manual rule probe", "rule", ruleID, "error", err)
			}
		}
	case http.StatusTooManyRequests:
		out.Status = "busy"
	default:
		out.Status = "timeout"
	}
}

func (s *Server) probePing(w http.ResponseWriter, r *http.Request, u User) {
	if s.setting("lookingGlass", "false") != "true" {
		fail(w, 403, "节点 Ping 测试已关闭")
		return
	}
	node, ok := s.probeNode(w, r, u)
	if !ok {
		return
	}
	if !node.Online || !node.AcceptPing {
		fail(w, 409, "请选择在线且支持 Ping 的节点")
		return
	}
	var input struct{ Host string }
	if !decode(w, r, &input) {
		return
	}
	host := strings.TrimSpace(input.Host)
	if len(host) < 1 || len(host) > 253 || strings.Contains(host, "%") {
		fail(w, 400, "请输入一个有效的域名或 IP")
		return
	}
	if _, err := netip.ParseAddr(host); err != nil {
		valid := true
		for label := range strings.SplitSeq(strings.TrimSuffix(host, "."), ".") {
			if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				valid = false
				break
			}
			for _, ch := range label {
				if !(ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch == '-') {
					valid = false
					break
				}
			}
		}
		if !valid {
			fail(w, 400, "请输入一个有效的域名或 IP")
			return
		}
	}
	visibility := s.setting("diagnoseIPVisibility", "admin")
	task := wire.DiagnosticTask{ID: token(), PingHost: host, PublicOnly: !u.Admin}
	s.runDiagnostic(w, r, node.ID, task, visibility == "all" || (visibility == "admin" && u.Admin))
}

func (s *Server) runDiagnostic(w http.ResponseWriter, r *http.Request, nodeID int64, task wire.DiagnosticTask, showIP bool) {
	result, status := s.waitDiagnostic(r.Context(), nodeID, task)
	switch status {
	case http.StatusOK:
		if !showIP {
			result.Address = ""
		}
		respond(w, 200, result)
	case http.StatusTooManyRequests:
		fail(w, status, "诊断任务繁忙，请稍后再试")
	case http.StatusGatewayTimeout:
		fail(w, status, "节点诊断超时")
	}
}

func (s *Server) waitDiagnostic(ctx context.Context, nodeID int64, task wire.DiagnosticTask) (wire.DiagnosticResult, int) {
	now := time.Now()
	s.mu.Lock()
	existing, exists := s.diagnostics[nodeID]
	if exists && existing.expires.After(now) {
		if !existing.background {
			s.mu.Unlock()
			return wire.DiagnosticResult{}, http.StatusTooManyRequests
		}
		delete(s.diagnostics, nodeID)
	}
	for id, diagnostic := range s.diagnostics {
		if !diagnostic.expires.After(now) {
			delete(s.diagnostics, id)
		}
	}
	if len(s.diagnostics) >= 32 {
		s.mu.Unlock()
		return wire.DiagnosticResult{}, http.StatusTooManyRequests
	}
	done := make(chan struct{})
	s.diagnostics[nodeID] = probeCheck{task: task, expires: now.Add(probeLease), done: done}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		if s.diagnostics[nodeID].task.ID == task.ID {
			delete(s.diagnostics, nodeID)
		}
		s.mu.Unlock()
	}()
	timeout := time.NewTimer(14 * time.Second)
	defer timeout.Stop()
	select {
	case <-ctx.Done():
		return wire.DiagnosticResult{}, http.StatusRequestTimeout
	case <-timeout.C:
		return wire.DiagnosticResult{}, http.StatusGatewayTimeout
	case <-done:
		s.mu.RLock()
		current := s.diagnostics[nodeID]
		s.mu.RUnlock()
		if current.result != nil && current.task.ID == task.ID {
			return *current.result, http.StatusOK
		}
		return wire.DiagnosticResult{}, http.StatusTooManyRequests
	}
}
