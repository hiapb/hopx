package panel

import (
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"hopx/internal/wire"

	"hopx/internal/certificate"
)

const groupSelect = "SELECT id,name,kind,first_port,last_port,ratio,user_group,offline_seconds,owner,allowed_from,allowed_to,user_groups,chain,port_ranges,reverse_groups,tls_ingress,ingress,folder,note,show_order,hide_status,relay_mode,default_network,connect_host,fallback_group,routing FROM groups"

func scanGroup(row scanner) (g wire.DeviceGroup, e error) {
	var from, to, groups, chain, reverse, ingress, routing string
	e = row.Scan(&g.ID, &g.Name, &g.Kind, &g.FirstPort, &g.LastPort, &g.Ratio, &g.UserGroup, &g.OfflineSeconds, &g.Owner, &from, &to, &groups, &chain, &g.PortRanges, &reverse, &g.TLSIngress, &ingress, &g.Folder, &g.Note, &g.ShowOrder, &g.HideStatus, &g.RelayMode, &g.DefaultNetwork, &g.ConnectHost, &g.FallbackGroup, &routing)
	if e == nil {
		e = json.Unmarshal([]byte(from), &g.AllowedFrom)
	}
	if e == nil {
		e = json.Unmarshal([]byte(to), &g.AllowedTo)
	}
	if e == nil {
		e = json.Unmarshal([]byte(groups), &g.UserGroups)
	}
	if e == nil {
		e = json.Unmarshal([]byte(chain), &g.Chain)
	}
	if e == nil {
		e = json.Unmarshal([]byte(reverse), &g.ReverseGroups)
	}
	if e == nil {
		e = json.Unmarshal([]byte(ingress), &g.Ingress)
	}
	if e == nil {
		e = json.Unmarshal([]byte(routing), &g.Routing)
	}
	return
}

func canUse(u User, g wire.DeviceGroup) bool {
	return u.Admin || g.Owner == u.ID || (g.Owner == 0 && ((len(g.UserGroups) > 0 && slices.Contains(g.UserGroups, u.Group)) || (len(g.UserGroups) == 0 && (g.UserGroup == 0 || g.UserGroup == u.Group))))
}

func (s *Server) groups() ([]wire.DeviceGroup, error) {
	rows, e := s.db.Query(groupSelect + " ORDER BY show_order,id")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	groups := []wire.DeviceGroup{}
	for rows.Next() {
		g, e := scanGroup(rows)
		if e != nil {
			return nil, e
		}
		groups = append(groups, g)
	}
	return groups, rows.Err()
}

func (s *Server) listGroups(w http.ResponseWriter, r *http.Request, u User) {
	if owner, _ := strconv.ParseInt(r.URL.Query().Get("owner"), 10, 64); u.Admin && owner > 0 && owner != u.ID {
		var err error
		u, err = readUser(s.db.QueryRowContext(r.Context(), userSelect+" WHERE id=?", owner))
		if errors.Is(err, sql.ErrNoRows) {
			fail(w, 404, "用户不存在")
			return
		}
		if err != nil {
			dbFailure(w, err)
			return
		}
	}
	groups, e := s.groups()
	if e != nil {
		dbFailure(w, e)
		return
	}
	type groupOption struct {
		wire.DeviceGroup
		Online *int `json:"onlineDevices,omitempty"`
	}
	online := make(map[int64]int)
	includeOnline := r.URL.Query().Get("online") == "1"
	showStatus := includeOnline && (u.Admin || s.setting("showNodeStatus", "true") != "false")
	if includeOnline {
		timeouts := make(map[int64]time.Duration, len(groups))
		for _, group := range groups {
			timeouts[group.ID] = time.Duration(group.OfflineSeconds) * time.Second
		}
		now := time.Now()
		s.mu.RLock()
		for _, device := range s.devices {
			if !device.LastSeen.IsZero() && now.Sub(device.LastSeen) < timeouts[device.GroupID] {
				online[device.GroupID]++
			}
		}
		s.mu.RUnlock()
	}
	allowed := []groupOption{}
	for _, g := range groups {
		if canUse(u, g) {
			visible := g.Routing.StatusVisibility != "none" && (u.Admin || g.Owner == u.ID || (showStatus && !g.HideStatus && g.Routing.StatusVisibility != "admin"))
			if !u.Admin {
				g.Chain = nil
				g.Note = ""
				g.ReverseGroups = nil
				if g.Ingress != nil {
					g.Ingress = &wire.IngressFilter{SiteOutboundOnly: g.Ingress.SiteOutboundOnly,
						BlockPersonal: g.Ingress.BlockPersonal, DisableUDP: g.Ingress.BlocksUDP()}
				}
				if g.Kind != "entry" && g.Kind != "both" {
					g.ConnectHost = ""
				}
				g.Routing = wire.RelayRouting{IngressMode: g.Routing.IngressMode}
			}
			option := groupOption{DeviceGroup: g}
			if includeOnline && g.Kind != "chain" && visible {
				count := online[g.ID]
				option.Online = &count
			}
			allowed = append(allowed, option)
		}
	}
	respond(w, 200, allowed)
}

func (s *Server) saveGroup(w http.ResponseWriter, r *http.Request, u User) {
	var g wire.DeviceGroup
	if !decode(w, r, &g) {
		return
	}
	g.ID = pathID(r)
	personal := !u.Admin || strings.HasPrefix(r.URL.Path, "/api/tunnels")
	if !u.Admin && !u.AllowDevice && s.setting("personalTunnels", "false") != "true" {
		fail(w, 403, "单端隧道已关闭")
		return
	}
	tx, e := s.db.Begin()
	if e != nil {
		dbFailure(w, e)
		return
	}
	defer tx.Rollback()
	var wasEntry bool
	if g.ID != 0 {
		existing, err := scanGroup(tx.QueryRow(groupSelect+" WHERE id=?", g.ID))
		if err != nil || (personal && existing.Owner != u.ID) {
			fail(w, 404, "设备组不存在")
			return
		}
		if (existing.Kind == "chain") != (g.Kind == "chain") {
			fail(w, 400, "链式出口与实体设备组不能互相转换")
			return
		}
		if (g.Kind == "relay" || g.Kind == "both") && g.Kind != existing.Kind {
			fail(w, 400, "请选择仅监控、入口、出口或链式出口")
			return
		}
		wasEntry = existing.Kind == "entry" || existing.Kind == "both"
		g.Owner = existing.Owner
	} else if u.Admin {
		if !personal && (g.Kind == "relay" || g.Kind == "both") {
			fail(w, 400, "请选择仅监控、入口、出口或链式出口")
			return
		}
		g.Owner = 0
	}
	if personal {
		g.Owner, g.Kind, g.Ratio, g.UserGroup = u.ID, "exit", 1000, u.Group
		g.AllowedFrom, g.AllowedTo = nil, nil
		g.Folder, g.Note, g.ShowOrder, g.HideStatus = "", "", 0, false
		g.ConnectHost, g.FallbackGroup = "", 0
		g.Routing = wire.RelayRouting{ApplyRelayMode: g.RelayMode != ""}
	}
	g.Name = strings.TrimSpace(g.Name)
	if g.DefaultNetwork == "" {
		g.DefaultNetwork = "tcp"
	}
	if !wire.ValidRelayMode(g.RelayMode) || !slices.Contains([]string{"tcp", "udp", "both"}, g.DefaultNetwork) {
		fail(w, 400, "设备组协议无效")
		return
	}
	g.Folder, g.Note = strings.TrimSpace(g.Folder), strings.TrimSpace(g.Note)
	if g.FirstPort == 0 {
		g.FirstPort = 10000
	}
	if g.LastPort == 0 {
		g.LastPort = 65525
	}
	if g.OfflineSeconds == 0 {
		g.OfflineSeconds = 30
	}
	g.PortRanges = strings.TrimSpace(g.PortRanges)
	if g.PortRanges != "" {
		spans, err := groupPorts(g)
		if err != nil {
			fail(w, 400, err.Error())
			return
		}
		g.FirstPort, g.LastPort = spans[0].first, spans[len(spans)-1].last
	}
	if g.Name == "" || len(g.Folder) > 200 || len(g.Note) > 1000 || g.FirstPort < 1 || g.LastPort > 65535 || g.FirstPort > g.LastPort || g.Ratio < 0 || g.Ratio > 100000 || g.OfflineSeconds < 15 || g.OfflineSeconds > 3600 {
		fail(w, 400, "设备组设置无效")
		return
	}
	switch g.Kind {
	case "entry", "exit", "relay", "both", "monitor":
		g.Chain = nil
	case "chain":
		if e := validateChain(g, lookupGroup(tx)); e != nil {
			fail(w, 400, e.Error())
			return
		}
	default:
		fail(w, 400, "无效的设备组类型")
		return
	}
	if g.Kind != "entry" && g.Kind != "both" {
		if wasEntry {
			var inUse bool
			if err := tx.QueryRow("SELECT EXISTS(SELECT 1 FROM rules WHERE entry=?)", g.ID).Scan(&inUse); err != nil {
				dbFailure(w, err)
				return
			}
			if inUse {
				fail(w, 409, "此设备组仍有转发规则，请先将规则迁移到其他入口")
				return
			}
		}
		g.ReverseGroups = nil
		g.Routing.IngressMode = ""
		g.TLSIngress = 0
		g.Ingress = nil
	}
	if !slices.Contains([]string{"", "all", "admin", "none"}, g.Routing.StatusVisibility) {
		fail(w, 400, "设备组探针可见性无效")
		return
	}
	if g.Routing.StatusVisibility != "" {
		g.HideStatus = g.Routing.StatusVisibility != "all"
	}
	if !slices.Contains([]string{"", "direct", "relay", "personal"}, g.Routing.IngressMode) {
		fail(w, 400, "入口转发模式无效")
		return
	}
	if g.TLSIngress < 0 || g.TLSIngress > 2 {
		fail(w, 400, "TLS 入站策略无效")
		return
	}
	if e = validateIngress(g.Ingress); e != nil {
		fail(w, 400, e.Error())
		return
	}
	if g.Routing.IngressMode == "personal" && g.Ingress != nil && g.Ingress.BlockPersonal {
		fail(w, 400, "只允许自有出口时不能同时禁止单端出口")
		return
	}
	g.ConnectHost = strings.TrimSpace(strings.ReplaceAll(g.ConnectHost, "\r\n", "\n"))
	if g.Kind != "entry" && g.Kind != "both" {
		g.ConnectHost = ""
	}
	if len(g.ConnectHost) > 4096 || strings.ContainsAny(g.ConnectHost, "\x00\r") || strings.Count(g.ConnectHost, "\n") > 31 {
		fail(w, 400, "入口展示地址无效")
		return
	}
	if g.Kind != "exit" && g.Kind != "both" && g.Kind != "chain" {
		g.FallbackGroup = 0
	}
	if g.FallbackGroup != 0 {
		fallback, err := lookupGroup(tx)(g.FallbackGroup)
		if err != nil || fallback.ID == g.ID || (fallback.Kind != "exit" && fallback.Kind != "both" && fallback.Kind != "chain") {
			fail(w, 400, "备用出口设备组无效")
			return
		}
	}
	if g.Kind != "entry" && g.Kind != "both" && g.Kind != "relay" {
		g.Routing.IPv6Groups = nil
		g.Routing.MaxFailures, g.Routing.RecoverySeconds = 0, 0
	}
	if g.Kind != "exit" && g.Kind != "both" && g.Kind != "relay" {
		g.Routing.AddressMode, g.Routing.StaticAddress, g.Routing.NativeUDP, g.Routing.ApplyRelayMode = "", "", false, false
	}
	g.Routing.StaticAddress = strings.TrimSpace(g.Routing.StaticAddress)
	switch g.Routing.AddressMode {
	case "static":
		if !targetOK(g.Routing.StaticAddress) {
			fail(w, 400, "固定出口地址应为有效的主机及端口")
			return
		}
	case "", "ipv4", "ipv6":
		g.Routing.StaticAddress = ""
	default:
		fail(w, 400, "出口连接地址策略无效")
		return
	}
	if len(g.Routing.IPv6Groups) > 1024 || slices.ContainsFunc(g.Routing.IPv6Groups, func(id int64) bool { return id < 0 }) ||
		g.Routing.MaxFailures < 0 || g.Routing.MaxFailures > 100 || g.Routing.RecoverySeconds < 0 || g.Routing.RecoverySeconds > 3600 {
		fail(w, 400, "出口优先级或故障转移设置无效")
		return
	}
	routing, _ := json.Marshal(g.Routing)
	from, _ := json.Marshal(g.AllowedFrom)
	to, _ := json.Marshal(g.AllowedTo)
	users, _ := json.Marshal(g.UserGroups)
	chain, _ := json.Marshal(g.Chain)
	reverse, _ := json.Marshal(g.ReverseGroups)
	ingress, _ := json.Marshal(g.Ingress)
	args := []any{g.Name, g.Kind, g.FirstPort, g.LastPort, g.Ratio, g.UserGroup, g.OfflineSeconds, g.Owner, string(from), string(to), string(users), string(chain), g.PortRanges, string(reverse), g.TLSIngress, string(ingress), g.Folder, g.Note, g.ShowOrder, g.HideStatus, g.RelayMode, g.DefaultNetwork, g.ConnectHost, g.FallbackGroup, string(routing)}
	if g.ID == 0 {
		result, e := tx.Exec("INSERT INTO groups(name,kind,first_port,last_port,ratio,user_group,offline_seconds,owner,allowed_from,allowed_to,user_groups,chain,port_ranges,reverse_groups,tls_ingress,ingress,folder,note,show_order,hide_status,relay_mode,default_network,connect_host,fallback_group,routing) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", args...)
		if e != nil {
			dbFailure(w, e)
			return
		}
		g.ID, _ = result.LastInsertId()
	} else {
		result, e := tx.Exec("UPDATE groups SET name=?,kind=?,first_port=?,last_port=?,ratio=?,user_group=?,offline_seconds=?,owner=?,allowed_from=?,allowed_to=?,user_groups=?,chain=?,port_ranges=?,reverse_groups=?,tls_ingress=?,ingress=?,folder=?,note=?,show_order=?,hide_status=?,relay_mode=?,default_network=?,connect_host=?,fallback_group=?,routing=? WHERE id=?", append(args, g.ID)...)
		if e != nil {
			dbFailure(w, e)
			return
		}
		if n, _ := result.RowsAffected(); n == 0 {
			fail(w, 404, "设备组不存在")
			return
		}
		if err := s.checkGroupCapacity(tx, g.ID); err != nil {
			fail(w, 409, err.Error())
			return
		}
	}
	if e = tx.Commit(); e != nil {
		dbFailure(w, e)
		return
	}
	respond(w, 200, g)
}

func (s *Server) deleteGroup(w http.ResponseWriter, r *http.Request, u User) {
	tx, e := s.db.Begin()
	if e != nil {
		dbFailure(w, e)
		return
	}
	defer tx.Rollback()
	id := pathID(r)
	existing, e := scanGroup(tx.QueryRow(groupSelect+" WHERE id=?", id))
	if e != nil || (!u.Admin && existing.Owner != u.ID) {
		fail(w, 404, "设备组不存在")
		return
	}
	var used int
	e = tx.QueryRow("SELECT EXISTS(SELECT 1 FROM rules r, json_each(r.json,'$.path') j WHERE j.value=? UNION ALL SELECT 1 FROM rules r, json_each(r.json,'$.backupPath') j WHERE j.value=? UNION ALL SELECT 1 FROM groups g, json_each(g.chain) j WHERE j.value=? UNION ALL SELECT 1 FROM groups WHERE fallback_group=?)", id, id, id, id).Scan(&used)
	if e != nil {
		dbFailure(w, e)
		return
	}
	if used != 0 {
		fail(w, 409, "设备组仍被链路使用")
		return
	}
	if _, e = tx.Exec("DELETE FROM groups WHERE id=?", id); e != nil {
		fail(w, 409, "设备组仍有节点或规则")
		return
	}
	if e = tx.Commit(); e != nil {
		dbFailure(w, e)
		return
	}
	w.WriteHeader(204)
}

type ruleRow struct {
	Runtime    string `json:"runtime"`
	ReportedAt int64  `json:"reportedAt,omitempty"`
	OwnerName  string `json:"ownerName,omitempty"`
	wire.Rule
	In               int64  `json:"in"`
	Out              int64  `json:"out"`
	EffectiveNetwork string `json:"effectiveNetwork"`
}

func (s *Server) ruleCount(w http.ResponseWriter, r *http.Request, u User) {
	where, args, err := s.ruleFilters(r, u)
	if err != nil {
		dbFailure(w, err)
		return
	}
	query := "SELECT count(*) FROM rules r JOIN groups g ON g.id=r.entry" + where
	var total int
	if err := s.db.QueryRowContext(r.Context(), query, args...).Scan(&total); err != nil {
		dbFailure(w, err)
		return
	}
	respond(w, 200, map[string]int{"total": total})
}

func (s *Server) ruleFilters(r *http.Request, u User) (string, []any, error) {
	q := " WHERE 1=1"
	var args []any
	if id, _ := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64); id > 0 {
		q += " AND r.id=?"
		args = append(args, id)
	}
	if !u.Admin {
		q += " AND r.owner=?"
		args = append(args, u.ID)
	} else if owner, _ := strconv.ParseInt(r.URL.Query().Get("owner"), 10, 64); owner > 0 {
		q += " AND r.owner=?"
		args = append(args, owner)
	}
	if search := r.URL.Query().Get("q"); search != "" {
		q += " AND (instr(json_extract(r.json,'$.name'),?)>0 OR instr(r.json,?)>0)"
		args = append(args, search, search)
	}
	if name := strings.TrimSpace(r.URL.Query().Get("name")); name != "" {
		q += " AND instr(lower(json_extract(r.json,'$.name')),lower(?))>0"
		args = append(args, name)
	}
	if entry, _ := strconv.ParseInt(r.URL.Query().Get("entry"), 10, 64); entry > 0 {
		q += " AND r.entry=?"
		args = append(args, entry)
	}
	if exit := r.URL.Query().Get("exit"); exit == "0" {
		q += " AND coalesce(json_array_length(json_extract(r.json,'$.path')),0)=0"
	} else if id, _ := strconv.ParseInt(exit, 10, 64); id > 0 {
		q += " AND json_extract(r.json,'$.path[#-1]')=?"
		args = append(args, id)
	}
	if port, _ := strconv.Atoi(r.URL.Query().Get("port")); port >= 1 && port <= 65535 {
		q += " AND r.port=?"
		args = append(args, port)
	}
	if target := strings.TrimSpace(r.URL.Query().Get("target")); target != "" {
		q += " AND EXISTS(SELECT 1 FROM json_each(r.json,'$.targets') WHERE instr(lower(value),lower(?))>0)"
		args = append(args, target)
	}
	if label := r.URL.Query().Get("label"); label != "" {
		q += " AND json_extract(r.json,'$.label')=?"
		args = append(args, label)
	} else if r.URL.Query().Get("ungrouped") == "1" {
		q += " AND coalesce(json_extract(r.json,'$.label'),'')=''"
	}
	if state := r.URL.Query().Get("state"); state == "enabled" || state == "disabled" {
		q += " AND coalesce(json_extract(r.json,'$.enabled'),0)=?"
		args = append(args, state == "enabled")
	} else if state == "failed" {
		ids, err := s.failedRuleEntries()
		if err != nil {
			return "", nil, err
		}
		groups, _ := json.Marshal(ids)
		q += " AND json_extract(r.json,'$.enabled')=1 AND r.entry IN (SELECT value FROM json_each(?))"
		args = append(args, string(groups))
	}
	return q, args, nil
}

func (s *Server) listRules(w http.ResponseWriter, r *http.Request, u User) {
	cursor, _ := strconv.ParseInt(r.URL.Query().Get("before"), 10, 64)
	if cursor < 1 {
		cursor = 1 << 62
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit < 1 || limit > 1000 {
		limit = 100
	}
	where, args, err := s.ruleFilters(r, u)
	if err != nil {
		dbFailure(w, err)
		return
	}
	ownerName := "''"
	if u.Admin && r.URL.Query().Get("owners") == "1" {
		ownerName = "(SELECT name FROM users WHERE id=r.owner)"
	}
	q := "SELECT r.id,r.owner,r.json,coalesce(t.inbound,0),coalesce(t.outbound,0),g.default_network,g.ingress," + ownerName + " FROM rules r JOIN groups g ON g.id=r.entry LEFT JOIN traffic t ON r.id=t.rule_id" + where + " AND r.id<?"
	args = append(args, cursor)
	order := "r.id DESC"
	query := r.URL.Query()
	column, direction := "", "ASC"
	switch query.Get("sort") {
	case "name":
		column = "json_extract(r.json,'$.name') COLLATE NOCASE"
	case "port":
		column = "r.port"
	case "traffic":
		column, direction = "(coalesce(t.inbound,0)+coalesce(t.outbound,0))", "DESC"
	case "entry":
		column = "g.name COLLATE NOCASE"
	case "exit":
		column = "coalesce((SELECT name FROM groups WHERE id=json_extract(r.json,'$.path[#-1]')), '') COLLATE NOCASE"
	}
	if column != "" {
		switch query.Get("direction") {
		case "asc":
			direction = "ASC"
		case "desc":
			direction = "DESC"
		}
		order = column + " " + direction + ", r.id DESC"
	}
	offset, _ := strconv.Atoi(query.Get("offset"))
	rows, e := s.db.Query(q+" ORDER BY "+order+" LIMIT ? OFFSET ?", append(args, limit, max(offset, 0))...)
	if e != nil {
		dbFailure(w, e)
		return
	}
	defer rows.Close()
	list := []ruleRow{}
	for rows.Next() {
		var row ruleRow
		var raw, ingress string
		var group wire.DeviceGroup
		var id, owner int64
		if e = rows.Scan(&id, &owner, &raw, &row.In, &row.Out, &group.DefaultNetwork, &ingress, &row.OwnerName); e == nil {
			e = json.Unmarshal([]byte(raw), &row.Rule)
		}
		if e == nil {
			e = json.Unmarshal([]byte(ingress), &group.Ingress)
		}
		if e != nil {
			dbFailure(w, e)
			return
		}
		row.ID, row.Owner = id, owner
		row.EffectiveNetwork = group.RuleNetwork(row.Rule)
		if group.Ingress.BlocksUDP() && row.EffectiveNetwork == "both" {
			row.EffectiveNetwork = "tcp"
		}
		list = append(list, row)
	}
	if e = rows.Err(); e != nil {
		dbFailure(w, e)
		return
	}
	if err := rows.Close(); err != nil {
		dbFailure(w, err)
		return
	}
	if err := s.ruleRuntimeStatus(list); err != nil {
		dbFailure(w, err)
		return
	}
	respond(w, 200, list)
}

func targetOK(target string) bool {
	host, port, e := net.SplitHostPort(target)
	n, parse := strconv.Atoi(port)
	return e == nil && parse == nil && n > 0 && n <= 65535 && host != "" && !strings.ContainsAny(host, " /\t\r\n")
}

type groupLookup func(int64) (wire.DeviceGroup, error)

func lookupGroup(tx *sql.Tx) groupLookup {
	return func(id int64) (wire.DeviceGroup, error) {
		return scanGroup(tx.QueryRow(groupSelect+" WHERE id=?", id))
	}
}

func validateChain(g wire.DeviceGroup, lookup groupLookup) error {
	if g.Owner != 0 || len(g.Chain) < 2 || len(g.Chain) > 8 {
		return errors.New("链式出口需要 2 至 8 个站点设备组")
	}
	seen := map[int64]bool{g.ID: true}
	for i, id := range g.Chain {
		hop, err := lookup(id)
		if err != nil || hop.Owner != 0 || seen[id] || (hop.Kind != "exit" && hop.Kind != "both" && (hop.Kind != "relay" || i == len(g.Chain)-1)) {
			return errors.New("链式出口包含无效、重复或非站点设备组")
		}
		seen[id] = true
	}
	return nil
}

func allowsLink(from, to wire.DeviceGroup) bool {
	allowed := len(from.AllowedTo) == 0 || slices.Contains(from.AllowedTo, to.ID)
	if from.Routing.IngressMode == "personal" {
		allowed = to.Owner != 0
	}
	if to.Owner != 0 && from.Ingress != nil {
		if from.Ingress.BlockPersonal {
			return false
		}
		if from.Ingress.SiteOutboundOnly {
			allowed = true
		}
	}
	return allowed && (len(to.AllowedFrom) == 0 || slices.Contains(to.AllowedFrom, from.ID))
}

func resolvePath(u User, entry wire.DeviceGroup, path []int64, lookup groupLookup) ([]int64, int64, error) {
	if len(path) > 8 {
		return nil, 0, errors.New("一条链路支持 8 跳")
	}
	if entry.Routing.IngressMode == "personal" && len(path) > 1 {
		return nil, 0, errors.New("该入口只允许一个自有出口")
	}
	seen := map[int64]bool{entry.ID: true}
	prev := entry
	for i, id := range path {
		hop, err := lookup(id)
		if err != nil || !canUse(u, hop) || seen[id] {
			return nil, 0, errors.New("链路包含无权限、无效或重复设备组")
		}
		if entry.Routing.IngressMode == "personal" && hop.Owner != u.ID {
			return nil, 0, errors.New("该入口只允许使用本用户的自有出口")
		}
		if hop.Owner != 0 && i != len(path)-1 {
			return nil, 0, errors.New("自有出口只能作为链路的最后一跳")
		}
		if !allowsLink(prev, hop) {
			return nil, 0, errors.New("相邻设备组之间不允许转发")
		}
		switch hop.Kind {
		case "chain":
			if len(path) != 1 || slices.Contains(hop.Chain, entry.ID) {
				return nil, 0, errors.New("虚拟链式出口须独立选择且不能包含入口")
			}
			if err = validateChain(hop, lookup); err != nil {
				return nil, 0, err
			}
			return hop.Chain, hop.Ratio, nil
		case "exit", "both":
		case "relay":
			if i == len(path)-1 {
				return nil, 0, errors.New("链路末端须为出口设备组")
			}
		default:
			return nil, 0, errors.New("无效的链路设备组")
		}
		prev = hop
		seen[id] = true
	}
	if len(path) == 0 {
		return nil, 0, nil
	}
	return path, prev.Ratio, nil
}

func validRule(tx *sql.Tx, u User, rule *wire.Rule) error {
	if rule.ProbeInterval != 0 && rule.ProbeInterval != 60 && rule.ProbeInterval != 300 {
		return errors.New("采样间隔请选择继承站点设置、1 分钟或 5 分钟")
	}
	rule.Name = strings.TrimSpace(rule.Name)
	rule.Label = strings.TrimSpace(rule.Label)
	if rule.Name == "" || len(rule.Name) > 200 || !validRuleFolder(rule.Label) || (!rule.TLSShared && len(rule.Targets) == 0) || len(rule.Targets) > 32 {
		return errors.New("请确认名称、分组与目标地址")
	}
	for i, target := range rule.Targets {
		target = strings.TrimSpace(target)
		if !targetOK(target) {
			return errors.New("目标必须是有效的 host:port，IPv6 地址请使用方括号")
		}
		rule.Targets[i] = target
	}
	if rule.Protocol == "" {
		rule.Protocol = "tcp"
	}
	switch rule.Protocol {
	case "tcp", "udp", "both", "inherit", "haproxy-tcp", "haproxy-both":
	default:
		return errors.New("无效的转发协议")
	}
	if rule.Strategy == "" {
		rule.Strategy = "round-robin"
	}
	switch rule.Strategy {
	case "round-robin", "random", "first", "ip-hash", "least-connections":
	default:
		return errors.New("无效的负载均衡策略")
	}
	if (rule.TLSCert == "") != (rule.TLSKey == "") {
		return errors.New("TLS 需要证书及私钥")
	}
	if rule.HasTLSPolicy() && rule.TLSCert == "" && rule.TLSSharedPort == 0 {
		return errors.New("TLS 握手限制需要证书及私钥")
	}
	if rule.TLSCert != "" {
		if _, err := tls.X509KeyPair([]byte(rule.TLSCert), []byte(rule.TLSKey)); err != nil {
			return errors.New("TLS 证书或私钥无效")
		}
	}
	if len(rule.TLSServerNames) > 32 || len(rule.TLSALPN) > 32 || (rule.TLSRequireEmpty && len(rule.TLSServerNames) > 0) {
		return errors.New("TLS 握手限制无效")
	}
	if rule.TLSOrigin < 0 || rule.TLSOrigin > 3 {
		return errors.New("回源 TLS 模式无效")
	}
	if len(rule.ResponseFilters) > 5 || slices.ContainsFunc(rule.ResponseFilters, func(value int) bool {
		return (value < 1 || value > 4) && value != 2000
	}) {
		return errors.New("回源响应筛选设置无效")
	}
	for i, name := range rule.TLSServerNames {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" || len(name) > 253 || strings.ContainsAny(name, " ,/\\\t\r\n") {
			return errors.New("TLS SNI 无效")
		}
		rule.TLSServerNames[i] = name
	}
	slices.Sort(rule.TLSServerNames)
	rule.TLSServerNames = slices.Compact(rule.TLSServerNames)
	for _, protocol := range rule.TLSALPN {
		if protocol == "" || len(protocol) > 255 {
			return errors.New("TLS ALPN 无效")
		}
	}
	if rule.ProxyInVersion < 0 || rule.ProxyInVersion > 2 || rule.ProxyOutVersion < 0 || rule.ProxyOutVersion > 2 {
		return errors.New("Proxy Protocol 版本无效")
	}
	if rule.Protocol != "tcp" && rule.Protocol != "inherit" && (rule.ProxyIn || (rule.ProxyOut && rule.ProxyOutVersion != 2) || rule.TLSCert != "" || rule.UsesSharedTLS()) {
		return errors.New("UDP 规则支持发送 Proxy Protocol v2，接收 Proxy Protocol 和 TLS 需要 TCP")
	}
	if rule.RateMbps < 0 || rule.RateMbps > 100000 || rule.MaxIPs < 0 || rule.MaxConns < 0 {
		return errors.New("规则限额无效")
	}
	lookup := lookupGroup(tx)
	g, e := lookup(rule.Entry)
	if errors.Is(e, sql.ErrNoRows) {
		return errors.New("入口设备组不存在")
	}
	if e != nil || !canUse(u, g) || (g.Kind != "entry" && g.Kind != "both") {
		return errors.New("入口设备组不可用")
	}
	if !g.AllowsIngressPath(*rule) {
		return errors.New("出口选择不符合入口设备组的直出或中转设置")
	}
	if !g.AllowsIngress(*rule) {
		return errors.New("规则不符合入口设备组的 TLS 入站策略")
	}
	if rule.UsesHAProxy() {
		if err := validateHAProxyRule(u, g, *rule); err != nil {
			return err
		}
	}
	if g.RuleNetwork(*rule) == "udp" && g.Ingress != nil && (g.Ingress.DisableUDP || len(g.Ingress.AllowedHosts) > 0) {
		return errors.New("该入口设备组禁止 UDP")
	}
	if e = validateSharedTLS(tx, u, rule); e != nil {
		return e
	}
	for _, path := range [][]int64{rule.Path, rule.BackupPath} {
		if _, _, e = resolvePath(u, g, path, lookup); e != nil {
			return e
		}
	}
	return selectRulePort(tx, g, rule)
}

func storeRule(tx *sql.Tx, u User, rule *wire.Rule) error {
	if rule.ID == 0 {
		if rule.Owner == 0 || !u.Admin {
			rule.Owner = u.ID
		}
	} else {
		var owner int64
		var previous string
		if e := tx.QueryRow("SELECT owner,json FROM rules WHERE id=?", rule.ID).Scan(&owner, &previous); e != nil || (!u.Admin && owner != u.ID) {
			return errors.New("规则不存在")
		}
		var old wire.Rule
		if err := json.Unmarshal([]byte(previous), &old); err != nil {
			return err
		}
		if old.Enabled && rule.Enabled && old.UsesHAProxy() != rule.UsesHAProxy() {
			return errors.New("请先暂停规则，等入口节点释放监听端口后再切换转发方式")
		}
		rule.Owner = owner
	}
	owner, e := readUser(tx.QueryRow(userSelect+" WHERE id=?", rule.Owner))
	if e != nil {
		return errors.New("用户不存在")
	}
	if !owner.Admin && (owner.Banned || owner.Expires <= time.Now().Unix() || (owner.Quota > 0 && owner.Used >= owner.Quota)) {
		return errors.New("该用户套餐不可用")
	}
	if rule.ID == 0 && !owner.Admin && (owner.MaxRules > 0 || owner.PlanID == 0) {
		var count int
		if e = tx.QueryRow("SELECT count(*) FROM rules WHERE owner=?", owner.ID).Scan(&count); e != nil {
			return e
		}
		if count >= owner.MaxRules {
			return errors.New("规则数已达到套餐额度")
		}
	}
	if rule.TLSGenerateFor != "" {
		host := strings.TrimSpace(rule.TLSGenerateFor)
		address := net.JoinHostPort(host, "443")
		validName := net.ParseIP(host) != nil || validTLSName(host)
		if !validName || rule.TLSSharedPort != 0 || rule.TLSCert != "" || rule.TLSKey != "" {
			return errors.New("自签证书需要有效的域名或 IP，且证书与私钥须留空")
		}
		rule.TLSCert, rule.TLSKey, e = certificate.SelfSigned(address)
		if e != nil {
			return fmt.Errorf("生成自签证书: %w", e)
		}
		rule.TLSGenerateFor = ""
	}
	if e = validRule(tx, owner, rule); e != nil {
		return e
	}
	var occupied bool
	if e = tx.QueryRow("SELECT EXISTS(SELECT 1 FROM rules WHERE entry=? AND port=? AND id<>?)", rule.Entry, rule.Port, rule.ID).Scan(&occupied); e != nil {
		return e
	}
	if occupied {
		return fmt.Errorf("入口端口 %d 已分配给其他规则", rule.Port)
	}
	if rule.UsesHAProxy() {
		if (owner.RateOverride != nil && *owner.RateOverride > 0) || (owner.IPsOverride != nil && *owner.IPsOverride > 0) ||
			(owner.ConnectionsOverride != nil && *owner.ConnectionsOverride > 0) {
			return errors.New("规则所属账号设有限额，请选择内置转发")
		}
		var restricted bool
		if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM plans WHERE id=? AND
			(coalesce(?,rate_mbps)>0 OR coalesce(?,max_ips)>0 OR coalesce(?,max_connections)>0))`,
			owner.PlanID, owner.RateOverride, owner.IPsOverride, owner.ConnectionsOverride).Scan(&restricted); err != nil {
			return err
		}
		if restricted {
			return errors.New("规则所属账号设有限额，请选择内置转发")
		}
	}
	raw, e := json.Marshal(rule)
	if e != nil {
		return e
	}
	if rule.ID == 0 {
		result, e := tx.Exec("INSERT INTO rules(owner,entry,port,json) VALUES(?,?,?,?)", rule.Owner, rule.Entry, rule.Port, string(raw))
		if e != nil {
			return errors.New("入口端口已占用，或规则无法保存")
		}
		rule.ID, e = result.LastInsertId()
		return e
	}
	_, e = tx.Exec("UPDATE rules SET entry=?,port=?,json=? WHERE id=?", rule.Entry, rule.Port, string(raw), rule.ID)
	if e != nil {
		return errors.New("入口端口已占用，或规则无法保存")
	}
	return nil
}

func validTLSName(host string) bool {
	if len(host) > 253 {
		return false
	}
	for label := range strings.SplitSeq(strings.TrimSuffix(host, "."), ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if !(char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '-') {
				return false
			}
		}
	}
	return true
}

func (s *Server) checkGroupCapacity(tx *sql.Tx, group int64) error {
	if group == 0 {
		return nil
	}
	var tcp, udp int
	err := tx.QueryRow(`WITH per_rule AS (
		SELECT CASE WHEN json_extract(r.json,'$.protocol')='haproxy-both' THEN 'both'
			WHEN json_extract(r.json,'$.protocol')='inherit' THEN
			CASE WHEN json_extract(r.json,'$.proxyIn')=1 OR (json_extract(r.json,'$.proxyOut')=1 AND coalesce(json_extract(r.json,'$.proxyOutVersion'),0)<>2)
				OR coalesce(json_extract(r.json,'$.tlsCert'),'')<>'' OR json_extract(r.json,'$.tlsShared')=1 THEN 'tcp' ELSE g.default_network END
			ELSE json_extract(r.json,'$.protocol') END AS network,
			coalesce(json_extract(g.ingress,'$.disableUDP'),0)=1 OR coalesce(json_array_length(g.ingress,'$.allowedHosts'),0)>0 AS no_udp
		FROM rules r JOIN groups g ON g.id=r.entry
		WHERE r.entry=? AND json_extract(r.json,'$.enabled')=1 AND coalesce(json_extract(r.json,'$.tlsSharedPort'),0)=0
		) SELECT coalesce(sum(network<>'udp'),0),coalesce(sum(NOT no_udp AND network IN ('udp','both')),0)
		FROM per_rule`, group).Scan(&tcp, &udp)
	if err != nil {
		return err
	}
	hasCapacity := false
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, device := range s.devices {
		if device.GroupID != group || device.Metrics.ListenerLimit <= 0 {
			continue
		}
		hasCapacity = true
		tcpBinds := min(max(1, device.Metrics.BindAddresses), device.Metrics.ListenerLimit+1)
		udpBinds := device.Metrics.UDPBindAddresses
		if udpBinds <= 0 {
			udpBinds = tcpBinds
		}
		need := tcp*tcpBinds + udp*udpBinds
		if need > device.Metrics.ListenerLimit {
			return fmt.Errorf("%s 的监听容量为 %d，发布会需要 %d 个监听", device.Name, device.Metrics.ListenerLimit, need)
		}
	}
	if !hasCapacity && tcp+udp > 1024 {
		return fmt.Errorf("入口组尚无容量上报，发布需要 %d 个监听，默认上限为 1024", tcp+udp)
	}
	return nil
}

func (s *Server) saveRule(w http.ResponseWriter, r *http.Request, u User) {
	var rule wire.Rule
	if !decode(w, r, &rule) {
		return
	}
	rule.ID = pathID(r)
	tx, e := s.db.Begin()
	if e != nil {
		dbFailure(w, e)
		return
	}
	defer tx.Rollback()
	if e = storeRule(tx, u, &rule); e != nil {
		fail(w, 400, e.Error())
		return
	}
	if rule.Enabled {
		if e = s.checkGroupCapacity(tx, rule.Entry); e != nil {
			fail(w, 409, e.Error())
			return
		}
	}
	if e = tx.Commit(); e != nil {
		dbFailure(w, e)
		return
	}
	respond(w, 200, rule)
}

func (s *Server) deleteRule(w http.ResponseWriter, r *http.Request, u User) {
	result, e := s.db.Exec("DELETE FROM rules WHERE id=? AND (owner=? OR ?)", pathID(r), u.ID, u.Admin)
	if e != nil {
		dbFailure(w, e)
		return
	}
	if n, _ := result.RowsAffected(); n == 0 {
		fail(w, 404, "规则不存在")
		return
	}
	w.WriteHeader(204)
}

func (s *Server) batchRules(w http.ResponseWriter, r *http.Request, u User) {
	var input struct {
		Action     string
		IDs        []int64
		Rules      []wire.Rule
		Label      string
		Entry      int64
		Path       []int64
		UpdatePath bool
	}
	if !decode(w, r, &input) {
		return
	}
	if len(input.IDs) > 1000 || len(input.Rules) > 1000 {
		fail(w, 400, "单批最多 1000 条规则")
		return
	}
	switch input.Action {
	case "import":
		if len(input.Rules) == 0 || len(input.IDs) != 0 {
			fail(w, 400, "请提供要导入的规则")
			return
		}
	case "enable", "disable", "label", "clear", "delete", "reroute":
		if len(input.IDs) == 0 || len(input.Rules) != 0 {
			fail(w, 400, "请选择要操作的规则")
			return
		}
	default:
		fail(w, 400, "未知批量操作")
		return
	}
	seen := make(map[int64]struct{}, len(input.IDs))
	for _, id := range input.IDs {
		if _, duplicate := seen[id]; id <= 0 || duplicate {
			fail(w, 400, "规则 ID 无效或重复")
			return
		}
		seen[id] = struct{}{}
	}
	if input.Action == "reroute" && (input.Entry < 0 || (input.Entry == 0 && !input.UpdatePath)) {
		fail(w, 400, "请选择新入口或出口")
		return
	}
	if input.Action == "label" {
		input.Label = strings.TrimSpace(input.Label)
		if !validRuleFolder(input.Label) {
			fail(w, 400, "规则分组名称无效")
			return
		}
	}
	tx, e := s.db.BeginTx(r.Context(), nil)
	if e != nil {
		dbFailure(w, e)
		return
	}
	defer tx.Rollback()
	affected := make(map[int64]bool)
	if input.Action == "import" {
		slices.SortStableFunc(input.Rules, func(a, b wire.Rule) int {
			if a.TLSShared == b.TLSShared {
				return 0
			}
			if a.TLSShared {
				return -1
			}
			return 1
		})
		for i := range input.Rules {
			input.Rules[i].ID = 0
			if e = storeRule(tx, u, &input.Rules[i]); e != nil {
				fail(w, 400, "第 "+strconv.Itoa(i+1)+" 条规则："+e.Error())
				return
			}
			if input.Rules[i].Enabled {
				affected[input.Rules[i].Entry] = true
			}
		}
	} else {
		for _, id := range input.IDs {
			var owner, group int64
			e = tx.QueryRow("SELECT owner,entry FROM rules WHERE id=?", id).Scan(&owner, &group)
			if errors.Is(e, sql.ErrNoRows) || (e == nil && owner != u.ID && !u.Admin) {
				fail(w, 404, "规则不存在")
				return
			}
			if e != nil {
				dbFailure(w, e)
				return
			}
			switch input.Action {
			case "reroute":
				var rule wire.Rule
				rule, e = rerouteRule(tx, u, id, input.Entry, input.Path, input.UpdatePath)
				if e != nil {
					fail(w, 400, "规则 #"+strconv.FormatInt(id, 10)+"："+e.Error())
					return
				}
				if rule.Enabled {
					affected[rule.Entry] = true
				}
			case "enable", "disable":
				value := "false"
				if input.Action == "enable" {
					value = "true"
					affected[group] = true
				}
				_, e = tx.Exec("UPDATE rules SET json=json_set(json,'$.enabled',json(?)) WHERE id=?", value, id)
			case "label":
				_, e = tx.Exec("UPDATE rules SET json=json_set(json,'$.label',?) WHERE id=?", input.Label, id)
			case "clear":
				_, e = tx.Exec("DELETE FROM traffic WHERE rule_id=?", id)
			case "delete":
				_, e = tx.Exec("DELETE FROM rules WHERE id=?", id)
			}
			if e != nil {
				dbFailure(w, e)
				return
			}
		}
	}
	for group := range affected {
		if e = s.checkGroupCapacity(tx, group); e != nil {
			fail(w, 409, e.Error())
			return
		}
	}
	if e = tx.Commit(); e != nil {
		dbFailure(w, e)
		return
	}
	respond(w, 200, map[string]any{"rules": input.Rules, "count": len(input.IDs) + len(input.Rules)})
}

func (s *Server) updateRulesByPort(w http.ResponseWriter, r *http.Request, u User) {
	var input struct {
		Entry   int64
		Owner   int64
		Changes []struct {
			Port   int
			Config json.RawMessage
		}
	}
	if !decode(w, r, &input) {
		return
	}
	if input.Entry < 1 || len(input.Changes) < 1 || len(input.Changes) > 1000 {
		fail(w, 400, "请选择入口并填写 1 至 1000 条规则")
		return
	}
	if !u.Admin || input.Owner < 1 {
		input.Owner = u.ID
	}
	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		dbFailure(w, err)
		return
	}
	defer tx.Rollback()
	seen := make(map[int]bool, len(input.Changes))
	for i, change := range input.Changes {
		prefix := fmt.Sprintf("第 %d 条规则：", i+1)
		if change.Port < 1 || change.Port > 65535 || seen[change.Port] {
			fail(w, 400, prefix+"监听端口缺失或重复，或未指定修改内容")
			return
		}
		seen[change.Port] = true
		var raw []byte
		var id int64
		err := tx.QueryRow("SELECT id,json FROM rules WHERE entry=? AND port=? AND owner=?", input.Entry, change.Port, input.Owner).Scan(&id, &raw)
		if errors.Is(err, sql.ErrNoRows) {
			fail(w, 404, prefix+"未找到对应端口的规则")
			return
		}
		var rule wire.Rule
		if err == nil {
			err = json.Unmarshal(raw, &rule)
		}
		if err != nil {
			dbFailure(w, err)
			return
		}
		rule.ID = id
		if err = applyRulePortChanges(&rule, change.Config); err != nil {
			fail(w, 400, prefix+err.Error())
			return
		}
		if err = storeRule(tx, u, &rule); err != nil {
			fail(w, 400, prefix+err.Error())
			return
		}
	}
	if err = s.checkGroupCapacity(tx, input.Entry); err != nil {
		fail(w, 409, err.Error())
		return
	}
	if err = tx.Commit(); err != nil {
		dbFailure(w, err)
		return
	}
	respond(w, 200, map[string]int{"count": len(input.Changes)})
}

func applyRulePortChanges(rule *wire.Rule, raw json.RawMessage) error {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields) == 0 {
		return errors.New("请提供要修改的规则字段")
	}
	for key := range fields {
		switch key {
		case "name", "targets", "strategy", "protocol", "proxyIn", "proxyInVersion", "proxyOut", "proxyOutVersion",
			"rateMbps", "maxIPs", "maxConns", "tlsCert", "tlsKey", "tlsGenerateFor", "tlsShared", "tlsSharedPort",
			"tlsAllowedNames", "tlsAllowedUsers", "tlsOrigin", "tlsRequireEmpty", "tlsServerNames", "tlsALPN", "responseFilters", "udpProbe", "probeInterval":
		default:
			return fmt.Errorf("不支持修改 %s", key)
		}
	}
	if err := json.Unmarshal(raw, rule); err != nil {
		return errors.New("规则字段类型错误")
	}
	return nil
}
