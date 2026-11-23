package panel

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"hopx/internal/wire"
)

func (s *Server) enrollment(w http.ResponseWriter, r *http.Request, u User) {
	id := pathID(r)
	ctx := r.Context()
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		dbFailure(w, e)
		return
	}
	defer tx.Rollback()
	g, e := scanGroup(tx.QueryRowContext(ctx, groupSelect+" WHERE id=?", id))
	if errors.Is(e, sql.ErrNoRows) || (e == nil && (g.Kind == "chain" || (!u.Admin && g.Owner != u.ID))) {
		fail(w, 404, "设备组不存在")
		return
	}
	if e != nil {
		dbFailure(w, e)
		return
	}
	var key string
	e = tx.QueryRowContext(ctx, "SELECT token FROM group_enrollments WHERE group_id=?", id).Scan(&key)
	if errors.Is(e, sql.ErrNoRows) {
		key = token()
		_, e = tx.ExecContext(ctx, "INSERT INTO group_enrollments(group_id,token) VALUES(?,?)", id, key)
	}
	if e != nil {
		dbFailure(w, e)
		return
	}
	if e = tx.Commit(); e != nil {
		dbFailure(w, e)
		return
	}
	base := s.publicURL
	if base == "" {
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		base = scheme + "://" + r.Host
	}
	w.Header().Set("Cache-Control", "no-store")
	respond(w, 201, map[string]any{"token": key, "panel": base, "groupName": g.Name, "installMirror": s.setting("nodeInstallMirror", ""), "relay": g.Kind != "entry" && g.Kind != "monitor", "relayMode": g.RelayMode, "reverseIngress": g.Kind == "entry" || g.Kind == "both", "reverseEgress": g.Kind == "exit" || g.Kind == "relay"})
}

func bearer(r *http.Request) string {
	scheme, credential, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || len(credential) > 96 {
		return ""
	}
	return credential
}

func (s *Server) registerNode(w http.ResponseWriter, r *http.Request) {
	var input wire.Registration
	credential := bearer(r)
	if len(credential) < 26 || len(credential) > 96 {
		fail(w, 401, "注册凭据无效或过期")
		return
	}
	if !decodeLimit(w, r, &input, 32<<10) {
		return
	}
	if strings.TrimSpace(input.Name) == "" || len(input.Name) > 96 || len(input.Region) > 64 || len(input.Address) > 256 {
		fail(w, 400, "节点信息无效")
		return
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		if ip := net.ParseIP(host); ip != nil && ip.IsGlobalUnicast() && !ip.IsPrivate() {
			if ip.To4() != nil && input.IPv4 == "" {
				input.IPv4 = host
			}
			if ip.To4() == nil && input.IPv6 == "" {
				input.IPv6 = host
			}
		}
	}
	if input.IPv4 != "" && net.ParseIP(input.IPv4).To4() == nil {
		fail(w, 400, "IPv4 无效")
		return
	}
	if input.IPv6 != "" && (net.ParseIP(input.IPv6) == nil || net.ParseIP(input.IPv6).To4() != nil) {
		fail(w, 400, "IPv6 无效")
		return
	}
	if !wire.ValidRelayMode(input.RelayTransport) {
		fail(w, 400, "中转传输无效")
		return
	}
	if input.ReverseAddress != "" {
		block, _ := pem.Decode([]byte(input.ReverseCertificate))
		if !targetOK(input.ReverseAddress) || len(input.ReverseToken) != 52 || block == nil {
			fail(w, 400, "反向入口设置无效")
			return
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			fail(w, 400, "反向入口证书无效")
			return
		}
	}
	if input.ReverseID != "" && (len(input.ReverseID) != 26 || len(input.RelayToken) != 52 || input.RelayAddress != "") {
		fail(w, 400, "反向出口设置无效")
		return
	}
	if input.RelayAddress != "" {
		block, _ := pem.Decode([]byte(input.RelayCert))
		if !targetOK(input.RelayAddress) || block == nil || len(input.RelayToken) < 32 {
			fail(w, 400, "中转监听信息无效")
			return
		}
		if _, e := x509.ParseCertificate(block.Bytes); e != nil {
			fail(w, 400, "中转证书无效")
			return
		}
	}
	tx, e := s.db.BeginTx(r.Context(), nil)
	if e != nil {
		dbFailure(w, e)
		return
	}
	defer tx.Rollback()
	var id int64
	e = tx.QueryRow("SELECT group_id FROM group_enrollments WHERE token=?", credential).Scan(&id)
	if errors.Is(e, sql.ErrNoRows) {
		e = tx.QueryRow("DELETE FROM invitations WHERE token=? AND expires>unixepoch() RETURNING group_id", digest(credential)).Scan(&id)
	}
	if e == sql.ErrNoRows {
		fail(w, 401, "注册凭据无效或过期")
		return
	}
	if e != nil {
		dbFailure(w, e)
		return
	}
	g, e := scanGroup(tx.QueryRow(groupSelect+" WHERE id=?", id))
	if e != nil {
		dbFailure(w, e)
		return
	}
	if g.Kind == "chain" {
		fail(w, 400, "链式出口无需注册实体节点")
		return
	}
	if input.ReverseAddress != "" && g.Kind != "entry" && g.Kind != "both" {
		fail(w, 400, "反向监听只在入口组使用")
		return
	}
	if input.ReverseID != "" && g.Kind != "exit" && g.Kind != "relay" {
		fail(w, 400, "反向节点需要出口或中转组")
		return
	}
	if input.ReverseID != "" {
		var duplicate bool
		if e = tx.QueryRow("SELECT EXISTS(SELECT 1 FROM devices WHERE json_extract(registration,'$.reverseId')=?)", input.ReverseID).Scan(&duplicate); e != nil {
			dbFailure(w, e)
			return
		}
		if duplicate {
			fail(w, 409, "反向节点标识已注册")
			return
		}
	}
	if g.Kind != "entry" && g.Kind != "monitor" && input.RelayAddress == "" && input.ReverseID == "" {
		fail(w, 400, "此设备组需要中转监听地址")
		return
	}
	key := token()
	payload, _ := json.Marshal(input)
	result, e := tx.Exec("INSERT INTO devices(group_id,token,registration) VALUES(?,?,?)", id, digest(key), string(payload))
	if e != nil {
		dbFailure(w, e)
		return
	}
	nodeID, e := result.LastInsertId()
	if e == nil {
		e = tx.Commit()
	}
	if e != nil {
		dbFailure(w, e)
		return
	}
	respond(w, 201, wire.Identity{ID: nodeID, Token: key})
}

func (s *Server) deviceSnapshot(forRouting bool) ([]wire.Device, error) {
	return s.deviceGroupSnapshot(forRouting, 0)
}

func (s *Server) deviceGroupSnapshot(forRouting bool, group int64) ([]wire.Device, error) {
	now := time.Now()
	lastBucket := "0"
	if forRouting && now.Before(s.warmUntil) {
		// Until the first new heartbeats arrive, use recent samples to preserve relay routes.
		lastBucket = "coalesce((SELECT bucket FROM probe_samples WHERE node=d.id ORDER BY bucket DESC LIMIT 1),0)"
	}
	query := "SELECT d.id,d.group_id,d.registration,g.offline_seconds,d.last_seen,d.token LIKE 'revoked:%'," + lastBucket + " FROM devices d JOIN groups g ON g.id=d.group_id"
	var args []any
	if group != 0 {
		query += " WHERE d.group_id=?"
		args = append(args, group)
	}
	rows, e := s.db.Query(query+" ORDER BY d.id", args...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	all := []wire.Device{}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for rows.Next() {
		var id, group, last, lastSeen int64
		var raw string
		var timeout int
		var revoked bool
		if e = rows.Scan(&id, &group, &raw, &timeout, &lastSeen, &revoked, &last); e != nil {
			return nil, e
		}
		d := s.devices[id]
		if e = json.Unmarshal([]byte(raw), &d.Registration); e != nil {
			return nil, e
		}
		if d.ActiveRelayMode != "" {
			d.RelayTransport = d.ActiveRelayMode
		}
		d.ID, d.GroupID, d.Online = id, group, !d.LastSeen.IsZero() && now.Sub(d.LastSeen) < time.Duration(timeout)*time.Second
		if d.LastSeen.IsZero() && last > 0 && now.Unix()-last < int64(timeout)+60 {
			d.Online = true
		}
		if d.LastSeen.IsZero() && lastSeen > 0 {
			d.LastSeen = time.Unix(lastSeen, 0)
		}
		d.Revoked = revoked
		d.Online = d.Online && !revoked
		if !d.Online {
			d.Metrics.InMbps = 0
			d.Metrics.OutMbps = 0
		}
		all = append(all, d)
	}
	return all, rows.Err()
}

func (s *Server) groupDevices(w http.ResponseWriter, r *http.Request, u User) {
	group, err := scanGroup(s.db.QueryRow(groupSelect+" WHERE id=?", pathID(r)))
	if err != nil || (!u.Admin && group.Owner != u.ID) {
		fail(w, 404, "设备组不存在")
		return
	}
	devices, err := s.visibleDevices(u, group.ID)
	if err != nil {
		dbFailure(w, err)
		return
	}
	respond(w, 200, devices)
}

func (s *Server) visibleNodes(u User) ([]wire.Device, error) {
	return s.visibleDevices(u, 0)
}

func (s *Server) invalidateNodeStatus(pattern string) {
	switch pattern {
	case "PUT /api/admin/settings", "PUT /api/admin/notifications/offline", "POST /api/node/register",
		"PATCH /api/nodes/{id}", "DELETE /api/nodes/{id}", "DELETE /api/admin/nodes/{id}",
		"POST /api/admin/groups", "PUT /api/admin/groups/{id}", "DELETE /api/admin/groups/{id}",
		"POST /api/tunnels", "PUT /api/tunnels/{id}", "DELETE /api/tunnels/{id}", "POST /api/groups/{id}/operations":
		s.nodeStatusMu.Lock()
		s.nodeStatus = nodeStatusSnapshot{}
		s.nodeStatusMu.Unlock()
	}
}

type nodeStatusSnapshot struct {
	until     time.Time
	groups    []wire.DeviceGroup
	devices   []wire.Device
	settings  map[string]string
	retention offlineNotificationSettings
}

func (s *Server) statusSnapshot(equipmentGroup int64) (nodeStatusSnapshot, error) {
	if equipmentGroup == 0 {
		s.nodeStatusMu.Lock()
		defer s.nodeStatusMu.Unlock()
		if time.Now().Before(s.nodeStatus.until) {
			return s.nodeStatus, nil
		}
	}
	settings := make(map[string]string, 3)
	rows, err := s.db.Query("SELECT key,value FROM settings WHERE key IN ('showNodeStatus','hideIPs','hideAdminIPs')")
	if err != nil {
		return nodeStatusSnapshot{}, err
	}
	for rows.Next() {
		var key, value string
		if err = rows.Scan(&key, &value); err != nil {
			rows.Close()
			return nodeStatusSnapshot{}, err
		}
		settings[key] = value
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nodeStatusSnapshot{}, err
	}
	out := nodeStatusSnapshot{settings: settings}
	if equipmentGroup == 0 {
		out.groups, err = s.groups()
		out.retention = s.offlineNotificationConfig()
	} else {
		var group wire.DeviceGroup
		group, err = scanGroup(s.db.QueryRow(groupSelect+" WHERE id=?", equipmentGroup))
		out.groups = []wire.DeviceGroup{group}
	}
	if err != nil {
		return nodeStatusSnapshot{}, err
	}
	out.devices, err = s.deviceGroupSnapshot(false, equipmentGroup)
	if err == nil && equipmentGroup == 0 {
		out.until = time.Now().Add(2 * time.Second)
		s.nodeStatus = out
	}
	return out, err
}

func (s *Server) visibleDevices(u User, equipmentGroup int64) ([]wire.Device, error) {
	snapshot, err := s.statusSnapshot(equipmentGroup)
	if err != nil {
		return nil, err
	}
	showStatus := u.Admin || snapshot.settings["showNodeStatus"] != "false"
	visible := make(map[int64]wire.DeviceGroup, len(snapshot.groups))
	expiry := make(map[int64]int64, len(snapshot.groups))
	now := time.Now().Unix()
	for _, g := range snapshot.groups {
		owns := g.Owner == u.ID
		if equipmentGroup != 0 {
			if u.Admin || owns {
				visible[g.ID] = g
			}
		} else if canUse(u, g) && g.Routing.StatusVisibility != "none" &&
			(u.Admin || owns || (!g.HideStatus && g.Routing.StatusVisibility != "admin" && showStatus)) {
			visible[g.ID] = g
			expiry[g.ID] = now - snapshot.retention.retentionThreshold(strconv.FormatInt(g.ID, 10), g.OfflineSeconds)
		}
	}
	list := []wire.Device{}
	for _, d := range snapshot.devices {
		g, ok := visible[d.GroupID]
		if !ok || (equipmentGroup == 0 && (d.Revoked || (!d.Online && !d.LastSeen.IsZero() && d.LastSeen.Unix() <= expiry[d.GroupID]))) {
			continue
		}
		registration := d.Registration
		d.Registration = wire.Registration{Name: registration.Name, Region: registration.Region, RelayTransport: registration.RelayTransport}
		if (u.Admin && snapshot.settings["hideAdminIPs"] != "true") ||
			(!u.Admin && (g.Owner == u.ID || snapshot.settings["hideIPs"] == "false")) {
			d.Address, d.IPv4, d.IPv6 = registration.Address, registration.IPv4, registration.IPv6
		}
		if !u.Admin || snapshot.settings["hideAdminIPs"] == "true" {
			d.UpdateError, d.ApplyError, d.Revision, d.NativeUDPError, d.RelayModeError = "", "", "", "", ""
		}
		list = append(list, d)
	}
	return list, nil
}

func (s *Server) pruneDeviceSessions() {
	groups, err := s.groups()
	if err != nil {
		return
	}
	config := s.offlineNotificationConfig()
	now := time.Now().Unix()
	expiry := make(map[int64]int64, len(groups))
	for _, group := range groups {
		expiry[group.ID] = now - config.retentionThreshold(strconv.FormatInt(group.ID, 10), group.OfflineSeconds)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, device := range s.devices {
		cutoff, registered := expiry[device.GroupID]
		if !registered || (!device.LastSeen.IsZero() && device.LastSeen.Unix() <= cutoff) {
			delete(s.devices, id)
			delete(s.probeStored, id)
			delete(s.diagnostics, id)
		}
	}
}

func (s *Server) listNodes(w http.ResponseWriter, r *http.Request, u User) {
	list, e := s.visibleNodes(u)
	if e != nil {
		dbFailure(w, e)
		return
	}
	respond(w, 200, list)
}

func (s *Server) events(w http.ResponseWriter, r *http.Request, u User) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		fail(w, 501, "实时订阅不可用")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("X-Accel-Buffering", "no")
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	previous := make(map[int64]wire.Device)
	for {
		current, e := s.sessionUser(r)
		if e != nil || current.Banned {
			return
		}
		list, e := s.visibleNodes(current)
		if e != nil {
			return
		}
		next := make(map[int64]wire.Device, len(list))
		updates := []wire.Device{}
		for _, d := range list {
			next[d.ID] = d
			if d != previous[d.ID] {
				updates = append(updates, d)
			}
		}
		removed := []int64{}
		for id := range previous {
			if _, ok := next[id]; !ok {
				removed = append(removed, id)
			}
		}
		raw, _ := json.Marshal(map[string]any{"items": updates, "removed": removed})
		_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, e = fmt.Fprintf(w, "data: %s\n\n", raw); e != nil {
			return
		}
		flusher.Flush()
		previous = next
		select {
		case <-r.Context().Done():
			return
		case <-tick.C:
		}
	}
}

func (s *Server) deleteNode(w http.ResponseWriter, r *http.Request, u User) {
	id := pathID(r)
	result, e := s.db.Exec("DELETE FROM devices WHERE id=? AND (? OR group_id IN (SELECT id FROM groups WHERE owner=?))", id, u.Admin, u.ID)
	if e != nil {
		dbFailure(w, e)
		return
	}
	if count, _ := result.RowsAffected(); count == 0 {
		fail(w, 404, "设备不存在")
		return
	}
	s.mu.Lock()
	delete(s.devices, id)
	delete(s.probeStored, id)
	delete(s.diagnostics, id)
	s.mu.Unlock()
	w.WriteHeader(204)
}

func routedHop(d wire.Device, policy wire.RelayRouting, preferIPv6 bool) (wire.Hop, bool) {
	hop := wire.Hop{Addr: d.RelayAddress, Cert: d.RelayCert, Token: d.RelayToken, Transport: d.RelayTransport, ReverseID: d.ReverseID}
	if hop.ReverseID != "" {
		return hop, true
	}
	_, port, err := net.SplitHostPort(hop.Addr)
	if err != nil {
		return hop, false
	}
	switch policy.AddressMode {
	case "static":
		hop.Addr = policy.StaticAddress
	case "ipv4":
		if d.IPv4 == "" {
			return hop, false
		}
		hop.Addr = net.JoinHostPort(d.IPv4, port)
	case "ipv6":
		if d.IPv6 == "" {
			return hop, false
		}
		hop.Addr = net.JoinHostPort(d.IPv6, port)
	default:
		if preferIPv6 && d.IPv6 != "" {
			hop.Addr = net.JoinHostPort(d.IPv6, port)
		}
	}
	if hop.Addr != d.RelayAddress {
		hop.AdvertisedAddr = d.RelayAddress
	}
	return hop, hop.Addr != ""
}

func (s *Server) routes(path []int64, entry wire.DeviceGroup, groups map[int64]wire.DeviceGroup, available map[int64][]wire.Device) [][]wire.Hop {
	if len(path) == 0 {
		return nil
	}
	choices := make([][]wire.Hop, len(path))
	count := 1
	source := entry
	for i, id := range path {
		policy := groups[id].Routing
		preferIPv6 := slices.Contains(source.Routing.IPv6Groups, 0) != slices.Contains(source.Routing.IPv6Groups, id)
		reverse := i == 0 && reverseEnabled(entry, id)
		staticNodes := 0
		for _, device := range available[id] {
			if reverse != (device.ReverseID != "") {
				continue
			}
			hop, ok := routedHop(device, policy, preferIPv6)
			if ok {
				hop.GroupID = id
				if len(path) == 1 && hop.ReverseID == "" && policy.NativeUDP {
					hop.NativeUDPKey = device.NativeUDPKey
					hop.NativeUDPMeter = device.AcceptExitMeter
				}
				choices[i] = append(choices[i], hop)
				if policy.AddressMode == "static" && hop.ReverseID == "" {
					staticNodes++
				}
			}
		}
		if staticNodes > 1 {
			// A static endpoint must have a single pinned node identity.
			choices[i] = slices.DeleteFunc(choices[i], func(hop wire.Hop) bool { return hop.ReverseID == "" })
		}
		source = groups[id]
		if len(choices[i]) == 0 {
			return nil
		}
		count = max(count, len(choices[i]))
	}
	count = min(count, 16)
	routes := make([][]wire.Hop, count)
	for i := range routes {
		for n, candidates := range choices {
			routes[i] = append(routes[i], candidates[(i+n)%len(candidates)])
		}
	}
	return routes
}

func (s *Server) nodeConfig(group int64) (cachedConfig, error) {
	s.configMu.RLock()
	current := s.configs[group]
	s.configMu.RUnlock()
	if time.Now().Before(current.until) {
		return current, nil
	}
	value, err, _ := s.configBuild.Do(strconv.FormatInt(group, 10), func() (any, error) {
		s.configMu.RLock()
		current := s.configs[group]
		s.configMu.RUnlock()
		if time.Now().Before(current.until) {
			return current, nil
		}
		tickets := make(map[wire.ExitMeter]string, len(current.meterTickets))
		config, err := s.compileGroupWithTickets(group, current.meterTickets, tickets)
		if err != nil {
			return nil, err
		}
		if current.value.Revision != config.Revision {
			current.previous = current.value
			current.value = config
		}
		current.until = time.Now().Add(time.Second)
		current.meterTickets = tickets
		s.configMu.Lock()
		s.configs[group] = current
		s.configMu.Unlock()
		return current, nil
	})
	if err != nil {
		return current, err
	}
	return value.(cachedConfig), nil
}

func configDelta(base, next wire.Config) *wire.ConfigDelta {
	if base.Revision == "" || base.Revision == next.Revision {
		return nil
	}
	old := make(map[int64]wire.Forward, len(base.Rules))
	for _, r := range base.Rules {
		old[r.ID] = r
	}
	delta := wire.ConfigDelta{Base: base.Revision, Revision: next.Revision}
	for _, r := range next.Rules {
		previous, existed := old[r.ID]
		if !existed || !reflect.DeepEqual(previous, r) {
			delta.Rules = append(delta.Rules, r)
		}
		delete(old, r.ID)
	}
	for id := range old {
		delta.Remove = append(delta.Remove, id)
	}
	slices.Sort(delta.Remove)
	return &delta
}

func (s *Server) compileGroup(group int64) (wire.Config, error) {
	return s.compileGroupWithTickets(group, nil, make(map[wire.ExitMeter]string))
}

func (s *Server) compileGroupWithTickets(group int64, previous, tickets map[wire.ExitMeter]string) (wire.Config, error) {
	groups, e := s.groups()
	if e != nil {
		return wire.Config{}, e
	}
	allowedGroups := make(map[int64]wire.DeviceGroup, len(groups))
	for _, g := range groups {
		allowedGroups[g.ID] = g
	}
	lookup := func(id int64) (wire.DeviceGroup, error) {
		g, exists := allowedGroups[id]
		if !exists {
			return g, sql.ErrNoRows
		}
		return g, nil
	}
	entry := allowedGroups[group]
	config := wire.Config{Rules: []wire.Forward{}}
	if entry.Kind != "entry" && entry.Kind != "both" {
		return withConfigRevision(config)
	}
	rows, e := s.db.Query(`SELECT r.id,r.json,u.id,u.admin,u.group_id,g.ratio,u.expires,u.quota_epoch,u.quota,
		coalesce(u.rate_override,p.rate_mbps,0),coalesce(u.ips_override,p.max_ips,0),coalesce(u.connections_override,p.max_connections,0)
		FROM rules r JOIN users u ON u.id=r.owner JOIN groups g ON g.id=r.entry LEFT JOIN plans p ON p.id=u.plan_id
		WHERE r.entry=? AND json_extract(r.json,'$.enabled')=1 AND u.banned=0
		AND (u.admin=1 OR (u.expires>unixepoch() AND (u.quota=0 OR u.used<u.quota))) ORDER BY r.id`, group)
	if e != nil {
		return wire.Config{}, e
	}
	defer rows.Close()
	type rulePaths struct {
		index           int
		primary, backup []int64
	}
	var routed []rulePaths
	for rows.Next() {
		var f wire.Forward
		var raw string
		var id int64
		var u User
		if e = rows.Scan(&id, &raw, &u.ID, &u.Admin, &u.Group, &f.Ratio, &f.Expires, &f.QuotaEpoch, &u.Quota, &f.UserRate, &f.UserIPs, &f.UserConnections); e != nil {
			return config, e
		}
		if e = json.Unmarshal([]byte(raw), &f.Rule); e != nil {
			return config, e
		}
		f.ID, f.Owner = id, u.ID
		f.Label = ""
		f.ProbeInterval = 0 // Sampling cadence is managed by the panel.
		if u.Admin {
			f.Expires = 0
		}

		if !canUse(u, entry) || !entry.AllowsIngress(f.Rule) || !entry.AllowsIngressPath(f.Rule) {
			continue
		}
		f.HAProxy = f.Rule.UsesHAProxy()
		if f.HAProxy && (validateHAProxyRule(u, entry, f.Rule) != nil || f.UserRate > 0 || f.UserIPs > 0 || f.UserConnections > 0) {
			continue
		}
		if f.HAProxy {
			f.HAProxyRatio = f.Ratio
		}
		f.Protocol = entry.RuleNetwork(f.Rule)
		if entry.Ingress.BlocksUDP() {
			if f.Protocol == "udp" {
				continue
			}
			if f.Protocol == "both" {
				f.Protocol = "tcp"
			}
		}
		if (f.Protocol == "tcp" || f.Protocol == "both") && entry.Ingress.InspectsTCP() {
			f.Ingress = entry.Ingress
		}
		primary, ratio, primaryErr := resolvePath(u, entry, f.Path, lookup)
		backup, backupRatio, backupErr := resolvePath(u, entry, f.BackupPath, lookup)
		if primaryErr != nil || backupErr != nil {
			continue
		}
		if len(f.BackupPath) == 0 && len(f.Path) != 0 {
			last := allowedGroups[f.Path[len(f.Path)-1]]
			if last.FallbackGroup > 0 {
				path := slices.Clone(f.Path)
				path[len(path)-1] = last.FallbackGroup
				if candidate, multiplier, err := resolvePath(u, entry, path, lookup); err == nil {
					f.BackupPath, backup, backupRatio = path, candidate, multiplier
				}
			}
		}
		meter := func(path, selected []int64, ratio int64) string {
			if len(path) == 0 {
				return ""
			}
			var virtualGroup int64
			if len(selected) == 1 && allowedGroups[selected[0]].Kind == "chain" {
				virtualGroup = selected[0]
			}
			identity := wire.ExitMeter{VirtualGroup: virtualGroup, Rule: f.ID, Owner: f.Owner, Group: path[len(path)-1], Epoch: f.QuotaEpoch,
				Ratio: ratio, Managed: !u.Admin && u.Quota > 0 && ratio > 0}
			ticket := previous[identity]
			if ticket == "" {
				ticket = identity.Sign(s.meterKey)
			}
			tickets[identity] = ticket
			return ticket
		}
		if !u.Admin && !entry.Routing.AllowPrivateTargets {
			f.PublicTargets = len(primary) == 0 || allowedGroups[primary[len(primary)-1]].Owner == 0
			f.PublicBackupTargets = len(backup) != 0 && allowedGroups[backup[len(backup)-1]].Owner == 0
		}
		f.ExitMeter, f.BackupExitMeter = meter(primary, f.Path, ratio), meter(backup, f.BackupPath, backupRatio)
		entryRatio := f.Ratio
		if f.ExitMeter != "" || f.BackupExitMeter != "" {
			f.EntryRatio = entryRatio
		}
		f.Ratio += ratio
		if len(backup) > 0 {
			backupRatio += entryRatio
			f.BackupRatio = &backupRatio
		}
		f.QuotaManaged = !u.Admin && u.Quota > 0 && (f.Ratio > 0 || (f.BackupRatio != nil && *f.BackupRatio > 0))
		f.MaxFailures, f.RecoverySeconds = entry.Routing.MaxFailures, entry.Routing.RecoverySeconds
		if len(primary) != 0 || len(backup) != 0 {
			routed = append(routed, rulePaths{len(config.Rules), primary, backup})
		}
		config.Rules = append(config.Rules, f)
	}
	if e = rows.Err(); e != nil {
		return config, e
	}
	rows.Close()
	if len(routed) != 0 {
		devices, err := s.deviceSnapshot(true)
		if err != nil {
			return config, err
		}
		available := make(map[int64][]wire.Device)
		for _, d := range devices {
			if d.Online && (d.RelayAddress != "" || d.ReverseID != "") {
				available[d.GroupID] = append(available[d.GroupID], d)
			}
		}
		routeCache := make(map[[8]int64][][]wire.Hop)
		routesFor := func(path []int64) [][]wire.Hop {
			if len(path) == 0 {
				return nil
			}
			var key [8]int64
			copy(key[:], path)
			routes, ok := routeCache[key]
			if !ok {
				routes = s.routes(path, entry, allowedGroups, available)
				routeCache[key] = routes
			}
			return routes
		}
		for _, rule := range routed {
			config.Rules[rule.index].Routes = routesFor(rule.primary)
			config.Rules[rule.index].Backup = routesFor(rule.backup)
		}
	}
	parents := make(map[int]wire.Rule)
	for _, f := range config.Rules {
		if f.TLSShared {
			parents[f.Port] = f.Rule
		}
	}
	config.Rules = slices.DeleteFunc(config.Rules, func(f wire.Forward) bool {
		if f.TLSSharedPort == 0 {
			return false
		}
		parent, exists := parents[f.TLSSharedPort]
		return !exists || !authorizeTLSNames(parent, f.Rule, f.Expires == 0)
	})
	return withConfigRevision(config)
}

func withConfigRevision(config wire.Config) (wire.Config, error) {
	packed, sets := wire.PackRoutes(config.Rules)
	raw, e := json.Marshal(wire.Config{Rules: packed, HopTable: wire.IndexHops(sets)})
	if e != nil {
		return config, e
	}
	checksum := sha256.New()
	checksum.Write([]byte("hopx-traffic-meter-v1\x00"))
	checksum.Write(raw)
	config.Revision = hex.EncodeToString(checksum.Sum(nil)[:16])
	return config, nil
}

// Store the Unix timestamp at midnight in UTC+8. Legacy rows used a UTC day number.
func trafficDay(at time.Time) int64 {
	const offset = 8 * 3600
	return ((at.Unix()+offset)/86400)*86400 - offset
}

func reportTrafficDay(report *wire.Report, now time.Time) int64 {
	at := report.CollectedAt
	if at == 0 && len(report.ID) > 21 && report.ID[20] == '-' {
		stamp, _ := strconv.ParseInt(report.ID[:20], 10, 64)
		at = stamp / int64(time.Second)
	}
	if at <= 0 || at > now.Unix() {
		at = now.Unix()
	}
	return trafficDay(time.Unix(at, 0))
}

func (s *Server) accountTraffic(node, group int64, report *wire.Report) (string, error) {
	if report == nil || report.ID == "" {
		return "", nil
	}
	if len(report.ID) > 96 || len(report.Traffic) > wire.MaxReportEntries {
		return "", fmt.Errorf("流量批次无效")
	}
	tx, e := s.db.Begin()
	if e != nil {
		return "", e
	}
	defer tx.Rollback()
	status, e := tx.Exec("INSERT OR IGNORE INTO traffic_batch(node,report) VALUES(?,?)", node, report.ID)
	if e != nil {
		return "", e
	}
	if n, _ := status.RowsAffected(); n == 0 {
		return report.ID, nil
	}
	type transfer struct{ in, out int64 }
	byOwner := make(map[int64]transfer)
	byGroup := make(map[int64]transfer)
	exits := make(map[int64]transfer)
	meterKey := s.meterKey.Public().(ed25519.PublicKey)
	add := func(totals map[int64]transfer, id int64, t wire.Traffic) {
		total := totals[id]
		totals[id] = transfer{total.in + t.In, total.out + t.Out}
	}
	for _, t := range report.Traffic {
		if t.In < 0 || t.Out < 0 || t.In > 1<<48 || t.Out > 1<<48 || t.Ratio < 0 || t.Ratio > 200000 {
			return "", fmt.Errorf("流量条目无效")
		}
		if t.ExitMeter != "" {
			meter, ok := wire.VerifyExitMeter(meterKey, t.ExitMeter, group)
			if !ok {
				// Stale spools from a replaced panel or registration are safe to discard.
				continue
			}
			add(byGroup, group, t)
			add(exits, group, t)
			if meter.VirtualGroup != 0 && meter.VirtualGroup != group {
				add(byGroup, meter.VirtualGroup, t)
				add(exits, meter.VirtualGroup, t)
			}
			if !meter.Managed && meter.Ratio > 0 {
				if e = debitTraffic(tx, meter.Owner, t.In+t.Out, meter.Ratio, meter.Epoch); e != nil {
					return "", e
				}
			}
			continue
		}
		var owner int64
		e = tx.QueryRow("SELECT owner FROM rules WHERE id=? AND entry=?", t.RuleID, group).Scan(&owner)
		if e == sql.ErrNoRows {
			continue
		}
		if e != nil {
			return "", e
		}
		if _, e = tx.Exec("INSERT INTO traffic(rule_id,inbound,outbound) VALUES(?,?,?) ON CONFLICT(rule_id) DO UPDATE SET inbound=inbound+excluded.inbound,outbound=outbound+excluded.outbound", t.RuleID, t.In, t.Out); e != nil {
			return "", e
		}
		add(byOwner, owner, t)
		add(byGroup, group, t)
		if !t.QuotaManaged && t.Ratio > 0 {
			if e = debitTraffic(tx, owner, t.In+t.Out, t.Ratio, -1); e != nil {
				return "", e
			}
		}
	}
	for id, sum := range exits {
		if _, e = tx.Exec("INSERT INTO exit_group_traffic SELECT id,?,? FROM groups WHERE id=? ON CONFLICT(group_id) DO UPDATE SET inbound=inbound+excluded.inbound,outbound=outbound+excluded.outbound", sum.in, sum.out, id); e != nil {
			return "", e
		}
	}
	now := time.Now()
	day := reportTrafficDay(report, now)
	if day < trafficDay(now)-7*86400 {
		return report.ID, tx.Commit()
	}
	for owner, sum := range byOwner {
		if _, e = tx.Exec("INSERT INTO daily_user_traffic VALUES(?,?,?,?) ON CONFLICT(day,user_id) DO UPDATE SET inbound=inbound+excluded.inbound,outbound=outbound+excluded.outbound", day, owner, sum.in, sum.out); e != nil {
			return "", e
		}
	}
	for id, sum := range byGroup {
		if _, e = tx.Exec("INSERT INTO daily_group_traffic VALUES(?,?,?,?) ON CONFLICT(day,group_id) DO UPDATE SET inbound=inbound+excluded.inbound,outbound=outbound+excluded.outbound", day, id, sum.in, sum.out); e != nil {
			return "", e
		}
	}
	if e = tx.Commit(); e != nil {
		return "", e
	}
	return report.ID, nil
}

func debitTraffic(tx *sql.Tx, owner, bytes, ratio, epoch int64) error {
	whole := bytes / 1000 * ratio
	fraction := bytes % 1000 * ratio
	_, err := tx.Exec("UPDATE users SET used=used+?+(billing_remainder+?)/1000,billing_remainder=(billing_remainder+?)%1000 WHERE id=? AND (?<0 OR quota_epoch=?)", whole, fraction, fraction, owner, epoch, epoch)
	return err
}

func (s *Server) releaseFor(osName, arch string) *wire.Release {
	if s.releaseDir == "" || osName != "linux" || (arch != "amd64" && arch != "arm64") {
		return nil
	}
	s.releaseMu.Lock()
	defer s.releaseMu.Unlock()
	if now := time.Now(); !now.Before(s.releaseUntil) {
		s.releaseUntil = now.Add(2 * time.Second)
		s.releases = nil
		if raw, err := os.ReadFile(filepath.Join(s.releaseDir, "manifest.json")); err == nil {
			var manifest map[string]wire.Release
			if json.Unmarshal(raw, &manifest) == nil {
				s.releases = manifest
			}
		}
	}
	release := s.releases[osName+"-"+arch]
	if release.Version == "" {
		return nil
	}
	return &release
}

func legacyRelayAddress(config wire.Config) wire.Config {
	var changed bool
	rules := config.Rules
	var updates map[*[]wire.Hop][][]wire.Hop
	adapt := func(routes [][]wire.Hop) [][]wire.Hop {
		if len(routes) == 0 {
			return routes
		}
		if result, ok := updates[&routes[0]]; ok {
			return result
		}
		result := routes
		for i, route := range routes {
			if !slices.ContainsFunc(route, func(hop wire.Hop) bool { return hop.AdvertisedAddr != "" }) {
				continue
			}
			if &result[0] == &routes[0] {
				result = slices.Clone(routes)
			}
			result[i] = slices.Clone(route)
			for j, hop := range result[i] {
				if hop.AdvertisedAddr != "" {
					hop.Addr, hop.AdvertisedAddr = hop.AdvertisedAddr, ""
					result[i][j] = hop
				}
			}
		}
		if updates == nil {
			updates = make(map[*[]wire.Hop][][]wire.Hop)
		}
		updates[&routes[0]] = result
		return result
	}
	for i, rule := range rules {
		primary, backup := adapt(rule.Routes), adapt(rule.Backup)
		same := func(a, b [][]wire.Hop) bool { return len(a) == 0 || &a[0] == &b[0] }
		if same(primary, rule.Routes) && same(backup, rule.Backup) {
			continue
		}
		if !changed {
			rules = slices.Clone(rules)
			changed = true
		}
		rule.Routes, rule.Backup = primary, backup
		rules[i] = rule
	}
	if changed {
		config.Rules = rules
		config.Revision = digest(config.Revision + ":legacy-relay-address")[:32]
	}
	return config
}

func (s *Server) syncNode(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.Header.Get("X-Node-ID"), 10, 64)
	credential := bearer(r)
	if id < 1 || credential == "" {
		fail(w, 401, "节点凭据无效")
		return
	}
	var group int64
	var raw, mode string
	var nativeUDP, applyMode bool
	if s.db.QueryRow(`SELECT d.group_id,d.registration,g.relay_mode,coalesce(json_extract(g.routing,'$.nativeUDP'),0),
		coalesce(json_extract(g.routing,'$.applyRelayMode'),0) FROM devices d JOIN groups g ON g.id=d.group_id
		WHERE d.id=? AND d.token=?`, id, digest(credential)).Scan(&group, &raw, &mode, &nativeUDP, &applyMode) != nil {
		fail(w, 401, "节点凭据无效")
		return
	}
	var input wire.Heartbeat
	if !decode(w, r, &input) {
		return
	}
	candidate := s.releaseFor(input.OS, input.Arch)
	if input.ManagedUpgrade != nil && !*input.ManagedUpgrade {
		candidate = nil
	}
	d := wire.Device{ID: id, GroupID: group, Version: input.Version, OS: input.OS, Arch: input.Arch, Revision: input.Revision, ApplyError: input.ApplyError, UpdateError: input.UpdateError, LastSeen: time.Now(), Online: true, Metrics: input.Metrics, AcceptRuleProbe: input.AcceptRuleProbe, AcceptPing: input.AcceptPing}
	d.AcceptRouteProbe = input.AcceptRouteProbe
	d.AcceptLinkProbe = input.AcceptLinkProbe
	d.AcceptHAProxy = input.AcceptHAProxy
	d.AcceptPortCheck = input.AcceptPortCheck
	d.AcceptExitMeter = input.AcceptExitMeter
	d.AcceptScopedReverse = input.AcceptScopedReverse
	if e := json.Unmarshal([]byte(raw), &d.Registration); e != nil {
		dbFailure(w, e)
		return
	}
	nativeUDP = nativeUDP && d.RelayAddress != ""
	if d.RelayAddress != "" && wire.ValidRelayMode(input.ActiveRelayMode) {
		d.ActiveRelayMode = input.ActiveRelayMode
		if len(input.RelayModeError) <= 240 {
			d.RelayModeError = input.RelayModeError
		}
	}
	if nativeUDP && len(input.NativeUDPKey) == 64 {
		if _, err := hex.DecodeString(input.NativeUDPKey); err == nil {
			d.NativeUDPKey, d.NativeUDP = input.NativeUDPKey, true
		}
	}
	if nativeUDP && len(input.NativeUDPError) <= 240 {
		d.NativeUDPError = input.NativeUDPError
	}
	if candidate != nil {
		d.TargetVersion = candidate.Version
	}
	s.mu.Lock()
	scopingChanged := s.devices[id].AcceptScopedReverse != d.AcceptScopedReverse
	s.devices[id] = d
	bucket := d.LastSeen.Unix() / 60 * 60
	needSample := s.probeStored[id] != bucket
	if needSample {
		s.probeStored[id] = bucket
	}
	s.mu.Unlock()
	if d.ReverseAddress != "" && scopingChanged {
		s.reverseMu.Lock()
		s.reverseRoutes = nil
		s.reverseMu.Unlock()
	}
	if needSample {
		if err := s.saveProbeSample(d, bucket); err != nil {
			s.mu.Lock()
			if s.probeStored[id] == bucket {
				delete(s.probeStored, id)
			}
			s.mu.Unlock()
		}
	}
	out := wire.Sync{EnableNativeUDP: nativeUDP}
	if input.AcceptExitMeter {
		out.MeterKey, out.MeterGroup = s.meterKey.Public().(ed25519.PublicKey), group
	}
	if applyMode && d.RelayAddress != "" {
		out.RelayMode = firstNonempty(mode, "tls")
	}
	out.Diagnostic = s.pollDiagnostic(id, input.Diagnostic)
	var e error
	if d.ReverseID != "" {
		out.Reverse, e = s.reverseEndpoints(group, d.ReverseID)
		if e != nil {
			dbFailure(w, e)
			return
		}
	}
	if out.Ack, e = s.accountTraffic(id, group, input.Report); e != nil {
		dbFailure(w, e)
		return
	}
	config, e := s.nodeConfig(group)
	if e != nil {
		dbFailure(w, e)
		return
	}
	if !input.AcceptExitMeter {
		config.value = legacyTrafficMeter(config.value)
		config.previous = legacyTrafficMeter(config.previous)
	}
	unsupportedRule := func(f wire.Forward) bool {
		return (!input.AcceptPublicTargets && requiresPublicTargetPolicy(f)) || (!input.AcceptTLSPolicy && f.HasTLSPolicy()) || (!input.AcceptSharedTLS && f.UsesSharedTLS()) ||
			(f.Ingress != nil && (!input.AcceptIngress || (!input.AcceptFET && slices.Contains(f.Ingress.BlockedTypes, "fet"))))
	}
	if (!input.AcceptPublicTargets || !input.AcceptTLSPolicy || !input.AcceptSharedTLS || !input.AcceptIngress || !input.AcceptFET) &&
		slices.ContainsFunc(config.value.Rules, unsupportedRule) {
		config.value.Rules = slices.DeleteFunc(slices.Clone(config.value.Rules), unsupportedRule)
		config.value.Revision = digest(fmt.Sprintf("%s:policy:%t:%t:%t:%t:%t", config.value.Revision, input.AcceptTLSPolicy, input.AcceptSharedTLS, input.AcceptIngress, input.AcceptFET, input.AcceptPublicTargets))[:32]
		config.previous = wire.Config{}
	}
	if !input.AcceptRelayTransports {
		config.value = compatibleRelayConfig(config.value)
		config.previous = compatibleRelayConfig(config.previous)
	}
	if !input.AcceptAlternateRelayAddress {
		config.value = legacyRelayAddress(config.value)
		config.previous = legacyRelayAddress(config.previous)
	}
	if !input.AcceptWebsocketMux {
		config.value = legacyWebsocketRoutes(config.value)
		config.previous = legacyWebsocketRoutes(config.previous)
	}
	if !input.AcceptHAProxy && slices.ContainsFunc(config.value.Rules, func(f wire.Forward) bool { return f.HAProxy }) {
		config.value.Rules = slices.DeleteFunc(slices.Clone(config.value.Rules), func(f wire.Forward) bool { return f.HAProxy })
		config.value.Revision = digest(config.value.Revision + ":without-haproxy")[:32]
		config.previous = wire.Config{}
	}
	if !input.AcceptUDPProxy {
		unsupportedUDP := func(f wire.Forward) bool {
			return f.ProxyOut && f.ProxyOutVersion == 2 && f.Protocol != "tcp"
		}
		if slices.ContainsFunc(config.value.Rules, unsupportedUDP) {
			filtered := make([]wire.Forward, 0, len(config.value.Rules))
			for _, rule := range config.value.Rules {
				if unsupportedUDP(rule) {
					if rule.Protocol == "udp" {
						continue
					}
					rule.Protocol = "tcp"
				}
				filtered = append(filtered, rule)
			}
			config.value.Rules = filtered
			config.value.Revision = digest(config.value.Revision + ":legacy-udp-proxy")[:32]
			config.previous = wire.Config{}
		}
	}
	if input.Revision != config.value.Revision {
		if input.AcceptDelta && input.Revision != "" && input.Revision == config.previous.Revision {
			out.Delta = configDelta(config.previous, config.value)
		}
		if out.Delta == nil {
			out.Config = &config.value
		}
		if input.AcceptRouteSets {
			if out.Delta != nil {
				out.Delta.Rules, out.Delta.RouteSets = wire.PackRoutes(out.Delta.Rules)
				if input.AcceptHopTable {
					out.Delta.HopTable = wire.IndexHops(out.Delta.RouteSets)
					out.Delta.RouteSets = nil
				}
			} else {
				packed := config.value
				packed.Rules, packed.RouteSets = wire.PackRoutes(packed.Rules)
				if input.AcceptHopTable {
					packed.HopTable = wire.IndexHops(packed.RouteSets)
					packed.RouteSets = nil
				}
				out.Config = &packed
			}
		}
	}
	if len(input.QuotaClaims) > 0 {
		out.QuotaGrants, out.ClosedGrants, e = s.allocateNodeQuota(id, group, input.QuotaGeneration, config.value.Rules, input.QuotaClaims, input.AcceptExitMeter)
		if e != nil {
			dbFailure(w, e)
			return
		}
	}
	out.Release = s.nodeRelease(d, candidate, config.value, input.UpgradePending)
	respond(w, 200, out)
}

func (s *Server) saveProbeSample(device wire.Device, bucket int64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	metric := device.Metrics
	if _, err := tx.Exec("INSERT OR IGNORE INTO probe_samples(node,bucket,cpu,ram,disk,inbound,outbound) VALUES(?,?,?,?,?,?,?)", device.ID, bucket, metric.CPU, metric.RAM, metric.Disk, metric.InMbps, metric.OutMbps); err != nil {
		return err
	}
	if _, err := tx.Exec("UPDATE devices SET last_seen=max(last_seen,?) WHERE id=?", device.LastSeen.Unix(), device.ID); err != nil {
		return err
	}
	return tx.Commit()
}

// Old ingress nodes can safely forward a protected rule with public IP
// literals. Hostnames require the capable node to verify and pin DNS results.
func requiresPublicTargetPolicy(rule wire.Forward) bool {
	if !rule.PublicTargets && !rule.PublicBackupTargets {
		return false
	}
	return slices.ContainsFunc(rule.Targets, func(target string) bool {
		host, _, err := net.SplitHostPort(target)
		if err != nil {
			return true
		}
		address, err := netip.ParseAddr(host)
		return err != nil || !wire.PublicDestination(address)
	})
}

// Old nodes discard unknown fields when persisting their routes. Give them a
// distinct revision so an upgraded node downloads the full metering config.
func legacyTrafficMeter(config wire.Config) wire.Config {
	if !slices.ContainsFunc(config.Rules, func(f wire.Forward) bool {
		return f.ExitMeter != "" || f.BackupExitMeter != ""
	}) {
		return config
	}
	config.Rules = slices.Clone(config.Rules)
	for i := range config.Rules {
		f := &config.Rules[i]
		f.ExitMeter, f.BackupExitMeter, f.EntryRatio = "", "", 0
	}
	config.Revision = digest(config.Revision + ":legacy-traffic-meter")[:32]
	return config
}

func compatibleRelayConfig(config wire.Config) wire.Config {
	unsupported := func(route []wire.Hop) bool {
		return slices.ContainsFunc(route, func(hop wire.Hop) bool {
			return hop.Transport == "ws" || hop.Transport == "http" || hop.Transport == "https"
		})
	}
	changed := false
	for i, rule := range config.Rules {
		if !slices.ContainsFunc(rule.Routes, unsupported) && !slices.ContainsFunc(rule.Backup, unsupported) {
			continue
		}
		if !changed {
			config.Rules = slices.Clone(config.Rules)
			changed = true
		}
		rule.Routes = slices.DeleteFunc(slices.Clone(rule.Routes), unsupported)
		rule.Backup = slices.DeleteFunc(slices.Clone(rule.Backup), unsupported)
		config.Rules[i] = rule
	}
	if changed {
		config.Revision = digest(config.Revision + ":legacy-relays")[:32]
	}
	return config
}

func legacyWebsocketRoutes(config wire.Config) wire.Config {
	contains := func(route []wire.Hop) bool {
		return slices.ContainsFunc(route, func(hop wire.Hop) bool { return hop.Transport == "wss-mux" })
	}
	rewrite := func(routes [][]wire.Hop) [][]wire.Hop {
		out := slices.Clone(routes)
		for i, route := range out {
			if contains(route) {
				out[i] = slices.Clone(route)
				for j := range out[i] {
					if out[i][j].Transport == "wss-mux" {
						out[i][j].Transport = "wss"
					}
				}
			}
		}
		return out
	}
	changed := false
	for i, rule := range config.Rules {
		if !slices.ContainsFunc(rule.Routes, contains) && !slices.ContainsFunc(rule.Backup, contains) {
			continue
		}
		if !changed {
			config.Rules = slices.Clone(config.Rules)
			changed = true
		}
		rule.Routes, rule.Backup = rewrite(rule.Routes), rewrite(rule.Backup)
		config.Rules[i] = rule
	}
	if changed {
		config.Revision = digest(config.Revision + ":legacy-wss")[:32]
	}
	return config
}
