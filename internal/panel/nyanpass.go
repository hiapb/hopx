package panel

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strconv"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
	"hopx/internal/wire"
)

const nyanpassSource = "nyanpass-20261022"

func queryLegacy[T any](tx *sql.Tx, query string, parse func(scanner) (T, error), args ...any) ([]T, error) {
	rows, err := tx.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []T
	for rows.Next() {
		value, err := parse(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, value)
	}
	return out, rows.Err()
}

// ImportNyanpass imports the official 20261022 SQLite schema. Runtime node keys
// and user sessions are issued afresh by HopX.
func (s *Server) ImportNyanpass(path, adminName, adminPassword string, dryRun bool) (MigrationResult, error) {
	db, err := openLegacy(path)
	if err != nil {
		return MigrationResult{}, err
	}
	defer db.Close()
	return s.importNyanpassDB(db, adminName, adminPassword, dryRun)
}

func (s *Server) ImportNyanpassMySQL(dsn, adminName, adminPassword string, dryRun bool) (MigrationResult, error) {
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return MigrationResult{}, err
	}
	defer db.Close()
	return s.importNyanpassDB(db, adminName, adminPassword, dryRun)
}

func (s *Server) importNyanpassDB(db *sql.DB, adminName, adminPassword string, dryRun bool) (MigrationResult, error) {
	tx, err := db.BeginTx(context.Background(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return MigrationResult{}, err
	}
	defer tx.Rollback()
	snapshot, err := readNyanpass(tx)
	if err != nil {
		return MigrationResult{}, err
	}
	if !dryRun {
		var available bool
		for _, u := range snapshot.Users {
			if u.Admin && !u.Banned && u.Name == adminName {
				available = true
			}
		}
		if !available {
			return MigrationResult{}, fmt.Errorf("指定的管理员 %q 不存在或已停用", adminName)
		}
		if len(adminPassword) < 10 || len(adminPassword) > 72 {
			return MigrationResult{}, fmt.Errorf("请通过 HOPX_MIGRATION_ADMIN_PASSWORD 设置迁移后的管理员密码")
		}
	}
	raw, err := json.Marshal(snapshot)
	if err != nil {
		return MigrationResult{}, err
	}
	return s.importSnapshot(bytes.NewReader(raw), dryRun, adminName, adminPassword)
}

func readNyanpass(tx *sql.Tx) (snapshot, error) {
	data := snapshot{Format: 1, Source: nyanpassSource}
	var err error
	data.Settings, err = nyanpassSettings(tx)
	if err != nil {
		return data, err
	}
	data.Users, err = queryLegacy(tx, `SELECT id,coalesce(username,''),coalesce(password,''),coalesce(balance,'0'),coalesce(inviter,0),coalesce(invite_code,''),coalesce(plan_id,0),coalesce(group_id,0),traffic_enable,traffic_used,expire,coalesce(max_rules,0),coalesce(auto_renew,0),coalesce(banned,0),coalesce(admin,0),coalesce(note,''),speed_limit,ip_limit,connection_limit,coalesce(aff_balance,'0'),coalesce(allow_device,0) FROM users ORDER BY id`, nyanpassUser)
	if err != nil {
		return data, fmt.Errorf("nyanpass users: %w", err)
	}
	data.UserGroups, err = queryLegacy(tx, "SELECT id,coalesce(name,'') FROM user_groups ORDER BY id", func(row scanner) (g named, e error) { e = row.Scan(&g.ID, &g.Name); return })
	if err != nil {
		return data, err
	}
	data.Plans, err = queryLegacy(tx, "SELECT id,coalesce(name,''),coalesce(`desc`,''),coalesce(price,'0'),coalesce(type,''),coalesce(multiple,1),coalesce(traffic,0),coalesce(max_rules,0),coalesce(group_id,0),coalesce(hide,0),coalesce(speed_limit,0),coalesce(ip_limit,0),coalesce(connection_limit,0) FROM plans ORDER BY id", nyanpassPlan)
	if err != nil {
		return data, err
	}
	groups, err := queryLegacy(tx, `SELECT id,coalesce(name,''),coalesce(type,''),coalesce(uid,0),coalesce(ratio,'0'),coalesce(enable_for_gid,''),coalesce(port_range,''),coalesce(allowed_in,''),coalesce(allowed_out,''),coalesce(down_sec,30),coalesce(fallback_group,0),coalesce(connect_host,''),coalesce(config,'{}'),
		coalesce((SELECT f.name FROM device_group_folder_rels rel JOIN device_group_folders f ON f.id=rel.folder_id WHERE rel.dg_id=g.id ORDER BY rel.show_order,f.id LIMIT 1),''),
		coalesce(note,''),coalesce(show_order,0),coalesce(hide_status,0) FROM device_groups g ORDER BY id`, nyanpassGroup)
	if err != nil {
		return data, err
	}
	chain, err := queryLegacy(tx, "SELECT group_id,this_hop,next_hop FROM chain_outbounds ORDER BY group_id,seq", func(row scanner) (item [3]int64, e error) { e = row.Scan(&item[0], &item[1], &item[2]); return })
	if err != nil {
		return data, err
	}
	paths := make(map[int64][]int64)
	for _, edge := range chain {
		path := paths[edge[0]]
		if len(path) == 0 {
			path = append(path, edge[1])
		} else if path[len(path)-1] != edge[1] {
			return data, fmt.Errorf("链式出口 %d 的第 %d 段不连续", edge[0], len(path))
		}
		if edge[2] > 0 {
			path = append(path, edge[2])
		}
		paths[edge[0]] = path
	}
	groupsByID := make(map[int64]nyanGroup, len(groups))
	for _, g := range groups {
		if path, exists := paths[g.ID]; exists {
			g.Kind, g.Chain = "chain", path
		}
		groupsByID[g.ID] = g
		data.DeviceGroups = append(data.DeviceGroups, g.DeviceGroup)
		if g.Kind != "chain" && g.Host != "" {
			data.Devices = append(data.Devices, sourceDevice{ID: g.ID, GroupID: g.ID, Name: g.Name, Address: g.Host})
		}
	}
	rules, err := queryLegacy(tx, `SELECT r.id,coalesce(r.name,''),coalesce(r.uid,0),r.paused,coalesce(r.listen_port,0),coalesce(r.device_group_in,0),coalesce(r.device_group_out,0),r.traffic_used,coalesce(r.config,'{}'),coalesce((SELECT f.name FROM forward_rule_folder_rels rel JOIN forward_rule_folders f ON f.id=rel.folder_id WHERE rel.rule_id=r.id ORDER BY f.id LIMIT 1),'') FROM forward_rules r ORDER BY r.id`, func(row scanner) (sourceRule, error) { return nyanpassRule(row, groupsByID) })
	if err != nil {
		return data, err
	}
	data.Rules = rules
	orderColumns, err := tx.Query("SELECT * FROM orders WHERE 1=0")
	if err != nil {
		return data, err
	}
	columnNames, err := orderColumns.Columns()
	orderColumns.Close()
	if err != nil {
		return data, err
	}
	paidTime := "0"
	for _, column := range columnNames {
		if column == "paid_time" {
			paidTime = "coalesce(paid_time,0)"
			break
		}
	}
	data.Orders, err = queryLegacy(tx, "SELECT id,coalesce(uid,0),coalesce(amount,'0'),coalesce(type,''),coalesce(status,''),coalesce(order_no,''),coalesce(message,''),coalesce(open_time,0),"+paidTime+" FROM orders ORDER BY id", nyanpassOrder)
	if err != nil {
		return data, err
	}
	affiliateHistory, err := queryLegacy(tx, `SELECT a.id,a.uid,coalesce(a.amount,'0'),coalesce(a.type,''),coalesce(a.status,''),coalesce(a.message,''),coalesce(a.created_at,'')
		FROM affiliate_logs a JOIN users u ON u.id=a.uid ORDER BY a.id`, nyanpassAffiliateRecord)
	if err != nil {
		return data, err
	}
	data.Orders = append(data.Orders, affiliateHistory...)
	groupNames := map[int64]bool{0: true}
	for _, g := range data.UserGroups {
		groupNames[g.ID] = true
	}
	for _, u := range data.Users {
		if !groupNames[u.Group] {
			groupNames[u.Group] = true
			data.UserGroups = append(data.UserGroups, named{ID: u.Group, Name: fmt.Sprintf("用户组 %d", u.Group)})
		}
	}
	for _, p := range data.Plans {
		if !groupNames[p.GroupID] {
			groupNames[p.GroupID] = true
			data.UserGroups = append(data.UserGroups, named{ID: p.GroupID, Name: fmt.Sprintf("用户组 %d", p.GroupID)})
		}
	}
	slices.SortFunc(data.UserGroups, func(a, b named) int {
		if a.ID < b.ID {
			return -1
		}
		if a.ID > b.ID {
			return 1
		}
		return 0
	})
	data.Vouchers, err = queryLegacy(tx, `SELECT coalesce(code,''),coalesce(plan_id,0),coalesce(count,0),coalesce(discount_ratio,'0') FROM redeem_codes ORDER BY id`, func(row scanner) (v voucher, e error) {
		var discount string
		e = row.Scan(&v.Code, &v.PlanID, &v.Remaining, &discount)
		if e == nil {
			v.Discount, e = scaledLegacy(discount, 10000)
		}
		v.Expiry = 253402300799
		return
	})
	return data, err
}

func nyanpassSettings(tx *sql.Tx) (map[string]string, error) {
	records, err := queryLegacy(tx, "SELECT `key`,coalesce(value,'') FROM kvs WHERE `key` IN ('site_info','site_notice','invite_config','payment_info')", func(row scanner) (item [2]string, e error) {
		e = row.Scan(&item[0], &item[1])
		return
	})
	if err != nil {
		return nil, err
	}
	settings := make(map[string]string)
	for _, record := range records {
		key, value := record[0], record[1]
		switch key {
		case "site_info":
			var info struct {
				Title             string `json:"title"`
				AllowRegister     bool   `json:"allow_register"`
				AllowPersonal     bool   `json:"allow_single_tunnel"`
				RegisterPolicy    int    `json:"register_policy"`
				RegisterChallenge int    `json:"register_captcha_policy"`
				HideIP            int    `json:"diagnose_hide_ip"`
			}
			if err = json.Unmarshal([]byte(value), &info); err != nil {
				return nil, fmt.Errorf("站点设置: %w", err)
			}
			if strings.TrimSpace(info.Title) != "" {
				settings["name"] = info.Title
			}
			settings["registration"] = "closed"
			if info.AllowRegister {
				settings["registration"] = "open"
				if info.RegisterPolicy == 1 {
					settings["registration"] = "no-invite"
				} else if info.RegisterPolicy == 2 {
					settings["registration"] = "invite"
				}
			}
			settings["registrationChallenge"] = strconv.FormatBool(info.RegisterChallenge == 1)
			settings["personalTunnels"] = strconv.FormatBool(info.AllowPersonal)
			settings["hideIPs"] = strconv.FormatBool(info.HideIP > 0)
			settings["hideAdminIPs"] = strconv.FormatBool(info.HideIP == 2)
		case "site_notice":
			settings["announcement"] = value
		case "invite_config":
			var info struct {
				Enable          bool            `json:"enable"`
				Rate            json.RawMessage `json:"commission_rate"`
				Cycle           bool            `json:"cycle"`
				RequireTelegram bool            `json:"force_bind_telegram"`
			}
			if err = json.Unmarshal([]byte(value), &info); err != nil {
				return nil, fmt.Errorf("邀请设置: %w", err)
			}
			if info.Enable {
				rate, err := scaledLegacy(strings.Trim(string(info.Rate), "\""), 10000)
				if err != nil || rate < 0 || rate > 10000 {
					return nil, errors.New("邀请返佣比例无效")
				}
				settings["referralRate"] = strconv.FormatInt(rate, 10)
			}
			settings["referralFirstOnly"] = strconv.FormatBool(!info.Cycle)
			settings["referralRequireBinding"] = strconv.FormatBool(info.RequireTelegram)
		case "payment_info":
			var info struct {
				MinDeposit json.RawMessage `json:"min_deposit"`
			}
			if err = json.Unmarshal([]byte(value), &info); err != nil {
				return nil, fmt.Errorf("支付设置: %w", err)
			}
			if info.MinDeposit != nil {
				minimum, err := scaledLegacy(strings.Trim(string(info.MinDeposit), "\""), 100)
				if err != nil || minimum < 1 || minimum > 100000000 {
					return nil, errors.New("最低充值金额无效")
				}
				settings["minRecharge"] = strconv.FormatInt(minimum, 10)
			}
		}
	}
	return settings, nil
}

func scaledLegacy(value string, scale int64) (int64, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, nil
	}
	number, ok := new(big.Rat).SetString(value)
	if !ok {
		return 0, fmt.Errorf("无效的十进制数 %q", value)
	}
	number.Mul(number, new(big.Rat).SetInt64(scale))
	integer := new(big.Int).Quo(number.Num(), number.Denom())
	if !integer.IsInt64() {
		return 0, fmt.Errorf("数字超出范围")
	}
	return integer.Int64(), nil
}

func nyanpassUser(row scanner) (u sourceUser, e error) {
	var balance, affiliate string
	var speed *int64
	e = row.Scan(&u.ID, &u.Name, &u.PasswordHash, &balance, &u.Inviter, &u.Invite, &u.PlanID, &u.Group, &u.Quota, &u.Used, &u.Expires, &u.MaxRules, &u.AutoRenew, &u.Banned, &u.Admin, &u.Note, &speed, &u.IPsOverride, &u.ConnectionsOverride, &affiliate, &u.AllowDevice)
	if e != nil {
		return
	}
	if speed != nil {
		rate := int(*speed / 125_000)
		if *speed > 0 {
			rate = max(1, rate)
		}
		u.RateOverride = &rate
	}
	u.Balance, e = scaledLegacy(balance, 100)
	if e == nil {
		u.AffiliateBalance, e = scaledLegacy(affiliate, 100)
	}
	if _, err := bcrypt.Cost([]byte(u.PasswordHash)); err != nil {
		u.PasswordHash = ""
		u.ResetRequired = true
	}
	return
}

func nyanpassPlan(row scanner) (p Plan, e error) {
	var kind, price string
	var hidden bool
	e = row.Scan(&p.ID, &p.Name, &p.Description, &price, &kind, &p.Duration, &p.Quota, &p.Rules, &p.GroupID, &hidden, &p.RateMbps, &p.MaxIPs, &p.MaxConnections)
	if e != nil {
		return
	}
	p.Price, e = scaledLegacy(price, 100)
	p.Enabled = !hidden
	p.RateMbps = int(int64(p.RateMbps) * 8 / 1_000_000)
	p.Kind = map[string]string{"PlanType_Day": "day", "PlanType_Month": "month", "PlanType_TrafficPack": "traffic", "PlanType_TrafficPack_CanStacked": "stack"}[kind]
	if p.Kind == "" {
		return p, fmt.Errorf("套餐 %d 的类型未识别", p.ID)
	}
	p.Duration = max(1, p.Duration)
	return
}

type nyanGroup struct {
	wire.DeviceGroup
	AllowedHosts []string
	Host         string
	Fallback     int64
	Direct       bool
	DisableUDP   bool
}

func legacyIDs(raw string) []int64 {
	var ids []int64
	for _, s := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == '，' || r == ' ' || r == '\n' }) {
		id, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
		if err == nil && id > 0 {
			ids = append(ids, id)
		}
	}
	return ids
}

func nyanpassGroup(row scanner) (g nyanGroup, e error) {
	var kind, ratio, gids, ports, allowIn, allowOut, config string
	var hideStatus int
	e = row.Scan(&g.ID, &g.Name, &kind, &g.Owner, &ratio, &gids, &ports, &allowIn, &allowOut, &g.OfflineSeconds, &g.Fallback, &g.Host, &config, &g.Folder, &g.Note, &g.ShowOrder, &hideStatus)
	if e != nil {
		return
	}
	g.HideStatus = hideStatus > 0
	if hideStatus >= 2 {
		g.Routing.StatusVisibility = "none"
	} else if hideStatus == 1 {
		g.Routing.StatusVisibility = "admin"
	}
	g.Kind = map[string]string{"DeviceGroupType_Inbound": "entry", "DeviceGroupType_OutboundBySite": "exit", "DeviceGroupType_OutboundByUser": "exit", "DeviceGroupType_AgentOnly": "monitor", "DeviceGroupType_ChainOutbound": "chain", "DeviceGroupType_OutboundChain": "chain"}[kind]
	if g.Kind == "" {
		if strings.Contains(strings.ToLower(kind), "chain") {
			g.Kind = "chain"
		} else {
			return g, fmt.Errorf("设备组 %d 的类型未识别", g.ID)
		}
	}
	g.Ratio, e = scaledLegacy(ratio, 1000)
	if e != nil {
		return
	}
	g.UserGroups = legacyIDs(gids)
	g.AllowedFrom, g.AllowedTo = legacyIDs(allowIn), legacyIDs(allowOut)
	g.OfflineSeconds = max(20, g.OfflineSeconds)
	g.FirstPort, g.LastPort = 1, 65535
	if g.Kind == "entry" {
		g.ConnectHost = g.Host
	}
	g.PortRanges = strings.TrimSpace(ports)
	if g.PortRanges != "" {
		spans, err := groupPorts(g.DeviceGroup)
		if err != nil {
			return g, fmt.Errorf("设备组 %d 的端口池: %w", g.ID, err)
		}
		g.FirstPort, g.LastPort = spans[0].first, spans[len(spans)-1].last
	}
	var metadata struct {
		AllowedHosts   []string `json:"allowed_host"`
		ReverseGroups  []int64  `json:"reverse_group"`
		TLSIngress     int      `json:"tls_inbound_policy"`
		RejectEmptySNI bool     `json:"tls_reject_empty_sni"`
		BlockedHosts   []string `json:"blocked_host"`
		BlockedPaths   []string `json:"blocked_path"`
		BlockedTypes   []string `json:"blocked_protocol"`
		Direct         bool
		DisableUDP     bool `json:"disable_udp"`
	}
	if config != "" {
		if e = json.Unmarshal([]byte(config), &metadata); e != nil {
			return g, fmt.Errorf("设备组 %d 配置: %w", g.ID, e)
		}
	}
	g.Direct, g.DisableUDP = metadata.Direct, metadata.DisableUDP
	if g.Kind == "entry" && g.Direct {
		g.Routing.IngressMode = "direct"
	}
	g.AllowedHosts = metadata.AllowedHosts
	g.ReverseGroups = metadata.ReverseGroups
	g.TLSIngress = metadata.TLSIngress
	if g.Kind == "entry" {
		f := &wire.IngressFilter{
			DisableUDP: metadata.DisableUDP, RejectEmptySNI: metadata.RejectEmptySNI,
			AllowedHosts: metadata.AllowedHosts, BlockedHosts: metadata.BlockedHosts,
			BlockedPaths: metadata.BlockedPaths, BlockedTypes: metadata.BlockedTypes,
			SiteOutboundOnly: true, BlockPersonal: strings.Contains(allowOut, "禁止单端"),
		}
		g.Ingress = f
	}
	return
}

func nyanpassRule(row scanner, groups map[int64]nyanGroup) (r sourceRule, e error) {
	var paused bool
	var out int64
	var raw string
	e = row.Scan(&r.ID, &r.Name, &r.Owner, &paused, &r.Port, &r.Entry, &out, &r.Inbound, &raw, &r.Label)
	if e != nil {
		return
	}
	r.LegacyConfig = raw
	var config struct {
		Targets  []string `json:"dest"`
		Policy   string   `json:"dest_policy"`
		ProxyIn  int      `json:"accept_proxy_protocol"`
		ProxyOut int      `json:"proxy_protocol"`
		Speed    int64    `json:"speed_limit"`
		MaxIPs   int      `json:"ip_limit"`
		MaxConns int      `json:"connection_limit"`
		TLS      *struct {
			SharedType    int      `json:"shared_type"`
			SharedUID     []int64  `json:"shared_uid"`
			ParentPort    int      `json:"parent_port"`
			OriginFetch   int      `json:"origin_fetch"`
			Shaping       []int    `json:"shaping"`
			SNI           string   `json:"sni"`
			EmptySNI      bool     `json:"empty_sni"`
			ForceEmptySNI bool     `json:"force_empty_sni"`
			ALPN          []string `json:"alpn"`
			Cert          []string `json:"cert"`
			Key           []string `json:"key"`
		} `json:"tls"`
	}
	if e = json.Unmarshal([]byte(raw), &config); e != nil {
		return r, fmt.Errorf("规则 %d 配置: %w", r.ID, e)
	}
	if config.TLS != nil && config.TLS.SharedType < 0 {
		config.TLS = nil
	}
	r.Enabled = !paused
	r.Protocol = "both"
	if groups[r.Entry].DisableUDP || config.ProxyIn != 0 || (config.ProxyOut != 0 && config.ProxyOut != 2) || config.TLS != nil {
		r.Protocol = "tcp"
	}
	if t := config.TLS; t != nil {
		r.TLSCert, r.TLSKey = strings.Join(t.Cert, "\n"), strings.Join(t.Key, "\n")
		r.SelfSigned = r.TLSCert == "" && r.TLSKey == "" && t.SharedType != 2
		r.TLSOrigin = t.OriginFetch
		switch t.SharedType {
		case 0:
		case 1:
			r.TLSShared = true
			r.TLSAllowedUsers = t.SharedUID
			r.TLSAllowedNames = groups[r.Entry].AllowedHosts
		case 2:
			r.TLSSharedPort = t.ParentPort
		default:
			return r, fmt.Errorf("规则 %d 的 TLS 共享类型未识别", r.ID)
		}
		r.ResponseFilters = t.Shaping
		r.TLSRequireEmpty, r.TLSALPN = t.ForceEmptySNI, t.ALPN
		if !t.EmptySNI && !t.ForceEmptySNI {
			r.TLSServerNames = strings.FieldsFunc(t.SNI, func(ch rune) bool { return ch == ',' || ch == '，' })
			for i := range r.TLSServerNames {
				r.TLSServerNames[i] = strings.ToLower(strings.TrimSpace(r.TLSServerNames[i]))
			}
		}
	}
	if out > 0 && !groups[r.Entry].Direct && !r.TLSShared {
		r.Path = []int64{out}
		if fallback := groups[out].Fallback; fallback > 0 {
			r.BackupPath = []int64{fallback}
		}
	}
	r.Targets = config.Targets
	if r.TLSShared {
		r.Targets = nil
		r.TLSServerNames, r.TLSALPN, r.TLSRequireEmpty, r.TLSOrigin = nil, nil, false, 0
	}
	r.Strategy = map[string]string{"round": "round-robin", "failover": "first", "ip_hash": "ip-hash", "least_load": "least-connections"}[config.Policy]
	if r.Strategy == "" {
		r.Strategy = "random"
	}
	r.ProxyIn, r.ProxyOut = config.ProxyIn != 0, config.ProxyOut != 0
	r.ProxyInVersion, r.ProxyOutVersion = min(2, max(0, config.ProxyIn)), min(2, max(0, config.ProxyOut))
	r.MaxIPs, r.MaxConns = config.MaxIPs, config.MaxConns
	r.RateMbps = int(config.Speed * 8 / 1_000_000)
	return
}

func nyanpassOrder(row scanner) (o Order, e error) {
	var value, kind, status string
	e = row.Scan(&o.ID, &o.UserID, &value, &kind, &status, &o.Reference, &o.Description, &o.Created, &o.PaidAt)
	if e != nil {
		return
	}
	o.Amount, e = scaledLegacy(value, 100)
	o.Kind = map[string]string{"OrderType_DepositToBalance": "payment", "OrderType_PurchaseByBalance": "purchase", "OrderType_Accounting": "manual"}[kind]
	if o.Kind == "" {
		o.Kind = kind
	}
	o.Status = map[string]string{"OrderStatus_Open": "pending", "OrderStatus_Closed": "closed", "OrderStatus_Finished": "paid"}[status]
	if o.Status == "" {
		o.Status = status
	}
	if o.Status == "paid" && o.Kind != "purchase" {
		o.Credit = o.Amount
	}
	return
}

func nyanpassAffiliateRecord(row scanner) (o Order, e error) {
	var id int64
	var amount, kind, status, message, created string
	e = row.Scan(&id, &o.UserID, &amount, &kind, &status, &message, &created)
	if e != nil {
		return
	}
	o.Amount, e = scaledLegacy(amount, 100)
	o.Kind, o.Status = "legacy_affiliate", "recorded"
	o.Reference = fmt.Sprintf("nyanpass-affiliate-%d", id)
	o.Description = strings.TrimSpace(strings.Join([]string{kind, status, message}, " "))
	for _, format := range []string{time.RFC3339Nano, "2006-01-02 15:04:05"} {
		if stamp, err := time.Parse(format, created); err == nil {
			o.Created = stamp.Unix()
			break
		}
	}
	return
}
