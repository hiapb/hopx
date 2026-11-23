package panel

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"golang.org/x/crypto/bcrypt"
	"hopx/internal/wire"

	"hopx/internal/certificate"
)

type sourceUser struct {
	ResetRequired bool `json:"resetRequired,omitempty"`
	User
	PasswordHash string `json:"passwordHash"`
	Inviter      int64  `json:"inviter"`
}

type sourceRule struct {
	wire.Rule
	LegacyConfig string `json:"legacyConfig,omitempty"`
	SelfSigned   bool   `json:"selfSigned,omitempty"`
	Inbound      int64  `json:"inbound"`
	Outbound     int64  `json:"outbound"`
}

type sourceDevice struct {
	ID      int64  `json:"id"`
	GroupID int64  `json:"groupId"`
	Name    string `json:"name"`
	Address string `json:"address"`
}

type snapshot struct {
	Settings      map[string]string  `json:"settings,omitempty"`
	Format        int                `json:"format"`
	Source        string             `json:"source"`
	UserGroups    []named            `json:"userGroups"`
	Users         []sourceUser       `json:"users"`
	DeviceGroups  []wire.DeviceGroup `json:"deviceGroups"`
	Devices       []sourceDevice     `json:"devices"`
	Rules         []sourceRule       `json:"rules"`
	Plans         []Plan             `json:"plans"`
	Orders        []Order            `json:"orders"`
	Vouchers      []voucher          `json:"vouchers"`
	Notifications []notice           `json:"notifications"`
}

type MigrationResult struct {
	BackupReviews    int            `json:"backupReviews"`
	ArchivedOrders   int            `json:"archivedOrders"`
	ImportedRules    int            `json:"importedRules"`
	ArchivedRules    int            `json:"archivedRules"`
	RuleIssues       map[string]int `json:"ruleIssues,omitempty"`
	AffiliateBalance int64          `json:"affiliateBalance"`
	PasswordResets   int            `json:"passwordResets"`
	Source           string         `json:"source"`
	Mode             string         `json:"mode"`
	Counts           map[string]int `json:"counts"`
	StagedRules      int            `json:"stagedRules"`
	Balance          int64          `json:"balance"`
	AccountedBytes   int64          `json:"accountedBytes"`
	RawBytes         int64          `json:"rawBytes"`
}

func (s *Server) Import(reader io.Reader, dryRun bool) (MigrationResult, error) {
	return s.importSnapshot(reader, dryRun, "", "")
}
func (s *Server) importSnapshot(reader io.Reader, dryRun bool, adminName, adminPassword string) (MigrationResult, error) {
	var out MigrationResult
	const maxSize = 128 << 20
	raw, e := io.ReadAll(io.LimitReader(reader, maxSize+1))
	if e != nil {
		return out, e
	}
	var in snapshot
	if len(raw) > maxSize || json.Unmarshal(raw, &in) != nil || in.Format != 1 || strings.TrimSpace(in.Source) == "" || len(in.Source) > 200 {
		return out, errors.New("快照格式无效")
	}
	out = summarizeSnapshot(in)
	tx, e := s.db.Begin()
	if e != nil {
		return out, e
	}
	defer tx.Rollback()
	sum := digest(string(raw))
	var previous string
	e = tx.QueryRow("SELECT checksum FROM migrations WHERE source=?", in.Source).Scan(&previous)
	if e == nil {
		if previous != sum {
			return out, errors.New("该来源已导入另一份快照")
		}
		out.Mode = "already-imported"
		return out, nil
	}
	if e != sql.ErrNoRows {
		return out, e
	}
	var count int
	if e = tx.QueryRow("SELECT (SELECT count(*) FROM users)+(SELECT count(*) FROM groups)+(SELECT count(*) FROM rules)").Scan(&count); e != nil {
		return out, e
	}
	if count != 0 {
		return out, errors.New("请使用独立的空目标库做首次导入")
	}
	if _, e = tx.Exec("INSERT INTO migrations(source,checksum) VALUES(?,?)", in.Source, sum); e != nil {
		return out, e
	}
	if e = applySnapshot(tx, in, adminName, adminPassword, &out); e != nil {
		return out, e
	}
	if dryRun {
		out.Mode = "dry-run"
		return out, nil
	}
	if e = tx.Commit(); e != nil {
		return out, e
	}
	return out, nil
}

func summarizeSnapshot(in snapshot) MigrationResult {
	out := MigrationResult{Source: in.Source, Mode: "imported", Counts: map[string]int{
		"users": len(in.Users), "userGroups": len(in.UserGroups), "deviceGroups": len(in.DeviceGroups), "devices": len(in.Devices),
		"rules": len(in.Rules), "plans": len(in.Plans), "orders": len(in.Orders), "vouchers": len(in.Vouchers), "notifications": len(in.Notifications),
		"settings": len(in.Settings),
	}}
	for _, u := range in.Users {
		if u.ResetRequired {
			out.PasswordResets++
		}
		out.Balance += u.Balance
		out.AffiliateBalance += u.AffiliateBalance
		out.AccountedBytes += u.Used
	}
	for _, r := range in.Rules {
		out.RawBytes += r.Inbound + r.Outbound
		if r.Enabled {
			out.StagedRules++
		}
	}
	return out
}

func applySnapshot(tx *sql.Tx, in snapshot, adminName, adminPassword string, report *MigrationResult) error {
	for key, value := range in.Settings {
		if _, e := tx.Exec("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", key, value); e != nil {
			return e
		}
	}
	for _, g := range in.UserGroups {
		if g.ID < 0 || g.Name == "" {
			return fmt.Errorf("无效用户组 %d", g.ID)
		}
		if _, e := tx.Exec("INSERT INTO user_groups(id,name) VALUES(?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name", g.ID, g.Name); e != nil {
			return e
		}
	}
	admins := 0
	for _, u := range in.Users {
		if u.ID <= 0 || u.Quota < 0 || u.Used < 0 || u.Balance < 0 || u.AffiliateBalance < 0 || u.Expires < 0 || u.MaxRules < 0 || !validUserOverrides(u.User) {
			return fmt.Errorf("无效用户 ID %d", u.ID)
		}
		if u.ResetRequired || (u.Admin && adminName == u.Name && adminPassword != "") {
			u.PasswordHash = "reset-required"
			if u.Admin && adminName == u.Name && adminPassword != "" {
				hash, err := bcrypt.GenerateFromPassword([]byte(adminPassword), bcrypt.DefaultCost)
				if err != nil {
					return err
				}
				u.PasswordHash = string(hash)
			}
		} else if _, e := bcrypt.Cost([]byte(u.PasswordHash)); e != nil {
			return fmt.Errorf("用户 %d 的密码哈希需要转换或执行密码重置", u.ID)
		}
		if u.Admin && !u.Banned {
			admins++
		}
		if u.Invite == "" {
			u.Invite = token()[:16]
		}
		_, e := tx.Exec("INSERT INTO users(id,name,password,admin,banned,group_id,quota,used,balance,expires,max_rules,plan_id,invite,auto_renew,note,rate_override,ips_override,connections_override,affiliate_balance,allow_device) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", u.ID, u.Name, []byte(u.PasswordHash), u.Admin, u.Banned, u.Group, u.Quota, u.Used, u.Balance, u.Expires, u.MaxRules, u.PlanID, u.Invite, u.AutoRenew, u.Note, u.RateOverride, u.IPsOverride, u.ConnectionsOverride, u.AffiliateBalance, u.AllowDevice)
		if e != nil {
			return fmt.Errorf("用户 %d 无法导入: %w", u.ID, e)
		}
	}
	if admins == 0 {
		return errors.New("快照需要一个可用管理员")
	}
	for _, u := range in.Users {
		if u.Inviter == 0 {
			continue
		}
		if _, e := tx.Exec("UPDATE users SET inviter=? WHERE id=?", u.Inviter, u.ID); e != nil {
			return e
		}
	}
	for _, g := range in.DeviceGroups {
		if g.ID <= 0 || g.FirstPort < 1 || g.LastPort > 65535 || g.FirstPort > g.LastPort || g.Ratio < 0 || g.OfflineSeconds < 15 || g.TLSIngress < 0 || g.TLSIngress > 2 {
			return fmt.Errorf("无效设备组 %d", g.ID)
		}
		if g.Owner > 0 {
			var exists bool
			if e := tx.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE id=?)", g.Owner).Scan(&exists); e != nil || !exists {
				return fmt.Errorf("设备组 %d 的所有者不存在", g.ID)
			}
		}
		from, _ := json.Marshal(g.AllowedFrom)
		to, _ := json.Marshal(g.AllowedTo)
		users, _ := json.Marshal(g.UserGroups)
		chain, _ := json.Marshal(g.Chain)
		reverse, _ := json.Marshal(g.ReverseGroups)
		if e := validateIngress(g.Ingress); e != nil {
			return fmt.Errorf("设备组 %d: %w", g.ID, e)
		}
		ingress, _ := json.Marshal(g.Ingress)
		if _, e := groupPorts(g); e != nil {
			return fmt.Errorf("设备组 %d: %w", g.ID, e)
		}
		routing, _ := json.Marshal(g.Routing)
		if _, e := tx.Exec("INSERT INTO groups(id,name,kind,first_port,last_port,ratio,user_group,offline_seconds,owner,allowed_from,allowed_to,user_groups,chain,port_ranges,reverse_groups,tls_ingress,ingress,folder,note,show_order,hide_status,connect_host,routing) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", g.ID, g.Name, g.Kind, g.FirstPort, g.LastPort, g.Ratio, g.UserGroup, g.OfflineSeconds, g.Owner, string(from), string(to), string(users), string(chain), g.PortRanges, string(reverse), g.TLSIngress, string(ingress), g.Folder, g.Note, g.ShowOrder, g.HideStatus, g.ConnectHost, string(routing)); e != nil {
			return e
		}
	}
	for _, g := range in.DeviceGroups {
		if g.Kind == "chain" {
			if err := validateChain(g, lookupGroup(tx)); err != nil {
				return fmt.Errorf("设备组 %d: %w", g.ID, err)
			}
		}
	}
	for _, d := range in.Devices {
		if d.ID <= 0 || d.Name == "" {
			return fmt.Errorf("无效设备 %d", d.ID)
		}
		if _, e := tx.Exec("INSERT INTO migration_devices(source,id,group_id,name,address) VALUES(?,?,?,?,?)", in.Source, d.ID, d.GroupID, d.Name, d.Address); e != nil {
			return e
		}
	}
	for _, p := range in.Plans {
		if p.ID <= 0 || p.Duration <= 0 || p.Price < 0 || p.Quota < 0 || p.Rules < 0 {
			return fmt.Errorf("无效套餐 %d", p.ID)
		}
		if _, e := tx.Exec("INSERT INTO plans(id,name,description,price,duration,quota,rules,group_id,enabled,rate_mbps,max_ips,max_connections,kind) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)", p.ID, p.Name, p.Description, p.Price, p.Duration, p.Quota, p.Rules, p.GroupID, p.Enabled, p.RateMbps, p.MaxIPs, p.MaxConnections, normalizedPlanKind(p.Kind)); e != nil {
			return e
		}
	}
	for _, u := range in.Users {
		if u.PlanID == 0 {
			continue
		}
		var exists bool
		if e := tx.QueryRow("SELECT EXISTS(SELECT 1 FROM plans WHERE id=?)", u.PlanID).Scan(&exists); e != nil || !exists {
			return fmt.Errorf("用户 %d 的套餐不存在", u.ID)
		}
	}
	rules := slices.Clone(in.Rules)
	slices.SortStableFunc(rules, func(a, b sourceRule) int {
		if a.TLSShared == b.TLSShared {
			return 0
		}
		if a.TLSShared {
			return -1
		}
		return 1
	})
	for _, r := range rules {
		if r.ID <= 0 || r.Port <= 0 || r.Inbound < 0 || r.Outbound < 0 {
			return fmt.Errorf("无效规则 %d", r.ID)
		}
		owner, e := readUser(tx.QueryRow(userSelect+" WHERE id=?", r.Owner))
		if e != nil {
			return e
		}
		if r.SelfSigned && r.TLSCert == "" && r.TLSKey == "" {
			host := "localhost"
			if len(r.TLSServerNames) > 0 {
				host = r.TLSServerNames[0]
			}
			r.TLSCert, r.TLSKey, e = certificate.SelfSigned(host + ":443")
			if e != nil {
				return fmt.Errorf("规则 %d 生成自签证书: %w", r.ID, e)
			}
		}
		e = validRule(tx, owner, &r.Rule)
		if e != nil && in.Source != nyanpassSource {
			return fmt.Errorf("规则 %d: %w", r.ID, e)
		}
		if e != nil {
			reason := e.Error()
			payload, err := json.Marshal(r)
			if err != nil {
				return err
			}
			if len(r.BackupPath) > 0 {
				r.BackupPath = nil
				if e = validRule(tx, owner, &r.Rule); e == nil {
					reason = "备用链路待核对"
				}
			}
			if _, err = tx.Exec("INSERT INTO migration_rule_issues(source,rule_id,reason,payload) VALUES(?,?,?,?)", in.Source, r.ID, reason, string(payload)); err != nil {
				return err
			}
			if report.RuleIssues == nil {
				report.RuleIssues = make(map[string]int)
			}
			report.RuleIssues[reason]++
			if e != nil {
				report.ArchivedRules++
				if r.Enabled {
					report.StagedRules--
				}
				continue
			}
			report.BackupReviews++
		}
		enabled := r.Enabled
		r.Enabled = false
		raw, e := json.Marshal(r.Rule)
		if e != nil {
			return e
		}
		if _, e = tx.Exec("INSERT INTO rules(id,owner,entry,port,json) VALUES(?,?,?,?,?)", r.ID, r.Owner, r.Entry, r.Port, string(raw)); e != nil {
			return e
		}
		if _, e = tx.Exec("INSERT INTO migration_rules(rule_id,source,was_enabled) VALUES(?,?,?)", r.ID, in.Source, enabled); e != nil {
			return e
		}
		if _, e = tx.Exec("INSERT INTO traffic(rule_id,inbound,outbound) VALUES(?,?,?)", r.ID, r.Inbound, r.Outbound); e != nil {
			return e
		}
		report.ImportedRules++
	}
	for _, o := range in.Orders {
		if in.Source == nyanpassSource {
			var exists bool
			if e := tx.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE id=?)", o.UserID).Scan(&exists); e != nil {
				return e
			}
			if !exists {
				payload, err := json.Marshal(o)
				if err != nil {
					return err
				}
				if _, err = tx.Exec("INSERT INTO migration_order_issues(source,order_id,payload) VALUES(?,?,?)", in.Source, o.ID, string(payload)); err != nil {
					return err
				}
				report.ArchivedOrders++
				continue
			}
		}
		var ref any
		if o.Reference != "" {
			ref = o.Reference
		}
		if _, e := tx.Exec("INSERT INTO orders(id,user_id,amount,credit,kind,status,reference,description,created,paid_at) VALUES(nullif(?,0),?,?,?,?,?,?,?,?,?)", o.ID, o.UserID, o.Amount, o.Credit, o.Kind, o.Status, ref, o.Description, o.Created, o.PaidAt); e != nil {
			return e
		}
	}
	for _, v := range in.Vouchers {
		if v.Remaining < 0 || v.Discount < 0 || v.Discount > 10000 {
			return fmt.Errorf("无效兑换码的套餐 ID %d", v.PlanID)
		}
		if _, e := tx.Exec("INSERT INTO redeem(code,plan_id,remaining,discount,expiry) VALUES(?,?,?,?,?)", v.Code, v.PlanID, v.Remaining, v.Discount, v.Expiry); e != nil {
			return e
		}
	}
	for _, n := range in.Notifications {
		if _, e := tx.Exec("INSERT INTO notifications(id,title,body,created) VALUES(?,?,?,?)", n.ID, n.Title, n.Body, n.Created); e != nil {
			return e
		}
	}
	return nil
}
