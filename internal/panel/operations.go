package panel

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"hopx/internal/wire"
)

func (s *Server) assignUserPlan(w http.ResponseWriter, r *http.Request, _ User) {
	var input struct {
		PlanID                      int64
		Quota, Group, Rules, Limits bool
	}
	if !decode(w, r, &input) {
		return
	}
	if input.PlanID < 0 || (input.PlanID == 0 && (input.Quota || input.Group || input.Rules || input.Limits)) {
		fail(w, 400, "请选择用于同步额度的套餐")
		return
	}
	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		dbFailure(w, err)
		return
	}
	defer tx.Rollback()
	var quota, group, maxRules int64
	if input.PlanID > 0 {
		err = tx.QueryRow("SELECT quota,group_id,rules FROM plans WHERE id=? AND archived=0", input.PlanID).Scan(&quota, &group, &maxRules)
		if errors.Is(err, sql.ErrNoRows) {
			fail(w, 404, "套餐不存在")
			return
		} else if err != nil {
			dbFailure(w, err)
			return
		}
	}
	if input.Group {
		if err = clearUnauthorizedRuleRoutes(tx, group, "u.id=? AND u.admin=0 AND u.group_id<>?", pathID(r), group); err != nil {
			dbFailure(w, err)
			return
		}
	}
	result, err := tx.Exec(`UPDATE users SET plan_id=?1, quota=CASE WHEN ? THEN ? ELSE quota END,
		used=CASE WHEN ? THEN 0 ELSE used END, billing_remainder=CASE WHEN ? THEN 0 ELSE billing_remainder END,
		quota_epoch=quota_epoch+CASE WHEN ? THEN 1 ELSE 0 END,
		max_rules=CASE WHEN ? THEN ? ELSE max_rules END, group_id=CASE WHEN ? THEN ? ELSE group_id END,
		rate_override=CASE WHEN ? THEN NULL ELSE rate_override END, ips_override=CASE WHEN ? THEN NULL ELSE ips_override END,
		connections_override=CASE WHEN ? THEN NULL ELSE connections_override END,
		auto_renew=CASE WHEN ?1>0 AND plan_id=0 AND auto_renew_configured=0 THEN 1 ELSE auto_renew END,
		auto_renew_configured=CASE WHEN ?1>0 OR plan_id>0 THEN 1 ELSE auto_renew_configured END WHERE id=?`,
		input.PlanID, input.Quota, quota, input.Quota, input.Quota, input.Quota, input.Rules, maxRules, input.Group, group, input.Limits, input.Limits, input.Limits, pathID(r))
	if err != nil {
		dbFailure(w, err)
		return
	}
	if count, _ := result.RowsAffected(); count == 0 {
		fail(w, 404, "账号不存在")
		return
	}
	if err = tx.Commit(); err != nil {
		dbFailure(w, err)
		return
	}
	w.WriteHeader(204)
}

func (s *Server) resetUserPassword(w http.ResponseWriter, r *http.Request, _ User) {
	var input struct{ Password string }
	if !decode(w, r, &input) {
		return
	}
	if len(input.Password) < 10 || len(input.Password) > 72 {
		fail(w, 400, "密码须为 10–72 字节")
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		dbFailure(w, err)
		return
	}
	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		dbFailure(w, err)
		return
	}
	defer tx.Rollback()
	id := pathID(r)
	if err = saveUserPassword(tx, id, hash); errors.Is(err, sql.ErrNoRows) {
		fail(w, 404, "账号不存在")
		return
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		dbFailure(w, err)
		return
	}
	w.WriteHeader(204)
}

func saveUserPassword(tx *sql.Tx, id int64, hash []byte) error {
	result, err := tx.Exec("UPDATE users SET password=? WHERE id=?", hash, id)
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count == 0 {
		return sql.ErrNoRows
	}
	_, err = tx.Exec("DELETE FROM sessions WHERE user_id=?", id)
	return err
}

func (s *Server) removeUser(w http.ResponseWriter, r *http.Request, admin User) {
	id := pathID(r)
	if id == admin.ID {
		fail(w, 400, "当前管理员账号必须保留")
		return
	}
	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		dbFailure(w, err)
		return
	}
	defer tx.Rollback()
	user, err := readUser(tx.QueryRow(userSelect+" WHERE id=?", id))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			fail(w, 404, "账号不存在")
		} else {
			dbFailure(w, err)
		}
		return
	}
	var retained bool
	err = tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM orders WHERE user_id=?
		UNION ALL SELECT 1 FROM users WHERE inviter=?
		UNION ALL SELECT 1 FROM groups WHERE owner=?
		UNION ALL SELECT 1 FROM quota_grants WHERE user_id=?)`, id, id, id, id).Scan(&retained)
	if err != nil {
		dbFailure(w, err)
		return
	}
	if retained || user.Balance != 0 || user.AffiliateBalance != 0 || user.Admin {
		fail(w, 409, "账号仍有账务、邀请、设备或管理员权限，需先处理关联数据")
		return
	}
	if _, err = tx.Exec("DELETE FROM users WHERE id=?", id); err == nil {
		err = tx.Commit()
	}
	if err != nil {
		dbFailure(w, err)
		return
	}
	w.WriteHeader(204)
}

func (s *Server) removeUnusedUsers(w http.ResponseWriter, r *http.Request, _ User) {
	var input struct{ Confirm bool }
	if !decode(w, r, &input) {
		return
	}
	const eligible = `u.admin=0 AND u.group_id=0 AND u.plan_id=0 AND u.expires<=unixepoch()
		AND u.balance=0 AND u.affiliate_balance=0
		AND NOT EXISTS(SELECT 1 FROM orders WHERE user_id=u.id)
		AND NOT EXISTS(SELECT 1 FROM users WHERE inviter=u.id)
		AND NOT EXISTS(SELECT 1 FROM groups WHERE owner=u.id)
		AND NOT EXISTS(SELECT 1 FROM quota_grants WHERE user_id=u.id)`
	var count int64
	if input.Confirm {
		result, err := s.db.ExecContext(r.Context(), "DELETE FROM users AS u WHERE "+eligible)
		if err != nil {
			dbFailure(w, err)
			return
		}
		count, _ = result.RowsAffected()
	} else if err := s.db.QueryRowContext(r.Context(), "SELECT count(*) FROM users AS u WHERE "+eligible).Scan(&count); err != nil {
		dbFailure(w, err)
		return
	}
	respond(w, 200, map[string]int64{"count": count})
}

func (s *Server) editNode(w http.ResponseWriter, r *http.Request, user User) {
	var input struct{ Name, Region, Address string }
	if !decode(w, r, &input) {
		return
	}
	input.Name, input.Region, input.Address = strings.TrimSpace(input.Name), strings.TrimSpace(input.Region), strings.TrimSpace(input.Address)
	if input.Name == "" || len(input.Name) > 96 || len(input.Region) > 64 || len(input.Address) > 256 {
		fail(w, 400, "节点名称、地区或地址无效")
		return
	}
	id := pathID(r)
	result, err := s.db.ExecContext(r.Context(), `UPDATE devices SET registration=json_set(registration,'$.name',?,'$.region',?,'$.address',?)
		WHERE id=? AND ( ? OR group_id IN (SELECT id FROM groups WHERE owner=?))`, input.Name, input.Region, input.Address, id, user.Admin, user.ID)
	if err != nil {
		dbFailure(w, err)
		return
	}
	if count, _ := result.RowsAffected(); count == 0 {
		fail(w, 404, "设备不存在")
		return
	}
	w.WriteHeader(204)
}

func (s *Server) groupOperations(w http.ResponseWriter, r *http.Request, u User) {
	id := pathID(r)
	group, err := scanGroup(s.db.QueryRowContext(r.Context(), groupSelect+" WHERE id=?", id))
	if err != nil || (!u.Admin && group.Owner != u.ID) {
		fail(w, 404, "设备组不存在")
		return
	}
	var input struct{ Action string }
	if !decode(w, r, &input) {
		return
	}
	switch input.Action {
	case "revoke-enrollments":
		ctx := r.Context()
		tx, beginErr := s.db.BeginTx(ctx, nil)
		if beginErr != nil {
			dbFailure(w, beginErr)
			return
		}
		defer tx.Rollback()
		if err = deleteGroupEnrollments(ctx, tx, id); err == nil {
			err = tx.Commit()
		}
	case "reset-credentials":
		if group.Kind == "chain" {
			fail(w, 400, "链式出口没有接入凭据")
			return
		}
		err = s.resetGroupCredentials(r.Context(), id)
	case "clear-traffic":
		_, err = s.db.ExecContext(r.Context(), "DELETE FROM traffic WHERE rule_id IN (SELECT id FROM rules WHERE entry=?)", id)
	default:
		fail(w, 400, "设备组操作无效")
		return
	}
	if err != nil {
		dbFailure(w, err)
		return
	}
	w.WriteHeader(204)
}

func deleteGroupEnrollments(ctx context.Context, tx *sql.Tx, groupID int64) error {
	if _, err := tx.ExecContext(ctx, "DELETE FROM group_enrollments WHERE group_id=?", groupID); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, "DELETE FROM invitations WHERE group_id=?", groupID)
	return err
}

func (s *Server) resetGroupCredentials(ctx context.Context, groupID int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = deleteGroupEnrollments(ctx, tx, groupID); err != nil {
		return err
	}
	// A revoked device keeps its inventory and samples. A new registration
	// receives a fresh identity and cannot continue the previous relay session.
	if _, err = tx.ExecContext(ctx, "UPDATE devices SET token='revoked:'||id WHERE group_id=?", groupID); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	s.mu.Lock()
	for id, device := range s.devices {
		if device.GroupID == groupID {
			delete(s.devices, id)
			delete(s.diagnostics, id)
		}
	}
	s.mu.Unlock()
	return nil
}

func (s *Server) clearGroupTraffic(w http.ResponseWriter, r *http.Request, _ User) {
	var input struct{ IDs []int64 }
	if !decode(w, r, &input) {
		return
	}
	if len(input.IDs) < 1 || len(input.IDs) > 1000 {
		fail(w, 400, "请选择 1 至 1000 个入口设备组")
		return
	}
	ids, _ := json.Marshal(input.IDs)
	_, err := s.db.ExecContext(r.Context(), `DELETE FROM traffic WHERE rule_id IN (
		SELECT r.id FROM rules r JOIN groups g ON g.id=r.entry
		WHERE g.kind IN ('entry','both') AND r.entry IN (SELECT value FROM json_each(?)))`, string(ids))
	if err != nil {
		dbFailure(w, err)
		return
	}
	w.WriteHeader(204)
}

func (s *Server) deviceFolders(w http.ResponseWriter, r *http.Request, _ User) {
	if r.Method == http.MethodGet {
		s.folderCounts(w, r, `SELECT name,sum(items) FROM (
			SELECT folder AS name,count(*) AS items FROM groups GROUP BY folder
			UNION ALL SELECT name,0 FROM device_folders
		) GROUP BY name ORDER BY name`)
		return
	}
	var input struct {
		IDs  []int64
		From *string
		Name string
	}
	if !decode(w, r, &input) {
		return
	}
	input.Name = strings.TrimSpace(input.Name)
	if len(input.Name) > 200 || strings.ContainsAny(input.Name, "\x00\r\n") ||
		len(input.IDs) > 1000 || (input.From != nil && len(input.IDs) != 0) {
		fail(w, 400, "请选择设备组或要整理的分组，并填写有效名称")
		return
	}
	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		dbFailure(w, err)
		return
	}
	defer tx.Rollback()
	switch {
	case input.From != nil:
		if *input.From == "" || len(*input.From) > 200 {
			fail(w, 400, "请选择已有分组")
			return
		}
		result, err := tx.Exec("UPDATE groups SET folder=? WHERE folder=?", input.Name, *input.From)
		if err != nil {
			dbFailure(w, err)
			return
		}
		deleted, err := tx.Exec("DELETE FROM device_folders WHERE name=?", *input.From)
		if err != nil {
			dbFailure(w, err)
			return
		}
		if a, _ := result.RowsAffected(); a == 0 {
			if b, _ := deleted.RowsAffected(); b == 0 {
				fail(w, 404, "分组已不存在")
				return
			}
		}
	case len(input.IDs) > 0:
		ids, _ := json.Marshal(input.IDs)
		result, err := tx.Exec("UPDATE groups SET folder=? WHERE id IN (SELECT value FROM json_each(?))", input.Name, string(ids))
		if err != nil {
			dbFailure(w, err)
			return
		}
		if count, _ := result.RowsAffected(); count != int64(len(input.IDs)) {
			fail(w, 409, "所选设备组有变化，请刷新后重试")
			return
		}
	case input.Name == "":
		fail(w, 400, "请填写新分组名称")
		return
	}
	if input.Name != "" {
		if _, err = tx.Exec("INSERT INTO device_folders(name) VALUES(?) ON CONFLICT DO NOTHING", input.Name); err != nil {
			dbFailure(w, err)
			return
		}
	}
	if err = tx.Commit(); err != nil {
		dbFailure(w, err)
		return
	}
	w.WriteHeader(204)
}

func (s *Server) nodeConfigSummary(w http.ResponseWriter, r *http.Request, u User) {
	id := pathID(r)
	var owner int64
	err := s.db.QueryRowContext(r.Context(), "SELECT owner FROM groups WHERE id=?", id).Scan(&owner)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && !u.Admin && owner != u.ID) {
		fail(w, 404, "设备组不存在")
		return
	}
	if err != nil {
		dbFailure(w, err)
		return
	}
	config, err := s.nodeConfig(id)
	if err != nil {
		dbFailure(w, err)
		return
	}
	type ruleSummary struct {
		ID         int64    `json:"id"`
		Name       string   `json:"name"`
		Port       int      `json:"port"`
		Network    string   `json:"network"`
		TargetList []string `json:"targets"`
		Path       []int64  `json:"path"`
		BackupPath []int64  `json:"backupPath"`
		Routes     int      `json:"routes"`
		Backup     int      `json:"backup"`
	}
	items := make([]ruleSummary, 0, len(config.value.Rules))
	for _, rule := range config.value.Rules {
		items = append(items, ruleSummary{
			ID: rule.ID, Name: rule.Name, Port: rule.Port, Network: rule.Protocol,
			TargetList: rule.Targets, Path: rule.Path, BackupPath: rule.BackupPath,
			Routes: len(rule.Routes), Backup: len(rule.Backup),
		})
	}
	respond(w, 200, map[string]any{"revision": config.value.Revision, "rules": items})
}

func (s *Server) ruleStatistics(w http.ResponseWriter, r *http.Request, u User) {
	var out struct {
		Today     int64 `json:"today"`
		Yesterday int64 `json:"yesterday"`
		Total     int   `json:"total"`
		Enabled   int   `json:"enabled"`
		Inbound   int64 `json:"inbound"`
		Outbound  int64 `json:"outbound"`
	}
	err := s.db.QueryRowContext(r.Context(), `SELECT count(*),coalesce(sum(json_extract(r.json,'$.enabled')=1 AND `+ruleRouteReadySQL+`),0),
		coalesce(sum(t.inbound),0),coalesce(sum(t.outbound),0)
		FROM rules r LEFT JOIN traffic t ON t.rule_id=r.id WHERE r.owner=? OR ?`, u.ID, u.Admin).
		Scan(&out.Total, &out.Enabled, &out.Inbound, &out.Outbound)
	if err != nil {
		dbFailure(w, err)
		return
	}
	day := trafficDay(time.Now())
	yesterday := day - 86400
	err = s.db.QueryRowContext(r.Context(), `SELECT coalesce(sum(CASE WHEN day=? THEN inbound+outbound END),0),
		coalesce(sum(CASE WHEN day=? THEN inbound+outbound END),0) FROM daily_user_traffic
		WHERE user_id=? AND day IN (?,?)`, day, yesterday, u.ID, day, yesterday).Scan(&out.Today, &out.Yesterday)
	if err != nil {
		dbFailure(w, err)
		return
	}
	respond(w, 200, out)
}

func validRuleFolder(name string) bool {
	return len(name) <= 100 && !strings.ContainsAny(name, "\x00\r\n")
}

func (s *Server) ruleFolders(w http.ResponseWriter, r *http.Request, u User) {
	owner, _ := strconv.ParseInt(r.URL.Query().Get("owner"), 10, 64)
	if !u.Admin {
		owner = u.ID
	}
	if r.Method == http.MethodGet {
		all := u.Admin && owner == 0
		s.folderCounts(w, r, `SELECT name,sum(items) FROM (
			SELECT coalesce(json_extract(json,'$.label'),'') AS name,count(*) AS items
			FROM rules WHERE owner=? OR ? GROUP BY 1
			UNION ALL SELECT name,0 FROM rule_folders WHERE owner=? OR ?
		) GROUP BY name ORDER BY name`, owner, all, owner, all)
		return
	}
	if owner == 0 {
		owner = u.ID
	}
	var input struct{ From, Name string }
	if !decode(w, r, &input) {
		return
	}
	input.Name = strings.TrimSpace(input.Name)
	if (input.From == "" && input.Name == "") || !validRuleFolder(input.From) || !validRuleFolder(input.Name) {
		fail(w, 400, "规则分组名称无效")
		return
	}
	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		dbFailure(w, err)
		return
	}
	defer tx.Rollback()
	if input.From != "" {
		result, err := tx.Exec("UPDATE rules SET json=json_set(json,'$.label',?) WHERE owner=? AND json_extract(json,'$.label')=?", input.Name, owner, input.From)
		if err != nil {
			dbFailure(w, err)
			return
		}
		deleted, err := tx.Exec("DELETE FROM rule_folders WHERE owner=? AND name=?", owner, input.From)
		if err != nil {
			dbFailure(w, err)
			return
		}
		if a, _ := result.RowsAffected(); a == 0 {
			if b, _ := deleted.RowsAffected(); b == 0 {
				fail(w, 404, "分组已不存在")
				return
			}
		}
	}
	if input.Name != "" {
		if _, err = tx.Exec("INSERT INTO rule_folders(owner,name) VALUES(?,?) ON CONFLICT DO NOTHING", owner, input.Name); err != nil {
			dbFailure(w, err)
			return
		}
	}
	if err = tx.Commit(); err != nil {
		dbFailure(w, err)
		return
	}
	w.WriteHeader(204)
}

func (s *Server) folderCounts(w http.ResponseWriter, r *http.Request, query string, args ...any) {
	rows, err := s.db.QueryContext(r.Context(), query, args...)
	if err != nil {
		dbFailure(w, err)
		return
	}
	defer rows.Close()
	type folder struct {
		Name  string `json:"name"`
		Count int    `json:"count"`
	}
	folders := []folder{}
	for rows.Next() {
		var item folder
		if err = rows.Scan(&item.Name, &item.Count); err != nil {
			dbFailure(w, err)
			return
		}
		folders = append(folders, item)
	}
	if err = rows.Err(); err != nil {
		dbFailure(w, err)
		return
	}
	respond(w, 200, folders)
}

func rerouteRule(tx *sql.Tx, u User, id, entry int64, path []int64, updatePath bool) (wire.Rule, error) {
	var rule wire.Rule
	var raw []byte
	if err := tx.QueryRow("SELECT json FROM rules WHERE id=?", id).Scan(&raw); err != nil {
		return rule, err
	}
	if err := json.Unmarshal(raw, &rule); err != nil {
		return rule, err
	}
	rule.ID = id
	if entry > 0 && entry != rule.Entry {
		if rule.UsesSharedTLS() {
			return rule, errors.New("共享 TLS 规则需要按父子关系切换入口")
		}
		rule.Entry, rule.Port = entry, 0
	}
	if updatePath {
		rule.Path = path
	}
	return rule, storeRule(tx, u, &rule)
}

func (s *Server) userReferral(w http.ResponseWriter, r *http.Request, _ User) {
	type settings struct {
		Custom              bool  `json:"custom"`
		Rate                int64 `json:"rate"`
		FirstOnly           bool  `json:"firstOnly"`
		RequireBinding      bool  `json:"requireBinding"`
		Inviter             int64 `json:"inviter"`
		RegistrationEnabled *bool `json:"registrationEnabled"`
	}
	id := pathID(r)
	var options settings
	if r.Method == http.MethodGet {
		err := s.db.QueryRowContext(r.Context(), `SELECT rs.user_id IS NOT NULL,coalesce(rs.rate,0),
			coalesce(rs.first_only,0),coalesce(rs.require_binding,0),coalesce(u.inviter,0),coalesce(rs.registration_enabled,1)
			FROM users u LEFT JOIN user_referral_settings rs ON u.id=rs.user_id WHERE u.id=?`, id).
			Scan(&options.Custom, &options.Rate, &options.FirstOnly, &options.RequireBinding, &options.Inviter, &options.RegistrationEnabled)
		if errors.Is(err, sql.ErrNoRows) {
			fail(w, 404, "账号不存在")
		} else if err != nil {
			dbFailure(w, err)
		} else {
			respond(w, 200, options)
		}
		return
	}
	if !decode(w, r, &options) {
		return
	}
	if options.Rate < 0 || options.Rate > 10000 {
		fail(w, 400, "返佣比例须为 0 至 10000")
		return
	}
	var err error
	if options.Custom {
		_, err = s.db.ExecContext(r.Context(), `INSERT INTO user_referral_settings(user_id,rate,first_only,require_binding,registration_enabled)
			VALUES(?,?,?,?,coalesce(?,1)) ON CONFLICT(user_id) DO UPDATE SET rate=excluded.rate,first_only=excluded.first_only,
			require_binding=excluded.require_binding,registration_enabled=coalesce(?,registration_enabled)`,
			id, options.Rate, options.FirstOnly, options.RequireBinding, options.RegistrationEnabled, options.RegistrationEnabled)
	} else {
		_, err = s.db.ExecContext(r.Context(), "DELETE FROM user_referral_settings WHERE user_id=?", id)
	}
	if err != nil {
		dbFailure(w, err)
		return
	}
	w.WriteHeader(204)
}

func (s *Server) removeInvalidRules(w http.ResponseWriter, r *http.Request, _ User) {
	var input struct{ Confirm bool }
	if !decode(w, r, &input) {
		return
	}
	const invalid = `NOT EXISTS(SELECT 1 FROM users WHERE id=r.owner)
		OR NOT EXISTS(SELECT 1 FROM groups WHERE id=r.entry)
		OR EXISTS(SELECT 1 FROM json_each(r.json,'$.path') p WHERE NOT EXISTS(SELECT 1 FROM groups WHERE id=p.value))
		OR EXISTS(SELECT 1 FROM json_each(r.json,'$.backupPath') p WHERE NOT EXISTS(SELECT 1 FROM groups WHERE id=p.value))`
	var count int64
	if input.Confirm {
		result, err := s.db.ExecContext(r.Context(), "DELETE FROM rules AS r WHERE "+invalid)
		if err != nil {
			dbFailure(w, err)
			return
		}
		count, _ = result.RowsAffected()
	} else if err := s.db.QueryRowContext(r.Context(), "SELECT count(*) FROM rules AS r WHERE "+invalid).Scan(&count); err != nil {
		dbFailure(w, err)
		return
	}
	respond(w, 200, map[string]int64{"count": count})
}

type userServiceInfo struct {
	Group                     string `json:"group"`
	Plan                      string `json:"plan"`
	RenewPrice                int64  `json:"renewPrice"`
	RateMbps                  int    `json:"rateMbps"`
	MaxIPs                    int    `json:"maxIPs"`
	MaxConnections            int    `json:"maxConnections"`
	InviteRegistrationEnabled bool   `json:"inviteRegistrationEnabled"`
	ReferralRate              int    `json:"referralRate"`
	ReferralFirstOnly         bool   `json:"referralFirstOnly"`
}

func (s *Server) loadUserService(ctx context.Context, id int64) (out userServiceInfo, err error) {
	err = s.db.QueryRowContext(ctx, `SELECT g.name,coalesce(p.name,''),coalesce(p.price,0),
		coalesce(u.rate_override,p.rate_mbps,0),coalesce(u.ips_override,p.max_ips,0),coalesce(u.connections_override,p.max_connections,0),
		coalesce(rs.registration_enabled,1) AND coalesce((SELECT value FROM settings WHERE key='registration'),'closed') NOT IN ('closed','no-invite'),
		coalesce(rs.rate,(SELECT CAST(value AS INTEGER) FROM settings WHERE key='referralRate'),0),
		coalesce(rs.first_only,(SELECT value='true' FROM settings WHERE key='referralFirstOnly'),0)
		FROM users u JOIN user_groups g ON g.id=u.group_id LEFT JOIN plans p ON p.id=u.plan_id
		LEFT JOIN user_referral_settings rs ON rs.user_id=u.id WHERE u.id=?`, id).
		Scan(&out.Group, &out.Plan, &out.RenewPrice, &out.RateMbps, &out.MaxIPs, &out.MaxConnections,
			&out.InviteRegistrationEnabled, &out.ReferralRate, &out.ReferralFirstOnly)
	return out, err
}

func (s *Server) userService(w http.ResponseWriter, r *http.Request, u User) {
	out, err := s.loadUserService(r.Context(), u.ID)
	if err != nil {
		dbFailure(w, err)
		return
	}
	respond(w, 200, out)
}
