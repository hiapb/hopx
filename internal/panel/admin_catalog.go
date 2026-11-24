package panel

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"
)

func (s *Server) archivePlan(w http.ResponseWriter, r *http.Request, _ User) {
	result, err := s.db.ExecContext(r.Context(), "UPDATE plans SET archived=1,enabled=0 WHERE id=? AND archived=0", pathID(r))
	if err != nil {
		dbFailure(w, err)
		return
	}
	if count, _ := result.RowsAffected(); count == 0 {
		fail(w, 404, "套餐不存在")
		return
	}
	w.WriteHeader(204)
}

func (s *Server) pushPlan(w http.ResponseWriter, r *http.Request, _ User) {
	var input struct{ Quota, Group, Rules, Limits, Expires bool }
	if !decode(w, r, &input) {
		return
	}
	if !input.Quota && !input.Group && !input.Rules && !input.Limits && !input.Expires {
		fail(w, 400, "请选择要更新的属性")
		return
	}
	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		dbFailure(w, err)
		return
	}
	defer tx.Rollback()
	plan, err := readPlan(tx.QueryRow("SELECT "+planColumns+" FROM plans WHERE id=? AND archived=0", pathID(r)))
	if errors.Is(err, sql.ErrNoRows) {
		fail(w, 404, "套餐不存在")
		return
	}
	if err != nil {
		dbFailure(w, err)
		return
	}
	if input.Group {
		if err = clearUnauthorizedRuleRoutes(tx, plan.GroupID, "u.plan_id=? AND u.admin=0 AND u.group_id<>?", plan.ID, plan.GroupID); err != nil {
			dbFailure(w, err)
			return
		}
	}
	result, err := tx.Exec(`UPDATE users SET quota=CASE WHEN ? THEN ? ELSE quota END,
		unlimited_traffic=CASE WHEN ? THEN ? ELSE unlimited_traffic END,
		expires=CASE WHEN ? THEN ? ELSE expires END,
		quota_epoch=quota_epoch+CASE WHEN ? THEN 1 ELSE 0 END,
		max_rules=CASE WHEN ? THEN ? ELSE max_rules END, group_id=CASE WHEN ? THEN ? ELSE group_id END,
		rate_override=CASE WHEN ? THEN NULL ELSE rate_override END,
		ips_override=CASE WHEN ? THEN NULL ELSE ips_override END,
		connections_override=CASE WHEN ? THEN NULL ELSE connections_override END WHERE plan_id=?`,
		input.Quota, plan.Quota, input.Quota, plan.UnlimitedTraffic, input.Expires, planExpiry(plan, time.Now().Unix()),
		input.Quota, input.Rules, plan.Rules, input.Group, plan.GroupID,
		input.Limits, input.Limits, input.Limits, plan.ID)
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		dbFailure(w, err)
		return
	}
	count, _ := result.RowsAffected()
	respond(w, 200, map[string]int64{"count": count})
}

func (s *Server) reorderPlans(w http.ResponseWriter, r *http.Request, _ User) {
	s.reorder(w, r, "UPDATE plans SET show_order=? WHERE id=? AND archived=0")
}

func (s *Server) reorderUserGroups(w http.ResponseWriter, r *http.Request, _ User) {
	s.reorder(w, r, "UPDATE user_groups SET show_order=? WHERE id=?")
}

func (s *Server) reorderDeviceGroups(w http.ResponseWriter, r *http.Request, _ User) {
	s.reorder(w, r, "UPDATE groups SET show_order=? WHERE id=?")
}

func (s *Server) reorder(w http.ResponseWriter, r *http.Request, statement string) {
	var in struct{ IDs []int64 }
	if !decode(w, r, &in) {
		return
	}
	if len(in.IDs) == 0 || len(in.IDs) > 5000 {
		fail(w, 400, "排序项数无效")
		return
	}
	seen := make(map[int64]bool, len(in.IDs))
	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		dbFailure(w, err)
		return
	}
	defer tx.Rollback()
	for i, id := range in.IDs {
		if id < 0 || seen[id] {
			fail(w, 400, "排序中包含无效或重复编号")
			return
		}
		seen[id] = true
		result, err := tx.Exec(statement, i+1, id)
		if err != nil {
			dbFailure(w, err)
			return
		}
		if count, _ := result.RowsAffected(); count != 1 {
			fail(w, 409, "列表已发生变化，请刷新后重试")
			return
		}
	}
	if err := tx.Commit(); err != nil {
		dbFailure(w, err)
		return
	}
	w.WriteHeader(204)
}

func (s *Server) deviceGroupTotals(w http.ResponseWriter, r *http.Request, u User) {
	groups, err := s.groups()
	if err != nil {
		dbFailure(w, err)
		return
	}
	type total struct {
		Online  int   `json:"online"`
		Devices int   `json:"devices"`
		Traffic int64 `json:"traffic"`
	}
	result := make(map[int64]total)
	for _, group := range groups {
		if u.Admin || group.Owner == u.ID {
			result[group.ID] = total{}
		}
	}
	devices, err := s.deviceSnapshot(false)
	if err != nil {
		dbFailure(w, err)
		return
	}
	for _, device := range devices {
		item, visible := result[device.GroupID]
		if !visible {
			continue
		}
		item.Devices++
		if device.Online {
			item.Online++
		}
		result[device.GroupID] = item
	}
	if u.Admin {
		rows, err := s.db.QueryContext(r.Context(), `SELECT group_id,sum(bytes) FROM (
			SELECT r.entry AS group_id,t.inbound+t.outbound AS bytes FROM traffic t JOIN rules r ON r.id=t.rule_id
			UNION ALL SELECT group_id,inbound+outbound FROM exit_group_traffic
		) GROUP BY group_id`)
		if err != nil {
			dbFailure(w, err)
			return
		}
		defer rows.Close()
		for rows.Next() {
			var id, traffic int64
			if err := rows.Scan(&id, &traffic); err != nil {
				dbFailure(w, err)
				return
			}
			item, ok := result[id]
			if ok {
				item.Traffic = traffic
				result[id] = item
			}
		}
		if err := rows.Err(); err != nil {
			dbFailure(w, err)
			return
		}
	}
	respond(w, 200, result)
}

func (s *Server) archiveOrders(w http.ResponseWriter, r *http.Request, _ User) {
	var in struct{ IDs []int64 }
	if !decode(w, r, &in) {
		return
	}
	if len(in.IDs) == 0 || len(in.IDs) > 1000 || slices.ContainsFunc(in.IDs, func(id int64) bool { return id < 1 }) {
		fail(w, 400, "请选择要移除的订单")
		return
	}
	ids, _ := json.Marshal(in.IDs)
	if _, err := s.db.ExecContext(r.Context(), "UPDATE orders SET archived=1 WHERE id IN (SELECT value FROM json_each(?))", string(ids)); err != nil {
		dbFailure(w, err)
		return
	}
	w.WriteHeader(204)
}

func (s *Server) batchRedeem(w http.ResponseWriter, r *http.Request, _ User) {
	var in struct {
		voucher
		Codes  []string
		Delete bool
	}
	if !decode(w, r, &in) {
		return
	}
	if len(in.Codes) < 1 || len(in.Codes) > 1000 {
		fail(w, 400, "一次可处理 1 至 1000 个兑换码")
		return
	}
	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		dbFailure(w, err)
		return
	}
	defer tx.Rollback()
	seen := make(map[string]bool, len(in.Codes))
	for _, value := range in.Codes {
		code := strings.TrimSpace(value)
		key := strings.ToLower(code)
		if len(code) < 4 || len(code) > 72 || seen[key] {
			fail(w, 400, "兑换码长度无效或有重复项")
			return
		}
		seen[key] = true
		if in.Delete {
			_, err = tx.Exec("DELETE FROM redeem WHERE code=?", code)
		} else {
			if in.Remaining < 1 || in.Discount < 0 || in.Discount > 10000 || in.Expiry <= time.Now().Unix() {
				fail(w, 400, "兑换码设置无效")
				return
			}
			var result sql.Result
			result, err = tx.Exec(`INSERT INTO redeem(code,plan_id,remaining,discount,expiry)
				SELECT ?,id,?,?,? FROM plans WHERE id=? AND archived=0 ON CONFLICT(code) DO NOTHING`,
				code, in.Remaining, in.Discount, in.Expiry, in.PlanID)
			if err == nil {
				count, _ := result.RowsAffected()
				if count != 1 {
					fail(w, 409, "兑换码已存在或套餐不可用")
					return
				}
			}
		}
		if err != nil {
			dbFailure(w, err)
			return
		}
	}
	if err := tx.Commit(); err != nil {
		dbFailure(w, err)
		return
	}
	respond(w, 200, map[string]int{"count": len(seen)})
}

func (s *Server) previewRedeem(w http.ResponseWriter, r *http.Request, _ User) {
	var in struct{ Code string }
	if !decode(w, r, &in) {
		return
	}
	var name string
	var price, discount, expiry int64
	err := s.db.QueryRow(`SELECT p.name,p.price,r.discount,r.expiry FROM redeem r JOIN plans p ON p.id=r.plan_id
		WHERE r.code=? AND r.remaining>0 AND r.expiry>unixepoch() AND p.archived=0`, strings.TrimSpace(in.Code)).Scan(&name, &price, &discount, &expiry)
	if errors.Is(err, sql.ErrNoRows) {
		fail(w, 404, "兑换码无效、已过期或已用完")
		return
	}
	if err != nil {
		dbFailure(w, err)
		return
	}
	respond(w, 200, map[string]any{"name": name, "price": price, "discount": discount, "payable": price * (10000 - discount) / 10000, "expiry": expiry})
}

func (s *Server) creditAffiliate(w http.ResponseWriter, r *http.Request, _ User) {
	s.manualCredit(w, r, true)
}
