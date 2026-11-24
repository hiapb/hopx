package panel

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type Plan struct {
	ShowOrder        int    `json:"showOrder"`
	Kind             string `json:"kind"`
	RateMbps         int    `json:"rateMbps"`
	MaxIPs           int    `json:"maxIPs"`
	MaxConnections   int    `json:"maxConnections"`
	ID               int64  `json:"id"`
	Name             string `json:"name"`
	Description      string `json:"description"`
	Price            int64  `json:"price"`
	Duration         int64  `json:"duration"`
	Quota            int64  `json:"quota"`
	UnlimitedTraffic bool   `json:"unlimitedTraffic"`
	Rules            int    `json:"rules"`
	GroupID          int64  `json:"groupId"`
	Enabled          bool   `json:"enabled"`
}

const planColumns = "id,name,description,price,duration,quota,unlimited_traffic,rules,group_id,enabled,rate_mbps,max_ips,max_connections,kind,show_order"

func readPlan(row scanner) (p Plan, e error) {
	e = row.Scan(&p.ID, &p.Name, &p.Description, &p.Price, &p.Duration, &p.Quota, &p.UnlimitedTraffic, &p.Rules, &p.GroupID, &p.Enabled, &p.RateMbps, &p.MaxIPs, &p.MaxConnections, &p.Kind, &p.ShowOrder)
	return
}

func (s *Server) listPlans(w http.ResponseWriter, r *http.Request, u User) {
	rows, e := s.db.Query("SELECT "+planColumns+" FROM plans WHERE archived=0 AND (enabled=1 OR ?) ORDER BY show_order,id", u.Admin)
	if e != nil {
		dbFailure(w, e)
		return
	}
	defer rows.Close()
	list := []Plan{}
	for rows.Next() {
		p, e := readPlan(rows)
		if e != nil {
			dbFailure(w, e)
			return
		}
		list = append(list, p)
	}
	respond(w, 200, list)
}

func (s *Server) savePlan(w http.ResponseWriter, r *http.Request, u User) {
	var p Plan
	if !decode(w, r, &p) {
		return
	}
	p.ID = pathID(r)
	p.Kind = normalizedPlanKind(p.Kind)
	if strings.TrimSpace(p.Name) == "" || len(p.Name) > 100 || p.Price < 0 || p.Price > 1<<40 || p.Duration < 1 || p.Duration > 3650 || p.Rules < 0 || p.Rules > 100000 || p.Quota < 0 || p.RateMbps < 0 || p.RateMbps > 100000 || p.MaxIPs < 0 || p.MaxConnections < 0 {
		fail(w, 400, "套餐数据无效")
		return
	}
	if p.UnlimitedTraffic {
		p.Quota = 0
	}
	args := []any{p.Name, p.Description, p.Price, p.Duration, p.Quota, p.UnlimitedTraffic, p.Rules, p.GroupID, p.Enabled, p.RateMbps, p.MaxIPs, p.MaxConnections, p.Kind, p.ShowOrder}
	var result sql.Result
	var e error
	if p.ID == 0 {
		result, e = s.db.Exec("INSERT INTO plans(name,description,price,duration,quota,unlimited_traffic,rules,group_id,enabled,rate_mbps,max_ips,max_connections,kind,show_order) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)", args...)
		if e == nil {
			p.ID, _ = result.LastInsertId()
		}
	} else {
		result, e = s.db.Exec("UPDATE plans SET name=?,description=?,price=?,duration=?,quota=?,unlimited_traffic=?,rules=?,group_id=?,enabled=?,rate_mbps=?,max_ips=?,max_connections=?,kind=?,show_order=? WHERE id=? AND archived=0", append(args, p.ID)...)
	}
	if e != nil {
		dbFailure(w, e)
		return
	}
	if count, _ := result.RowsAffected(); count == 0 {
		fail(w, 404, "套餐不存在")
		return
	}
	respond(w, 200, p)
}

func normalizedPlanKind(value string) string {
	switch value {
	case "month", "traffic", "stack":
		return value
	default:
		return "day"
	}
}

func planExpiry(p Plan, start int64) int64 {
	switch p.Kind {
	case "month":
		return time.Unix(start, 0).AddDate(0, int(p.Duration), 0).Unix()
	case "traffic", "stack":
		return 253402300799
	default:
		return start + p.Duration*86400
	}
}

func planTerms(p Plan, existing, expires, oldQuota, oldUsed, now int64, renewing bool) (int64, int64, error) {
	if existing != p.ID {
		expires = now
	}
	start := max(expires, now)
	if renewing {
		start = now
	}
	quota := p.Quota
	if p.Kind == "stack" && existing == p.ID && expires > now && !p.UnlimitedTraffic && quota > 0 {
		left := max(0, oldQuota-oldUsed)
		if left > int64(^uint64(0)>>1)-quota {
			return 0, 0, errors.New("套餐流量超出可计量范围")
		}
		quota += left
	}
	return planExpiry(p, start), quota, nil
}

func purchase(tx *sql.Tx, id int64, p Plan, price int64, kind string) error {
	var existing, expires, oldQuota, oldUsed, oldGroup int64
	var admin bool
	if e := tx.QueryRow("SELECT plan_id,expires,quota,used,group_id,admin FROM users WHERE id=? AND banned=0", id).
		Scan(&existing, &expires, &oldQuota, &oldUsed, &oldGroup, &admin); e != nil {
		return e
	}
	next, quota, e := planTerms(p, existing, expires, oldQuota, oldUsed, time.Now().Unix(), kind == "renew")
	if e != nil {
		return e
	}
	result, e := tx.Exec(`UPDATE users SET balance=balance-?,plan_id=?,expires=?,quota=?,unlimited_traffic=?,used=0,billing_remainder=0,
		quota_epoch=quota_epoch+1,max_rules=?,group_id=?,
		auto_renew=CASE WHEN plan_id=0 AND auto_renew_configured=0 THEN 1 ELSE auto_renew END,
		auto_renew_configured=1 WHERE id=? AND balance>=?`, price, p.ID, next, quota, p.UnlimitedTraffic, p.Rules, p.GroupID, id, price)
	if e != nil {
		return e
	}
	if count, _ := result.RowsAffected(); count == 0 {
		return errors.New("钱包余额不足")
	}
	if oldGroup != p.GroupID && !admin {
		if e = clearUnauthorizedRuleRoutes(tx, p.GroupID, "r.owner=?", id); e != nil {
			return e
		}
	}
	order, e := tx.Exec("INSERT INTO orders(user_id,amount,credit,kind,status,description) VALUES(?,?,0,?,'paid',?)", id, price, kind, p.Name)
	if e != nil || price == 0 {
		return e
	}
	var inviter sql.NullInt64
	var rate string
	var firstOnly, requireBinding bool
	e = tx.QueryRow(`SELECT inviter,coalesce((SELECT value FROM settings WHERE key='referralRate'),'0'),
		coalesce((SELECT value='true' FROM settings WHERE key='referralFirstOnly'),0),
		coalesce((SELECT value='true' FROM settings WHERE key='referralRequireBinding'),0)
		FROM users WHERE id=?`, id).Scan(&inviter, &rate, &firstOnly, &requireBinding)
	if e != nil {
		return e
	}
	basisPoints, _ := strconv.ParseInt(rate, 10, 64)
	if inviter.Valid {
		err := tx.QueryRow("SELECT rate,first_only,require_binding FROM user_referral_settings WHERE user_id=?", inviter.Int64).
			Scan(&basisPoints, &firstOnly, &requireBinding)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
	}
	basisPoints = min(max(0, basisPoints), 10000)
	reward := price/10000*basisPoints + price%10000*basisPoints/10000
	if !inviter.Valid || inviter.Int64 == id || reward <= 0 {
		return nil
	}
	if firstOnly {
		current, err := order.LastInsertId()
		if err != nil {
			return err
		}
		var purchased bool
		if e = tx.QueryRow("SELECT EXISTS(SELECT 1 FROM orders WHERE user_id=? AND id<>? AND kind IN ('purchase','renew','redeem') AND status='paid' AND amount>0)", id, current).Scan(&purchased); e != nil || purchased {
			return e
		}
	}
	if requireBinding {
		var linked bool
		if e = tx.QueryRow("SELECT EXISTS(SELECT 1 FROM telegram_links WHERE user_id=?)", inviter.Int64).Scan(&linked); e != nil || !linked {
			return e
		}
	}
	if _, e = tx.Exec("UPDATE users SET affiliate_balance=affiliate_balance+? WHERE id=?", reward, inviter.Int64); e != nil {
		return e
	}
	_, e = tx.Exec("INSERT INTO orders(user_id,amount,credit,kind,status,description) VALUES(?,?,0,'referral','paid','邀请返佣')", inviter.Int64, reward)
	return e
}

func (s *Server) buyPlan(w http.ResponseWriter, r *http.Request, u User) {
	tx, e := s.db.Begin()
	if e != nil {
		dbFailure(w, e)
		return
	}
	defer tx.Rollback()
	p, e := readPlan(tx.QueryRow("SELECT "+planColumns+" FROM plans WHERE id=? AND archived=0 AND enabled=1", pathID(r)))
	if e != nil {
		fail(w, 404, "套餐不可用")
		return
	}
	if e = purchase(tx, u.ID, p, p.Price, "purchase"); e != nil {
		fail(w, 409, e.Error())
		return
	}
	if e = tx.Commit(); e != nil {
		dbFailure(w, e)
		return
	}
	w.WriteHeader(204)
}

func (s *Server) renew() {
	rows, e := s.db.Query(`SELECT u.id,u.plan_id FROM users u JOIN plans p ON p.id=u.plan_id
		WHERE u.auto_renew=1 AND u.banned=0 AND u.plan_id>0 AND u.expires>0 AND p.archived=0 AND u.balance>=p.price
		AND (p.unlimited_traffic=1 OR p.quota>0)
		AND (u.expires<=unixepoch() OR (u.unlimited_traffic=0 AND u.used>=u.quota)) ORDER BY u.id LIMIT 100`)
	if e != nil {
		return
	}
	var users [][2]int64
	for rows.Next() {
		var id, plan int64
		if rows.Scan(&id, &plan) == nil {
			users = append(users, [2]int64{id, plan})
		}
	}
	rows.Close()
	for _, u := range users {
		tx, e := s.db.Begin()
		if e != nil {
			return
		}
		p, e := readPlan(tx.QueryRow("SELECT "+planColumns+` FROM plans p WHERE p.id=? AND p.archived=0 AND (p.unlimited_traffic=1 OR p.quota>0)
			AND EXISTS(SELECT 1 FROM users u WHERE u.id=? AND u.auto_renew=1 AND u.banned=0
			AND u.plan_id=p.id AND u.expires>0 AND u.balance>=p.price AND (u.expires<=unixepoch() OR (u.unlimited_traffic=0 AND u.used>=u.quota)))`, u[1], u[0]))
		if e == nil && purchase(tx, u[0], p, p.Price, "renew") == nil {
			_ = tx.Commit()
		}
		_ = tx.Rollback()
	}
}

type Order struct {
	UserName    string `json:"userName"`
	PaidAt      int64  `json:"paidAt"`
	ID          int64  `json:"id"`
	UserID      int64  `json:"userId"`
	Amount      int64  `json:"amount"`
	Credit      int64  `json:"credit"`
	Kind        string `json:"kind"`
	Status      string `json:"status"`
	Reference   string `json:"reference"`
	Description string `json:"description"`
	Created     int64  `json:"created"`
}

func (s *Server) listOrders(w http.ResponseWriter, r *http.Request, u User) {
	all := u.Admin && r.URL.Query().Get("all") == "1"
	query := r.URL.Query()
	name := strings.TrimSpace(query.Get("q"))
	kind, status := query.Get("kind"), query.Get("status")
	affiliate := query.Get("affiliate") == "1"
	offset, _ := strconv.Atoi(query.Get("offset"))
	limit, _ := strconv.Atoi(query.Get("limit"))
	if limit <= 0 {
		limit = 500
	}
	rows, e := s.db.Query(`SELECT o.id,o.user_id,u.name,o.amount,o.credit,o.kind,o.status,
		coalesce(o.reference,''),o.description,o.created,
		CASE WHEN o.status='paid' AND o.paid_at=0 THEN o.created ELSE o.paid_at END
		FROM orders o JOIN users u ON u.id=o.user_id
		WHERE o.archived=0 AND (o.user_id=? OR ?) AND
		(o.kind IN ('referral','affiliate_transfer','affiliate_manual','legacy_affiliate'))=? AND (?='' OR o.kind=?) AND (?='' OR o.status=?)
		AND (?='' OR instr(lower(u.name),lower(?))>0 OR instr(lower(coalesce(o.reference,'')),lower(?))>0
		OR CAST(o.id AS TEXT)=? OR CAST(o.user_id AS TEXT)=?)
		ORDER BY o.id DESC LIMIT ? OFFSET ?`, u.ID, all, affiliate, kind, kind, status, status, name, name, name, name, name, min(limit, 500), max(0, offset))
	if e != nil {
		dbFailure(w, e)
		return
	}
	defer rows.Close()
	list := []Order{}
	for rows.Next() {
		var o Order
		if e = rows.Scan(&o.ID, &o.UserID, &o.UserName, &o.Amount, &o.Credit, &o.Kind, &o.Status, &o.Reference, &o.Description, &o.Created, &o.PaidAt); e != nil {
			dbFailure(w, e)
			return
		}
		if affiliate && o.Kind == "affiliate_transfer" {
			o.Amount = -o.Amount
		}
		list = append(list, o)
	}
	if err := rows.Err(); err != nil {
		dbFailure(w, err)
		return
	}
	respond(w, 200, list)
}

func creditBalance(tx *sql.Tx, id, amount int64, reference, description, kind string) error {
	var ref any
	if reference != "" {
		ref = reference
	}
	result, e := tx.Exec("INSERT OR IGNORE INTO orders(user_id,amount,credit,kind,status,reference,description) VALUES(?,?,?,?, 'paid',?,?)", id, amount, amount, kind, ref, description)
	if e != nil {
		return e
	}
	if n, _ := result.RowsAffected(); n == 0 {
		var existing int64
		if e = tx.QueryRow("SELECT count(*) FROM orders WHERE reference=? AND user_id=? AND credit=?", reference, id, amount).Scan(&existing); e != nil {
			return e
		}
		if existing != 1 {
			return errors.New("订单号已使用")
		}
		return nil
	}
	update, e := tx.Exec("UPDATE users SET balance=balance+? WHERE id=? AND balance+?>=0", amount, id, amount)
	if e != nil {
		return e
	}
	if n, _ := update.RowsAffected(); n != 1 {
		return errors.New("用户不存在或余额不足")
	}
	return nil
}

type manualAccounting struct {
	UserID, Amount  int64
	Description     string
	ExpectedBalance *int64
	Affiliate       bool
}

func (input manualAccounting) valid() bool {
	return input.UserID > 0 && input.Amount != 0 && input.Amount >= -(1<<40) &&
		input.Amount <= 1<<40 && len(input.Description) <= 2000
}

func (s *Server) previewAccounting(w http.ResponseWriter, r *http.Request, _ User) {
	var input manualAccounting
	if !decode(w, r, &input) {
		return
	}
	if !input.valid() {
		fail(w, 400, "记账金额或说明无效")
		return
	}
	var name string
	var balance int64
	err := s.db.QueryRowContext(r.Context(), "SELECT name,CASE WHEN ? THEN affiliate_balance ELSE balance END FROM users WHERE id=?", input.Affiliate, input.UserID).
		Scan(&name, &balance)
	if errors.Is(err, sql.ErrNoRows) {
		fail(w, 404, "账号不存在")
		return
	}
	if err != nil {
		dbFailure(w, err)
		return
	}
	respond(w, 200, map[string]any{"name": name, "balance": balance, "after": balance + input.Amount})
}

func (s *Server) credit(w http.ResponseWriter, r *http.Request, _ User) {
	s.manualCredit(w, r, false)
}

func (s *Server) manualCredit(w http.ResponseWriter, r *http.Request, affiliate bool) {
	var input manualAccounting
	if !decode(w, r, &input) {
		return
	}
	if !input.valid() {
		fail(w, 400, "记账金额或说明无效")
		return
	}
	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		dbFailure(w, err)
		return
	}
	defer tx.Rollback()
	if input.ExpectedBalance != nil {
		var current int64
		err := tx.QueryRow("SELECT CASE WHEN ? THEN affiliate_balance ELSE balance END FROM users WHERE id=?", affiliate, input.UserID).Scan(&current)
		if errors.Is(err, sql.ErrNoRows) {
			fail(w, 404, "账号不存在")
			return
		}
		if err != nil {
			dbFailure(w, err)
			return
		}
		if current != *input.ExpectedBalance {
			fail(w, 409, "余额已变化，请重新预览")
			return
		}
	}
	if affiliate {
		result, err := tx.Exec("UPDATE users SET affiliate_balance=affiliate_balance+? WHERE id=? AND affiliate_balance+?>=0", input.Amount, input.UserID, input.Amount)
		if err != nil {
			dbFailure(w, err)
			return
		}
		if count, _ := result.RowsAffected(); count != 1 {
			fail(w, 409, "用户不存在或佣金余额不足")
			return
		}
		if _, err := tx.Exec("INSERT INTO orders(user_id,amount,credit,kind,status,description) VALUES(?,?,0,'affiliate_manual','paid',?)", input.UserID, input.Amount, input.Description); err != nil {
			dbFailure(w, err)
			return
		}
	} else if err := creditBalance(tx, input.UserID, input.Amount, "", input.Description, "manual"); err != nil {
		fail(w, 409, err.Error())
		return
	}
	if err := tx.Commit(); err != nil {
		dbFailure(w, err)
		return
	}
	w.WriteHeader(204)
}

func (s *Server) payment(w http.ResponseWriter, r *http.Request) {
	if s.paymentSecret == "" {
		fail(w, 503, "支付回调未配置")
		return
	}
	raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
	if e != nil {
		fail(w, 400, "订单数据无效")
		return
	}
	provided, e := hex.DecodeString(r.Header.Get("X-HopX-Signature"))
	mac := hmac.New(sha256.New, []byte(s.paymentSecret))
	_, _ = mac.Write(raw)
	if e != nil || !hmac.Equal(mac.Sum(nil), provided) {
		fail(w, 401, "支付签名无效")
		return
	}
	var in struct {
		Provider, Reference string
		UserID, Amount      int64
	}
	if json.Unmarshal(raw, &in) != nil || in.UserID < 1 || in.Amount < 1 || in.Amount > 1<<40 || in.Provider == "" || strings.Contains(in.Provider, ":") || in.Reference == "" || len(in.Reference) > 200 {
		fail(w, 400, "订单数据无效")
		return
	}
	tx, e := s.db.Begin()
	if e != nil {
		dbFailure(w, e)
		return
	}
	defer tx.Rollback()
	if e = creditBalance(tx, in.UserID, in.Amount, in.Provider+":"+in.Reference, "支付充值", "payment"); e != nil {
		fail(w, 409, e.Error())
		return
	}
	if e = tx.Commit(); e != nil {
		dbFailure(w, e)
		return
	}
	respond(w, 200, map[string]bool{"ok": true})
}

type voucher struct {
	PlanName  string `json:"planName"`
	Code      string `json:"code"`
	PlanID    int64  `json:"planId"`
	Remaining int    `json:"remaining"`
	Discount  int64  `json:"discount"`
	Expiry    int64  `json:"expiry"`
}

func (s *Server) redeemAdmin(w http.ResponseWriter, r *http.Request, u User) {
	switch r.Method {
	case "GET":
		rows, e := s.db.Query("SELECT r.code,r.plan_id,r.remaining,r.discount,r.expiry,p.name FROM redeem r JOIN plans p ON p.id=r.plan_id ORDER BY r.code")
		if e != nil {
			dbFailure(w, e)
			return
		}
		defer rows.Close()
		list := []voucher{}
		for rows.Next() {
			var v voucher
			if e = rows.Scan(&v.Code, &v.PlanID, &v.Remaining, &v.Discount, &v.Expiry, &v.PlanName); e != nil {
				dbFailure(w, e)
				return
			}
			list = append(list, v)
		}
		respond(w, 200, list)
	case "POST":
		var v voucher
		if !decode(w, r, &v) {
			return
		}
		v.Code = strings.TrimSpace(v.Code)
		if len(v.Code) < 4 || len(v.Code) > 72 || v.Remaining < 1 || v.Discount < 0 || v.Discount > 10000 || v.Expiry <= time.Now().Unix() {
			fail(w, 400, "兑换码设置无效")
			return
		}
		if _, e := s.db.Exec("INSERT INTO redeem(code,plan_id,remaining,discount,expiry) VALUES(?,?,?,?,?)", v.Code, v.PlanID, v.Remaining, v.Discount, v.Expiry); e != nil {
			fail(w, 409, "兑换码已存在或套餐无效")
			return
		}
		respond(w, 201, v)
	case "DELETE":
		if _, e := s.db.Exec("DELETE FROM redeem WHERE code=?", r.PathValue("code")); e != nil {
			dbFailure(w, e)
			return
		}
		w.WriteHeader(204)
	}
}

func (s *Server) redeem(w http.ResponseWriter, r *http.Request, u User) {
	var input struct {
		Code            string
		ExpectedPayable *int64
	}
	if !decode(w, r, &input) {
		return
	}
	tx, e := s.db.Begin()
	if e != nil {
		dbFailure(w, e)
		return
	}
	defer tx.Rollback()
	var id, discount int64
	e = tx.QueryRow("UPDATE redeem SET remaining=remaining-1 WHERE code=? AND remaining>0 AND expiry>unixepoch() RETURNING plan_id,discount", strings.TrimSpace(input.Code)).Scan(&id, &discount)
	if e != nil {
		fail(w, 404, "兑换码无效、已过期或已用完")
		return
	}
	p, e := readPlan(tx.QueryRow("SELECT "+planColumns+" FROM plans WHERE id=? AND archived=0", id))
	if e != nil {
		fail(w, 404, "套餐不可用")
		return
	}
	payable := p.Price * (10000 - discount) / 10000
	if input.ExpectedPayable != nil && *input.ExpectedPayable != payable {
		fail(w, 409, "兑换金额已更新，请重新查询")
		return
	}
	if e = purchase(tx, u.ID, p, payable, "redeem"); e != nil {
		fail(w, 409, e.Error())
		return
	}
	if e = tx.Commit(); e != nil {
		dbFailure(w, e)
		return
	}
	w.WriteHeader(204)
}

func userListFilter(r *http.Request) (string, []any) {
	query := r.URL.Query()
	name := strings.TrimSpace(query.Get("q"))
	role, banned := query.Get("role"), query.Get("banned")
	group, plan := query.Get("group"), query.Get("plan")
	return ` FROM users WHERE (?='' OR instr(lower(name),lower(?))>0 OR CAST(id AS TEXT)=?)
		AND (?='' OR admin=?) AND (?='' OR banned=?) AND (?='' OR group_id=?) AND (?='' OR plan_id=?)`,
		[]any{name, name, name, role, role == "admin", banned, banned == "true", group, group, plan, plan}
}

func (s *Server) countUsers(w http.ResponseWriter, r *http.Request, _ User) {
	where, args := userListFilter(r)
	var total int
	if err := s.db.QueryRowContext(r.Context(), "SELECT count(*)"+where, args...).Scan(&total); err != nil {
		dbFailure(w, err)
		return
	}
	respond(w, 200, map[string]int{"total": total})
}

func (s *Server) users(w http.ResponseWriter, r *http.Request, u User) {
	switch r.Method {
	case "GET":
		query := r.URL.Query()
		where, args := userListFilter(r)
		offset, _ := strconv.Atoi(query.Get("offset"))
		limit, _ := strconv.Atoi(query.Get("limit"))
		if limit < 1 || limit > 501 {
			limit = 500
		}
		order := "id DESC"
		sortColumn := ""
		switch query.Get("sort") {
		case "id":
			sortColumn = "id"
		case "name":
			sortColumn = "name COLLATE NOCASE"
		case "expires":
			sortColumn = "expires"
		case "balance":
			sortColumn = "balance"
		case "traffic":
			sortColumn = "used"
		case "rules":
			sortColumn = "max_rules"
		}
		if sortColumn != "" {
			direction := " DESC"
			if query.Get("direction") == "asc" || (query.Get("direction") == "" && sortColumn == "name COLLATE NOCASE") {
				direction = " ASC"
			}
			order = sortColumn + direction + ",id" + direction
		}
		rows, e := s.db.QueryContext(r.Context(), strings.TrimSuffix(userSelect, " FROM users")+",coalesce((SELECT chat_id FROM telegram_links WHERE user_id=users.id),0),quota_epoch"+
			where+" ORDER BY "+order+" LIMIT ? OFFSET ?", append(args, limit, max(offset, 0))...)
		if e != nil {
			dbFailure(w, e)
			return
		}
		defer rows.Close()
		type account struct {
			User
			TelegramID int64 `json:"telegramId,omitempty"`
			QuotaEpoch int64 `json:"quotaEpoch"`
		}
		list := []account{}
		for rows.Next() {
			var a account
			if err := scanUser(rows, &a.User, &a.TelegramID, &a.QuotaEpoch); err != nil {
				dbFailure(w, err)
				return
			}
			list = append(list, a)
		}
		if err := rows.Err(); err != nil {
			dbFailure(w, err)
			return
		}
		respond(w, 200, list)
	case "POST":
		var in struct{ Name, Password string }
		if !decode(w, r, &in) {
			return
		}
		if e := s.addUser(in.Name, in.Password, false, sql.NullInt64{}); e != nil {
			fail(w, 400, "账号无法创建")
			return
		}
		respond(w, 201, map[string]bool{"ok": true})
	case "PUT":
		var in struct {
			User
			Password          string
			UsageAdjustment   *struct{ From, To, Epoch int64 }
			BalanceAdjustment *struct{ From, To int64 }
		}
		if !decode(w, r, &in) {
			return
		}
		id := pathID(r)
		if (id == u.ID && (!in.Admin || in.Banned)) || in.Quota < 0 || in.MaxRules < 0 || in.Expires < 0 || id < 1 || !validUserOverrides(in.User) {
			fail(w, 400, "账号设置无效")
			return
		}
		if a := in.UsageAdjustment; a != nil && (a.From < 0 || a.To < 0 || a.To > 1<<53-1 || a.Epoch < 0) {
			fail(w, 400, "已用流量无效")
			return
		}
		if a := in.BalanceAdjustment; a != nil && (a.From < 0 || a.To < 0 || a.To > 1<<53-1 || a.From > 1<<53-1) {
			fail(w, 400, "钱包余额无效")
			return
		}
		var hash []byte
		if in.Password != "" {
			if len(in.Password) < 10 || len(in.Password) > 72 {
				fail(w, 400, "密码须为 10–72 字节")
				return
			}
			var err error
			hash, err = bcrypt.GenerateFromPassword([]byte(in.Password), bcrypt.DefaultCost)
			if err != nil {
				dbFailure(w, err)
				return
			}
		}
		tx, e := s.db.Begin()
		if e != nil {
			dbFailure(w, e)
			return
		}
		defer tx.Rollback()
		if in.UnlimitedTraffic {
			in.Quota = 0
		}
		if !in.Admin {
			if e = clearUnauthorizedRuleRoutes(tx, in.Group, "u.id=? AND (u.group_id<>? OR u.admin=1)", id, in.Group); e != nil {
				dbFailure(w, e)
				return
			}
		}
		adjustUsage := in.UsageAdjustment != nil && in.UsageAdjustment.To != in.UsageAdjustment.From
		result, e := tx.Exec(`UPDATE users SET admin=?,banned=?,group_id=?,
			quota_epoch=quota_epoch+CASE WHEN NOT ? AND (unlimited_traffic<>? OR quota<>?) THEN 1 ELSE 0 END,
			quota=?,unlimited_traffic=?,max_rules=?,expires=?,note=?,rate_override=?,ips_override=?,connections_override=?,allow_device=? WHERE id=?`,
			in.Admin, in.Banned, in.Group, adjustUsage, in.UnlimitedTraffic, in.Quota, in.Quota, in.UnlimitedTraffic,
			in.MaxRules, in.Expires, in.Note, in.RateOverride, in.IPsOverride, in.ConnectionsOverride, in.AllowDevice, id)
		if e != nil {
			dbFailure(w, e)
			return
		}
		if count, _ := result.RowsAffected(); count == 0 {
			fail(w, 404, "账号不存在")
			return
		}
		if a := in.UsageAdjustment; a != nil && a.To != a.From {
			result, e = tx.Exec(`UPDATE users SET used=?,billing_remainder=0,quota_epoch=quota_epoch+1
				WHERE id=? AND used=? AND quota_epoch=?`, a.To, id, a.From, a.Epoch)
			if e != nil {
				dbFailure(w, e)
				return
			}
			if count, _ := result.RowsAffected(); count == 0 {
				fail(w, 409, "已用流量已变化，请重新打开用户资料")
				return
			}
		}
		if a := in.BalanceAdjustment; a != nil && a.To != a.From {
			var balance int64
			if e = tx.QueryRow("SELECT balance FROM users WHERE id=?", id).Scan(&balance); e != nil {
				dbFailure(w, e)
				return
			}
			if balance != a.From {
				fail(w, 409, "钱包余额已变化，请重新打开用户资料")
				return
			}
			if e = creditBalance(tx, id, a.To-a.From, "", "管理员调整钱包余额", "manual"); e != nil {
				dbFailure(w, e)
				return
			}
		}
		if len(hash) > 0 {
			e = saveUserPassword(tx, id, hash)
		}
		if e == nil {
			e = tx.Commit()
		}
		if e != nil {
			dbFailure(w, e)
			return
		}
		w.WriteHeader(204)
	}
}

type named struct {
	ShowOrder int    `json:"showOrder"`
	UserCount int    `json:"userCount"`
	ID        int64  `json:"id"`
	Name      string `json:"name"`
}

func (s *Server) userGroups(w http.ResponseWriter, r *http.Request, u User) {
	switch r.Method {
	case "GET":
		rows, e := s.db.Query("SELECT g.id,g.name,g.show_order,(SELECT count(*) FROM users WHERE group_id=g.id) FROM user_groups g ORDER BY g.show_order,g.id")
		if e != nil {
			dbFailure(w, e)
			return
		}
		defer rows.Close()
		list := []named{}
		for rows.Next() {
			var g named
			if e = rows.Scan(&g.ID, &g.Name, &g.ShowOrder, &g.UserCount); e != nil {
				dbFailure(w, e)
				return
			}
			list = append(list, g)
		}
		respond(w, 200, list)
	case "POST", "PUT":
		var g named
		if !decode(w, r, &g) {
			return
		}
		g.Name = strings.TrimSpace(g.Name)
		if r.Method == "PUT" {
			value, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
			if err != nil || value < 0 {
				fail(w, 400, "分组编号无效")
				return
			}
			g.ID = value
		}
		if g.Name == "" || len(g.Name) > 100 || g.ID < 0 {
			fail(w, 400, "分组名称或编号无效")
			return
		}
		var result sql.Result
		var err error
		if r.Method == "POST" && g.ID == 0 {
			result, err = s.db.Exec("INSERT INTO user_groups(name,show_order) VALUES(?,?)", g.Name, g.ShowOrder)
			if err == nil {
				g.ID, _ = result.LastInsertId()
			}
		} else {
			result, err = s.db.Exec("UPDATE user_groups SET name=?,show_order=? WHERE id=?", g.Name, g.ShowOrder, g.ID)
		}
		if err != nil {
			dbFailure(w, err)
			return
		}
		if count, _ := result.RowsAffected(); count == 0 {
			fail(w, 404, "用户组不存在")
			return
		}
		respond(w, 200, g)
	case "DELETE":
		id := pathID(r)
		if id == 0 {
			fail(w, 400, "默认用户组须保留")
			return
		}
		tx, err := s.db.BeginTx(r.Context(), nil)
		if err != nil {
			dbFailure(w, err)
			return
		}
		defer tx.Rollback()
		var authorized bool
		err = tx.QueryRowContext(r.Context(), `SELECT EXISTS (
			SELECT 1 FROM groups g, json_each(g.user_groups) AS selected
			WHERE g.owner=0 AND selected.value=?
		)`, id).Scan(&authorized)
		if err != nil {
			dbFailure(w, err)
			return
		}
		if authorized {
			fail(w, 409, "用户组仍被设备组授权，请先移除授权")
			return
		}
		if _, err = tx.ExecContext(r.Context(), "DELETE FROM user_groups WHERE id=?", id); err != nil {
			fail(w, 409, "用户组仍被使用")
			return
		}
		if err = tx.Commit(); err != nil {
			dbFailure(w, err)
			return
		}
		w.WriteHeader(204)
	}
}

type homeLink struct {
	Title string `json:"title"`
	URL   string `json:"url"`
}

func parseHomeLinks(value string) ([]homeLink, error) {
	links := []homeLink{}
	if strings.TrimSpace(value) == "" {
		return links, nil
	}
	if err := json.Unmarshal([]byte(value), &links); err != nil || links == nil {
		return nil, errors.New("推广链接格式无效")
	}
	for i := range links {
		link := &links[i]
		link.Title = strings.TrimSpace(link.Title)
		link.URL = strings.TrimSpace(link.URL)
		if link.Title == "" {
			return nil, errors.New("请填写推广链接名称")
		}
		address, err := url.Parse(link.URL)
		if err != nil || address.Hostname() == "" || address.User != nil ||
			(address.Scheme != "https" && address.Scheme != "http") {
			return nil, errors.New("推广链接须填写完整的 HTTP 或 HTTPS 地址")
		}
	}
	return links, nil
}

func (s *Server) settings(w http.ResponseWriter, r *http.Request, u User) {
	keys := map[string]string{"name": "HopX", "announcement": "", "registration": "closed", "personalTunnels": "false", "epayGateway": "", "epayPID": "", "epayKey": "", "referralRate": "0", "minRecharge": "100", "telegramUsername": "", "telegramToken": "", "telegramWebhookSecret": "", "registrationChallenge": "false"}
	keys["referralFirstOnly"], keys["referralRequireBinding"] = "false", "false"
	keys["hideAdminIPs"] = "false"
	keys["lookingGlass"], keys["diagnoseIPVisibility"] = "false", "admin"
	keys["ruleProbeInterval"] = "300"
	keys["nodeInstallMirror"] = ""
	keys["homeLinks"] = "[]"
	keys["registrationVerification"] = verificationOff
	keys["registrationTurnstileSiteKey"] = ""
	keys["registrationTurnstileSecret"] = ""
	for _, key := range []string{"showShop", "showOrders", "showNodeStatus", "invitesEnabled"} {
		keys[key] = "true"
	}
	for _, kind := range []string{"epusdt", "tokenpay", "cryptomus"} {
		for _, field := range []string{"Gateway", "PID", "Key", "Network", "Currency", "SHA256"} {
			keys[kind+field] = ""
		}
	}
	for _, kind := range gatewayKinds {
		keys[kind+"Enabled"], keys[kind+"Fee"], keys[kind+"Callback"] = "auto", "0", ""
	}
	if r.Method == "GET" {
		for k, d := range keys {
			if k != "registrationTurnstileSecret" {
				keys[k] = s.setting(k, d)
			}
		}
		registration, err := readRegistrationVerification(s.db)
		if err != nil {
			dbFailure(w, err)
			return
		}
		keys["registrationVerification"] = registration.kind
		keys["registrationTurnstileSecretConfigured"] = strconv.FormatBool(registration.secret != "")
		respond(w, 200, keys)
		return
	}
	var in map[string]string
	if !decode(w, r, &in) {
		return
	}
	tx, e := s.db.Begin()
	if e != nil {
		dbFailure(w, e)
		return
	}
	defer tx.Rollback()
	for k, v := range in {
		switch k {
		case "registrationVerification":
			if v != verificationOff && v != verificationArithmetic && v != verificationTurnstile {
				fail(w, 400, "请选择有效的验证码类型")
				return
			}
		case "registrationTurnstileSiteKey", "registrationTurnstileSecret":
			v = strings.TrimSpace(v)
			if v != "" && !validTurnstileKey(v) {
				fail(w, 400, "Turnstile 密钥格式无效")
				return
			}
		}
		if k == "ruleProbeInterval" && v != "60" && v != "300" {
			fail(w, 400, "采样间隔请选择 1 分钟或 5 分钟")
			return
		}
		if k == "nodeInstallMirror" {
			v = strings.TrimRight(strings.TrimSpace(v), "/")
			if !validPaymentCallback(v) {
				fail(w, 400, "海外安装线路需要 HTTPS 站点根地址")
				return
			}
		}
		if (k == "showShop" || k == "showOrders" || k == "showNodeStatus" || k == "invitesEnabled") && v != "true" && v != "false" {
			fail(w, 400, "菜单显示设置无效")
			return
		}
		for _, kind := range gatewayKinds {
			switch k {
			case kind + "Enabled":
				if v != "auto" && v != "true" && v != "false" {
					fail(w, 400, "支付通道状态无效")
					return
				}
			case kind + "Fee":
				rate, err := strconv.Atoi(v)
				if err != nil || rate < 0 || rate > 10000 {
					fail(w, 400, "支付费率须在 0% 至 100% 之间")
					return
				}
			case kind + "Callback":
				if !validPaymentCallback(v) {
					fail(w, 400, "回调地址应为 HTTPS 站点根地址")
					return
				}
			}
		}
		if (k == "lookingGlass" && v != "true" && v != "false") ||
			(k == "diagnoseIPVisibility" && v != "all" && v != "admin" && v != "none") {
			fail(w, 400, "诊断权限设置无效")
			return
		}
		if k == "minRecharge" {
			minimum, err := strconv.Atoi(v)
			if err != nil || minimum < 1 || minimum > 100000000 {
				fail(w, 400, "最低充值金额无效")
				return
			}
		}
		if k == "referralRate" {
			n, e := strconv.Atoi(v)
			if e != nil || n < 0 || n > 10000 {
				fail(w, 400, "邀请返佣比例无效")
				return
			}
		}
		if _, ok := keys[k]; !ok || len(v) > 10000 || (k == "registration" && v != "open" && v != "closed" && v != "invite" && v != "no-invite") {
			fail(w, 400, "站点设置无效")
			return
		}
		if k == "homeLinks" {
			links, err := parseHomeLinks(v)
			if err != nil {
				fail(w, 400, err.Error())
				return
			}
			encoded, err := json.Marshal(links)
			if err != nil {
				dbFailure(w, err)
				return
			}
			v = string(encoded)
		}
		if _, e = tx.Exec("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", k, v); e != nil {
			dbFailure(w, e)
			return
		}
	}
	registration, err := readRegistrationVerification(tx)
	if err != nil {
		dbFailure(w, err)
		return
	}
	if registration.kind == verificationTurnstile && (!validTurnstileKey(registration.siteKey) || !validTurnstileKey(registration.secret)) {
		fail(w, 400, "请填写 Turnstile 站点密钥和服务端密钥")
		return
	}
	if e = tx.Commit(); e != nil {
		dbFailure(w, e)
		return
	}
	w.WriteHeader(204)
}

func (s *Server) listInvites(w http.ResponseWriter, r *http.Request, u User) {
	all := u.Admin && r.URL.Query().Get("all") == "1"
	rows, e := s.db.Query("SELECT id,name,inviter,created FROM users WHERE inviter IS NOT NULL AND (inviter=? OR ?) ORDER BY id DESC LIMIT 500", u.ID, all)
	if e != nil {
		dbFailure(w, e)
		return
	}
	defer rows.Close()
	type invite struct {
		ID      int64  `json:"id"`
		Name    string `json:"name"`
		Inviter int64  `json:"inviter"`
		Created int64  `json:"created"`
	}
	list := []invite{}
	for rows.Next() {
		var a invite
		if e = rows.Scan(&a.ID, &a.Name, &a.Inviter, &a.Created); e != nil {
			dbFailure(w, e)
			return
		}
		list = append(list, a)
	}
	respond(w, 200, list)
}

type notice struct {
	ID      int64  `json:"id"`
	Title   string `json:"title"`
	Body    string `json:"body"`
	Created int64  `json:"created"`
}

func (s *Server) listNotifications(w http.ResponseWriter, r *http.Request, u User) {
	rows, e := s.db.Query("SELECT id,title,body,created FROM notifications WHERE topic='' ORDER BY id DESC LIMIT 100")
	if e != nil {
		dbFailure(w, e)
		return
	}
	defer rows.Close()
	list := []notice{}
	for rows.Next() {
		var n notice
		if e = rows.Scan(&n.ID, &n.Title, &n.Body, &n.Created); e != nil {
			dbFailure(w, e)
			return
		}
		list = append(list, n)
	}
	respond(w, 200, list)
}
func (s *Server) createNotification(w http.ResponseWriter, r *http.Request, u User) {
	var n struct {
		notice
		Telegram bool
	}
	if !decode(w, r, &n) {
		return
	}
	if strings.TrimSpace(n.Title) == "" || strings.TrimSpace(n.Body) == "" || len(n.Title) > 200 || len(n.Body) > 10000 {
		fail(w, 400, "标题和内容不能为空")
		return
	}
	tx, e := s.db.Begin()
	if e != nil {
		dbFailure(w, e)
		return
	}
	defer tx.Rollback()
	result, e := tx.Exec("INSERT INTO notifications(title,body) VALUES(?,?)", n.Title, n.Body)
	if e == nil && n.Telegram {
		id, _ := result.LastInsertId()
		_, e = tx.Exec("INSERT INTO notification_deliveries(notification_id,user_id) SELECT ?,l.user_id FROM telegram_links l JOIN users u ON u.id=l.user_id WHERE l.enabled=1 AND u.banned=0", id)
	}
	if e == nil {
		e = tx.Commit()
	}
	if e != nil {
		dbFailure(w, e)
		return
	}
	respond(w, 201, map[string]bool{"ok": true})
}
