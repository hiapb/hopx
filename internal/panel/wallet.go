package panel

import (
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"time"
)

func (s *Server) walletTransfer(w http.ResponseWriter, r *http.Request, u User) {
	var form struct {
		Recipient string
		Amount    int64
	}
	if !decode(w, r, &form) {
		return
	}
	if form.Amount < 1 || form.Amount > 1<<40 || strings.TrimSpace(form.Recipient) == "" {
		fail(w, 400, "划转金额或收款账号无效")
		return
	}
	tx, err := s.db.Begin()
	if err != nil {
		dbFailure(w, err)
		return
	}
	defer tx.Rollback()
	var recipient int64
	err = tx.QueryRow("SELECT id FROM users WHERE name=? AND banned=0", strings.TrimSpace(form.Recipient)).Scan(&recipient)
	if err == sql.ErrNoRows || recipient == u.ID {
		fail(w, 400, "收款账号不可用")
		return
	}
	if err != nil {
		dbFailure(w, err)
		return
	}
	if err = creditBalance(tx, u.ID, -form.Amount, "", "划转给 "+strings.TrimSpace(form.Recipient), "transfer"); err != nil {
		fail(w, 409, err.Error())
		return
	}
	if err = creditBalance(tx, recipient, form.Amount, "", "收到 "+u.Name+" 的划转", "transfer"); err != nil {
		dbFailure(w, err)
		return
	}
	if err = tx.Commit(); err != nil {
		dbFailure(w, err)
		return
	}
	w.WriteHeader(204)
}

func (s *Server) renewUser(w http.ResponseWriter, r *http.Request, u User) {
	var input struct {
		ExpectedPlan  *int64
		ExpectedPrice *int64
		ExpectedEpoch *int64
	}
	if r.Method == http.MethodPost && r.ContentLength != 0 && !decode(w, r, &input) {
		return
	}
	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		dbFailure(w, err)
		return
	}
	defer tx.Rollback()
	account, err := readUser(tx.QueryRow(userSelect+" WHERE id=?", u.ID))
	if err != nil {
		dbFailure(w, err)
		return
	}
	if account.PlanID == 0 {
		fail(w, 409, "当前账号没有可续费套餐")
		return
	}
	plan, err := readPlan(tx.QueryRow("SELECT "+planColumns+" FROM plans WHERE id=? AND archived=0", account.PlanID))
	if errors.Is(err, sql.ErrNoRows) {
		fail(w, 409, "当前套餐已删除")
		return
	}
	if err != nil {
		dbFailure(w, err)
		return
	}
	var epoch int64
	if err = tx.QueryRow("SELECT quota_epoch FROM users WHERE id=?", account.ID).Scan(&epoch); err != nil {
		dbFailure(w, err)
		return
	}
	if r.Method == http.MethodGet {
		next, quota, err := planTerms(plan, account.PlanID, account.Expires, account.Quota, account.Used, time.Now().Unix(), true)
		if err != nil {
			fail(w, 409, err.Error())
			return
		}
		respond(w, 200, map[string]any{
			"planId": plan.ID, "name": plan.Name, "kind": plan.Kind, "price": plan.Price,
			"expires": account.Expires, "nextExpires": next, "quota": quota, "balance": account.Balance, "epoch": epoch,
		})
		return
	}
	if (input.ExpectedPlan != nil && *input.ExpectedPlan != plan.ID) || (input.ExpectedPrice != nil && *input.ExpectedPrice != plan.Price) ||
		(input.ExpectedEpoch != nil && *input.ExpectedEpoch != epoch) {
		fail(w, 409, "套餐或用量周期已变化，请重新预览")
		return
	}
	if err = purchase(tx, u.ID, plan, plan.Price, "renew"); err != nil {
		fail(w, 409, err.Error())
		return
	}
	if err = tx.Commit(); err != nil {
		dbFailure(w, err)
		return
	}
	w.WriteHeader(204)
}

func (s *Server) affiliateTransfer(w http.ResponseWriter, r *http.Request, u User) {
	var form struct{ Amount int64 }
	if !decode(w, r, &form) {
		return
	}
	if form.Amount < 1 || form.Amount > 1<<40 {
		fail(w, 400, "划转金额无效")
		return
	}
	tx, err := s.db.Begin()
	if err != nil {
		dbFailure(w, err)
		return
	}
	defer tx.Rollback()
	result, err := tx.Exec("UPDATE users SET affiliate_balance=affiliate_balance-? WHERE id=? AND affiliate_balance>=?", form.Amount, u.ID, form.Amount)
	if err != nil {
		dbFailure(w, err)
		return
	}
	if n, _ := result.RowsAffected(); n != 1 {
		fail(w, 409, "佣金余额不足")
		return
	}
	if err = creditBalance(tx, u.ID, form.Amount, "", "佣金转入钱包", "affiliate_transfer"); err == nil {
		err = tx.Commit()
	}
	if err != nil {
		dbFailure(w, err)
		return
	}
	w.WriteHeader(204)
}
