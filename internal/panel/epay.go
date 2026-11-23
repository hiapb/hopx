package panel

import (
	"context"
	"crypto/md5"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

func epayFields(values url.Values, secret string) string {
	keys := make([]string, 0, len(values))
	for k := range values {
		if k != "sign" && k != "sign_type" && values.Get(k) != "" {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+values.Get(key))
	}
	hash := md5.Sum([]byte(strings.Join(parts, "&") + secret))
	return hex.EncodeToString(hash[:])
}

func cents(raw string) (int64, error) {
	whole, fraction, decimal := strings.Cut(raw, ".")
	if len(whole) < 1 || len(whole) > 10 || (decimal && (len(fraction) < 1 || len(fraction) > 2)) {
		return 0, fmt.Errorf("invalid money")
	}
	if len(fraction) == 0 {
		fraction = "00"
	} else if len(fraction) == 1 {
		fraction += "0"
	}
	w, e := strconv.ParseUint(whole, 10, 64)
	if e != nil {
		return 0, e
	}
	f, e := strconv.ParseUint(fraction, 10, 64)
	if e != nil {
		return 0, e
	}
	return int64(w*100 + f), nil
}

func (s *Server) paymentURL(ctx context.Context, config paymentChannel, reference string, amount int64, channel string) (checkoutDestination, error) {
	origin := strings.TrimRight(s.publicURL, "/")
	merchant, key := config.Merchant, config.Secret
	target, err := gatewayURL(config.Endpoint)
	if origin == "" || key == "" || merchant == "" || err != nil || target.Host == "" || target.Scheme != "https" || target.User != nil {
		return checkoutDestination{}, fmt.Errorf("易支付未配置")
	}
	values := target.Query()
	mapi := strings.HasSuffix(target.Path, "/mapi.php") || values.Get("mapi") == "1"
	values.Del("mapi")
	if mapi && !strings.HasSuffix(target.Path, "/mapi.php") {
		target.Path = strings.TrimSuffix(strings.TrimRight(target.Path, "/"), "/submit.php") + "/mapi.php"
	}
	if !mapi && !strings.HasSuffix(target.Path, "/submit.php") {
		target.Path = strings.TrimRight(target.Path, "/") + "/submit.php"
	}
	values.Set("pid", merchant)
	values.Set("type", firstNonempty(values.Get("type"), channel))
	if mapi {
		values.Set("device", firstNonempty(values.Get("device"), "pc"))
	}
	values.Set("out_trade_no", reference)
	values.Set("notify_url", config.callbackURL(s.publicURL))
	values.Set("return_url", origin+"/#/orders")
	values.Set("name", "HopX 余额充值")
	values.Set("money", fmt.Sprintf("%d.%02d", amount/100, amount%100))
	values.Set("sign_type", "MD5")
	values.Set("sign", epayFields(values, key))
	if !mapi {
		target.RawQuery = values.Encode()
		return checkoutDestination{URL: target.String()}, nil
	}
	target.RawQuery = ""
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), strings.NewReader(values.Encode()))
	if err != nil {
		return checkoutDestination{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := http.Client{Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return checkoutDestination{}, fmt.Errorf("易支付网关连接失败")
	}
	defer resp.Body.Close()
	var result struct {
		Code   json.RawMessage
		URL    string `json:"payurl"`
		QRCode string `json:"qrcode"`
	}
	if resp.StatusCode != 200 || json.NewDecoder(io.LimitReader(resp.Body, 256<<10)).Decode(&result) != nil || (string(result.Code) != "1" && string(result.Code) != `"1"`) {
		return checkoutDestination{}, fmt.Errorf("易支付网关未接受订单")
	}
	if _, err := gatewayURL(result.URL); err == nil {
		return checkoutDestination{URL: result.URL}, nil
	}
	qr, err := url.Parse(result.QRCode)
	if err == nil && qr.Host != "" && qr.User == nil && len(result.QRCode) <= 1000 &&
		slices.Contains([]string{"https", "weixin", "alipays"}, qr.Scheme) {
		return checkoutDestination{URL: result.QRCode, QR: true}, nil
	}
	return checkoutDestination{}, fmt.Errorf("易支付网关未返回有效的支付地址")
}

func (s *Server) epayCheckout(w http.ResponseWriter, r *http.Request, u User) {
	var input struct {
		Amount  int64
		Channel string
		Gateway string
	}
	if !decode(w, r, &input) {
		return
	}
	minimum, _ := strconv.ParseInt(s.setting("minRecharge", "100"), 10, 64)
	if input.Amount < max(1, minimum) || input.Amount > 100000000 {
		fail(w, 400, "充值金额低于最低限额或超出范围")
		return
	}
	config, err := s.paymentChannel(firstNonempty(input.Gateway, "epay"))
	if err == sql.ErrNoRows {
		fail(w, 400, "支付网关无效")
		return
	}
	if err != nil {
		dbFailure(w, err)
		return
	}
	kind := config.Kind
	if kind == "epay" {
		switch input.Channel {
		case "alipay", "wxpay", "qqpay":
		default:
			fail(w, 400, "支付方式无效")
			return
		}
	}
	if !config.Enabled || !config.ready(s.publicURL) {
		fail(w, 503, "支付网关未启用或未配置")
		return
	}
	fee := gatewayFee(input.Amount, config.Fee)
	total := input.Amount + fee
	ref := token()
	result, err := s.db.Exec(`INSERT INTO orders(user_id,amount,credit,kind,status,reference,description,checkout_channel,checkout_fee)
		SELECT ?,?,0,?,'pending',?,'钱包充值',?,?
		WHERE ?='' OR EXISTS(SELECT 1 FROM payment_channels WHERE id=? AND config=? AND archived=0)`,
		u.ID, total, kind, config.reference(ref), input.Channel, fee, config.ID, config.ID, config.storedConfig)
	if err != nil {
		dbFailure(w, err)
		return
	}
	if count, _ := result.RowsAffected(); count == 0 {
		fail(w, 409, "支付通道已更新，请重新选择")
		return
	}
	checkout, err := s.createCheckout(r.Context(), config, ref, total, u.ID, input.Channel)
	if err != nil {
		fail(w, 503, err.Error())
		return
	}
	if _, err = s.db.Exec("UPDATE orders SET checkout_url=?,checkout_qr=? WHERE reference=?", checkout.URL, checkout.QR, config.reference(ref)); err != nil {
		dbFailure(w, err)
		return
	}

	respond(w, 201, checkout)
}

func (s *Server) resumeCheckout(w http.ResponseWriter, r *http.Request, u User) {
	var reference, channel, kind string
	var next checkoutDestination
	var amount int64
	err := s.db.QueryRow("SELECT reference,amount,checkout_channel,kind,checkout_url,checkout_qr FROM orders WHERE id=? AND user_id=? AND status='pending'", pathID(r), u.ID).Scan(&reference, &amount, &channel, &kind, &next.URL, &next.QR)
	if err == sql.ErrNoRows || !enabledGateway(kind) {
		fail(w, 404, "待支付订单不存在")
		return
	}
	if err != nil {
		dbFailure(w, err)
		return
	}
	if next.URL == "" {
		ref := strings.TrimPrefix(reference, kind+":")
		gateway := kind
		if id, tail, found := strings.Cut(ref, ":"); found {
			gateway, ref = id, tail
		}
		config, lookupErr := s.paymentChannel(gateway)
		if lookupErr != nil || config.Kind != kind {
			fail(w, 503, "订单支付通道不可用")
			return
		}
		next, err = s.createCheckout(r.Context(), config, ref, amount, u.ID, channel)
		if err != nil {
			fail(w, 503, err.Error())
			return
		}
		if _, err = s.db.Exec("UPDATE orders SET checkout_url=?,checkout_qr=? WHERE id=?", next.URL, next.QR, pathID(r)); err != nil {
			dbFailure(w, err)
			return
		}
	}

	respond(w, 200, next)
}

func settleOrder(tx *sql.Tx, id, user, amount int64) error {
	update, err := tx.Exec("UPDATE orders SET status='paid',credit=?,paid_at=unixepoch() WHERE id=? AND status='pending'", amount, id)
	if err != nil {
		return err
	}
	count, err := update.RowsAffected()
	if err != nil || count == 0 {
		return err
	}
	if _, err = tx.Exec("UPDATE users SET balance=balance+? WHERE id=?", amount, user); err != nil {
		return err
	}
	return queueTelegramEvent(tx, "income", "充值到账", fmt.Sprintf("订单 #%d 已入账 ¥%d.%02d。", id, amount/100, amount%100), user)
}

func (s *Server) manualSettle(w http.ResponseWriter, r *http.Request, u User) {
	tx, err := s.db.Begin()
	if err != nil {
		dbFailure(w, err)
		return
	}
	defer tx.Rollback()
	id := pathID(r)
	var user, amount int64
	var status string
	err = tx.QueryRow("SELECT user_id,amount-checkout_fee,status FROM orders WHERE id=? AND kind IN ('epay','epusdt','tokenpay','cryptomus')", id).Scan(&user, &amount, &status)
	if err == sql.ErrNoRows {
		fail(w, 404, "充值订单不存在")
		return
	}
	if err != nil {
		dbFailure(w, err)
		return
	}
	if status != "paid" && status != "pending" {
		fail(w, 409, "订单无法补单")
		return
	}
	if status == "pending" {
		err = settleOrder(tx, id, user, amount)
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

func (s *Server) epayNotify(w http.ResponseWriter, r *http.Request) {
	channel, _ := s.paymentChannel("epay")
	s.epayNotifyChannel(w, r, channel)
}

func (s *Server) epayNotifyChannel(w http.ResponseWriter, r *http.Request, channel paymentChannel) {
	key, merchant := channel.Secret, channel.Merchant
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil || key == "" || merchant == "" {
		http.Error(w, "invalid callback", 400)
		return
	}
	form := r.Form
	for _, values := range form {
		if len(values) != 1 {
			http.Error(w, "duplicate parameter", 400)
			return
		}
	}
	ref := form.Get("out_trade_no")
	if ref == "" || len(ref) > 128 || strings.Contains(ref, ":") ||
		form.Get("pid") != merchant || form.Get("trade_status") != "TRADE_SUCCESS" ||
		subtle.ConstantTimeCompare([]byte(epayFields(form, key)), []byte(strings.ToLower(form.Get("sign")))) != 1 {
		http.Error(w, "invalid callback", 401)
		return
	}
	amount, e := cents(form.Get("money"))
	if e != nil || amount <= 0 {
		http.Error(w, "invalid amount", 400)
		return
	}
	tx, e := s.db.Begin()
	if e != nil {
		dbFailure(w, e)
		return
	}
	defer tx.Rollback()
	var order, user, expected, fee int64
	var status string
	e = tx.QueryRow("SELECT id,user_id,amount,checkout_fee,status FROM orders WHERE reference=? AND kind='epay'", channel.reference(ref)).Scan(&order, &user, &expected, &fee, &status)
	if e == sql.ErrNoRows || amount != expected {
		http.Error(w, "order mismatch", 400)
		return
	}
	if e != nil {
		dbFailure(w, e)
		return
	}
	if status == "paid" {
		_, _ = fmt.Fprint(w, "success")
		return
	}
	if status != "pending" {
		http.Error(w, "order is not pending", 409)
		return
	}
	e = settleOrder(tx, order, user, amount-fee)
	if e == nil {
		e = tx.Commit()
	}
	if e != nil {
		dbFailure(w, e)
		return
	}
	_, _ = fmt.Fprint(w, "success")
}
