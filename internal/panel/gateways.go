package panel

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

type gatewaySettings struct {
	Endpoint string `json:"endpoint"`
	Merchant string `json:"merchant"`
	Secret   string `json:"secret"`
	Network  string `json:"network"`
	Currency string `json:"currency"`
	SHA256   bool   `json:"sha256"`
}

func (s *Server) gateway(kind string) gatewaySettings {
	return gatewaySettings{
		Endpoint: s.setting(kind+"Gateway", ""), Merchant: s.setting(kind+"PID", ""), Secret: s.setting(kind+"Key", ""),
		Network: s.setting(kind+"Network", ""), Currency: s.setting(kind+"Currency", ""), SHA256: s.setting(kind+"SHA256", "false") == "true",
	}
}

var gatewayKinds = []string{"epay", "epusdt", "tokenpay", "cryptomus"}

func gatewayFee(amount int64, basisPoints int) int64 {
	return (amount*int64(basisPoints) + 5000) / 10000
}

func enabledGateway(kind string) bool {
	return slices.Contains(gatewayKinds, kind)
}

func gatewayURL(value string) (*url.URL, error) {
	endpoint, err := url.Parse(value)
	if err != nil || endpoint.Host == "" || endpoint.Scheme != "https" || endpoint.User != nil {
		return nil, errors.New("支付网关应配置为有效的 HTTPS 地址")
	}
	return endpoint, nil
}

func digestMD5(value string) string {
	sum := md5.Sum([]byte(value))
	return hex.EncodeToString(sum[:])
}

func canonicalDigest(fields map[string]any, exclude, secret string, sha bool) string {
	keys := make([]string, 0, len(fields))
	for key, value := range fields {
		if key != exclude && value != nil && fmt.Sprint(value) != "" {
			keys = append(keys, key)
		}
	}
	slices.Sort(keys)
	values := make([]string, 0, len(keys))
	for _, key := range keys {
		values = append(values, key+"="+fmt.Sprint(fields[key]))
	}
	canonical := strings.Join(values, "&")
	if !sha {
		return digestMD5(canonical + secret)
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(canonical))
	return hex.EncodeToString(mac.Sum(nil))
}

type checkoutDestination struct {
	URL string `json:"url"`
	QR  bool   `json:"qr,omitempty"`
}

func (s *Server) createCheckout(ctx context.Context, cfg paymentChannel, ref string, amount, userID int64, channel string) (checkoutDestination, error) {
	kind := cfg.Kind
	if kind == "epay" {
		return s.paymentURL(ctx, cfg, ref, amount, channel)
	}
	endpoint, err := gatewayURL(cfg.Endpoint)
	if err != nil || cfg.Secret == "" || s.publicURL == "" {
		return checkoutDestination{}, errors.New("支付网关未配置")
	}
	callback := cfg.callbackURL(s.publicURL)
	returnURL := strings.TrimRight(s.publicURL, "/") + "/#/orders"
	value := fmt.Sprintf("%d.%02d", amount/100, amount%100)
	decimal := json.Number(strings.TrimRight(strings.TrimRight(value, "0"), "."))
	var fields map[string]any
	switch kind {
	case "epusdt":
		fields = map[string]any{"order_id": ref, "amount": decimal, "notify_url": callback, "redirect_url": returnURL}
		if cfg.Merchant != "" {
			fields["pid"] = cfg.Merchant
			fields["currency"] = "cny"
			if cfg.Network != "" {
				fields["network"] = cfg.Network
			}
			if cfg.Currency != "" {
				fields["token"] = cfg.Currency
			}
		}
		fields["signature"] = canonicalDigest(fields, "signature", cfg.Secret, cfg.SHA256)
	case "tokenpay":
		currency := cfg.Currency
		if currency == "" {
			currency = "USDT_TRC20"
		}
		fields = map[string]any{"OutOrderId": ref, "OrderUserKey": fmt.Sprint(userID), "ActualAmount": decimal, "Currency": currency, "NotifyUrl": callback, "RedirectUrl": returnURL}
		fields["Signature"] = canonicalDigest(fields, "Signature", cfg.Secret, cfg.SHA256)
	case "cryptomus":
		if cfg.Merchant == "" {
			return checkoutDestination{}, errors.New("Cryptomus 商户 ID 未设置")
		}
		currency := cfg.Currency
		if currency == "" {
			currency = "CNY"
		}
		fields = map[string]any{"order_id": ref, "amount": value, "currency": strings.ToUpper(currency), "url_callback": callback, "url_return": returnURL}
		if cfg.Network != "" {
			fields["network"] = cfg.Network
		}
	default:
		return checkoutDestination{}, errors.New("支付网关不可用")
	}
	body, err := json.Marshal(fields)
	if err != nil {
		return checkoutDestination{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return checkoutDestination{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	if kind == "cryptomus" {
		request.Header.Set("merchant", cfg.Merchant)
		request.Header.Set("sign", digestMD5(base64.StdEncoding.EncodeToString(body)+cfg.Secret))
	}
	client := http.Client{Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		return checkoutDestination{}, errors.New("支付网关连接失败")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return checkoutDestination{}, errors.New("支付网关未接受订单")
	}
	var data struct {
		StatusCode int             `json:"status_code"`
		Success    bool            `json:"success"`
		State      int             `json:"state"`
		Data       json.RawMessage `json:"data"`
		Result     struct{ URL string }
	}
	if err = json.NewDecoder(io.LimitReader(response.Body, 256<<10)).Decode(&data); err != nil {
		return checkoutDestination{}, errors.New("支付网关返回格式无效")
	}
	var redirect string
	switch kind {
	case "epusdt":
		var checkout struct {
			PaymentURL string `json:"payment_url"`
		}
		if data.StatusCode == 200 && json.Unmarshal(data.Data, &checkout) == nil {
			redirect = checkout.PaymentURL
		}
	case "tokenpay":
		if data.Success {
			_ = json.Unmarshal(data.Data, &redirect)
		}
	case "cryptomus":
		if data.State == 0 {
			redirect = data.Result.URL
		}
	}
	if _, err = gatewayURL(redirect); err != nil {
		return checkoutDestination{}, errors.New("支付网关未返回有效的收银台地址")
	}
	return checkoutDestination{URL: redirect}, nil
}

func (s *Server) gatewayCallback(w http.ResponseWriter, r *http.Request) {
	kind := r.PathValue("gateway")
	if !enabledGateway(kind) || kind == "epay" {
		http.NotFound(w, r)
		return
	}
	channel, _ := s.paymentChannel(kind)
	s.gatewayCallbackChannel(w, r, channel)
}

func (s *Server) gatewayCallbackChannel(w http.ResponseWriter, r *http.Request, config paymentChannel) {
	kind := config.Kind
	if config.Secret == "" {
		http.Error(w, "gateway unavailable", 503)
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
	if err != nil {
		http.Error(w, "invalid callback", 400)
		return
	}
	var params map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err = decoder.Decode(&params); err != nil || decoder.Decode(new(any)) != io.EOF {
		http.Error(w, "invalid callback", 400)
		return
	}
	field := func(k string) string {
		if v, ok := params[k]; ok {
			return fmt.Sprint(v)
		}
		return ""
	}
	var expected, provided, reference, amount, receipt string
	var paid bool
	switch kind {
	case "epusdt":
		expected = canonicalDigest(params, "signature", config.Secret, config.SHA256)
		provided, reference, amount, receipt = field("signature"), field("order_id"), field("amount"), "ok"
		paid = field("status") == "2"
	case "tokenpay":
		expected = canonicalDigest(params, "Signature", config.Secret, config.SHA256)
		provided, reference, amount, receipt = field("Signature"), field("OutOrderId"), field("ActualAmount"), "ok"
		paid = field("Status") == "1" && (field("BaseCurrency") == "" || strings.EqualFold(field("BaseCurrency"), "CNY"))
	case "cryptomus":
		provided, reference, amount, receipt = field("sign"), field("order_id"), field("amount"), "ok"
		unsigned, err := unsignedCryptomus(raw)
		if err != nil {
			http.Error(w, "invalid callback", 400)
			return
		}
		expected = digestMD5(base64.StdEncoding.EncodeToString(unsigned) + config.Secret)
		paid = field("status") == "paid" || field("status") == "paid_over"
		if field("currency") != "" && !strings.EqualFold(field("currency"), firstNonempty(config.Currency, "CNY")) {
			paid = false
		}
	}
	if !paid || reference == "" || len(reference) > 128 || strings.Contains(reference, ":") || subtle.ConstantTimeCompare([]byte(strings.ToLower(provided)), []byte(expected)) != 1 {
		http.Error(w, "invalid signature or payment status", 401)
		return
	}
	total, err := scaledLegacy(amount, 100)
	if err != nil || total < 1 {
		http.Error(w, "invalid amount", 400)
		return
	}
	tx, err := s.db.Begin()
	if err != nil {
		dbFailure(w, err)
		return
	}
	defer tx.Rollback()
	var id, user, expectedAmount, fee int64
	var status string
	err = tx.QueryRow("SELECT id,user_id,amount,checkout_fee,status FROM orders WHERE reference=? AND kind=?", config.reference(reference), kind).Scan(&id, &user, &expectedAmount, &fee, &status)
	if err == sql.ErrNoRows || total != expectedAmount {
		http.Error(w, "order mismatch", 400)
		return
	}
	if err != nil {
		dbFailure(w, err)
		return
	}
	if status == "paid" {
		_, _ = io.WriteString(w, receipt)
		return
	}
	if status != "pending" {
		http.Error(w, "order unavailable", 409)
		return
	}
	if err = settleOrder(tx, id, user, total-fee); err == nil {
		err = tx.Commit()
	}
	if err != nil {
		dbFailure(w, err)
		return
	}
	_, _ = io.WriteString(w, receipt)
}

func firstNonempty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// The callback signature uses the provider's JSON field order and escaped
// slashes. Preserve that order when excluding the sign parameter.
func unsignedCryptomus(raw []byte) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return nil, errors.New("invalid callback object")
	}
	var output bytes.Buffer
	output.WriteByte('{')
	seen := make(map[string]bool)
	count := 0
	for decoder.More() {
		label, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		key, ok := label.(string)
		if !ok || seen[key] {
			return nil, errors.New("invalid callback key")
		}
		seen[key] = true
		var value json.RawMessage
		if err = decoder.Decode(&value); err != nil {
			return nil, err
		}
		if key == "sign" {
			continue
		}
		if count > 0 {
			output.WriteByte(',')
		}
		encoded, _ := json.Marshal(key)
		output.Write(encoded)
		output.WriteByte(':')
		var compact bytes.Buffer
		if err = json.Compact(&compact, value); err != nil {
			return nil, err
		}
		output.Write(compact.Bytes())
		count++
	}
	if _, err = decoder.Token(); err != nil {
		return nil, err
	}
	output.WriteByte('}')
	return []byte(phpSlashes(output.String())), nil
}

func phpSlashes(value string) string {
	var output strings.Builder
	escaped := false
	for _, b := range value {
		if b == '/' && !escaped {
			output.WriteByte('\\')
		}
		output.WriteRune(b)
		escaped = b == '\\' && !escaped
	}
	return output.String()
}
