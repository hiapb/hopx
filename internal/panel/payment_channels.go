package panel

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

var paymentChannelID = regexp.MustCompile(`^ch_[A-Za-z0-9]{26}$`)

type paymentChannel struct {
	ID           string `json:"id"`
	Kind         string `json:"kind"`
	Name         string `json:"name"`
	Enabled      bool   `json:"enabled"`
	Fee          int    `json:"fee"`
	Callback     string `json:"callback"`
	Revision     string `json:"revision,omitempty"`
	storedConfig string
	gatewaySettings
}

type channelOption struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
	Name string `json:"name,omitempty"`
	Fee  int    `json:"fee"`
}

func (s *Server) paymentChannel(id string) (paymentChannel, error) {
	if enabledGateway(id) {
		fee, _ := strconv.Atoi(s.setting(id+"Fee", "0"))
		return paymentChannel{Kind: id, Enabled: s.setting(id+"Enabled", "auto") != "false", Fee: fee,
			Callback: s.setting(id+"Callback", ""), gatewaySettings: s.gateway(id)}, nil
	}
	if !paymentChannelID.MatchString(id) {
		return paymentChannel{}, sql.ErrNoRows
	}
	var raw string
	var archived bool
	if err := s.db.QueryRow("SELECT config,archived FROM payment_channels WHERE id=?", id).Scan(&raw, &archived); err != nil {
		return paymentChannel{}, err
	}
	var c paymentChannel
	err := json.Unmarshal([]byte(raw), &c)
	c.ID, c.storedConfig = id, raw
	c.Enabled = c.Enabled && !archived
	return c, err
}

func (c paymentChannel) reference(ref string) string {
	if c.ID != "" {
		return c.Kind + ":" + c.ID + ":" + ref
	}
	return c.Kind + ":" + ref
}

func (c paymentChannel) callbackURL(origin string) string {
	base := strings.TrimRight(firstNonempty(c.Callback, origin), "/") + "/api/payment/"
	if c.ID != "" {
		return base + "channels/" + c.ID
	}
	return base + c.Kind
}

func (c paymentChannel) ready(publicURL string) bool {
	_, err := gatewayURL(c.Endpoint)
	return err == nil && publicURL != "" && c.Secret != "" && ((c.Kind != "epay" && c.Kind != "cryptomus") || c.Merchant != "")
}

func (s *Server) paymentChannels(w http.ResponseWriter, r *http.Request, _ User) {
	if r.Method == http.MethodGet {
		entries, err := s.activePaymentChannels()
		if err != nil {
			dbFailure(w, err)
			return
		}
		respond(w, 200, entries)
		return
	}
	id := r.PathValue("channel")
	if r.Method == http.MethodDelete {
		result, err := s.db.Exec("UPDATE payment_channels SET archived=1 WHERE id=? AND archived=0", id)
		if err != nil {
			dbFailure(w, err)
			return
		}
		if n, _ := result.RowsAffected(); n == 0 {
			fail(w, 404, "支付通道不存在")
			return
		}
		w.WriteHeader(204)
		return
	}
	var c paymentChannel
	if !decode(w, r, &c) {
		return
	}
	c.ID = id
	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		dbFailure(w, err)
		return
	}
	defer tx.Rollback()
	if err = savePaymentChannel(tx, &c); err != nil {
		writePaymentChannelError(w, err, "")
		return
	}
	if err = tx.Commit(); err != nil {
		dbFailure(w, err)
		return
	}
	respond(w, 200, c)
}

type paymentChannelError struct {
	status  int
	message string
}

func (e paymentChannelError) Error() string { return e.message }

func writePaymentChannelError(w http.ResponseWriter, err error, prefix string) {
	var problem paymentChannelError
	if errors.As(err, &problem) {
		fail(w, problem.status, prefix+problem.message)
		return
	}
	dbFailure(w, err)
}

func savePaymentChannel(tx *sql.Tx, c *paymentChannel) error {
	c.Name, c.Endpoint, c.Callback = strings.TrimSpace(c.Name), strings.TrimSpace(c.Endpoint), strings.TrimSpace(c.Callback)
	c.Merchant, c.Secret = strings.TrimSpace(c.Merchant), strings.TrimSpace(c.Secret)
	if !enabledGateway(c.Kind) || c.Name == "" || len(c.Name) > 100 || c.Fee < 0 || c.Fee > 10000 ||
		len(c.Secret) > 2048 || len(c.Endpoint) > 2048 || len(c.Callback) > 2048 ||
		len(c.Merchant) > 512 || len(c.Currency) > 64 || len(c.Network) > 64 || !validPaymentCallback(c.Callback) {
		return paymentChannelError{400, "支付通道名称、类型、费率或地址无效"}
	}
	if !c.ready("configured") {
		return paymentChannelError{400, "请填写 HTTPS 网关及该通道要求的密钥和商户号"}
	}
	id := c.ID
	if id == "" {
		c.ID = "ch_" + token()
	} else {
		var raw string
		err := tx.QueryRow("SELECT config FROM payment_channels WHERE id=? AND archived=0", id).Scan(&raw)
		if errors.Is(err, sql.ErrNoRows) {
			return paymentChannelError{404, "支付通道不存在"}
		}
		if err != nil {
			return err
		}
		if c.Revision != "" && c.Revision != digest(raw) {
			return paymentChannelError{409, "支付通道已被修改，请重新加载"}
		}
		var previous paymentChannel
		if err := json.Unmarshal([]byte(raw), &previous); err != nil {
			return err
		}
		if previous.Kind != c.Kind {
			return paymentChannelError{400, "已有通道的支付类型不可更改"}
		}
		if previous.gatewaySettings != c.gatewaySettings {
			var pending bool
			if err := tx.QueryRow("SELECT EXISTS(SELECT 1 FROM orders WHERE reference GLOB ? AND status='pending')", c.reference("*")).Scan(&pending); err != nil {
				return err
			}
			if pending {
				return paymentChannelError{409, "此通道还有待支付订单，可先停用或归档，并另外添加通道"}
			}
		}
	}
	c.Revision = ""
	raw, err := json.Marshal(c)
	if err != nil {
		return err
	}
	if id == "" {
		_, err = tx.Exec("INSERT INTO payment_channels(id,config,show_order) SELECT ?,?,coalesce(max(show_order),0)+1 FROM payment_channels WHERE archived=0", c.ID, string(raw))
	} else {
		_, err = tx.Exec("UPDATE payment_channels SET config=? WHERE id=?", string(raw), id)
	}
	c.Revision = digest(string(raw))
	return err
}

func (s *Server) savePaymentChannels(w http.ResponseWriter, r *http.Request, _ User) {
	var input struct {
		Channels []paymentChannel
	}
	if !decode(w, r, &input) {
		return
	}
	if len(input.Channels) < 1 || len(input.Channels) > 200 {
		fail(w, 400, "一次可保存 1 至 200 个支付通道")
		return
	}
	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		dbFailure(w, err)
		return
	}
	defer tx.Rollback()
	var first int
	if err = tx.QueryRow("SELECT coalesce(min(show_order),0) FROM payment_channels WHERE archived=0").Scan(&first); err != nil {
		dbFailure(w, err)
		return
	}
	first -= len(input.Channels)
	seen := make(map[string]bool, len(input.Channels))
	for i := range input.Channels {
		channel := &input.Channels[i]
		if channel.ID != "" && seen[channel.ID] {
			fail(w, 400, "通道 ID 重复")
			return
		}
		if err = savePaymentChannel(tx, channel); err != nil {
			writePaymentChannelError(w, err, fmt.Sprintf("第 %d 个通道：", i+1))
			return
		}
		seen[channel.ID] = true
		if _, err = tx.Exec("UPDATE payment_channels SET show_order=? WHERE id=?", first+i, channel.ID); err != nil {
			dbFailure(w, err)
			return
		}
	}
	if err = tx.Commit(); err != nil {
		dbFailure(w, err)
		return
	}
	respond(w, 200, input.Channels)
}

func (s *Server) activePaymentChannels() ([]paymentChannel, error) {
	rows, err := s.db.Query("SELECT config FROM payment_channels WHERE archived=0 ORDER BY show_order,rowid")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	entries := []paymentChannel{}
	for rows.Next() {
		var raw string
		var c paymentChannel
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(raw), &c); err != nil {
			return nil, err
		}
		c.Revision = digest(raw)
		entries = append(entries, c)
	}
	return entries, rows.Err()
}

func validPaymentCallback(value string) bool {
	if value == "" {
		return true
	}
	endpoint, err := gatewayURL(value)
	return err == nil && (endpoint.Path == "" || endpoint.Path == "/") && endpoint.RawQuery == "" && endpoint.Fragment == ""
}

func (s *Server) paymentChannelCallback(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("channel")
	if !paymentChannelID.MatchString(id) {
		http.NotFound(w, r)
		return
	}
	channel, err := s.paymentChannel(id)
	if err == sql.ErrNoRows {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		dbFailure(w, err)
		return
	}
	if channel.Kind == "epay" {
		s.epayNotifyChannel(w, r, channel)
	} else if r.Method == http.MethodPost {
		s.gatewayCallbackChannel(w, r, channel)
	} else {
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}
