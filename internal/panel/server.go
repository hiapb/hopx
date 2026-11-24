package panel

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/sync/singleflight"
	"hopx/internal/wire"
	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schema string

type cachedConfig struct {
	previous     wire.Config
	value        wire.Config
	until        time.Time
	meterTickets map[wire.ExitMeter]string
}

type Server struct {
	meterKey           ed25519.PrivateKey
	warmUntil          time.Time
	version            string
	diagnostics        map[int64]probeCheck
	guard              authGuard
	captcha            captchaStore
	db                 *sql.DB
	ui                 fs.FS
	publicURL          string
	releaseDir         string
	paymentSecret      string
	mu                 sync.RWMutex
	devices            map[int64]wire.Device
	releaseMu          sync.Mutex
	releaseUntil       time.Time
	releases           map[string]wire.Release
	rolloutMu          sync.Mutex
	rollout            nodeRollout
	nodeStatusMu       sync.Mutex
	nodeStatus         nodeStatusSnapshot
	reverseMu          sync.Mutex
	reverseRoutes      map[int64][]reverseRoute
	reverseRoutesUntil time.Time
	configMu           sync.RWMutex
	configBuild        singleflight.Group
	configs            map[int64]cachedConfig
	telegramNodeStatus map[int64]bool
	probeStored        map[int64]int64
}

type Options struct {
	Version                                                                  string
	Database, AdminName, AdminPassword, PublicURL, ReleaseDir, PaymentSecret string
	UI                                                                       fs.FS
}

type User struct {
	AffiliateBalance    int64  `json:"affiliateBalance"`
	AllowDevice         bool   `json:"allowDevice"`
	RateOverride        *int   `json:"rateOverride"`
	IPsOverride         *int   `json:"ipsOverride"`
	ConnectionsOverride *int   `json:"connectionsOverride"`
	ID                  int64  `json:"id"`
	Name                string `json:"name"`
	Admin               bool   `json:"admin"`
	Banned              bool   `json:"banned"`
	Group               int64  `json:"group"`
	Quota               int64  `json:"quota"`
	Used                int64  `json:"used"`
	Balance             int64  `json:"balance"`
	Expires             int64  `json:"expires"`
	MaxRules            int    `json:"maxRules"`
	PlanID              int64  `json:"planId"`
	Invite              string `json:"invite"`
	AutoRenew           bool   `json:"autoRenew"`
	Note                string `json:"note"`
}

const userSelect = "SELECT id,name,admin,banned,group_id,quota,used,balance,expires,max_rules,plan_id,invite,auto_renew,note,rate_override,ips_override,connections_override,affiliate_balance,allow_device FROM users"

type scanner interface{ Scan(...any) error }

func validUserOverrides(u User) bool {
	return (u.RateOverride == nil || (*u.RateOverride >= 0 && *u.RateOverride <= 100000)) &&
		(u.IPsOverride == nil || *u.IPsOverride >= 0) &&
		(u.ConnectionsOverride == nil || *u.ConnectionsOverride >= 0)
}

func readUser(row scanner) (u User, err error) {
	err = scanUser(row, &u)
	return
}

func scanUser(row scanner, u *User, extra ...any) error {
	fields := []any{&u.ID, &u.Name, &u.Admin, &u.Banned, &u.Group, &u.Quota, &u.Used, &u.Balance, &u.Expires, &u.MaxRules, &u.PlanID, &u.Invite, &u.AutoRenew, &u.Note, &u.RateOverride, &u.IPsOverride, &u.ConnectionsOverride, &u.AffiliateBalance, &u.AllowDevice}
	return row.Scan(append(fields, extra...)...)
}

func Open(o Options) (*Server, error) {
	db, err := sql.Open("sqlite", o.Database)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err = db.Exec("PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;" + schema); err != nil {
		db.Close()
		return nil, err
	}
	columns := map[string]map[string]string{
		"groups": {
			"owner": "INTEGER NOT NULL DEFAULT 0", "allowed_from": "TEXT NOT NULL DEFAULT '[]'", "allowed_to": "TEXT NOT NULL DEFAULT '[]'",
			"user_groups": "TEXT NOT NULL DEFAULT '[]'", "chain": "TEXT NOT NULL DEFAULT '[]'", "port_ranges": "TEXT NOT NULL DEFAULT ''",
			"reverse_groups": "TEXT NOT NULL DEFAULT '[]'", "tls_ingress": "INTEGER NOT NULL DEFAULT 0", "ingress": "TEXT NOT NULL DEFAULT 'null'",
			"folder": "TEXT NOT NULL DEFAULT ''", "note": "TEXT NOT NULL DEFAULT ''", "show_order": "INTEGER NOT NULL DEFAULT 0", "hide_status": "INTEGER NOT NULL DEFAULT 0",
			"relay_mode": "TEXT NOT NULL DEFAULT ''", "default_network": "TEXT NOT NULL DEFAULT 'tcp'",
			"connect_host": "TEXT NOT NULL DEFAULT ''", "fallback_group": "INTEGER NOT NULL DEFAULT 0", "routing": "TEXT NOT NULL DEFAULT '{}'",
		},
		"users": {
			"billing_remainder": "INTEGER NOT NULL DEFAULT 0", "quota_epoch": "INTEGER NOT NULL DEFAULT 0",
			"rate_override": "INTEGER", "ips_override": "INTEGER", "connections_override": "INTEGER",
			"affiliate_balance": "INTEGER NOT NULL DEFAULT 0", "allow_device": "INTEGER NOT NULL DEFAULT 0",
		},
		"user_groups":            {"show_order": "INTEGER NOT NULL DEFAULT 0"},
		"devices":                {"last_seen": "INTEGER NOT NULL DEFAULT 0"},
		"user_referral_settings": {"registration_enabled": "INTEGER NOT NULL DEFAULT 1"},
		"payment_channels":       {"show_order": "INTEGER NOT NULL DEFAULT 0"},
		"notifications":          {"topic": "TEXT NOT NULL DEFAULT ''"},
		"telegram_links":         {"income": "INTEGER NOT NULL DEFAULT 0", "updown": "INTEGER NOT NULL DEFAULT 0"},
		"plans":                  {"rate_mbps": "INTEGER NOT NULL DEFAULT 0", "max_ips": "INTEGER NOT NULL DEFAULT 0", "max_connections": "INTEGER NOT NULL DEFAULT 0", "kind": "TEXT NOT NULL DEFAULT 'day'", "show_order": "INTEGER NOT NULL DEFAULT 0", "archived": "INTEGER NOT NULL DEFAULT 0"},
		"orders":                 {"checkout_channel": "TEXT NOT NULL DEFAULT ''", "checkout_url": "TEXT NOT NULL DEFAULT ''", "checkout_fee": "INTEGER NOT NULL DEFAULT 0", "checkout_qr": "INTEGER NOT NULL DEFAULT 0", "paid_at": "INTEGER NOT NULL DEFAULT 0", "archived": "INTEGER NOT NULL DEFAULT 0"},
	}
	for table, defs := range columns {
		for name, definition := range defs {
			var exists int
			err = db.QueryRow("SELECT count(*) FROM pragma_table_info(?) WHERE name=?", table, name).Scan(&exists)
			if err == nil && exists == 0 {
				_, err = db.Exec("ALTER TABLE " + table + " ADD COLUMN " + name + " " + definition)
			}
			if err != nil {
				db.Close()
				return nil, err
			}
		}
	}
	s := &Server{db: db, ui: o.UI, publicURL: o.PublicURL, releaseDir: o.ReleaseDir, paymentSecret: o.PaymentSecret, version: o.Version, warmUntil: time.Now().Add(15 * time.Second), devices: make(map[int64]wire.Device), configs: make(map[int64]cachedConfig), probeStored: make(map[int64]int64), diagnostics: make(map[int64]probeCheck), guard: authGuard{clients: make(map[string]attempt), bcrypt: make(chan struct{}, 4)}, captcha: captchaStore{items: make(map[string]challenge)}}
	if err = s.loadMeterKey(); err != nil {
		db.Close()
		return nil, err
	}
	if err = s.loadRollout(); err != nil {
		db.Close()
		return nil, err
	}
	var count int
	if err = db.QueryRow("SELECT count(*) FROM users WHERE admin=1").Scan(&count); err != nil {
		db.Close()
		return nil, err
	}
	if count == 0 && o.AdminPassword != "" {
		if o.AdminName == "" {
			o.AdminName = "admin"
		}
		if err = s.addUser(o.AdminName, o.AdminPassword, true, sql.NullInt64{}); err != nil {
			db.Close()
			return nil, err
		}
	}
	return s, nil
}

func (s *Server) Close() error { return s.db.Close() }

func token() string {
	return rand.Text()
}

func digest(value string) string {
	h := sha256.Sum256([]byte(value))
	return hex.EncodeToString(h[:])
}

func (s *Server) addUser(name, password string, admin bool, inviter sql.NullInt64) error {
	name = strings.TrimSpace(name)
	if len(name) < 2 || len(name) > 64 || len(password) < 10 || len(password) > 72 {
		return errors.New("账号须为 2–64 字节，密码须为 10–72 字节")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	_, err = s.db.Exec("INSERT INTO users(name,password,admin,invite,inviter) VALUES(?,?,?,?,?)", name, hash, admin, token()[:16], inviter)
	return err
}

func respond(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if v != nil {
		_ = json.NewEncoder(w).Encode(v)
	}
}

func fail(w http.ResponseWriter, status int, msg string) {
	respond(w, status, map[string]string{"error": msg})
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	return decodeLimit(w, r, v, 8<<20)
}

func decodeLimit(w http.ResponseWriter, r *http.Request, v any, limit int64) bool {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	d := json.NewDecoder(r.Body)
	if err := d.Decode(v); err != nil {
		fail(w, 400, "请求数据格式错误")
		return false
	}
	if err := d.Decode(new(any)); err != io.EOF {
		fail(w, 400, "请求数据格式错误")
		return false
	}
	return true
}

func dbFailure(w http.ResponseWriter, err error) {
	slog.Error("database request", "error", err)
	fail(w, 500, "操作失败")
}

func pathID(r *http.Request) int64 {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	return id
}

func (s *Server) sessionUser(r *http.Request) (User, error) {
	c, err := r.Cookie("hopx_session")
	if err != nil {
		return User{}, err
	}
	return readUser(s.db.QueryRowContext(r.Context(), userSelect+" WHERE id=(SELECT user_id FROM sessions WHERE token=? AND expires>unixepoch())", digest(c.Value)))
}

func (s *Server) auth(w http.ResponseWriter, r *http.Request) (User, bool) {
	u, err := s.sessionUser(r)
	if errors.Is(err, http.ErrNoCookie) {
		fail(w, 401, "请先登录")
		return User{}, false
	}
	if err != nil || u.Banned {
		fail(w, 401, "登录已失效")
		return User{}, false
	}
	return u, true
}

type userHandler func(http.ResponseWriter, *http.Request, User)

func (s *Server) authorized(admin bool, h userHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, ok := s.auth(w, r)
		if !ok {
			return
		}
		if admin && !u.Admin {
			fail(w, 403, "需要管理员权限")
			return
		}
		h(w, r, u)
	}
}

func (s *Server) setting(key, fallback string) string {
	var value string
	if s.db.QueryRow("SELECT value FROM settings WHERE key=?", key).Scan(&value) != nil {
		return fallback
	}
	return value
}

func (s *Server) cookie(w http.ResponseWriter, r *http.Request, value string, age int) {
	secure := r.TLS != nil || strings.HasPrefix(s.publicURL, "https://")
	if !secure && r.Header.Get("Sec-Fetch-Site") == "same-origin" {
		origin := browserOrigin(r.Header.Get("Origin"))
		secure = origin != nil && origin.Scheme == "https"
	}
	http.SetCookie(w, &http.Cookie{Name: "hopx_session", Value: value, Path: "/", HttpOnly: true, Secure: secure, SameSite: http.SameSiteStrictMode, MaxAge: age})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if !s.guard.allow(r.RemoteAddr) {
		fail(w, 429, "请求过于频繁")
		return
	}
	select {
	case s.guard.bcrypt <- struct{}{}:
		defer func() { <-s.guard.bcrypt }()
	default:
		fail(w, 429, "登录繁忙，请稍后再试")
		return
	}

	var input struct{ Name, Password string }
	if !decodeLimit(w, r, &input, 4096) {
		return
	}
	if len(input.Name) > 64 || len(input.Password) > 72 {
		fail(w, 401, "账号或密码错误")
		return
	}
	var hash []byte
	var id int64
	var banned bool
	err := s.db.QueryRow("SELECT id,password,banned FROM users WHERE name=?", input.Name).Scan(&id, &hash, &banned)
	if err != nil || bcrypt.CompareHashAndPassword(hash, []byte(input.Password)) != nil || banned {
		fail(w, 401, "账号或密码错误")
		return
	}
	session := token()
	_, err = s.db.Exec("INSERT INTO sessions(token,user_id,expires) VALUES(?,?,?)", digest(session), id, time.Now().Add(7*24*time.Hour).Unix())
	if err != nil {
		dbFailure(w, err)
		return
	}
	s.cookie(w, r, session, 604800)
	respond(w, 200, map[string]bool{"ok": true})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request, u User) {
	c, _ := r.Cookie("hopx_session")
	_, _ = s.db.Exec("DELETE FROM sessions WHERE token=?", digest(c.Value))
	s.cookie(w, r, "", -1)
	w.WriteHeader(204)
}

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Name, Password, Invite, ChallengeID, TurnstileToken string
		Answer                                              int
	}
	if !decodeLimit(w, r, &input, 4096) {
		return
	}
	if !s.guard.allow(r.RemoteAddr) {
		fail(w, 429, "请求过于频繁")
		return
	}
	config, err := readRegistrationVerification(s.db)
	if err != nil {
		dbFailure(w, err)
		return
	}
	if config.mode == "closed" {
		fail(w, 403, "注册已关闭")
		return
	}
	switch config.kind {
	case verificationOff:
	case verificationArithmetic:
		if !s.checkChallenge(input.ChallengeID, input.Answer) {
			fail(w, 400, "注册验证无效或已过期")
			return
		}
	case verificationTurnstile:
		valid, err := verifyTurnstile(r.Context(), turnstileClient, config.secret, input.TurnstileToken)
		if err != nil {
			fail(w, 503, "注册验证暂不可用，请稍后重试")
			return
		}
		if !valid {
			fail(w, 400, "Turnstile 验证无效或已过期")
			return
		}
	default:
		fail(w, 503, "注册验证配置无效")
		return
	}
	select {
	case s.guard.bcrypt <- struct{}{}:
		defer func() { <-s.guard.bcrypt }()
	default:
		fail(w, 429, "注册繁忙，请稍后再试")
		return
	}
	mode := config.mode
	var inviter sql.NullInt64
	if input.Invite != "" && mode != "no-invite" {
		if s.db.QueryRow(`SELECT u.id FROM users u LEFT JOIN user_referral_settings rs ON rs.user_id=u.id
			WHERE u.invite=? AND coalesce(rs.registration_enabled,1)=1`, input.Invite).Scan(&inviter) != nil {
			fail(w, 400, "邀请码无效")
			return
		}
	} else if mode == "invite" {
		fail(w, 400, "需要邀请码")
		return
	}
	if err := s.addUser(input.Name, input.Password, false, inviter); err != nil {
		fail(w, 400, "无法注册，请检查账号、密码或重复账号")
		return
	}
	respond(w, 201, map[string]bool{"ok": true})
}

func (s *Server) me(w http.ResponseWriter, r *http.Request, u User) {
	if !u.Admin {
		u.Note = ""
	}
	respond(w, 200, u)
}

func (s *Server) profile(w http.ResponseWriter, r *http.Request, u User) {
	var input struct {
		Password, NewPassword string
		AutoRenew             *bool
		ResetInvite           bool
	}
	if !decode(w, r, &input) {
		return
	}
	tx, err := s.db.Begin()
	if err != nil {
		dbFailure(w, err)
		return
	}
	defer tx.Rollback()
	if input.NewPassword != "" {
		var hash []byte
		err = tx.QueryRow("SELECT password FROM users WHERE id=?", u.ID).Scan(&hash)
		if err != nil || bcrypt.CompareHashAndPassword(hash, []byte(input.Password)) != nil {
			fail(w, 400, "当前密码错误")
			return
		}
		if len(input.NewPassword) < 10 || len(input.NewPassword) > 72 {
			fail(w, 400, "密码须为 10–72 字节")
			return
		}
		hash, err = bcrypt.GenerateFromPassword([]byte(input.NewPassword), bcrypt.DefaultCost)
		if err == nil {
			err = saveUserPassword(tx, u.ID, hash)
		}
	}
	if err == nil && input.AutoRenew != nil {
		_, err = tx.Exec("UPDATE users SET auto_renew=? WHERE id=?", *input.AutoRenew, u.ID)
	}
	if err == nil && input.ResetInvite {
		_, err = tx.Exec("UPDATE users SET invite=? WHERE id=?", token()[:16], u.ID)
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

func (s *Server) site(w http.ResponseWriter, r *http.Request) {
	available := []string{}
	fees := make(map[string]int, len(gatewayKinds))
	options := []channelOption{}
	for _, kind := range gatewayKinds {
		channel, _ := s.paymentChannel(kind)
		if channel.Enabled && channel.ready(s.publicURL) {
			available = append(available, kind)
			fees[kind] = channel.Fee
			options = append(options, channelOption{ID: kind, Kind: kind, Fee: channel.Fee})
		}
	}
	if channels, err := s.activePaymentChannels(); err == nil {
		for _, channel := range channels {
			if channel.Enabled && channel.ready(s.publicURL) {
				options = append(options, channelOption{ID: channel.ID, Kind: channel.Kind, Name: channel.Name, Fee: channel.Fee})
			}
		}
	}
	homeLinks, _ := parseHomeLinks(s.setting("homeLinks", "[]"))
	registration, err := readRegistrationVerification(s.db)
	if err != nil {
		dbFailure(w, err)
		return
	}
	var turnstileSiteKey string
	if registration.mode != "closed" && registration.kind == verificationTurnstile {
		turnstileSiteKey = registration.siteKey
	}
	respond(w, 200, map[string]any{
		"name": s.setting("name", "HopX"), "announcement": s.setting("announcement", ""), "homeLinks": homeLinks,
		"registration": registration.mode, "registrationVerification": registration.kind,
		"registrationChallenge": strconv.FormatBool(registration.kind == verificationArithmetic), "registrationTurnstileSiteKey": turnstileSiteKey,
		"personalTunnels": s.setting("personalTunnels", "false"), "epay": strconv.FormatBool(slices.Contains(available, "epay")),
		"paymentGateways": strings.Join(available, ","), "paymentFees": fees, "paymentChannels": options, "minRecharge": s.setting("minRecharge", "100"), "version": s.version,
		"lookingGlass":      s.setting("lookingGlass", "false"),
		"ruleProbeInterval": s.setting("ruleProbeInterval", "300"),
		"showShop":          s.setting("showShop", "true"), "showOrders": s.setting("showOrders", "true"),
		"showNodeStatus": s.setting("showNodeStatus", "true"), "invitesEnabled": s.setting("invitesEnabled", "true"),
	})
}

func (s *Server) Handler() http.Handler {
	m := http.NewServeMux()
	user := func(pattern string, h userHandler) { m.Handle(pattern, s.authorized(false, h)) }
	admin := func(pattern string, h userHandler) { m.Handle(pattern, s.authorized(true, h)) }
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if err := s.db.PingContext(r.Context()); err != nil {
			fail(w, 503, "database unavailable")
			return
		}
		respond(w, 200, map[string]bool{"ok": true})
	})
	m.HandleFunc("GET /api/site", s.site)
	m.HandleFunc("POST /api/login", s.login)
	m.HandleFunc("POST /api/register", s.register)
	m.HandleFunc("GET /api/register/challenge", s.makeChallenge)
	m.HandleFunc("POST /api/node/register", s.registerNode)
	m.HandleFunc("POST /api/node/sync", s.syncNode)
	m.HandleFunc("POST /api/payment/webhook", s.payment)
	m.HandleFunc("POST /api/telegram/webhook", s.telegramWebhook)
	user("GET /api/telegram", s.telegramSettings)
	user("POST /api/telegram", s.telegramSettings)
	user("PATCH /api/telegram", s.telegramSettings)
	m.HandleFunc("GET /api/payment/epay", s.epayNotify)
	m.HandleFunc("POST /api/payment/epay", s.epayNotify)
	m.HandleFunc("POST /api/payment/{gateway}", s.gatewayCallback)
	m.HandleFunc("GET /api/payment/channels/{channel}", s.paymentChannelCallback)
	m.HandleFunc("POST /api/payment/channels/{channel}", s.paymentChannelCallback)
	user("POST /api/payment/checkout", s.epayCheckout)
	user("POST /api/orders/{id}/checkout", s.resumeCheckout)
	admin("POST /api/admin/orders/{id}/settle", s.manualSettle)
	admin("POST /api/admin/orders/archive", s.archiveOrders)
	user("GET /api/me", s.me)
	user("GET /api/me/service", s.userService)
	user("PATCH /api/me", s.profile)
	user("POST /api/me/renew", s.renewUser)
	user("GET /api/me/renew", s.renewUser)
	user("POST /api/me/transfer", s.walletTransfer)
	user("POST /api/me/affiliate-transfer", s.affiliateTransfer)
	user("POST /api/logout", s.logout)
	user("GET /api/groups", s.listGroups)
	user("GET /api/groups/totals", s.deviceGroupTotals)
	user("GET /api/groups/{id}/devices", s.groupDevices)
	user("GET /api/groups/{id}/configuration", s.nodeConfigSummary)
	user("GET /api/node-package/{arch}", s.nodePackage)
	user("POST /api/tunnels", s.saveGroup)
	user("PUT /api/tunnels/{id}", s.saveGroup)
	user("DELETE /api/tunnels/{id}", s.deleteGroup)
	user("POST /api/tunnels/{id}/enrollment", s.enrollment)
	user("GET /api/nodes", s.listNodes)
	user("GET /api/nodes/events", s.events)
	user("GET /api/nodes/{id}/history", s.probeHistory)
	user("POST /api/nodes/{id}/diagnose", s.probeDiagnose)
	user("POST /api/nodes/{id}/ping", s.probePing)
	user("POST /api/nodes/{id}/connectivity", s.probeConnectivity)
	user("PATCH /api/nodes/{id}", s.editNode)
	user("GET /api/rules", s.listRules)
	user("GET /api/rules/count", s.ruleCount)
	user("GET /api/rules/folders", s.ruleFolders)
	user("PUT /api/rules/folders", s.ruleFolders)
	user("GET /api/rules/statistics", s.ruleStatistics)
	user("POST /api/rules", s.saveRule)
	user("POST /api/rules/preflight", s.preflightRule)
	user("POST /api/rules/{id}/diagnose", s.diagnoseRule)
	user("GET /api/rules/{id}/diagnose/history", s.ruleProbeHistory)
	user("PUT /api/rules/{id}", s.saveRule)
	user("DELETE /api/rules/{id}", s.deleteRule)
	user("POST /api/rules/batch", s.batchRules)
	user("POST /api/rules/batch/by-port", s.updateRulesByPort)
	admin("POST /api/admin/rules/{id}/haproxy", s.haProxyConfig)
	user("GET /api/plans", s.listPlans)
	user("POST /api/plans/{id}/buy", s.buyPlan)
	user("GET /api/orders", s.listOrders)
	user("POST /api/redeem", s.redeem)
	user("GET /api/invites", s.listInvites)
	user("GET /api/notifications", s.listNotifications)
	admin("GET /api/admin/settings", s.settings)
	admin("GET /api/admin/statistics", s.adminStatistics)
	admin("GET /api/admin/payment-channels", s.paymentChannels)
	admin("POST /api/admin/payment-channels", s.paymentChannels)
	admin("PUT /api/admin/payment-channels", s.savePaymentChannels)
	admin("PUT /api/admin/payment-channels/{channel}", s.paymentChannels)
	admin("DELETE /api/admin/payment-channels/{channel}", s.paymentChannels)
	admin("PUT /api/admin/settings", s.settings)
	admin("GET /api/admin/users", s.users)
	admin("GET /api/admin/users/count", s.countUsers)
	admin("POST /api/admin/users", s.users)
	admin("PUT /api/admin/users/{id}", s.users)
	admin("PUT /api/admin/users/{id}/password", s.resetUserPassword)
	admin("DELETE /api/admin/users/{id}", s.removeUser)
	admin("PUT /api/admin/users/{id}/plan", s.assignUserPlan)
	admin("GET /api/admin/users/{id}/referral", s.userReferral)
	admin("PUT /api/admin/users/{id}/referral", s.userReferral)
	admin("POST /api/admin/users/cleanup", s.removeUnusedUsers)
	admin("POST /api/admin/rules/cleanup", s.removeInvalidRules)
	admin("GET /api/admin/user-groups", s.userGroups)
	admin("POST /api/admin/user-groups", s.userGroups)
	admin("PUT /api/admin/user-groups/{id}", s.userGroups)
	admin("POST /api/admin/user-groups/reorder", s.reorderUserGroups)
	admin("POST /api/admin/groups/reorder", s.reorderDeviceGroups)
	admin("DELETE /api/admin/user-groups/{id}", s.userGroups)
	admin("POST /api/admin/groups", s.saveGroup)
	admin("POST /api/admin/groups/clear-traffic", s.clearGroupTraffic)
	admin("GET /api/admin/groups/folders", s.deviceFolders)
	admin("PUT /api/admin/groups/folders", s.deviceFolders)
	admin("PUT /api/admin/groups/{id}", s.saveGroup)
	admin("DELETE /api/admin/groups/{id}", s.deleteGroup)
	admin("POST /api/admin/groups/{id}/enrollment", s.enrollment)
	user("POST /api/groups/{id}/operations", s.groupOperations)
	admin("GET /api/admin/groups/{id}/configuration", s.nodeConfigSummary)
	user("DELETE /api/nodes/{id}", s.deleteNode)
	admin("DELETE /api/admin/nodes/{id}", s.deleteNode)
	admin("GET /api/admin/node-rollout", s.nodeRolloutStatus)
	admin("POST /api/admin/node-rollout/resume", s.resumeNodeRollout)
	admin("POST /api/admin/plans", s.savePlan)
	admin("PUT /api/admin/plans/{id}", s.savePlan)
	admin("DELETE /api/admin/plans/{id}", s.archivePlan)
	admin("POST /api/admin/plans/{id}/push", s.pushPlan)
	admin("POST /api/admin/plans/reorder", s.reorderPlans)
	admin("GET /api/admin/redeem", s.redeemAdmin)
	admin("POST /api/admin/redeem", s.redeemAdmin)
	admin("POST /api/admin/redeem/batch", s.batchRedeem)
	user("POST /api/redeem/preview", s.previewRedeem)
	admin("DELETE /api/admin/redeem/{code}", s.redeemAdmin)
	admin("POST /api/admin/credit", s.credit)
	admin("POST /api/admin/accounting/preview", s.previewAccounting)
	admin("POST /api/admin/affiliate/credit", s.creditAffiliate)
	admin("POST /api/admin/notifications", s.createNotification)
	admin("GET /api/admin/notifications/offline", s.offlineNotifications)
	admin("PUT /api/admin/notifications/offline", s.offlineNotifications)
	if s.releaseDir != "" {
		m.HandleFunc("GET /releases/{file...}", s.releaseFile)
	}
	if s.ui != nil {
		pages := http.FileServerFS(s.ui)
		m.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				fail(w, 404, "接口不存在")
				return
			}
			if r.URL.Path != "/" {
				if _, err := fs.Stat(s.ui, strings.TrimPrefix(r.URL.Path, "/")); err != nil {
					if strings.HasPrefix(r.URL.Path, "/assets/") {
						http.NotFound(w, r)
						return
					}
					copy := r.Clone(r.Context())
					copy.URL.Path = "/"
					r = copy
				}
			}
			if r.URL.Path == "/" {
				w.Header().Set("Cache-Control", "no-cache")
			} else if strings.HasPrefix(r.URL.Path, "/assets/") {
				w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			}
			pages.ServeHTTP(w, r)
		})
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' https://challenges.cloudflare.com; frame-src https://challenges.cloudflare.com; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
		if r.TLS != nil || strings.HasPrefix(s.publicURL, "https://") {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Cache-Control", "no-store")
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && !s.browserWriteAllowed(r) {
			_, pattern := m.Handler(r)
			switch pattern {
			case "POST /api/payment/webhook", "POST /api/payment/epay", "POST /api/payment/{gateway}", "POST /api/payment/channels/{channel}":
				// Payment providers authenticate their callbacks inside the matched handler.
			default:
				fail(w, 403, "跨站请求已拒绝")
				return
			}
		}
		m.ServeHTTP(w, r)
		s.invalidateReverseRoutes(r.Pattern)
		s.invalidateNodeStatus(r.Pattern)
	})
}

func (s *Server) browserWriteAllowed(r *http.Request) bool {
	site := r.Header.Get("Sec-Fetch-Site")
	if site == "cross-site" {
		return false
	}
	header := r.Header.Get("Origin")
	if header == "" {
		return true
	}
	origin := browserOrigin(header)
	if origin == nil {
		return false
	}
	// Fetch Metadata describes the browser-facing origin even when a TLS
	// reverse proxy changes the scheme or Host before forwarding the request.
	if site == "same-origin" {
		return true
	}
	if strings.EqualFold(header, strings.TrimRight(s.publicURL, "/")) {
		return true
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return origin.Scheme == scheme && strings.EqualFold(origin.Host, r.Host)
}

func browserOrigin(value string) *url.URL {
	origin, err := url.Parse(value)
	if err != nil || (origin.Scheme != "http" && origin.Scheme != "https") ||
		origin.User != nil || origin.Hostname() == "" || origin.Path != "" ||
		origin.ForceQuery || origin.RawQuery != "" || strings.Contains(value, "#") {
		return nil
	}
	return origin
}

func (s *Server) Maintenance(ctx context.Context) {
	go s.monitorRuleLinks(ctx)
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			if _, err := s.db.ExecContext(ctx, "DELETE FROM sessions WHERE expires<=unixepoch(); DELETE FROM invitations WHERE expires<=unixepoch(); DELETE FROM probe_samples WHERE bucket<unixepoch()-86400*7; DELETE FROM telegram_tokens WHERE expiry<=unixepoch(); DELETE FROM notifications WHERE topic<>'' AND created<unixepoch()-86400*7; DELETE FROM daily_user_traffic WHERE day<unixepoch()/86400-7 OR day BETWEEN 1000000 AND ((unixepoch()+28800)/86400-7)*86400-28801; DELETE FROM daily_group_traffic WHERE day<unixepoch()/86400-7 OR day BETWEEN 1000000 AND ((unixepoch()+28800)/86400-7)*86400-28801"); err != nil {
				slog.Error("maintenance", "error", err)
			}
			s.renew()
			s.queueTelegramDeviceStatus()
			s.pruneDeviceSessions()
			if _, err := s.db.ExecContext(ctx, "DELETE FROM rule_probe_samples WHERE sampled < unixepoch()-604800"); err != nil && ctx.Err() == nil {
				slog.Error("expire rule probe history", "error", err)
			}
			s.deliverTelegram(ctx)
		}
	}
}

func (s *Server) Backup(target string) error {
	if _, err := os.Stat(target); err == nil {
		return errors.New("backup destination already exists")
	}
	_, err := s.db.Exec("VACUUM INTO ?", target)
	return err
}
