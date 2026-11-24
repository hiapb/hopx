package panel

import (
	"bytes"
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var botName = regexp.MustCompile(`^[A-Za-z0-9_]{5,32}$`)
var botToken = regexp.MustCompile(`^[0-9]+:[A-Za-z0-9_-]{20,80}$`)
var botSecret = regexp.MustCompile(`^[a-zA-Z0-9_-]{20,128}$`)

type offlineNotificationSettings struct {
	Default int64            `json:"default"`
	Groups  map[string]int64 `json:"groups"`
}

func (config offlineNotificationSettings) offlineThreshold(groupID string, offlineSeconds int) int64 {
	grace, custom := config.Groups[groupID]
	if !custom {
		grace = config.Default
	}
	return int64(offlineSeconds) + grace
}

func (s *Server) offlineNotificationConfig() offlineNotificationSettings {
	config := offlineNotificationSettings{Groups: map[string]int64{}}
	_ = json.Unmarshal([]byte(s.setting("offlineNotifications", "{}")), &config)
	return config
}

func (s *Server) offlineNotifications(w http.ResponseWriter, r *http.Request, _ User) {
	if r.Method == http.MethodGet {
		respond(w, 200, s.offlineNotificationConfig())
		return
	}
	var config offlineNotificationSettings
	if !decode(w, r, &config) {
		return
	}
	if config.Default < 0 || config.Default > 86400*30 || len(config.Groups) > 10000 {
		fail(w, 400, "离线通知宽限期须为 0 至 2592000 秒")
		return
	}
	for id, seconds := range config.Groups {
		group, err := strconv.ParseInt(id, 10, 64)
		if err != nil || group < 1 || seconds < 0 || seconds > 86400*30 {
			fail(w, 400, "设备组或宽限期无效")
			return
		}
	}
	raw, _ := json.Marshal(config)
	if _, err := s.db.ExecContext(r.Context(), "INSERT INTO settings(key,value) VALUES('offlineNotifications',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", string(raw)); err != nil {
		dbFailure(w, err)
		return
	}
	w.WriteHeader(204)
}

func (s *Server) telegramSettings(w http.ResponseWriter, r *http.Request, u User) {
	switch r.Method {
	case "GET":
		var enabled, income, updown bool
		e := s.db.QueryRow("SELECT enabled,income,updown FROM telegram_links WHERE user_id=?", u.ID).Scan(&enabled, &income, &updown)
		if e != nil && e != sql.ErrNoRows {
			dbFailure(w, e)
			return
		}
		respond(w, 200, map[string]bool{"linked": e == nil, "enabled": enabled, "income": income, "updown": updown, "available": botName.MatchString(s.setting("telegramUsername", "")) && botToken.MatchString(s.setting("telegramToken", "")) && botSecret.MatchString(s.setting("telegramWebhookSecret", ""))})
	case "POST":
		user := s.setting("telegramUsername", "")
		if !botName.MatchString(user) || !botToken.MatchString(s.setting("telegramToken", "")) || !botSecret.MatchString(s.setting("telegramWebhookSecret", "")) {
			fail(w, 503, "Telegram 机器人未配置")
			return
		}
		key := token()
		if _, e := s.db.Exec("INSERT INTO telegram_tokens(token,user_id,expiry) VALUES(?,?,unixepoch()+600)", digest(key), u.ID); e != nil {
			dbFailure(w, e)
			return
		}
		respond(w, 201, map[string]string{"url": "https://t.me/" + user + "?start=" + url.QueryEscape("bind-"+key)})
	case "PATCH":
		var in struct {
			Enabled *bool
			Income  *bool
			Updown  *bool
			Unlink  bool
		}
		if !decode(w, r, &in) {
			return
		}
		var e error
		if in.Unlink {
			tx, err := s.db.Begin()
			if err != nil {
				dbFailure(w, err)
				return
			}
			defer tx.Rollback()
			if _, e = tx.Exec("DELETE FROM telegram_links WHERE user_id=?", u.ID); e == nil {
				_, e = tx.Exec("DELETE FROM telegram_tokens WHERE user_id=?", u.ID)
			}
			if e == nil {
				_, e = tx.Exec("DELETE FROM notification_deliveries WHERE user_id=? AND state='queued'", u.ID)
			}
			if e == nil {
				e = tx.Commit()
			}
		} else {
			_, e = s.db.Exec("UPDATE telegram_links SET enabled=coalesce(?,enabled),income=coalesce(?,income),updown=coalesce(?,updown) WHERE user_id=?", in.Enabled, in.Income, in.Updown, u.ID)
		}
		if e != nil {
			dbFailure(w, e)
			return
		}
		w.WriteHeader(204)
	}
}

func (s *Server) telegramWebhook(w http.ResponseWriter, r *http.Request) {
	secret := s.setting("telegramWebhookSecret", "")
	if !botSecret.MatchString(secret) || subtle.ConstantTimeCompare([]byte(secret), []byte(r.Header.Get("X-Telegram-Bot-Api-Secret-Token"))) != 1 {
		fail(w, 401, "invalid Telegram webhook")
		return
	}
	var in struct {
		Message *struct {
			Text string
			Chat struct {
				ID   int64
				Type string
			}
		}
	}
	if !decode(w, r, &in) {
		return
	}
	if in.Message == nil || in.Message.Chat.Type != "private" || in.Message.Chat.ID <= 0 {
		respond(w, 200, map[string]bool{"ok": true})
		return
	}
	value := strings.TrimSpace(in.Message.Text)
	key, ok := strings.CutPrefix(value, "/start bind-")
	if !ok || len(key) != 26 {
		respond(w, 200, map[string]bool{"ok": true})
		return
	}
	tx, e := s.db.Begin()
	if e != nil {
		dbFailure(w, e)
		return
	}
	defer tx.Rollback()
	var userID int64
	e = tx.QueryRow("DELETE FROM telegram_tokens WHERE token=? AND expiry>unixepoch() RETURNING user_id", digest(key)).Scan(&userID)
	if e == sql.ErrNoRows {
		respond(w, 200, map[string]bool{"ok": true})
		return
	}
	if e != nil {
		dbFailure(w, e)
		return
	}
	var another bool
	e = tx.QueryRow("SELECT EXISTS(SELECT 1 FROM telegram_links WHERE chat_id=? AND user_id<>?)", in.Message.Chat.ID, userID).Scan(&another)
	if e != nil {
		dbFailure(w, e)
		return
	}
	if another {
		respond(w, 200, map[string]bool{"ok": true})
		return
	}
	_, e = tx.Exec("INSERT INTO telegram_links(user_id,chat_id,enabled) VALUES(?,?,1) ON CONFLICT(user_id) DO UPDATE SET chat_id=excluded.chat_id,enabled=1", userID, in.Message.Chat.ID)
	if e == nil {
		e = tx.Commit()
	}
	if e != nil {
		dbFailure(w, e)
		return
	}
	respond(w, 200, map[string]bool{"ok": true})
}

func queueTelegramEvent(tx *sql.Tx, topic, title, body string, userID int64) error {
	var selection string
	switch topic {
	case "income":
		selection = "l.income=1 AND u.id=?"
	case "updown":
		selection = "l.updown=1 AND (u.admin=1 OR u.id=?)"
	default:
		return errors.New("invalid Telegram notification topic")
	}
	recipients := " FROM telegram_links l JOIN users u ON u.id=l.user_id WHERE l.enabled=1 AND u.banned=0 AND " + selection
	var id int64
	err := tx.QueryRow("INSERT INTO notifications(topic,title,body) SELECT ?,?,? WHERE EXISTS(SELECT 1"+recipients+") RETURNING id", topic, title, body, userID).Scan(&id)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	_, err = tx.Exec("INSERT INTO notification_deliveries(notification_id,user_id) SELECT ?,u.id"+recipients, id, userID)
	return err
}

func (s *Server) queueTelegramDeviceStatus() {
	if !botToken.MatchString(s.setting("telegramToken", "")) {
		s.telegramNodeStatus = nil
		return
	}
	devices, err := s.deviceSnapshot(false)
	if err != nil {
		slog.Error("Telegram device snapshot", "error", err)
		return
	}
	config := s.offlineNotificationConfig()
	groups, err := s.groups()
	if err != nil {
		slog.Error("Telegram device groups", "error", err)
		return
	}
	offlineAfter := make(map[int64]time.Duration, len(groups))
	for _, group := range groups {
		offlineAfter[group.ID] = time.Duration(config.offlineThreshold(strconv.FormatInt(group.ID, 10), group.OfflineSeconds)) * time.Second
	}
	now := time.Now()
	next := make(map[int64]bool, len(devices))
	for _, device := range devices {
		previous, known := s.telegramNodeStatus[device.ID]
		online := device.Online
		if known && previous && !online && !device.LastSeen.IsZero() && now.Sub(device.LastSeen) < offlineAfter[device.GroupID] {
			online = true
		}
		next[device.ID] = online
		if !known || previous == online {
			continue
		}
		status := "离线"
		if online {
			status = "已恢复"
		}
		err := func() error {
			tx, err := s.db.Begin()
			if err != nil {
				return err
			}
			defer tx.Rollback()
			var owner int64
			if err := tx.QueryRow("SELECT owner FROM groups WHERE id=?", device.GroupID).Scan(&owner); err != nil {
				return err
			}
			body := fmt.Sprintf("%s（设备 #%d）%s。", device.Name, device.ID, status)
			if err := queueTelegramEvent(tx, "updown", "设备"+status, body, owner); err != nil {
				return err
			}
			return tx.Commit()
		}()
		if err != nil {
			slog.Error("Telegram device notification", "device", device.ID, "error", err)
			next[device.ID] = previous
		}
	}
	s.telegramNodeStatus = next
}

func (s *Server) deliverTelegram(ctx context.Context) {
	key := s.setting("telegramToken", "")
	if !botToken.MatchString(key) {
		return
	}
	rows, e := s.db.QueryContext(ctx, "SELECT d.notification_id,d.user_id,l.chat_id,n.title,n.body,d.tries FROM notification_deliveries d JOIN telegram_links l ON l.user_id=d.user_id AND l.enabled=1 JOIN notifications n ON n.id=d.notification_id WHERE d.state='queued' AND d.next_try<=unixepoch() AND (n.topic='' OR (n.topic='income' AND l.income=1) OR (n.topic='updown' AND l.updown=1)) ORDER BY d.notification_id,d.user_id LIMIT 15")
	if e != nil {
		return
	}
	type message struct {
		notification, user, chat int64
		title, body              string
		tries                    int
	}
	var queue []message
	for rows.Next() {
		var m message
		if e = rows.Scan(&m.notification, &m.user, &m.chat, &m.title, &m.body, &m.tries); e != nil {
			break
		}
		queue = append(queue, m)
	}
	rows.Close()
	client := &http.Client{Timeout: 4 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for _, m := range queue {
		if ctx.Err() != nil {
			return
		}
		msg := []rune(m.title + "\n\n" + m.body)
		data, _ := json.Marshal(map[string]any{"chat_id": m.chat, "text": string(msg[:min(len(msg), 4096)])})
		req, e := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.telegram.org/bot"+key+"/sendMessage", bytes.NewReader(data))
		if e == nil {
			req.Header.Set("Content-Type", "application/json")
			response, err := client.Do(req)
			e = err
			if e == nil {
				response.Body.Close()
				if response.StatusCode != 200 {
					e = errors.New("Telegram delivery unsuccessful")
				}
			}
		}
		state := "sent"
		if e != nil {
			state = "queued"
			if m.tries >= 4 {
				state = "failed"
			}
		}
		_, _ = s.db.ExecContext(ctx, "UPDATE notification_deliveries SET state=?,tries=tries+1,next_try=unixepoch()+? WHERE notification_id=? AND user_id=?", state, 60<<m.tries, m.notification, m.user)
	}
}
