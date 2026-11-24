package panel

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	verificationOff        = "off"
	verificationArithmetic = "arithmetic"
	verificationTurnstile  = "turnstile"
	turnstileAction        = "register"
	turnstileEndpoint      = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
)

type registrationVerification struct {
	mode, kind, siteKey, secret string
}

type settingsReader interface {
	QueryRow(string, ...any) *sql.Row
}

func readRegistrationVerification(db settingsReader) (registrationVerification, error) {
	var config registrationVerification
	err := db.QueryRow(`SELECT
		coalesce((SELECT value FROM settings WHERE key='registration'),'closed'),
		coalesce((SELECT value FROM settings WHERE key='registrationVerification'),
			CASE WHEN (SELECT value FROM settings WHERE key='registrationChallenge')='true' THEN 'arithmetic' ELSE 'off' END),
		coalesce((SELECT value FROM settings WHERE key='registrationTurnstileSiteKey'),''),
		coalesce((SELECT value FROM settings WHERE key='registrationTurnstileSecret'),'')`).
		Scan(&config.mode, &config.kind, &config.siteKey, &config.secret)
	return config, err
}

func validTurnstileKey(key string) bool {
	return len(key) > 0 && len(key) <= 256 && strings.IndexFunc(key, func(ch rune) bool {
		return !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '_')
	}) == -1
}

var turnstileClient = &http.Client{
	Timeout: 5 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

var turnstileSlots = make(chan struct{}, 8)

func verifyTurnstile(ctx context.Context, client *http.Client, secret, token string) (bool, error) {
	if len(token) == 0 || len(token) > 2048 {
		return false, nil
	}
	if !validTurnstileKey(secret) {
		return false, errors.New("Turnstile secret unavailable")
	}
	select {
	case turnstileSlots <- struct{}{}:
		defer func() { <-turnstileSlots }()
	default:
		return false, errors.New("Turnstile verification busy")
	}
	body := url.Values{"secret": {secret}, "response": {token}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, turnstileEndpoint, strings.NewReader(body))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, errors.New("Turnstile service unavailable")
	}
	var result struct {
		Success bool   `json:"success"`
		Action  string `json:"action"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<10)).Decode(&result); err != nil {
		return false, err
	}
	return result.Success && result.Action == turnstileAction, nil
}
