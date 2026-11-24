package panel

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestRegistrationVerificationSettings(t *testing.T) {
	panel, err := Open(Options{Database: filepath.Join(t.TempDir(), "registration.db"), AdminPassword: "test-password-123"})
	if err != nil {
		t.Fatal(err)
	}
	defer panel.Close()
	if _, err = panel.db.Exec(`INSERT INTO settings(key, value) VALUES ('registration', 'open'), ('registrationChallenge', 'true')`); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(panel.Handler())
	defer server.Close()
	jar, _ := cookiejar.New(nil)
	admin := &http.Client{Jar: jar}
	guest := server.Client()
	url := server.URL + "/api"
	testRequest(t, admin, "POST", url+"/login", nil, map[string]string{"name": "admin", "password": "test-password-123"}, 200, nil)
	var settings map[string]string
	testRequest(t, admin, "GET", url+"/admin/settings", nil, nil, 200, &settings)
	if settings["registrationVerification"] != verificationArithmetic {
		t.Fatal("the existing arithmetic setting was not carried forward")
	}
	var question struct {
		ID          string
		Left, Right int
	}
	testRequest(t, guest, "GET", url+"/register/challenge", nil, nil, 200, &question)
	testRequest(t, guest, "POST", url+"/register", nil, map[string]any{
		"name": "arithmetic-user", "password": "test-password-123", "challengeId": question.ID, "answer": question.Left + question.Right,
	}, 201, nil)
	testRequest(t, admin, "PUT", url+"/admin/settings", nil, map[string]string{
		"registrationVerification": verificationTurnstile,
	}, 400, nil)
	const siteKey, secret = "site-key-fixture", "private-secret-fixture"
	testRequest(t, admin, "PUT", url+"/admin/settings", nil, map[string]string{
		"registrationVerification": verificationTurnstile, "registrationTurnstileSiteKey": siteKey,
		"registrationTurnstileSecret": secret,
	}, 204, nil)
	testRequest(t, admin, "PUT", url+"/admin/settings", nil, map[string]string{"announcement": "配置保留"}, 204, nil)
	settings = nil
	testRequest(t, admin, "GET", url+"/admin/settings", nil, nil, 200, &settings)
	if settings["registrationTurnstileSecret"] != "" || settings["registrationTurnstileSecretConfigured"] != "true" {
		t.Fatal("admin settings exposed the stored secret or lost its configuration status")
	}
	var site json.RawMessage
	testRequest(t, guest, "GET", url+"/site", nil, nil, 200, &site)
	if strings.Contains(string(site), secret) || !strings.Contains(string(site), siteKey) {
		t.Fatal("public site should return just the site key")
	}
	testRequest(t, guest, "GET", url+"/register/challenge", nil, nil, 404, nil)
	testRequest(t, guest, "POST", url+"/register", nil, map[string]string{
		"name": "unverified-user", "password": "test-password-123",
	}, 400, nil)
	testRequest(t, admin, "PUT", url+"/admin/settings", nil, map[string]string{"registrationVerification": verificationOff}, 204, nil)
	testRequest(t, guest, "POST", url+"/register", nil, map[string]string{
		"name": "open-user", "password": "test-password-123",
	}, 201, nil)
}

type siteverifyTransport func(*http.Request) (*http.Response, error)

func (f siteverifyTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestTurnstileSiteverify(t *testing.T) {
	for _, tc := range []struct {
		name, response string
		status         int
		valid, wantErr bool
	}{
		{"valid", `{"success":true,"action":"register"}`, 200, true, false},
		{"wrong action", `{"success":true,"action":"login"}`, 200, false, false},
		{"duplicate", `{"success":false,"error-codes":["timeout-or-duplicate"]}`, 200, false, false},
		{"unavailable", `{}`, 503, false, true},
		{"invalid response", `{"success":`, 200, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &http.Client{Transport: siteverifyTransport(func(r *http.Request) (*http.Response, error) {
				if r.URL.String() != turnstileEndpoint || r.Method != http.MethodPost ||
					r.ParseForm() != nil || r.Form.Get("secret") != "secret-fixture" || r.Form.Get("response") != "test-token" {
					t.Fatal("invalid Siteverify request")
				}
				return &http.Response{StatusCode: tc.status, Body: io.NopCloser(strings.NewReader(tc.response))}, nil
			})}
			valid, err := verifyTurnstile(context.Background(), client, "secret-fixture", "test-token")
			if valid != tc.valid || (err != nil) != tc.wantErr {
				t.Fatalf("verifyTurnstile = %v, %v", valid, err)
			}
		})
	}
}
