package panel

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	"hopx/internal/wire"
)

func testRequest(t *testing.T, client *http.Client, method, url string, headers map[string]string, payload any, want int, response any) {
	t.Helper()
	var raw []byte
	if payload != nil {
		var err error
		raw, err = json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
	}
	req, err := http.NewRequest(method, url, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != want {
		var body any
		_ = json.NewDecoder(resp.Body).Decode(&body)
		t.Fatalf("%s %s -> %d (want %d): %v", method, url, resp.StatusCode, want, body)
	}
	if response != nil {
		if err = json.NewDecoder(resp.Body).Decode(response); err != nil {
			t.Fatal(err)
		}
	}
}

func subscribeTestAdmin(t *testing.T, client *http.Client, base string) {
	t.Helper()
	var plan Plan
	testRequest(t, client, "POST", base+"/admin/plans", nil, Plan{Name: "Test plan", Duration: 30, Enabled: true, UnlimitedTraffic: true}, 200, &plan)
	testRequest(t, client, "POST", fmt.Sprintf("%s/plans/%d/buy", base, plan.ID), nil, nil, 204, nil)
}

func giveFixtureUsersActivePlan(t *testing.T, panel *Server) {
	t.Helper()
	_, err := panel.db.Exec(`
		INSERT INTO plans(id,name,description,price,duration,quota,unlimited_traffic,rules,group_id) VALUES (1,'Fixture','',0,1,0,1,0,0);
		UPDATE users SET plan_id=1,expires=unixepoch()+86400,unlimited_traffic=1;
	`)
	if err != nil {
		t.Fatal(err)
	}
}

func TestBrowserLoginThroughReverseProxy(t *testing.T) {
	panel, err := Open(Options{
		Database:      filepath.Join(t.TempDir(), "proxy.db"),
		AdminPassword: "test-password-123",
		PublicURL:     "http://127.0.0.1:38571",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer panel.Close()
	handler := panel.Handler()
	for _, tc := range []struct {
		name, origin, fetchSite string
		status                  int
		secure                  bool
	}{
		{"HTTPS proxy with rewritten Host", "https://panel.example.com", "same-origin", 200, true},
		{"cross-site request", "https://other.example.com", "cross-site", 403, false},
		{"same-site sibling", "https://other.example.com", "same-site", 403, false},
		{"opaque origin", "null", "same-origin", 403, false},
		{"local HTTP access", "http://127.0.0.1:38571", "", 200, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:38571/api/login",
				bytes.NewBufferString(`{"name":"admin","password":"test-password-123"}`))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Origin", tc.origin)
			req.Header.Set("Sec-Fetch-Site", tc.fetchSite)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tc.status {
				t.Fatalf("login returned %d, want %d: %s", rec.Code, tc.status, rec.Body)
			}
			cookies := rec.Result().Cookies()
			if tc.status == 200 {
				if len(cookies) != 1 || cookies[0].Secure != tc.secure ||
					!cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
					t.Fatal("unexpected login cookie attributes")
				}
			} else if len(cookies) != 0 {
				t.Fatal("rejected login issued a cookie")
			}
		})
	}
}

func TestNodeEnrollmentAndIdempotentAccounting(t *testing.T) {
	panel, err := Open(Options{Database: filepath.Join(t.TempDir(), "test.db"), AdminPassword: "test-password-123", PaymentSecret: "test-secret"})
	if err != nil {
		t.Fatal(err)
	}
	defer panel.Close()
	s := httptest.NewServer(panel.Handler())
	defer s.Close()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	url := s.URL + "/api"
	testRequest(t, client, "POST", url+"/login", nil, map[string]string{"name": "admin", "password": "test-password-123"}, 200, nil)
	subscribeTestAdmin(t, client, url)
	var group wire.DeviceGroup
	testRequest(t, client, "POST", url+"/admin/groups", nil, wire.DeviceGroup{Name: "entry", Kind: "entry", Ratio: 2000}, 200, &group)
	var invite map[string]any
	enrollmentURL := fmt.Sprintf("%s/admin/groups/%d/enrollment", url, group.ID)
	testRequest(t, client, "POST", enrollmentURL, nil, nil, 201, &invite)
	var identity wire.Identity
	registration := wire.Registration{Name: "test node"}
	enrollment := map[string]string{"Authorization": "Bearer " + invite["token"].(string)}
	testRequest(t, client, "POST", url+"/node/register", enrollment, registration, 201, &identity)
	var second wire.Identity
	testRequest(t, client, "POST", url+"/node/register", enrollment, wire.Registration{Name: "second node"}, 201, &second)
	if identity.ID == second.ID || identity.Token == second.Token {
		t.Fatal("machines received the same node identity")
	}
	var reopened map[string]any
	testRequest(t, client, "POST", enrollmentURL, nil, nil, 201, &reopened)
	if invite["token"] != reopened["token"] {
		t.Fatal("opening the enrollment dialog changed the group credential")
	}
	proxied := map[string]string{"Origin": "https://panel.example.com", "Sec-Fetch-Site": "same-origin"}
	testRequest(t, client, "POST", enrollmentURL, proxied, nil, 201, &reopened)
	if reopened["panel"] != proxied["Origin"] || reopened["token"] != invite["token"] {
		t.Fatal("enrollment did not use the browser-facing origin through the reverse proxy")
	}
	operation := fmt.Sprintf("%s/groups/%d/operations", url, group.ID)
	testRequest(t, client, "POST", operation, nil, map[string]string{"action": "revoke-enrollments"}, 204, nil)
	testRequest(t, client, "POST", url+"/node/register", enrollment, registration, 401, nil)
	testRequest(t, client, "POST", enrollmentURL, nil, nil, 201, &reopened)
	if invite["token"] == reopened["token"] {
		t.Fatal("revoked credential was reused")
	}
	var rule wire.Rule
	testRequest(t, client, "POST", url+"/rules", nil, wire.Rule{Name: "tcp", Entry: group.ID, Targets: []string{"127.0.0.1:12345"}, Enabled: true}, 200, &rule)
	header := map[string]string{"Authorization": "Bearer " + identity.Token, "X-Node-ID": fmt.Sprint(identity.ID)}
	var sync wire.Sync
	ping := wire.Heartbeat{Version: "test", OS: "linux", Arch: "arm64"}
	testRequest(t, client, "POST", url+"/node/sync", header, ping, 200, &sync)
	if sync.Config == nil || len(sync.Config.Rules) != 1 || sync.Config.Rules[0].ID != rule.ID {
		t.Fatalf("config: %+v", sync.Config)
	}
	secondHeader := map[string]string{"Authorization": "Bearer " + second.Token, "X-Node-ID": fmt.Sprint(second.ID)}
	var secondSync wire.Sync
	testRequest(t, client, "POST", url+"/node/sync", secondHeader, ping, 200, &secondSync)
	if secondSync.Config == nil || secondSync.Config.Revision != sync.Config.Revision {
		t.Fatalf("second device did not receive the group configuration: %+v", secondSync)
	}
	var nodes []wire.Device
	testRequest(t, client, "GET", url+"/nodes", nil, nil, 200, &nodes)
	if len(nodes) != 2 || nodes[0].ID != identity.ID || nodes[1].ID != second.ID || !nodes[0].Online || !nodes[1].Online {
		t.Fatalf("node status did not list both machines online: %+v", nodes)
	}
	var diagnostics struct {
		Total int
		Nodes []entryDiagnostic
	}
	testRequest(t, client, "POST", fmt.Sprintf("%s/rules/%d/diagnose", url, rule.ID), nil, nil, 200, &diagnostics)
	if diagnostics.Total != 2 || len(diagnostics.Nodes) != 2 || diagnostics.Nodes[0].Name != registration.Name || diagnostics.Nodes[1].Name != "second node" {
		t.Fatalf("rule diagnostics did not list both machines: %+v", diagnostics)
	}
	ping.Revision = sync.Config.Revision
	ping.Report = &wire.Report{ID: "one", Traffic: []wire.Traffic{{RuleID: rule.ID, In: 10, Out: 5, Ratio: 2000}}}
	for range 2 {
		sync = wire.Sync{}
		testRequest(t, client, "POST", url+"/node/sync", header, ping, 200, &sync)
		if sync.Config != nil || sync.Ack != "one" {
			t.Fatalf("sync: %+v", sync)
		}
	}
	var me User
	testRequest(t, client, "GET", url+"/me", nil, nil, 200, &me)
	if me.Used != 30 {
		t.Fatalf("usage = %d", me.Used)
	}
	testRequest(t, client, "POST", url+"/admin/groups/clear-traffic", nil, map[string][]int64{"ids": {group.ID}}, 204, nil)
	testRequest(t, client, "POST", url+"/node/sync", header, ping, 200, &sync)
	var rules []ruleRow
	testRequest(t, client, "GET", url+"/rules", nil, nil, 200, &rules)
	if len(rules) != 1 || rules[0].In != 0 || rules[0].Out != 0 {
		t.Fatalf("acknowledged batch restored cleared traffic: %+v", rules)
	}
	testRequest(t, client, "GET", url+"/me", nil, nil, 200, &me)
	if me.Used != 30 {
		t.Fatalf("clearing rule statistics changed billed usage: %d", me.Used)
	}
	ping.Report = nil
	ping.AcceptDelta = true
	for _, action := range []string{"disable", "enable"} {
		testRequest(t, client, "POST", url+"/rules/batch", nil, map[string]any{"action": action, "ids": []int64{rule.ID}}, 200, nil)
		panel.configMu.Lock()
		cached := panel.configs[group.ID]
		cached.until = time.Time{}
		panel.configs[group.ID] = cached
		panel.configMu.Unlock()
		sync = wire.Sync{}
		testRequest(t, client, "POST", url+"/node/sync", header, ping, 200, &sync)
		if sync.Delta == nil || sync.Delta.Base != ping.Revision || sync.Delta.Revision == ping.Revision {
			t.Fatalf("%s returned an invalid config delta: %+v", action, sync.Delta)
		}
		if action == "disable" && (len(sync.Delta.Remove) != 1 || sync.Delta.Remove[0] != rule.ID || len(sync.Delta.Rules) != 0) {
			t.Fatalf("disabling rule did not remove it: %+v", sync.Delta)
		}
		if action == "enable" && (len(sync.Delta.Rules) != 1 || sync.Delta.Rules[0].ID != rule.ID || len(sync.Delta.Remove) != 0) {
			t.Fatalf("enabling rule did not restore it: %+v", sync.Delta)
		}
		ping.Revision = sync.Delta.Revision
	}
	callback := map[string]any{"provider": "testing", "reference": "payment-1", "userId": me.ID, "amount": 100}
	raw, _ := json.Marshal(callback)
	mac := hmac.New(sha256.New, []byte("test-secret"))
	mac.Write(raw)
	for range 2 {
		testRequest(t, client, "POST", url+"/payment/webhook", map[string]string{"X-HopX-Signature": hex.EncodeToString(mac.Sum(nil))}, callback, 200, nil)
	}
	testRequest(t, client, "GET", url+"/me", nil, nil, 200, &me)
	if me.Balance != 100 {
		t.Fatalf("balance = %d", me.Balance)
	}
	testRequest(t, client, "POST", operation, nil, map[string]string{"action": "reset-credentials"}, 204, nil)
	testRequest(t, client, "POST", url+"/node/sync", header, ping, 401, nil)
	testRequest(t, client, "POST", url+"/node/register", map[string]string{"Authorization": "Bearer " + reopened["token"].(string)}, registration, 401, nil)
}

func TestRulePortPreflightValidatesWithoutReservingPort(t *testing.T) {
	panel, err := Open(Options{Database: filepath.Join(t.TempDir(), "preflight.db"), AdminPassword: "test-password-123", PaymentSecret: "test-secret"})
	if err != nil {
		t.Fatal(err)
	}
	defer panel.Close()
	server := httptest.NewServer(panel.Handler())
	defer server.Close()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	base := server.URL + "/api"
	testRequest(t, client, "POST", base+"/login", nil, map[string]string{"name": "admin", "password": "test-password-123"}, 200, nil)
	subscribeTestAdmin(t, client, base)
	var group wire.DeviceGroup
	testRequest(t, client, "POST", base+"/admin/groups", nil,
		wire.DeviceGroup{Name: "preflight entry", Kind: "entry", FirstPort: 47000, LastPort: 47010, Ratio: 1000}, 200, &group)
	payload := wire.Rule{Name: "preflight", Entry: group.ID, Port: 47001, Targets: []string{"127.0.0.1:1"}, Enabled: true, Protocol: "both"}
	for range 2 {
		var result struct {
			Port  int
			Mode  string
			Total int
			Nodes []rulePortCheck
		}
		testRequest(t, client, "POST", base+"/rules/preflight", nil, payload, 200, &result)
		if result.Port != payload.Port || result.Mode != "node" || result.Total != 0 {
			t.Fatalf("preflight result: %+v", result)
		}
	}
	var first, second wire.Rule
	testRequest(t, client, "POST", base+"/rules", nil, payload, 200, &first)
	testRequest(t, client, "POST", base+"/rules/preflight", nil, payload, 400, nil)
	testRequest(t, client, "POST", base+"/rules", nil,
		wire.Rule{Name: "occupied", Entry: group.ID, Port: first.Port, Targets: []string{"127.0.0.1:2"}, Enabled: true, Protocol: "tcp"}, 400, nil)
	payload.Port = 0
	payload.Name = "automatic"
	testRequest(t, client, "POST", base+"/rules", nil, payload, 200, &second)
	if second.Port == first.Port {
		t.Fatalf("automatic assignment reused occupied port %d", first.Port)
	}

	var enrollment struct{ Token string }
	testRequest(t, client, "POST", fmt.Sprintf("%s/admin/groups/%d/enrollment", base, group.ID), nil, nil, 201, &enrollment)
	var node wire.Identity
	testRequest(t, client, "POST", base+"/node/register", map[string]string{"Authorization": "Bearer " + enrollment.Token},
		wire.Registration{Name: "entry node"}, 201, &node)
	nodeHeaders := map[string]string{"Authorization": "Bearer " + node.Token, "X-Node-ID": fmt.Sprint(node.ID)}
	testRequest(t, client, "POST", base+"/node/sync", nodeHeaders, wire.Heartbeat{AcceptPortCheck: true}, 200, nil)

	payload.Name, payload.Port = "live check", 47009
	saveWithNode := func(occupied bool) *httptest.ResponseRecorder {
		t.Helper()
		raw, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodPost, base+"/rules", bytes.NewReader(raw))
		for _, cookie := range client.Jar.Cookies(request.URL) {
			request.AddCookie(cookie)
		}
		recorder := httptest.NewRecorder()
		done := make(chan struct{})
		go func() {
			defer close(done)
			panel.Handler().ServeHTTP(recorder, request)
		}()
		var task *wire.DiagnosticTask
		deadline := time.Now().Add(2 * time.Second)
		for task == nil && time.Now().Before(deadline) {
			task = panel.pollDiagnostic(node.ID, nil)
			if task == nil {
				time.Sleep(5 * time.Millisecond)
			}
		}
		if task == nil || task.PortCheck == nil || task.PortCheck.Port != payload.Port || task.PortCheck.Network != "both" {
			t.Fatalf("rule creation did not request TCP and UDP checks: %+v", task)
		}
		var total struct{ Total int }
		testRequest(t, client, "GET", base+"/rules/count", nil, nil, 200, &total)
		if total.Total != 2 {
			t.Fatalf("rule was already committed during the node check: %+v", total)
		}
		status := "available"
		if occupied {
			status = "occupied"
		}
		panel.pollDiagnostic(node.ID, &wire.DiagnosticResult{ID: task.ID, Bindings: []wire.PortBinding{
			{Network: "tcp", Status: "available"}, {Network: "udp", Status: status},
		}})
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("save did not finish after node check")
		}
		return recorder
	}
	if result := saveWithNode(true); result.Code != 409 || !bytes.Contains(result.Body.Bytes(), []byte("已被占用")) {
		t.Fatalf("occupied socket was accepted: %d %s", result.Code, result.Body.String())
	}
	if result := saveWithNode(false); result.Code != 200 {
		t.Fatalf("available socket was rejected: %d %s", result.Code, result.Body.String())
	}
}

func TestMigrationDryRunPreservesEmptyTarget(t *testing.T) {
	s, err := Open(Options{Database: filepath.Join(t.TempDir(), "migration.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	password, err := bcrypt.GenerateFromPassword([]byte("fixture-password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	input := snapshot{
		Format: 1, Source: "nyanpass-synthetic",
		Users:        []sourceUser{{User: User{ID: 17, Name: "fixture-admin", Admin: true, Balance: 42, Used: 100}, PasswordHash: string(password)}},
		DeviceGroups: []wire.DeviceGroup{{ID: 11, Name: "fixture-entry", Kind: "entry", Ratio: 1000, FirstPort: 12000, LastPort: 12100, OfflineSeconds: 30}},
		Devices:      []sourceDevice{{ID: 44, GroupID: 11, Name: "legacy"}},
		Rules:        []sourceRule{{Rule: wire.Rule{ID: 5, Owner: 17, Name: "fixture-rule", Entry: 11, Port: 12000, Targets: []string{"127.0.0.1:9999"}, Enabled: true}, Inbound: 7, Outbound: 8}},
	}
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	report, err := s.Import(bytes.NewReader(raw), true)
	if err != nil {
		t.Fatal(err)
	}
	if report.Mode != "dry-run" || report.StagedRules != 1 || report.RawBytes != 15 || report.Balance != 42 {
		t.Fatalf("report: %+v", report)
	}
	var count int
	if err = s.db.QueryRow("SELECT count(*) FROM users").Scan(&count); err != nil || count != 0 {
		t.Fatalf("dry-run wrote rows: %d (%v)", count, err)
	}
	report, err = s.Import(bytes.NewReader(raw), false)
	if err != nil || report.Mode != "imported" {
		t.Fatalf("import: %+v (%v)", report, err)
	}
	var enabled bool
	if err = s.db.QueryRow("SELECT json_extract(json,'$.enabled') FROM rules WHERE id=5").Scan(&enabled); err != nil || enabled {
		t.Fatalf("migrated rule enabled: %v (%v)", enabled, err)
	}
	report, err = s.Import(bytes.NewReader(raw), false)
	if err != nil || report.Mode != "already-imported" {
		t.Fatalf("idempotency: %+v (%v)", report, err)
	}
}

func TestRelayRouteSurvivesPanelRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "restart.db")
	s, err := Open(Options{Database: path, AdminPassword: "fixture-password"})
	if err != nil {
		t.Fatal(err)
	}
	giveFixtureUsersActivePlan(t, s)
	_, err = s.db.Exec(`
		INSERT INTO groups(id,name,kind,first_port,last_port,ratio,user_group,offline_seconds) VALUES
			(1,'entry','entry',10000,20000,1000,0,30),(2,'exit','exit',10000,20000,1000,0,30);
		INSERT INTO devices(id,group_id,token,registration) VALUES (1,2,'fixture','{"name":"exit","relayAddress":"exit.test:443"}');
		INSERT INTO probe_samples(node,bucket,cpu,ram,disk,inbound,outbound) VALUES (1,unixepoch()/60*60,0,0,0,0,0);
		INSERT INTO rules(id,owner,entry,port,json) VALUES (1,1,1,10001,'{"name":"rule","entry":1,"port":10001,"protocol":"tcp","enabled":true,"path":[2],"targets":["target.test:443"]}');
	`)
	s.Close()
	if err != nil {
		t.Fatal(err)
	}
	s, err = Open(Options{Database: path})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	config, err := s.compileGroup(1)
	if err != nil || len(config.Rules) != 1 || len(config.Rules[0].Routes) != 1 {
		t.Fatalf("expected recent relay in the initial config: %+v, %v", config, err)
	}
	devices, err := s.deviceSnapshot(false)
	if err != nil || len(devices) != 1 || devices[0].Online {
		t.Fatalf("expected dashboard to wait for an actual heartbeat: %+v, %v", devices, err)
	}
	s.warmUntil = time.Time{}
	config, err = s.compileGroup(1)
	if err != nil || len(config.Rules) != 1 || len(config.Rules[0].Routes) != 0 {
		t.Fatalf("expected grace to expire: %+v, %v", config, err)
	}
}

func TestQuotaReservationsAcrossNodes(t *testing.T) {
	s, err := Open(Options{Database: filepath.Join(t.TempDir(), "quota.db"), AdminPassword: "fixture-password"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	giveFixtureUsersActivePlan(t, s)
	if _, err = s.db.Exec("UPDATE users SET quota=100,unlimited_traffic=0,expires=unixepoch()+600 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	rules := []wire.Forward{{Rule: wire.Rule{Owner: 1}, QuotaManaged: true}}
	claims := []wire.QuotaClaim{{Owner: 1, Want: true}}
	g, _, err := s.allocateQuota(10, token(), rules, claims)
	if err != nil || len(g) != 1 || g[0].Allocated != 100000 {
		t.Fatalf("first grant: %+v (%v)", g, err)
	}
	held, _, err := s.allocateQuota(11, token(), rules, claims)
	if err != nil || len(held) != 0 {
		t.Fatalf("duplicate reservations: %+v (%v)", held, err)
	}
	close := []wire.QuotaClaim{{Owner: 1, ID: g[0].ID, Spent: 65000, Close: true}}
	for range 2 {
		if _, _, err = s.allocateQuota(10, token(), rules, close); err != nil {
			t.Fatal(err)
		}
	}
	remaining, _, err := s.allocateQuota(11, token(), rules, claims)
	if err != nil || len(remaining) != 1 || remaining[0].Allocated != 35000 {
		t.Fatalf("remaining: %+v (%v)", remaining, err)
	}
}

func TestPaymentGatewaysValidateAmountAndDeduplicate(t *testing.T) {
	s, err := Open(Options{Database: filepath.Join(t.TempDir(), "gateway.db"), AdminPassword: "fixture-password", PublicURL: "https://panel.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, kind := range []string{"epusdt", "tokenpay", "cryptomus"} {
		if _, err = s.db.Exec("INSERT INTO settings(key,value) VALUES(?,?)", kind+"Key", "fixture-gateway-key"); err != nil {
			t.Fatal(err)
		}
		if _, err = s.db.Exec("INSERT INTO orders(user_id,amount,credit,kind,status,reference,description) VALUES(1,123,0,?,'pending',?,'fixture')", kind, kind+":test-order"); err != nil {
			t.Fatal(err)
		}
	}
	handler := s.Handler()
	for _, kind := range []string{"epusdt", "tokenpay", "cryptomus"} {
		for _, amount := range []string{"1.24", "1.23", "1.23"} {
			fields := map[string]any{}
			switch kind {
			case "epusdt":
				fields = map[string]any{"order_id": "test-order", "status": 2, "amount": json.Number(amount)}
				fields["signature"] = canonicalDigest(fields, "signature", "fixture-gateway-key", false)
			case "tokenpay":
				fields = map[string]any{"OutOrderId": "test-order", "Status": 1, "ActualAmount": amount}
				fields["Signature"] = canonicalDigest(fields, "Signature", "fixture-gateway-key", false)
			case "cryptomus":
				fields = map[string]any{"order_id": "test-order", "status": "paid", "amount": amount}
				payload, _ := json.Marshal(fields)
				unsigned, err := unsignedCryptomus(payload)
				if err != nil {
					t.Fatal(err)
				}
				fields["sign"] = digestMD5(base64.StdEncoding.EncodeToString(unsigned) + "fixture-gateway-key")
			}
			raw, _ := json.Marshal(fields)
			request := httptest.NewRequest(http.MethodPost, "/api/payment/"+kind, bytes.NewReader(raw))
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			want := 200
			if amount != "1.23" {
				want = 400
			}
			if response.Code != want {
				t.Fatalf("%s: got %d, expected %d (%s)", kind, response.Code, want, response.Body)
			}
		}
	}
	var balance int64
	if err = s.db.QueryRow("SELECT balance FROM users WHERE id=1").Scan(&balance); err != nil || balance != 369 {
		t.Fatalf("balance %d (%v)", balance, err)
	}
}
