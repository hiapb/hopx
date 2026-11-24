package panel

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"hopx/internal/wire"
)

func TestAdministrativeOperationsAndRuleOwnership(t *testing.T) {
	panel, err := Open(Options{Database: filepath.Join(t.TempDir(), "test.db"), AdminPassword: "test-password-123"})
	if err != nil {
		t.Fatal(err)
	}
	defer panel.Close()
	server := httptest.NewServer(panel.Handler())
	defer server.Close()
	jar, _ := cookiejar.New(nil)
	admin := &http.Client{Jar: jar}
	jar, _ = cookiejar.New(nil)
	member := &http.Client{Jar: jar}
	base := server.URL + "/api"
	testRequest(t, admin, "POST", base+"/login", nil, map[string]string{"name": "admin", "password": "test-password-123"}, 200, nil)
	subscribeTestAdmin(t, admin, base)
	account := map[string]string{"name": "member", "password": "test-password-123"}
	testRequest(t, admin, "POST", base+"/admin/users", nil, account, 201, nil)
	testRequest(t, member, "POST", base+"/login", nil, account, 200, nil)
	var user User
	testRequest(t, member, "GET", base+"/me", nil, nil, 200, &user)
	memberPath := fmt.Sprintf("%s/admin/users/%d", base, user.ID)
	testRequest(t, member, "GET", base+"/admin/settings", nil, nil, 403, nil)
	testRequest(t, member, "PUT", memberPath+"/plan", nil, map[string]int{"planId": 0}, 403, nil)
	var memberGroup named
	testRequest(t, admin, "POST", base+"/admin/user-groups", nil, named{Name: "Members"}, 200, &memberGroup)
	var plan Plan
	testRequest(t, admin, "POST", base+"/admin/plans", nil, Plan{Name: "test", Duration: 30, Rules: 15, Quota: 200, GroupID: memberGroup.ID}, 200, &plan)
	testRequest(t, admin, "PUT", memberPath+"/plan", nil, map[string]any{"planId": plan.ID, "quota": true, "rules": true, "group": true}, 204, nil)
	testRequest(t, member, "GET", base+"/me", nil, nil, 200, &user)
	if user.Quota != 200 || user.MaxRules != 15 || user.PlanID != plan.ID || !user.AutoRenew {
		t.Fatalf("plan fields not synchronized: %+v", user)
	}
	testRequest(t, admin, "PUT", memberPath+"/referral", nil, map[string]any{"custom": true, "rate": 1500}, 204, nil)
	testRequest(t, admin, "PUT", base+"/admin/settings", nil, map[string]string{"registration": "invite"}, 204, nil)
	testRequest(t, admin, "PUT", memberPath+"/referral", nil, map[string]any{"custom": true, "rate": 1500, "registrationEnabled": false}, 204, nil)
	testRequest(t, admin, "PUT", memberPath+"/referral", nil, map[string]any{"custom": true, "rate": 1600}, 204, nil)
	var service struct{ InviteRegistrationEnabled bool }
	testRequest(t, member, "GET", base+"/me/service", nil, nil, 200, &service)
	if service.InviteRegistrationEnabled {
		t.Fatal("updating commission re-enabled a disabled invitation")
	}
	registration := map[string]string{"name": "invited", "password": "test-password-123", "invite": user.Invite}
	testRequest(t, member, "POST", base+"/register", nil, registration, 400, nil)
	testRequest(t, admin, "PUT", memberPath+"/referral", nil, map[string]any{"custom": false}, 204, nil)
	testRequest(t, member, "GET", base+"/me/service", nil, nil, 200, &service)
	if !service.InviteRegistrationEnabled {
		t.Fatal("returning to site settings did not restore invitations")
	}
	testRequest(t, member, "POST", base+"/register", nil, registration, 201, nil)
	user.Note = "admin-only note"
	user.AllowDevice = true
	testRequest(t, admin, "PUT", memberPath, nil, user, 204, nil)
	testRequest(t, member, "GET", base+"/me", nil, nil, 200, &user)
	if user.Note != "" {
		t.Fatal("member could read an admin note")
	}
	var personal wire.DeviceGroup
	testRequest(t, member, "POST", base+"/tunnels", nil, wire.DeviceGroup{Name: "personal", Kind: "exit"}, 200, &personal)
	testRequest(t, member, "GET", fmt.Sprintf("%s/groups/%d/configuration", base, personal.ID), nil, nil, 200, nil)
	var first, last wire.DeviceGroup
	testRequest(t, admin, "POST", base+"/admin/groups", nil, wire.DeviceGroup{Name: "entry", Kind: "entry"}, 200, &first)
	testRequest(t, admin, "POST", base+"/admin/groups", nil, wire.DeviceGroup{Name: "second", Kind: "entry"}, 200, &last)
	testRequest(t, member, "GET", fmt.Sprintf("%s/groups/%d/configuration", base, first.ID), nil, nil, 404, nil)
	testRequest(t, admin, "GET", fmt.Sprintf("%s/groups/%d/configuration", base, first.ID), nil, nil, 200, nil)
	var rule wire.Rule
	testRequest(t, admin, "POST", base+"/rules", nil, wire.Rule{Name: "test", Entry: first.ID, Targets: []string{"127.0.0.1:1024"}, Enabled: true}, 200, &rule)
	groupPath := fmt.Sprintf("%s/admin/groups/%d", base, first.ID)
	exit := first
	exit.Kind = "exit"
	testRequest(t, admin, "PUT", groupPath, nil, exit, 409, nil)
	config, err := panel.compileGroup(first.ID)
	if err != nil || len(config.Rules) != 1 || config.Rules[0].ID != rule.ID {
		t.Fatalf("type change affected active rules: %+v, %v", config, err)
	}
	batchPath := base + "/rules/batch"
	for _, invalid := range []map[string]any{
		{"action": "unknown"},
		{"action": "delete"},
		{"action": "import"},
		{"action": "delete", "ids": []int64{rule.ID, rule.ID}},
		{"action": "reroute", "ids": []int64{rule.ID}},
	} {
		testRequest(t, admin, "POST", batchPath, nil, invalid, 400, nil)
	}
	newRule := wire.Rule{Name: "batch-conflict", Entry: first.ID, Targets: []string{"127.0.0.1:1024"}}
	conflict := newRule
	conflict.Port = rule.Port
	testRequest(t, admin, "POST", batchPath, nil, map[string]any{"action": "import", "rules": []wire.Rule{newRule, conflict}}, 400, nil)
	move := map[string]any{"action": "reroute", "ids": []int64{rule.ID}, "entry": last.ID, "updatePath": true}
	testRequest(t, member, "POST", base+"/rules/batch", nil, move, 404, nil)
	testRequest(t, admin, "POST", base+"/rules/batch", nil, move, 200, nil)
	testRequest(t, admin, "PUT", groupPath, nil, exit, 200, nil)
	var rows []ruleRow
	testRequest(t, admin, "GET", base+"/rules", nil, nil, 200, &rows)
	if len(rows) != 1 || rows[0].Entry != last.ID || rows[0].ID != rule.ID {
		t.Fatalf("rule move: %+v", rows)
	}
	before, err := panel.compileGroup(last.ID)
	if err != nil {
		t.Fatal(err)
	}
	testRequest(t, admin, "POST", base+"/rules/batch", nil, map[string]any{
		"action": "label", "ids": []int64{rule.ID}, "label": "admin folder",
	}, 200, nil)
	testRequest(t, member, "PUT", base+"/rules/folders?owner=1", nil, map[string]string{"from": "admin folder", "name": ""}, 404, nil)
	testRequest(t, admin, "PUT", base+"/rules/folders?owner=1", nil, map[string]string{"from": "admin folder", "name": "new folder"}, 204, nil)
	var count struct{ Total int }
	testRequest(t, admin, "GET", base+"/rules/count?label=new+folder", nil, nil, 200, &count)
	if count.Total != 1 {
		t.Fatalf("renamed folder count: %d", count.Total)
	}
	after, err := panel.compileGroup(last.ID)
	if err != nil || before.Revision != after.Revision {
		t.Fatalf("moving rule folders changed node configuration: %v", err)
	}
	request := wire.Rule{Name: "tls", Entry: last.ID, Targets: []string{"127.0.0.1:1024"}, Enabled: true, TLSGenerateFor: "tls.example.test"}
	testRequest(t, admin, "POST", base+"/rules", nil, request, 200, &rule)
	keyPair, err := tls.X509KeyPair([]byte(rule.TLSCert), []byte(rule.TLSKey))
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil || cert.VerifyHostname(request.TLSGenerateFor) != nil {
		t.Fatalf("generated certificate does not match %s: %v", request.TLSGenerateFor, err)
	}
	request.TLSGenerateFor = "invalid:name"
	testRequest(t, admin, "POST", base+"/rules", nil, request, 400, nil)
	enrollmentURL := fmt.Sprintf("%s/admin/groups/%d/enrollment", base, last.ID)
	var invite map[string]any
	testRequest(t, admin, "POST", enrollmentURL, nil, nil, 201, &invite)
	op := fmt.Sprintf("%s/groups/%d/operations", base, last.ID)
	testRequest(t, member, "POST", op, nil, map[string]string{"action": "revoke-enrollments"}, 404, nil)
	testRequest(t, admin, "POST", op, nil, map[string]string{"action": "revoke-enrollments"}, 204, nil)
	testRequest(t, admin, "POST", base+"/node/register", map[string]string{"Authorization": "Bearer " + invite["token"].(string)}, wire.Registration{Name: "node"}, 401, nil)

	var personalEntry, siteExit wire.DeviceGroup
	testRequest(t, admin, "POST", base+"/admin/groups", nil,
		wire.DeviceGroup{Name: "site exit", Kind: "exit", UserGroups: []int64{memberGroup.ID}}, 200, &siteExit)
	testRequest(t, admin, "POST", base+"/admin/groups", nil, wire.DeviceGroup{
		Name: "personal ingress", Kind: "entry", UserGroups: []int64{memberGroup.ID},
		Routing: wire.RelayRouting{IngressMode: "personal"}, AllowedTo: []int64{siteExit.ID},
	}, 200, &personalEntry)
	input := wire.Rule{Owner: user.ID, Name: "personal only", Entry: personalEntry.ID, Targets: []string{"127.0.0.1:1024"}, Enabled: true}
	_, err = panel.db.Exec("UPDATE users SET expires=unixepoch()+3600 WHERE id=?", user.ID)
	if err != nil {
		t.Fatal(err)
	}
	testRequest(t, admin, "POST", base+"/rules", nil, input, 400, nil)
	input.Path = []int64{siteExit.ID}
	testRequest(t, admin, "POST", base+"/rules", nil, input, 400, nil)
	input.Path = []int64{personal.ID}
	testRequest(t, admin, "POST", base+"/rules", nil, input, 200, &rule)
	change := map[string]any{"port": rule.Port, "config": map[string]any{"maxConns": 18}}
	testRequest(t, member, "POST", base+"/rules/batch/by-port", nil, map[string]any{"entry": personalEntry.ID, "changes": []any{change}}, 200, nil)
	testRequest(t, member, "POST", base+"/rules/batch/by-port", nil, map[string]any{"entry": last.ID, "owner": 1, "changes": []any{change}}, 404, nil)
	input.Path = []int64{personal.ID, siteExit.ID}
	testRequest(t, admin, "POST", base+"/rules", nil, input, 400, nil)
	reset := map[string]string{"password": "another-fixture-password"}
	testRequest(t, member, "PUT", memberPath+"/password", nil, reset, 403, nil)
	testRequest(t, admin, "PUT", memberPath+"/password", nil, reset, 204, nil)
	testRequest(t, member, "GET", base+"/me", nil, nil, 401, nil)
	testRequest(t, member, "POST", base+"/login", nil, map[string]string{"name": user.Name, "password": reset["password"]}, 200, nil)
	var afterReset User
	testRequest(t, member, "GET", base+"/me", nil, nil, 200, &afterReset)
	if afterReset.PlanID != plan.ID || afterReset.Quota != 200 || !afterReset.AllowDevice {
		t.Fatal("password reset changed the member's service settings")
	}
}

func TestAccountingAndRenewalPreviews(t *testing.T) {
	panel, err := Open(Options{Database: filepath.Join(t.TempDir(), "test.db"), AdminPassword: "test-password-123"})
	if err != nil {
		t.Fatal(err)
	}
	defer panel.Close()
	server := httptest.NewServer(panel.Handler())
	defer server.Close()
	jar, _ := cookiejar.New(nil)
	admin := &http.Client{Jar: jar}
	base := server.URL + "/api"
	testRequest(t, admin, "POST", base+"/login", nil, map[string]string{"name": "admin", "password": "test-password-123"}, 200, nil)
	var user User
	testRequest(t, admin, "GET", base+"/me", nil, nil, 200, &user)
	input := manualAccounting{UserID: user.ID, Amount: 500}
	var quote struct{ Balance, After int64 }
	testRequest(t, admin, "POST", base+"/admin/accounting/preview", nil, input, 200, &quote)
	if quote.Balance != 0 || quote.After != input.Amount {
		t.Fatalf("incorrect balance preview: %+v", quote)
	}
	input.ExpectedBalance = &quote.Balance
	testRequest(t, admin, "POST", base+"/admin/credit", nil, input, 204, nil)
	testRequest(t, admin, "POST", base+"/admin/credit", nil, input, 409, nil)

	var plan Plan
	testRequest(t, admin, "POST", base+"/admin/plans", nil, Plan{Name: "traffic plan", Kind: "traffic", Price: 100, Duration: 1, Rules: 1, Quota: 4096}, 200, &plan)
	testRequest(t, admin, "PUT", fmt.Sprintf("%s/admin/users/%d/plan", base, user.ID), nil, map[string]int64{"planId": plan.ID}, 204, nil)
	var renewal struct{ PlanID, Price, Epoch int64 }
	testRequest(t, admin, "GET", base+"/me/renew", nil, nil, 200, &renewal)
	if renewal.PlanID != plan.ID || renewal.Price != plan.Price {
		t.Fatalf("incorrect renewal preview: %+v", renewal)
	}
	confirm := map[string]int64{"expectedPlan": renewal.PlanID, "expectedPrice": renewal.Price, "expectedEpoch": renewal.Epoch}
	testRequest(t, admin, "POST", base+"/me/renew", nil, confirm, 204, nil)
	testRequest(t, admin, "POST", base+"/me/renew", nil, confirm, 409, nil)
	testRequest(t, admin, "GET", base+"/me", nil, nil, 200, &user)
	if user.Balance != 400 {
		t.Fatalf("unexpected balance after retry: %d", user.Balance)
	}
}

func TestAutomaticRenewalSkipsUnfundedAccounts(t *testing.T) {
	panel, err := Open(Options{Database: filepath.Join(t.TempDir(), "renew.db"), AdminPassword: "test-password-123"})
	if err != nil {
		t.Fatal(err)
	}
	defer panel.Close()
	_, err = panel.db.Exec(`
		INSERT INTO plans(id,name,description,price,duration,quota,rules,group_id) VALUES (1,'Paid','',100,30,100,0,0);
		WITH RECURSIVE numbers(n) AS (VALUES(2) UNION ALL SELECT n+1 FROM numbers WHERE n<102)
		INSERT INTO users(id,name,password,invite,plan_id,expires,auto_renew,balance)
			SELECT n,'member'||n,X'00','fixture'||n,1,unixepoch()-60,1,CASE WHEN n=102 THEN 100 ELSE 0 END FROM numbers;
	`)
	if err != nil {
		t.Fatal(err)
	}
	panel.renew()
	var id int64
	if err = panel.db.QueryRow("SELECT user_id FROM orders WHERE kind='renew'").Scan(&id); err != nil || id != 102 {
		t.Fatalf("funded account was not renewed: user %d, %v", id, err)
	}
}

func TestSyncPlanExpiryAndExplicitTrafficLimit(t *testing.T) {
	panel, err := Open(Options{Database: filepath.Join(t.TempDir(), "plan.db"), AdminPassword: "test-password-123"})
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

	plan := Plan{Name: "Fixture", Kind: "traffic", Duration: 1, Enabled: true, Price: 100, Quota: 500, UnlimitedTraffic: true}
	testRequest(t, client, "POST", base+"/admin/plans", nil, plan, 200, &plan)
	if plan.Quota != 0 || !plan.UnlimitedTraffic {
		t.Fatalf("unlimited plan did not normalize quota: %+v", plan)
	}
	assign := base + "/admin/users/1/plan"
	testRequest(t, client, "PUT", assign, nil, map[string]any{"planId": plan.ID, "quota": true, "expires": true}, 204, nil)
	var user User
	testRequest(t, client, "GET", base+"/me", nil, nil, 200, &user)
	if user.Expires != 253402300799 || !user.UnlimitedTraffic || user.ServiceBlock != "" {
		t.Fatalf("assignment did not apply unlimited time and traffic: %+v", user)
	}

	plan.UnlimitedTraffic, plan.Kind, plan.Duration = false, "day", 10
	adminPlan := fmt.Sprintf("%s/admin/plans/%d", base, plan.ID)
	testRequest(t, client, "PUT", adminPlan, nil, plan, 200, nil)
	start := time.Now().Unix()
	testRequest(t, client, "POST", adminPlan+"/push", nil, map[string]bool{"quota": true, "expires": true}, 200, nil)
	testRequest(t, client, "GET", base+"/me", nil, nil, 200, &user)
	if user.UnlimitedTraffic || user.Quota != 0 || user.ServiceBlock != "套餐流量已用完，请续费" ||
		user.Expires < start+10*86400 || user.Expires > time.Now().Unix()+10*86400 {
		t.Fatalf("push did not apply zero traffic and the new expiry: %+v", user)
	}
	if _, err = panel.db.Exec("UPDATE users SET balance=500 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	panel.renew()
	var orders int
	if err = panel.db.QueryRow("SELECT count(*) FROM orders WHERE kind='renew'").Scan(&orders); err != nil || orders != 0 {
		t.Fatalf("zero-quota plan triggered automatic renewal: %d, %v", orders, err)
	}
	var quote struct {
		Quota            int64
		UnlimitedTraffic bool
	}
	testRequest(t, client, "GET", base+"/me/renew", nil, nil, 200, &quote)
	if quote.Quota != 0 || quote.UnlimitedTraffic {
		t.Fatalf("zero-quota renewal was quoted as unlimited: %+v", quote)
	}
	plan.UnlimitedTraffic = true
	testRequest(t, client, "PUT", adminPlan, nil, plan, 200, nil)
	testRequest(t, client, "POST", base+"/me/renew", nil, map[string]any{
		"expectedPrice": plan.Price, "expectedQuota": quote.Quota, "expectedUnlimitedTraffic": quote.UnlimitedTraffic,
	}, 409, nil)
	testRequest(t, client, "GET", base+"/me", nil, nil, 200, &user)
	if user.Balance != 500 || user.UnlimitedTraffic {
		t.Fatalf("stale renewal quote changed the account: %+v", user)
	}
}

func TestTrafficQuotaSchemaUpgradeKeepsZero(t *testing.T) {
	options := Options{Database: filepath.Join(t.TempDir(), "plan.db"), AdminPassword: "test-password-123"}
	panel, err := Open(options)
	if err != nil {
		t.Fatal(err)
	}
	_, err = panel.db.Exec(`
		ALTER TABLE users DROP COLUMN unlimited_traffic;
		ALTER TABLE plans DROP COLUMN unlimited_traffic;
		INSERT INTO plans(id,name,description,price,duration,quota,rules,group_id) VALUES(1,'Zero traffic','',0,30,0,0,0);
		UPDATE users SET plan_id=1,quota=0,expires=unixepoch()+86400 WHERE id=1;
	`)
	panel.Close()
	if err != nil {
		t.Fatal(err)
	}
	panel, err = Open(options)
	if err != nil {
		t.Fatal(err)
	}
	defer panel.Close()
	plan, err := readPlan(panel.db.QueryRow("SELECT " + planColumns + " FROM plans WHERE id=1"))
	if err != nil || plan.Quota != 0 || plan.UnlimitedTraffic {
		t.Fatalf("upgraded plan must have zero traffic: %+v, %v", plan, err)
	}
	user, err := readUser(panel.db.QueryRow(userSelect + " WHERE id=1"))
	if err != nil || user.Quota != 0 || user.UnlimitedTraffic {
		t.Fatalf("upgraded user must have zero traffic: %+v, %v", user, err)
	}
}

func TestOfflineNotificationGrace(t *testing.T) {
	panel, err := Open(Options{Database: filepath.Join(t.TempDir(), "test.db"), AdminPassword: "test-password-123"})
	if err != nil {
		t.Fatal(err)
	}
	defer panel.Close()
	server := httptest.NewServer(panel.Handler())
	defer server.Close()
	jar, _ := cookiejar.New(nil)
	admin := &http.Client{Jar: jar}
	base := server.URL + "/api"
	testRequest(t, admin, "POST", base+"/login", nil, map[string]string{"name": "admin", "password": "test-password-123"}, 200, nil)
	var group wire.DeviceGroup
	testRequest(t, admin, "POST", base+"/admin/groups", nil, wire.DeviceGroup{Name: "grace", Kind: "entry", OfflineSeconds: 30}, 200, &group)
	groupID := fmt.Sprint(group.ID)
	var enrollment struct{ Token string }
	testRequest(t, admin, "POST", base+"/admin/groups/"+groupID+"/enrollment", nil, nil, 201, &enrollment)
	var node wire.Identity
	testRequest(t, admin, "POST", base+"/node/register", map[string]string{"Authorization": "Bearer " + enrollment.Token}, wire.Registration{Name: "grace node"}, 201, &node)
	if _, err := panel.db.Exec("INSERT INTO telegram_links(user_id,chat_id,updown) VALUES(1,12345,1); INSERT INTO settings(key,value) VALUES('telegramToken','123456:mocked-test-bot-token-only')"); err != nil {
		t.Fatal(err)
	}
	config := offlineNotificationSettings{Default: 120, Groups: map[string]int64{groupID: 45}}
	testRequest(t, admin, "PUT", base+"/admin/notifications/offline", nil, config, 204, nil)
	var saved offlineNotificationSettings
	testRequest(t, admin, "GET", base+"/admin/notifications/offline", nil, nil, 200, &saved)
	if saved.Default != 120 || saved.Groups[groupID] != 45 {
		t.Fatalf("notification policy was not persisted: %+v", saved)
	}
	sample := func(age time.Duration, want int) {
		t.Helper()
		panel.devices[node.ID] = wire.Device{ID: node.ID, GroupID: group.ID, LastSeen: time.Now().Add(-age)}
		panel.queueTelegramDeviceStatus()
		var count int
		if err = panel.db.QueryRow("SELECT count(*) FROM notifications WHERE topic='updown'").Scan(&count); err != nil || count != want {
			t.Fatalf("notifications at %v = %d, want %d: %v", age, count, want, err)
		}
	}
	sample(0, 0)
	sample(40*time.Second, 0)
	sample(0, 0)
	sample(90*time.Second, 1)
	sample(0, 2)
}
