package panel

import (
	"context"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"hopx/internal/wire"
)

func TestRuleSubscriptionLifecycle(t *testing.T) {
	const password = "subscription-test-password"
	panel, err := Open(Options{Database: filepath.Join(t.TempDir(), "panel.db"), AdminPassword: password})
	if err != nil {
		t.Fatal(err)
	}
	defer panel.Close()
	server := httptest.NewServer(panel.Handler())
	defer server.Close()
	base := server.URL + "/api"
	adminJar, _ := cookiejar.New(nil)
	admin := &http.Client{Jar: adminJar}
	memberJar, _ := cookiejar.New(nil)
	member := &http.Client{Jar: memberJar}
	testRequest(t, admin, "POST", base+"/login", nil, map[string]string{"name": "admin", "password": password}, 200, nil)
	account := map[string]string{"name": "member", "password": password}
	testRequest(t, admin, "POST", base+"/admin/users", nil, account, 201, nil)
	testRequest(t, member, "POST", base+"/login", nil, account, 200, nil)
	var memberInfo User
	testRequest(t, member, "GET", base+"/me", nil, nil, 200, &memberInfo)
	if memberInfo.ServiceBlock != "请先订购套餐" || memberInfo.AutoRenew {
		t.Fatalf("unsubscribed member: %+v", memberInfo)
	}

	var group named
	testRequest(t, admin, "POST", base+"/admin/user-groups", nil, named{Name: "Paid"}, 200, &group)
	var entry wire.DeviceGroup
	for _, ids := range [][]int64{{0}, {group.ID + 1}} {
		testRequest(t, admin, "POST", base+"/admin/groups", nil,
			wire.DeviceGroup{Name: "invalid authorization", Kind: "entry", UserGroups: ids}, 400, nil)
	}
	testRequest(t, admin, "POST", base+"/admin/groups", nil, wire.DeviceGroup{Name: "entry", Kind: "entry", Ratio: 1000}, 200, &entry)
	entryURL := fmt.Sprintf("%s/admin/groups/%d", base, entry.ID)
	input := wire.Rule{Name: "forward", Entry: entry.ID, Targets: []string{"1.1.1.1:443"}, Enabled: true}
	for _, client := range []*http.Client{admin, member} {
		testRequest(t, client, "POST", base+"/rules", nil, input, 400, nil)
		testRequest(t, client, "POST", base+"/rules/preflight", nil, input, 400, nil)
		testRequest(t, client, "POST", base+"/rules/batch", nil, map[string]any{"action": "import", "rules": []wire.Rule{input}}, 400, nil)
	}
	input.Owner = memberInfo.ID
	testRequest(t, admin, "POST", base+"/rules", nil, input, 400, nil)
	input.Owner = 0

	var plan Plan
	testRequest(t, admin, "POST", base+"/admin/plans", nil,
		Plan{Name: "Metered", Duration: 30, Enabled: true, Quota: 100, GroupID: group.ID}, 200, &plan)
	buy := fmt.Sprintf("%s/plans/%d/buy", base, plan.ID)
	testRequest(t, member, "POST", buy, nil, nil, 204, nil)
	memberInfo.ServiceBlock = ""
	testRequest(t, member, "GET", base+"/me", nil, nil, 200, &memberInfo)
	if memberInfo.Group != group.ID || memberInfo.PlanID != plan.ID || !memberInfo.AutoRenew {
		t.Fatalf("purchase did not apply the package user group: %+v", memberInfo)
	}
	if _, err = panel.db.Exec("UPDATE users SET expires=unixepoch()-1 WHERE id=?", memberInfo.ID); err != nil {
		t.Fatal(err)
	}
	panel.renew()
	testRequest(t, member, "GET", base+"/me", nil, nil, 200, &memberInfo)
	if memberInfo.ServiceBlock != "" || !memberInfo.AutoRenew {
		t.Fatalf("automatic renewal did not renew the first plan: %+v", memberInfo)
	}
	testRequest(t, member, "PATCH", base+"/me", nil, map[string]bool{"autoRenew": false}, 204, nil)
	if _, err = panel.db.Exec("UPDATE users SET expires=unixepoch()-1 WHERE id=?", memberInfo.ID); err != nil {
		t.Fatal(err)
	}
	panel.renew()
	testRequest(t, member, "GET", base+"/me", nil, nil, 200, &memberInfo)
	if memberInfo.AutoRenew || memberInfo.ServiceBlock == "" {
		t.Fatalf("user who opted out was automatically renewed: %+v", memberInfo)
	}
	testRequest(t, member, "POST", buy, nil, nil, 204, nil)
	var visible []wire.DeviceGroup
	testRequest(t, member, "GET", base+"/groups", nil, nil, 200, &visible)
	if len(visible) != 0 {
		t.Fatalf("empty authorization exposed a device group: %+v", visible)
	}
	testRequest(t, member, "POST", base+"/rules", nil, input, 400, nil)
	entry.UserGroups = []int64{group.ID}
	testRequest(t, admin, "PUT", entryURL, nil, entry, 200, nil)
	testRequest(t, member, "GET", base+"/groups", nil, nil, 200, &visible)
	if len(visible) != 1 || visible[0].ID != entry.ID {
		t.Fatalf("explicit authorization did not expose the device group: %+v", visible)
	}
	var saved wire.Rule
	testRequest(t, member, "POST", base+"/rules", nil, input, 200, &saved)
	// An explicit empty list also clears a single-group authorization from old clients.
	cleared := map[string]any{"name": entry.Name, "kind": entry.Kind, "ratio": entry.Ratio, "userGroup": group.ID, "userGroups": []int64{}}
	testRequest(t, admin, "PUT", entryURL, nil, cleared, 200, nil)
	config, err := panel.compileGroup(entry.ID)
	if err != nil || len(config.Rules) != 0 {
		t.Fatalf("clearing authorization left a forward published: %+v, %v", config, err)
	}
	testRequest(t, admin, "PUT", entryURL, nil, entry, 200, nil)
	var enrollment struct{ Token string }
	testRequest(t, admin, "POST", fmt.Sprintf("%s/admin/groups/%d/enrollment", base, entry.ID), nil, nil, 201, &enrollment)
	var node wire.Identity
	testRequest(t, admin, "POST", base+"/node/register", map[string]string{"Authorization": "Bearer " + enrollment.Token},
		wire.Registration{Name: "localhost", Region: "Private region"}, 201, &node)
	headers := map[string]string{"Authorization": "Bearer " + node.Token, "X-Node-ID": fmt.Sprint(node.ID)}
	testRequest(t, admin, "POST", base+"/node/sync", headers, wire.Heartbeat{AcceptLinkProbe: true}, 200, nil)
	ruleURL := fmt.Sprintf("%s/rules/%d", base, saved.ID)
	testRequest(t, member, "POST", ruleURL+"/diagnose", nil, nil, 200, nil)
	entry.Routing.StatusVisibility = "admin"
	testRequest(t, admin, "PUT", entryURL, nil, entry, 200, nil)
	var status struct{ Nodes []entryDiagnostic }
	testRequest(t, admin, "POST", ruleURL+"/diagnose?status=1", nil, nil, 200, &status)
	if len(status.Nodes) != 1 || status.Nodes[0].Region != "Private region" || status.Nodes[0].ID != node.ID {
		t.Fatalf("administrator did not receive the node identity: %+v", status.Nodes)
	}
	status.Nodes = nil
	testRequest(t, member, "POST", ruleURL+"/diagnose?status=1", nil, nil, 200, &status)
	if len(status.Nodes) != 1 || status.Nodes[0].Name != "入口 1" || status.Nodes[0].ID != 0 ||
		status.Nodes[0].Region != "" || status.Nodes[0].CountryCode != "" {
		t.Fatalf("private node identity exposed: %+v", status.Nodes)
	}
	links := []wire.LinkProbe{{Network: "tcp", Lane: "primary", MeasuresTarget: true,
		Traces: []wire.RouteTrace{{Steps: []wire.ProbeStep{{Status: "ok", LatencyMS: 4}}}}}}
	panel.saveRuleProbe(context.Background(), saved.ID, links)

	for _, state := range []struct {
		name, reason string
	}{
		{"exhausted", "套餐流量已用完，请续费"},
		{"expired", "套餐已到期，请续费"},
		{"unsubscribed", "请先订购套餐"},
	} {
		t.Run(state.name, func(t *testing.T) {
			before, err := panel.compileGroup(entry.ID)
			if err != nil || len(before.Rules) != 1 || before.Rules[0].Expires <= 0 || !before.Rules[0].QuotaManaged {
				t.Fatalf("initial forwarding config: %+v, %v", before, err)
			}
			switch state.name {
			case "exhausted":
				generation := token()
				claim := wire.QuotaClaim{Owner: memberInfo.ID, Epoch: before.Rules[0].QuotaEpoch, Want: true}
				grants, _, err := panel.allocateQuota(node.ID, generation, before.Rules, []wire.QuotaClaim{claim})
				if err != nil || len(grants) != 1 || grants[0].Allocated != plan.Quota*1000 {
					t.Fatalf("metered subscription grant: %+v, %v", grants, err)
				}
				claim.ID, claim.Spent = grants[0].ID, grants[0].Allocated
				grants, _, err = panel.allocateQuota(node.ID, generation, before.Rules, []wire.QuotaClaim{claim})
				if err != nil || len(grants) != 0 {
					t.Fatalf("exhausted subscription received more quota: %+v, %v", grants, err)
				}
			case "expired":
				_, err = panel.db.Exec("UPDATE users SET expires=unixepoch()-86400,used=25 WHERE id=?", memberInfo.ID)
			case "unsubscribed":
				_, err = panel.db.Exec("UPDATE users SET plan_id=0 WHERE id=?", memberInfo.ID)
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, client := range []*http.Client{member, admin} {
				var response map[string]string
				testRequest(t, client, "POST", ruleURL+"/diagnose", nil, nil, 403, &response)
				if response["error"] != state.reason {
					t.Fatalf("unexpected diagnosis response: %v", response)
				}
				testRequest(t, client, "GET", ruleURL+"/diagnose/history", nil, nil, 403, nil)
			}
			testRequest(t, member, "POST", base+"/rules", nil, input, 400, nil)
			delegated := input
			delegated.Owner = memberInfo.ID
			testRequest(t, admin, "POST", base+"/rules", nil, delegated, 400, nil)
			var rows []ruleRow
			testRequest(t, member, "GET", base+"/rules", nil, nil, 200, &rows)
			if len(rows) != 1 || rows[0].ID != saved.ID || !rows[0].Enabled ||
				rows[0].ServiceBlock != state.reason || rows[0].Runtime != "subscription_blocked" {
				t.Fatalf("existing rule state: %+v", rows)
			}
			after, err := panel.compileGroup(entry.ID)
			if err != nil || after.Revision == before.Revision || len(after.Rules) != 0 {
				t.Fatalf("inactive subscription left a forward published: %+v, %v", after, err)
			}

			if _, err = panel.db.Exec("UPDATE rule_probe_samples SET sampled=unixepoch()-600 WHERE rule=?", saved.ID); err != nil {
				t.Fatal(err)
			}
			cursor, err := panel.probeRuleBatch(context.Background(), 0)
			if err != nil || cursor != 0 {
				t.Fatalf("ineligible rule reached probe scheduler: cursor %d, %v", cursor, err)
			}
			panel.saveRuleProbe(context.Background(), saved.ID, links)
			var samples int
			if err = panel.db.QueryRow("SELECT count(*) FROM rule_probe_samples WHERE rule=?", saved.ID).Scan(&samples); err != nil || samples != 1 {
				t.Fatalf("sample count while paused = %d, %v", samples, err)
			}

			purchasedAt := time.Now().Unix()
			if state.name == "unsubscribed" || state.name == "expired" {
				testRequest(t, member, "POST", buy, nil, nil, 204, nil)
			} else {
				testRequest(t, member, "POST", base+"/me/renew", nil, map[string]any{}, 204, nil)
			}
			restored, err := panel.compileGroup(entry.ID)
			if err != nil || len(restored.Rules) != 1 || restored.Rules[0].ID != saved.ID || restored.Rules[0].Port != saved.Port {
				t.Fatalf("purchase or renewal did not republish the rule: %+v, %v", restored, err)
			}
			if state.name == "expired" {
				var renewed User
				testRequest(t, member, "GET", base+"/me", nil, nil, 200, &renewed)
				if renewed.PlanID != plan.ID || renewed.Group != plan.GroupID || renewed.Quota != plan.Quota || renewed.Used != 0 ||
					renewed.Expires < purchasedAt+plan.Duration*86400 || renewed.Expires > time.Now().Unix()+plan.Duration*86400 {
					t.Fatalf("repurchase did not start a fresh package: %+v", renewed)
				}
				oldEpoch, newEpoch := before.Rules[0].QuotaEpoch, restored.Rules[0].QuotaEpoch
				report := wire.Report{ID: "after-purchase", Traffic: []wire.Traffic{
					{RuleID: saved.ID, Out: 20, Ratio: 1000, QuotaEpoch: &oldEpoch},
					{RuleID: saved.ID, Out: 1, Ratio: 1000, QuotaEpoch: &newEpoch},
				}}
				if _, err := panel.accountTraffic(node.ID, entry.ID, &report); err != nil {
					t.Fatal(err)
				}
				testRequest(t, member, "GET", base+"/me", nil, nil, 200, &renewed)
				if renewed.Used != 1 {
					t.Fatalf("usage in new package = %d, want 1", renewed.Used)
				}
				var traffic int64
				if err := panel.db.QueryRow("SELECT outbound FROM traffic WHERE rule_id=?", saved.ID).Scan(&traffic); err != nil || traffic != 21 {
					t.Fatalf("reported rule traffic = %d, want 21 (%v)", traffic, err)
				}
			}
			var history struct{ Lanes []probeHistoryLane }
			testRequest(t, member, "GET", ruleURL+"/diagnose/history", nil, nil, 200, &history)
			if len(history.Lanes) != 1 || history.Lanes[0].Samples != 1 {
				t.Fatalf("history after renewal: %+v", history)
			}
			testRequest(t, member, "POST", ruleURL+"/diagnose", nil, nil, 200, nil)
			rows = nil
			testRequest(t, member, "GET", base+"/rules", nil, nil, 200, &rows)
			if len(rows) != 1 || rows[0].ID != saved.ID || rows[0].Port != saved.Port || rows[0].ServiceBlock != "" {
				t.Fatalf("rule after renewal: %+v", rows)
			}
		})
	}
	input.Name = "after renewal"
	testRequest(t, member, "POST", base+"/rules", nil, input, 200, nil)

	var otherGroup named
	testRequest(t, admin, "POST", base+"/admin/user-groups", nil, named{Name: "Other"}, 200, &otherGroup)
	sharedGroups := []int64{group.ID, otherGroup.ID}
	createDeviceGroup := func(name, kind string, users, chain []int64) wire.DeviceGroup {
		t.Helper()
		var added wire.DeviceGroup
		testRequest(t, admin, "POST", base+"/admin/groups", nil,
			wire.DeviceGroup{Name: name, Kind: kind, UserGroups: users, Chain: chain}, 200, &added)
		return added
	}
	newEntry := createDeviceGroup("shared entry", "entry", sharedGroups, nil)
	oldExit := createDeviceGroup("old exit", "exit", []int64{group.ID}, nil)
	newExit := createDeviceGroup("shared exit", "exit", sharedGroups, nil)
	oldChain := createDeviceGroup("old chain", "chain", []int64{group.ID}, []int64{oldExit.ID, newExit.ID})
	route := wire.Rule{Name: "keep backup", Entry: newEntry.ID, Targets: input.Targets, Enabled: true,
		Path: []int64{oldChain.ID}, BackupPath: []int64{newExit.ID}}
	var chainRule, backupRule, permittedRule wire.Rule
	testRequest(t, member, "POST", base+"/rules", nil, route, 200, &chainRule)
	route.Name, route.Path, route.BackupPath = "keep primary", []int64{newExit.ID}, []int64{oldExit.ID}
	testRequest(t, member, "POST", base+"/rules", nil, route, 200, &backupRule)
	route.Name, route.BackupPath = "keep all", nil
	testRequest(t, member, "POST", base+"/rules", nil, route, 200, &permittedRule)

	var otherPlan Plan
	testRequest(t, admin, "POST", base+"/admin/plans", nil,
		Plan{Name: "Other plan", Duration: 15, Enabled: true, GroupID: otherGroup.ID, Quota: 300, Rules: 8}, 200, &otherPlan)
	if _, err = panel.db.Exec("UPDATE users SET expires=unixepoch()-86400,used=50 WHERE id=?", memberInfo.ID); err != nil {
		t.Fatal(err)
	}
	testRequest(t, member, "POST", fmt.Sprintf("%s/plans/%d/buy", base, otherPlan.ID), nil, nil, 204, nil)
	testRequest(t, member, "GET", base+"/me", nil, nil, 200, &memberInfo)
	if memberInfo.Group != otherGroup.ID || memberInfo.PlanID != otherPlan.ID || memberInfo.Quota != otherPlan.Quota ||
		memberInfo.Used != 0 || memberInfo.MaxRules != otherPlan.Rules || memberInfo.AutoRenew {
		t.Fatalf("switching plans did not apply the new terms: %+v", memberInfo)
	}
	config, err = panel.compileGroup(entry.ID)
	if err != nil || len(config.Rules) != 0 {
		t.Fatalf("new plan preserved access to the old group: %+v, %v", config, err)
	}
	var rows []ruleRow
	testRequest(t, member, "GET", base+"/rules", nil, nil, 200, &rows)
	if len(rows) != 5 {
		t.Fatalf("switching plans changed the saved rules: %+v", rows)
	}
	byID := make(map[int64]ruleRow, len(rows))
	for _, row := range rows {
		byID[row.ID] = row
	}
	clearedEntry, clearedChain, clearedBackup := byID[saved.ID], byID[chainRule.ID], byID[backupRule.ID]
	if clearedEntry.Entry != 0 || clearedEntry.Port != 0 || clearedEntry.Runtime != "route_repair" ||
		clearedEntry.RouteRepair == nil || !clearedEntry.RouteRepair.Entry || clearedEntry.Out != 21 ||
		clearedChain.Entry != newEntry.ID || len(clearedChain.Path) != 0 || clearedChain.RouteRepair == nil ||
		!clearedChain.RouteRepair.Path || len(clearedChain.BackupPath) != 1 || clearedChain.BackupPath[0] != newExit.ID ||
		len(clearedBackup.Path) != 1 || clearedBackup.Path[0] != newExit.ID || len(clearedBackup.BackupPath) != 0 ||
		clearedBackup.RouteRepair == nil || !clearedBackup.RouteRepair.BackupPath || byID[permittedRule.ID].RouteRepair != nil {
		t.Fatalf("wrong routes cleared after switch: %+v", rows)
	}
	config, err = panel.compileGroup(newEntry.ID)
	if err != nil || len(config.Rules) != 1 || config.Rules[0].ID != permittedRule.ID {
		t.Fatalf("pending rules are still published: %+v, %v", config, err)
	}
	chainURL := fmt.Sprintf("%s/rules/%d", base, chainRule.ID)
	testRequest(t, member, "POST", chainURL+"/diagnose", nil, nil, 409, nil)
	testRequest(t, member, "PUT", chainURL, nil, clearedChain.Rule, 400, nil)
	testRequest(t, member, "POST", base+"/rules/batch", nil, map[string]any{"action": "enable", "ids": []int64{chainRule.ID}}, 400, nil)
	clearedChain.Path = []int64{newExit.ID}
	var repaired wire.Rule
	testRequest(t, member, "PUT", chainURL, nil, clearedChain.Rule, 200, &repaired)
	if repaired.RouteRepair != nil || !repaired.Enabled || repaired.Port != chainRule.Port {
		t.Fatalf("selecting a new exit did not restore the rule: %+v", repaired)
	}
	backupURL := fmt.Sprintf("%s/rules/%d", base, backupRule.ID)
	testRequest(t, member, "PUT", backupURL, nil, clearedBackup.Rule, 400, nil)
	clearedBackup.ConfirmRoute = true
	repaired = wire.Rule{}
	testRequest(t, member, "PUT", backupURL, nil, clearedBackup.Rule, 200, &repaired)
	if repaired.RouteRepair != nil || repaired.ConfirmRoute || len(repaired.Path) != 1 || len(repaired.BackupPath) != 0 {
		t.Fatalf("confirming a route without a backup did not restore the rule: %+v", repaired)
	}
	clearedEntry.Entry = newEntry.ID
	repaired = wire.Rule{}
	testRequest(t, member, "PUT", ruleURL, nil, clearedEntry.Rule, 200, &repaired)
	if repaired.RouteRepair != nil || repaired.ID != saved.ID || repaired.Entry != newEntry.ID || repaired.Port <= 0 {
		t.Fatalf("selecting a new entry did not restore the rule: %+v", repaired)
	}
}
