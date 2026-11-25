package panel

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"hopx/internal/wire"
)

func TestRuleProbeIntervalKeepsExistingHistory(t *testing.T) {
	s, err := Open(Options{Database: filepath.Join(t.TempDir(), "panel.db"), AdminPassword: "sampling-fixture-password"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	server := httptest.NewServer(s.Handler())
	defer server.Close()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	base := server.URL + "/api"
	testRequest(t, client, "POST", base+"/login", nil, map[string]string{"name": "admin", "password": "sampling-fixture-password"}, 200, nil)
	subscribeTestAdmin(t, client, base)
	var group wire.DeviceGroup
	testRequest(t, client, "POST", base+"/admin/groups", nil, wire.DeviceGroup{Name: "probe ingress", Kind: "entry", Ratio: 1000}, 200, &group)

	create := func(name string, interval int) wire.Rule {
		t.Helper()
		input := wire.Rule{Name: name, Entry: group.ID, Enabled: true, Targets: []string{"127.0.0.1:443"}, ProbeInterval: interval}
		var saved wire.Rule
		testRequest(t, client, "POST", base+"/rules", nil, input, 200, &saved)
		return saved
	}
	inherited := create("inherited", 0)
	fast := create("minute", 60)
	normal := create("five minutes", 300)
	testRequest(t, client, "POST", base+"/rules", nil,
		wire.Rule{Name: "invalid", Entry: group.ID, Targets: []string{"127.0.0.1:443"}, ProbeInterval: 15}, 400, nil)

	links := []wire.LinkProbe{{Network: "tcp", Lane: "primary", MeasuresTarget: true,
		Traces: []wire.RouteTrace{{Steps: []wire.ProbeStep{{Status: "ok", LatencyMS: 4}}}}}}
	raw, err := json.Marshal(links)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().Truncate(5 * time.Minute).Add(-10 * time.Minute)
	for _, id := range []int64{inherited.ID, fast.ID, normal.ID} {
		_, err := s.db.Exec(`INSERT INTO rule_probe_samples(rule,bucket,sampled,links)
			VALUES(?,?,?,?)`, id, (at.Unix()-90)/300, at.Unix()-90, string(raw))
		if err != nil {
			t.Fatal(err)
		}
	}
	testRequest(t, client, "PUT", base+"/admin/settings", nil, map[string]string{"ruleProbeInterval": "30"}, 400, nil)
	testRequest(t, client, "PUT", base+"/admin/settings", nil, map[string]string{"ruleProbeInterval": "60"}, 204, nil)

	assertHistory := func(id int64, interval, attempts int) {
		t.Helper()
		var history struct {
			Interval        int
			CompleteBuckets int
			SampledBuckets  int
			Lanes           []probeHistoryLane
			Points          []probeHistoryPoint
		}
		testRequest(t, client, "GET", fmt.Sprintf("%s/rules/%d/diagnose/history?range=live", base, id), nil, nil, 200, &history)
		if history.Interval != interval || len(history.Lanes) != 1 || history.Lanes[0].Attempts != attempts ||
			len(history.Lanes[0].Points) != 3600/interval || len(history.Points) != 3600/interval ||
			history.SampledBuckets != attempts {
			t.Fatalf("rule %d history interval=%d, lanes=%+v", id, history.Interval, history.Lanes)
		}
	}
	save := func(rule int64, interval int64) {
		if err := s.saveManualRuleProbe(context.Background(), probeKey(rule, interval, at), group.ID, links); err != nil {
			t.Error(err)
		}
	}
	var updates sync.WaitGroup
	for range 5 {
		updates.Go(func() { save(inherited.ID, 60) })
	}
	updates.Wait()
	save(fast.ID, 60)
	save(normal.ID, 300)
	assertHistory(inherited.ID, 60, 2)
	assertHistory(fast.ID, 60, 2)
	assertHistory(normal.ID, 300, 2)

	before, err := s.compileGroup(group.ID)
	if err != nil {
		t.Fatal(err)
	}
	inherited.ProbeInterval = 300
	testRequest(t, client, "PUT", fmt.Sprintf("%s/rules/%d", base, inherited.ID), nil, inherited, 200, nil)
	assertHistory(inherited.ID, 300, 2)
	after, err := s.compileGroup(group.ID)
	if err != nil {
		t.Fatal(err)
	}
	if before.Revision != after.Revision {
		t.Fatal("sampling interval triggered a forwarding configuration change")
	}
	testRequest(t, client, "PUT", base+"/admin/settings", nil, map[string]string{"ruleProbeInterval": "300"}, 204, nil)
	assertHistory(fast.ID, 60, 2)
	assertHistory(normal.ID, 300, 2)
}

func TestPeriodicProbeRetriesAndKeepsLateReportAfterRestart(t *testing.T) {
	ctx := context.Background()
	options := Options{Database: filepath.Join(t.TempDir(), "panel.db"), AdminPassword: "sampling-fixture-password"}
	panel, err := Open(options)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { panel.Close() }()
	server := httptest.NewServer(panel.Handler())
	defer func() { server.Close() }()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	base := server.URL + "/api"
	testRequest(t, client, "POST", base+"/login", nil, map[string]string{"name": "admin", "password": options.AdminPassword}, 200, nil)
	subscribeTestAdmin(t, client, base)
	var group wire.DeviceGroup
	testRequest(t, client, "POST", base+"/admin/groups", nil, wire.DeviceGroup{Name: "ingress", Kind: "entry", Ratio: 1000}, 200, &group)
	var rule, unavailable wire.Rule
	testRequest(t, client, "POST", base+"/rules", nil, wire.Rule{
		Name: "periodic", Entry: group.ID, Enabled: true, Targets: []string{"127.0.0.1:443"}, ProbeInterval: 300,
	}, 200, &rule)
	testRequest(t, client, "POST", base+"/rules", nil, wire.Rule{
		Name: "unavailable", Entry: group.ID, Enabled: true, Targets: []string{"127.0.0.1:444"}, ProbeInterval: 300,
	}, 200, &unavailable)
	var enrollment struct{ Token string }
	testRequest(t, client, "POST", fmt.Sprintf("%s/admin/groups/%d/enrollment", base, group.ID), nil, nil, 201, &enrollment)
	credentials := make(map[int64]string)
	for _, name := range []string{"first", "fallback"} {
		var node wire.Identity
		testRequest(t, client, "POST", base+"/node/register", map[string]string{"Authorization": "Bearer " + enrollment.Token},
			wire.Registration{Name: name}, 201, &node)
		credentials[node.ID] = node.Token
	}
	cache, err := panel.nodeConfig(group.ID)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().Truncate(5 * time.Minute).Add(-10 * time.Minute)
	now := at.Add(280 * time.Second)
	panel.warmUntil = at.Add(-time.Hour)
	for id := range credentials {
		panel.devices[id] = wire.Device{ID: id, GroupID: group.ID, Revision: cache.value.Revision,
			AcceptLinkProbe: true, LastSeen: now, Online: true}
	}
	if err := panel.planRuleProbes(ctx, now); err != nil {
		t.Fatal(err)
	}
	if err := panel.planRuleProbes(ctx, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	// Exercise the second rule's slot without claiming a task.
	if _, err := panel.db.Exec("UPDATE rule_probe_slots SET due=at+interval WHERE rule=?", unavailable.ID); err != nil {
		t.Fatal(err)
	}
	dispatch := func(now time.Time) (int64, wire.DiagnosticTask) {
		t.Helper()
		if err := panel.probeRuleBatch(ctx, now, now.Unix()-2); err != nil {
			t.Fatal(err)
		}
		for node, check := range panel.diagnostics {
			if check.task.RuleID == rule.ID && check.ready {
				offered, err := panel.offerRuleProbe(ctx, node, digest(credentials[node]), check.task.ID)
				if err != nil || !offered {
					t.Fatalf("offer = %v, %v", offered, err)
				}
				return node, check.task
			}
		}
		t.Fatal("no periodic probe dispatched")
		return 0, wire.DiagnosticTask{}
	}
	firstNode, first := dispatch(now)
	if err := panel.receiveRuleProbe(ctx, firstNode, digest(credentials[firstNode]),
		&wire.DiagnosticResult{ID: first.ID, RuleStatus: "busy"}, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	panel.pollDiagnostic(firstNode, &wire.DiagnosticResult{ID: first.ID})
	secondNode, second := dispatch(now.Add(4 * time.Second))
	if secondNode == firstNode || second.ID == first.ID || second.ProbeOffset != at.Unix()/300 {
		t.Fatalf("retry did not keep the slot and use an alternate entry: first=%+v second=%+v", first, second)
	}
	expired := at.Add(317 * time.Second)
	if err := panel.probeRuleBatch(ctx, expired, expired.Unix()-2); err != nil {
		t.Fatal(err)
	}
	assertStored := func(rule int64, want string) {
		t.Helper()
		var state string
		if err := panel.db.QueryRow("SELECT status FROM rule_probe_slots WHERE rule=? AND at=? AND interval=300", rule, at.Unix()).
			Scan(&state); err != nil || state != want {
			t.Fatalf("stored status for rule %d = %q, %v, want %q", rule, state, err, want)
		}
	}
	assertStored(rule.ID, "timeout")
	assertStored(unavailable.ID, "offline")

	server.Close()
	if err := panel.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(options)
	if err != nil {
		t.Fatal(err)
	}
	panel = reopened
	server = httptest.NewServer(panel.Handler())
	base = server.URL + "/api"
	result := &wire.DiagnosticResult{ID: second.ID, RuleStatus: "running", Links: []wire.LinkProbe{
		{Network: "tcp", Lane: "primary", MeasuresTarget: true,
			Traces: []wire.RouteTrace{{Hops: 1, Steps: []wire.ProbeStep{{GroupID: group.ID, Status: "ok", LatencyMS: 8}, {Status: "failed"}}}}},
		{Network: "tcp", Lane: "backup", MeasuresTarget: true,
			Traces: []wire.RouteTrace{{Steps: []wire.ProbeStep{{Status: "ok", LatencyMS: 12}}}}},
	}}
	report := func(node int64) {
		t.Helper()
		headers := map[string]string{"Authorization": "Bearer " + credentials[node], "X-Node-ID": fmt.Sprint(node)}
		testRequest(t, client, "POST", base+"/node/sync", headers, wire.Heartbeat{AcceptLinkProbe: true, Diagnostic: result}, 200, nil)
	}
	report(firstNode)
	assertStored(rule.ID, "timeout")
	report(secondNode)
	report(secondNode)
	assertStored(rule.ID, "sampled")
	var history struct {
		Lanes                           []probeHistoryLane
		Points                          []probeHistoryPoint
		CompleteBuckets, SampledBuckets int
	}
	testRequest(t, client, "GET", fmt.Sprintf("%s/rules/%d/diagnose/history?range=live", base, rule.ID), nil, nil, 200, &history)
	if len(history.Points) != 12 || history.CompleteBuckets != 12 || history.SampledBuckets != 1 || len(history.Lanes) != 2 {
		t.Fatalf("unexpected timeline coverage or lanes: %+v", history)
	}
	primary, backup := history.Lanes[0], history.Lanes[1]
	if primary.Attempts != 1 || primary.Failed != 1 || len(primary.Segments) != 2 ||
		primary.Segments[0].Failed != 0 || primary.Segments[1].Failed != 1 ||
		backup.Attempts != 1 || backup.Failed != 0 {
		t.Fatalf("retry or missing periods changed the measured statistics: %+v", history.Lanes)
	}
	for _, point := range primary.Points {
		want := 0
		if point.At == at.Unix() {
			want = 1
		}
		if point.Attempts != want || point.Recorded != want {
			t.Fatalf("result did not appear in its dispatch slot: %+v", point)
		}
	}

	history.Lanes = nil
	testRequest(t, client, "GET", fmt.Sprintf("%s/rules/%d/diagnose/history?range=live", base, unavailable.ID), nil, nil, 200, &history)
	if len(history.Points) != 12 || len(history.Lanes) != 0 || history.SampledBuckets != 0 || history.CompleteBuckets != 12 {
		t.Fatalf("unexpected coverage without measured samples: %+v", history)
	}
	for _, point := range history.Points {
		if point.At == at.Unix() && point.Status != "offline" {
			t.Fatalf("offline slot lost its state: %+v", point)
		}
	}
}
