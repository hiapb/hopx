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
	for _, id := range []int64{inherited.ID, fast.ID, normal.ID} {
		_, err := s.db.Exec(`INSERT INTO rule_probe_samples(rule,bucket,sampled,links)
			VALUES(?,(unixepoch()-90)/300,unixepoch()-90,?)`, id, string(raw))
		if err != nil {
			t.Fatal(err)
		}
	}
	testRequest(t, client, "PUT", base+"/admin/settings", nil, map[string]string{"ruleProbeInterval": "30"}, 400, nil)
	testRequest(t, client, "PUT", base+"/admin/settings", nil, map[string]string{"ruleProbeInterval": "60"}, 204, nil)

	assertHistory := func(id int64, interval, attempts int) {
		t.Helper()
		var history struct {
			Interval int
			Lanes    []probeHistoryLane
		}
		testRequest(t, client, "GET", fmt.Sprintf("%s/rules/%d/diagnose/history?range=live", base, id), nil, nil, 200, &history)
		if history.Interval != interval || len(history.Lanes) != 1 || history.Lanes[0].Attempts != attempts ||
			len(history.Lanes[0].Points) != 3600/interval+1 {
			t.Fatalf("rule %d history interval=%d, lanes=%+v", id, history.Interval, history.Lanes)
		}
	}
	var updates sync.WaitGroup
	for range 5 {
		updates.Go(func() { s.saveRuleProbe(context.Background(), inherited.ID, links) })
	}
	updates.Wait()
	s.saveRuleProbe(context.Background(), fast.ID, links)
	s.saveRuleProbe(context.Background(), normal.ID, links)
	assertHistory(inherited.ID, 60, 2)
	assertHistory(fast.ID, 60, 2)
	assertHistory(normal.ID, 300, 1)

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
	assertHistory(normal.ID, 300, 1)
}
