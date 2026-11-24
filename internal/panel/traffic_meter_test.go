package panel

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"hopx/internal/wire"
)

func TestTrafficDayAndQueuedReports(t *testing.T) {
	midnight := time.Date(2026, 11, 22, 16, 0, 0, 0, time.UTC)
	before := midnight.Add(-time.Second)
	if got := trafficDay(before); got != midnight.Unix()-86400 {
		t.Fatalf("before midnight: %d", got)
	}
	if got := trafficDay(midnight); got != midnight.Unix() {
		t.Fatalf("at midnight: %d", got)
	}
	for _, report := range []wire.Report{
		{ID: "queued", CollectedAt: before.Unix()},
		{ID: fmt.Sprintf("%020d-legacy", before.UnixNano())},
	} {
		if got := reportTrafficDay(&report, midnight); got != midnight.Unix()-86400 {
			t.Fatalf("late report assigned to %d", got)
		}
	}
}

func TestTrafficAttributionAndQuota(t *testing.T) {
	s, err := Open(Options{Database: filepath.Join(t.TempDir(), "traffic.db"), AdminPassword: "fixture-password"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	giveFixtureUsersActivePlan(t, s)
	_, err = s.db.Exec(`
		INSERT INTO groups(id,name,kind,first_port,last_port,ratio,user_group,offline_seconds,chain) VALUES
			(1,'entry','entry',10000,20000,1500,0,30,'[]'),(2,'exit','exit',10000,20000,3000,0,30,'[]'),
			(3,'virtual','chain',10000,20000,500,0,30,'[4,2]'),(4,'relay','relay',10000,20000,4000,0,30,'[]');
		INSERT INTO devices(id,group_id,token,registration) VALUES (1,1,'entry','{}'),(2,2,'exit','{}');
		INSERT INTO rules(id,owner,entry,port,json) VALUES
			(1,1,1,10001,'{"name":"rule","entry":1,"port":10001,"protocol":"tcp","enabled":true,"path":[3],"targets":["127.0.0.1:443"]}'),
			(2,1,2,10001,'{}');
	`)
	if err != nil {
		t.Fatal(err)
	}
	config, err := s.compileGroup(1)
	if err != nil || len(config.Rules) != 1 {
		t.Fatalf("config: %+v, %v", config, err)
	}
	rule := config.Rules[0]
	legacy := legacyTrafficMeter(config)
	if legacy.Revision == config.Revision || legacy.Rules[0].ExitMeter != "" || legacy.Rules[0].Ratio != rule.Ratio || config.Rules[0].ExitMeter != rule.ExitMeter {
		t.Fatalf("invalid legacy meter config: %+v", legacy)
	}
	meter, ok := wire.VerifyExitMeter(s.meterKey.Public().(ed25519.PublicKey), rule.ExitMeter, 2)
	if !ok || meter.Ratio != 500 || meter.VirtualGroup != 3 || rule.EntryRatio != 1500 || rule.Ratio != 2000 {
		t.Fatalf("invalid virtual-chain billing: %+v, %+v", rule, meter)
	}
	entry := wire.Report{ID: "entry-batch", Traffic: []wire.Traffic{
		{RuleID: 1, In: 39, Out: 250, Ratio: 1500},
		{RuleID: 2, In: 40, Out: 300, Ratio: 2000},
		{RuleID: 1, In: 61, Out: 250, Ratio: 1500},
	}}
	exit := wire.Report{ID: "exit-batch", Traffic: []wire.Traffic{{ExitMeter: rule.ExitMeter, In: 80, Out: 400}}}
	for range 2 {
		for _, report := range []struct {
			group int64
			value *wire.Report
		}{{1, &entry}, {2, &exit}} {
			if ack, err := s.accountTraffic(report.group, report.group, report.value); err != nil || ack != report.value.ID {
				t.Fatalf("traffic report: %q, %v", ack, err)
			}
		}
	}
	if _, err = s.accountTraffic(1, 1, &exit); err != nil {
		t.Fatal(err)
	}
	for _, want := range []struct {
		sql string
		sum int64
	}{
		{"SELECT used FROM users WHERE id=1", 1140},
		{"SELECT inbound+outbound FROM traffic WHERE rule_id=1", 600},
		{"SELECT count(*) FROM traffic WHERE rule_id=2", 0},
		{"SELECT sum(inbound+outbound) FROM daily_user_traffic", 600},
		{"SELECT inbound+outbound FROM daily_group_traffic WHERE group_id=1", 600},
		{"SELECT inbound+outbound FROM daily_group_traffic WHERE group_id=2", 480},
		{"SELECT inbound+outbound FROM exit_group_traffic WHERE group_id=3", 480},
	} {
		var got int64
		if err := s.db.QueryRow(want.sql).Scan(&got); err != nil || got != want.sum {
			t.Fatalf("%s: got %d, want %d (%v)", want.sql, got, want.sum, err)
		}
	}
	recorder := httptest.NewRecorder()
	s.adminStatistics(recorder, httptest.NewRequest("GET", "/", nil), User{Admin: true})
	var stats struct {
		TrafficToday int64
		GroupsToday  []trafficRank
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &stats); err != nil || stats.TrafficToday != 600 || len(stats.GroupsToday) != 3 {
		t.Fatalf("dashboard stats: %s (%v)", recorder.Body.String(), err)
	}

	if _, err = s.db.Exec("UPDATE users SET used=0,quota=1200,unlimited_traffic=0,expires=unixepoch()+600 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	rule.QuotaManaged = true
	meter.Managed = true
	exitTicket := meter.Sign(s.meterKey)
	entryGeneration, exitGeneration := token(), token()
	entryClaim := wire.QuotaClaim{Owner: 1, Want: true}
	exitClaim := wire.QuotaClaim{Owner: 1, Want: true, ExitMeter: exitTicket}
	ingress, _, err := s.allocateNodeQuota(1, 1, entryGeneration, []wire.Forward{rule}, []wire.QuotaClaim{entryClaim}, true)
	if err != nil || len(ingress) != 1 {
		t.Fatalf("entry grant: %+v (%v)", ingress, err)
	}
	egress, _, err := s.allocateNodeQuota(2, 2, exitGeneration, nil, []wire.QuotaClaim{exitClaim}, true)
	if err != nil || len(egress) != 1 || ingress[0].Allocated+egress[0].Allocated > 1200000 {
		t.Fatalf("exit grant: %+v (%v)", egress, err)
	}
	entryClaim.ID, entryClaim.Spent = ingress[0].ID, 600000
	exitClaim.ID, exitClaim.Spent = egress[0].ID, 240000
	for range 2 {
		if _, _, err = s.allocateNodeQuota(1, 1, entryGeneration, []wire.Forward{rule}, []wire.QuotaClaim{entryClaim}, true); err != nil {
			t.Fatal(err)
		}
		if _, _, err = s.allocateNodeQuota(2, 2, exitGeneration, nil, []wire.QuotaClaim{exitClaim}, true); err != nil {
			t.Fatal(err)
		}
	}
	exit.ID, exit.Traffic[0].ExitMeter = "managed-exit", exitTicket
	if _, err = s.accountTraffic(2, 2, &exit); err != nil {
		t.Fatal(err)
	}
	var used int64
	if err = s.db.QueryRow("SELECT used FROM users WHERE id=1").Scan(&used); err != nil || used != 840 {
		t.Fatalf("settled quota: %d (%v)", used, err)
	}
}
