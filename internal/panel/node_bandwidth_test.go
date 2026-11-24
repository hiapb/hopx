package panel

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"hopx/internal/wire"
)

func TestNodeBandwidthStreamAndCheckpoint(t *testing.T) {
	panel, err := Open(Options{Database: filepath.Join(t.TempDir(), "test.db"), AdminPassword: "test-password-123"})
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
	var group wire.DeviceGroup
	testRequest(t, client, "POST", base+"/admin/groups", nil, wire.DeviceGroup{Name: "probe", Kind: "monitor"}, 200, &group)
	var enrollment struct{ Token string }
	testRequest(t, client, "POST", fmt.Sprintf("%s/admin/groups/%d/enrollment", base, group.ID), nil, nil, 201, &enrollment)
	var node wire.Identity
	testRequest(t, client, "POST", base+"/node/register", map[string]string{"Authorization": "Bearer " + enrollment.Token},
		wire.Registration{Name: "first"}, 201, &node)
	headers := map[string]string{"Authorization": "Bearer " + node.Token, "X-Node-ID": fmt.Sprint(node.ID)}
	sample := wire.Bandwidth{HasTotals: true, InBytes: 100, OutBytes: 200}
	heartbeat := wire.Heartbeat{Metrics: wire.Metrics{Bandwidth: sample}}
	var sync wire.Sync
	testRequest(t, client, "POST", base+"/node/sync", headers, heartbeat, 200, &sync)
	if sync.LiveBandwidth {
		t.Fatal("node asked to send bandwidth before a subscriber connected")
	}
	bandwidthURL := base + "/node/bandwidth"
	testRequest(t, client, "POST", bandwidthURL, headers, sample, 401, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, "GET", base+"/nodes/events", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	stream := bufio.NewReader(response.Body)
	readLine := func() string {
		t.Helper()
		line, err := stream.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(line)
	}
	if line := readLine(); !strings.HasPrefix(line, "data: ") || response.StatusCode != 200 {
		t.Fatalf("no initial snapshot: %d %q", response.StatusCode, line)
	}
	if line := readLine(); line != "" {
		t.Fatalf("initial snapshot not terminated: %q", line)
	}
	sync = wire.Sync{}
	testRequest(t, client, "POST", base+"/node/sync", headers, heartbeat, 200, &sync)
	if !sync.LiveBandwidth {
		t.Fatal("subscribed node was not asked for bandwidth")
	}
	sample.InMbps, sample.OutMbps = 13.5, 5.2
	sample.InBytes, sample.OutBytes = 900, 1800
	testRequest(t, client, "POST", bandwidthURL, map[string]string{"Authorization": "Bearer wrong", "X-Node-ID": headers["X-Node-ID"]}, sample, 401, nil)
	testRequest(t, client, "POST", bandwidthURL, headers, sample, 204, nil)
	testRequest(t, client, "POST", bandwidthURL, headers, sample, 429, nil)
	if line := readLine(); line != "event: bandwidth" {
		t.Fatalf("missing bandwidth event: %q", line)
	}
	var changes []bandwidthEvent
	if err := json.Unmarshal([]byte(strings.TrimPrefix(readLine(), "data: ")), &changes); err != nil {
		t.Fatal(err)
	}
	if len(changes) != 1 || changes[0].ID != node.ID || changes[0].Bandwidth != sample {
		t.Fatalf("wrong bandwidth update: %+v", changes)
	}
	var inbound, outbound int64
	if err := panel.db.QueryRow("SELECT in_bytes,out_bytes FROM devices WHERE id=?", node.ID).Scan(&inbound, &outbound); err != nil ||
		inbound != 100 || outbound != 200 {
		t.Fatalf("live update changed the database checkpoint: %d %d %v", inbound, outbound, err)
	}

	cancel()
	deadline := time.Now().Add(time.Second)
	for {
		panel.mu.RLock()
		subscribed := panel.nodeBandwidth[node.ID] != nil
		panel.mu.RUnlock()
		if !subscribed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("bandwidth subscription did not close")
		}
		time.Sleep(10 * time.Millisecond)
	}
	sync = wire.Sync{}
	testRequest(t, client, "POST", base+"/node/sync", headers, heartbeat, 200, &sync)
	if sync.LiveBandwidth {
		t.Fatal("node kept uploading after the last viewer left")
	}
	panel.mu.Lock()
	delete(panel.devices, node.ID)
	panel.mu.Unlock()
	panel.invalidateNodeStatus("POST /api/node/register")
	var devices []wire.Device
	testRequest(t, client, "GET", base+"/nodes", nil, nil, 200, &devices)
	if len(devices) != 1 || devices[0].Online || devices[0].Metrics.Bandwidth != heartbeat.Metrics.Bandwidth {
		t.Fatalf("offline node lost its saved counters: %+v", devices)
	}
}
