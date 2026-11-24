package node

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"testing"
	"time"

	"hopx/internal/wire"
)

func TestForwardStopsWhenSubscriptionEnds(t *testing.T) {
	for _, mode := range []string{"builtin", "haproxy", "haproxy-metered"} {
		t.Run(mode, func(t *testing.T) {
			var binary string
			if mode != "builtin" {
				var err error
				binary, err = exec.LookPath("haproxy")
				if err != nil && bundledHAProxy == "" || runtime.GOOS != "linux" {
					t.Skip("requires Linux with HAProxy available")
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			engine := NewEngine("127.0.0.1", 16, 64)
			engine.proxy.binary = binary
			engine.proxy.stateDir = t.TempDir()
			defer engine.Close()
			target, address, siblingAddress := tcpEcho(t, 's'), freeTCP(t), freeTCP(t)
			port := func(address string) int {
				_, value, _ := net.SplitHostPort(address)
				result, _ := strconv.Atoi(value)
				return result
			}
			rule := wire.Forward{HAProxy: mode != "builtin", Expires: time.Now().Add(3 * time.Second).Unix(),
				Rule: wire.Rule{ID: 1, Enabled: true, Protocol: "tcp", Port: port(address), Targets: []string{target}}}
			sibling := rule
			sibling.ID, sibling.Port, sibling.Expires = 2, port(siblingAddress), time.Now().Add(time.Minute).Unix()
			if mode == "haproxy-metered" {
				rule.Expires = sibling.Expires
				rule.QuotaManaged, rule.HAProxyRatio = true, 1000
				engine.proxy.reportUntil = time.Now().Add(2 * time.Second)
			}
			if err := engine.Apply(ctx, wire.Config{Revision: "paid", Rules: []wire.Forward{rule, sibling}}, nil); err != nil {
				t.Fatal(err)
			}
			dial := func(address string) net.Conn {
				t.Helper()
				conn, err := net.DialTimeout("tcp", address, time.Second)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = conn.Close() })
				exercise(t, conn, 's')
				return conn
			}
			requireClosed := func(conn net.Conn) {
				t.Helper()
				_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
				_, err := conn.Read(make([]byte, 1))
				if err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
					t.Fatalf("forwarding connection remained open: %v", err)
				}
			}
			client, other := dial(address), dial(siblingAddress)
			requireClosed(client)
			exercise(t, other, 's')
			if conn, err := net.DialTimeout("tcp", address, time.Second); err == nil {
				defer conn.Close()
				requireClosed(conn)
			}

			rule.Expires = time.Now().Add(time.Minute).Unix()
			engine.authorizeProxyTraffic(5 * time.Second)
			if err := engine.Apply(ctx, wire.Config{Revision: "renewed", Rules: []wire.Forward{rule, sibling}}, nil); err != nil {
				t.Fatal(err)
			}
			client = dial(address)
			blocked, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer blocked.Close()
			conflict := sibling
			conflict.ID, conflict.Port = 3, blocked.Addr().(*net.TCPAddr).Port
			err = engine.Apply(ctx, wire.Config{Revision: "blocked", Rules: []wire.Forward{sibling, conflict}}, nil)
			if err == nil {
				t.Fatal("applying a conflicting configuration succeeded")
			}
			requireClosed(client)
			dial(siblingAddress)
			if err := engine.Apply(ctx, wire.Config{Revision: "removed", Rules: []wire.Forward{sibling}}, nil); err != nil {
				// HAProxy can wait for the previous process to drain before accepting a further revision.
				_ = other.Close()
				deadline := time.Now().Add(5 * time.Second)
				for err != nil && time.Now().Before(deadline) {
					time.Sleep(25 * time.Millisecond)
					err = engine.Apply(ctx, wire.Config{Revision: "removed", Rules: []wire.Forward{sibling}}, nil)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			requireClosed(client)
			dial(siblingAddress)
		})
	}
}

func TestManagedHAProxy(t *testing.T) {
	binary, err := exec.LookPath("haproxy")
	if err != nil && bundledHAProxy == "" || runtime.GOOS != "linux" {
		t.Skip("requires Linux with HAProxy available")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	engine := NewEngine("127.0.0.1", 1024, 2048)
	engine.proxy.binary = binary
	engine.proxy.stateDir = t.TempDir()
	defer engine.Close()
	tcpTarget := tcpEcho(t, 'h')
	udpTarget, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udpTarget.Close()
	go func() {
		buffer := make([]byte, 512)
		for {
			n, peer, err := udpTarget.ReadFrom(buffer)
			if err != nil {
				return
			}
			_, _ = udpTarget.WriteTo(buffer[:n], peer)
		}
	}()
	targetAddr := udpTarget.LocalAddr().String()
	bridge, err := net.Listen("tcp", targetAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()
	go func() {
		for {
			conn, err := bridge.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
		}
	}()
	count := 2
	if os.Getenv("HOPX_LOADTEST") == "1" {
		count = 512
	}
	config := wire.Config{Revision: "first"}
	for i := range count {
		protocol, target := "both", targetAddr
		if i == 0 {
			protocol, target = "tcp", tcpTarget
		}
		config.Rules = append(config.Rules, wire.Forward{
			HAProxy: true,
			Rule:    wire.Rule{ID: int64(i + 1), Enabled: true, Protocol: protocol, Port: 21000 + i, Targets: []string{target}},
		})
	}
	if err := engine.Apply(ctx, config, nil); err != nil {
		t.Fatal(err)
	}
	if _, countListeners, _ := engine.Status(); countListeners != 2*count-1 {
		t.Fatalf("listener count %d, want %d", countListeners, 2*count-1)
	}
	pid := engine.proxy.active.command.Process.Pid
	t.Logf("%d rules with %d listeners share HAProxy PID %d", count, 2*count-1, pid)
	roundTrip := func(network string, port int, want string) {
		t.Helper()
		conn, err := net.DialTimeout(network, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		if _, err := conn.Write([]byte("ping")); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(want))
		if _, err := io.ReadFull(conn, got); err != nil || string(got) != want {
			t.Fatalf("%s %d got %q: %v", network, port, got, err)
		}
	}
	roundTrip("tcp", 21000, "hphihnhg")
	for i := 1; i < count; i++ {
		roundTrip("tcp", 21000+i, "ping")
		roundTrip("udp", 21000+i, "ping")
	}
	if samples := engine.Traffic(); len(samples) != count {
		t.Fatalf("traffic reported for %d rules, want %d", len(samples), count)
	}
	over := wire.Config{Revision: "over", Rules: append(append([]wire.Forward{}, config.Rules...), wire.Forward{
		HAProxy: true,
		Rule:    wire.Rule{ID: int64(count + 1), Enabled: true, Protocol: "both", Port: 21000 + count, Targets: []string{targetAddr}},
	})}
	if count == 512 {
		if err := engine.Apply(ctx, over, nil); err == nil || engine.proxy.active.command.Process.Pid != pid {
			t.Fatalf("overcapacity config changed active process: %v", err)
		}
	}
	// A config that needs a TCP port already owned by another process must leave the active proxy serving.
	conflict, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conflict.Close()
	bad := wire.Config{Revision: "conflict", Rules: append([]wire.Forward{}, config.Rules...)}
	bad.Rules[0].Port = conflict.Addr().(*net.TCPAddr).Port
	if err := engine.Apply(ctx, bad, nil); err == nil || engine.proxy.active.command.Process.Pid != pid {
		t.Fatalf("port conflict changed active process: %v", err)
	}
	roundTrip("tcp", 21000, "hphihnhg")
	config.Revision = "second"
	config.Rules[0].Targets = []string{tcpEcho(t, 'j')}
	if err := engine.Apply(ctx, config, nil); err != nil {
		t.Fatal(err)
	}
	if engine.proxy.active.command.Process.Pid == pid {
		t.Fatal("HAProxy did not reload")
	}
	deadline := time.After(4 * time.Second)
	select {
	case <-engine.proxy.draining.done:
	case <-deadline:
		t.Fatal("idle predecessor did not exit")
	}
	roundTrip("tcp", 21000, "jpjijnjg")
	if err := engine.Apply(ctx, wire.Config{Revision: "clear"}, nil); err != nil {
		t.Fatal(fmt.Errorf("remove managed rules: %w", err))
	}
}

func TestHAProxyHandoffKeepsTCPAndUDP(t *testing.T) {
	engine := NewEngine("127.0.0.1", 16, 64)
	engine.proxy.binary, _ = exec.LookPath("haproxy")
	engine.proxy.stateDir = t.TempDir()
	if runtime.GOOS != "linux" || !engine.proxy.available() {
		t.Skip("requires Linux with HAProxy available")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer engine.Close()
	address := freeTCP(t)
	_, portString, _ := net.SplitHostPort(address)
	port, _ := strconv.Atoi(portString)
	target := tcpEcho(t, 'x')
	udp, err := net.ListenPacket("udp", target)
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	go func() {
		buffer := make([]byte, 1024)
		for {
			n, peer, err := udp.ReadFrom(buffer)
			if err != nil {
				return
			}
			_, _ = udp.WriteTo(buffer[:n], peer)
		}
	}()
	config := wire.Config{Revision: "builtin", Rules: []wire.Forward{
		{Rule: wire.Rule{ID: 1, Enabled: true, Port: port, Protocol: "both", Targets: []string{target}}},
	}}
	if err := engine.Apply(ctx, config, nil); err != nil {
		t.Fatal(err)
	}
	dial := func(network string) net.Conn {
		t.Helper()
		conn, err := net.DialTimeout(network, address, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		return conn
	}
	config.Rules[0].HAProxyRatio = 2000
	builtin, datagrams := dial("tcp"), dial("udp")
	checkUDP := func() {
		t.Helper()
		_ = datagrams.SetDeadline(time.Now().Add(time.Second))
		if _, err := datagrams.Write([]byte("echo")); err != nil {
			t.Fatal(err)
		}
		reply := make([]byte, 4)
		if _, err := io.ReadFull(datagrams, reply); err != nil || string(reply) != "echo" {
			t.Fatalf("UDP reply %q: %v", reply, err)
		}
	}
	exercise(t, builtin, 'x')
	checkUDP()
	key := listenerKey{host: "127.0.0.1", network: "tcp", port: port}
	listener := engine.listeners[key]
	config.Revision, config.Rules[0].HAProxy = "proxy", true
	cancelledSave := errors.New("simulated snapshot write failure")
	if err := engine.Apply(ctx, config, func() error { return cancelledSave }); !errors.Is(err, cancelledSave) {
		t.Fatalf("snapshot failure did not prevent cutover: %v", err)
	}
	if engine.proxy.active != nil || listener.tcpDone == nil {
		t.Fatal("snapshot failure changed the active TCP engine")
	}
	exercise(t, builtin, 'x')
	if err := engine.Apply(ctx, config, nil); err != nil {
		t.Fatal(err)
	}
	if bundledHAProxy != "" {
		files, err := os.ReadDir(engine.proxy.stateDir)
		if err != nil || len(files) != 0 {
			t.Fatalf("HAProxy executable was left on disk: %v, %v", files, err)
		}
	}
	if engine.listeners[key] != listener || listener.tcpDone != nil {
		t.Fatal("HAProxy did not take over the existing listener")
	}
	exercise(t, builtin, 'x')
	managed := dial("tcp")
	exercise(t, managed, 'x')
	checkUDP()
	config.Revision, config.Rules[0].HAProxy = "builtin-again", false
	if err := engine.Apply(ctx, config, nil); err != nil {
		t.Fatal(err)
	}
	if engine.listeners[key] != listener || listener.tcpDone == nil {
		t.Fatal("built-in forwarding did not resume on the same listener")
	}
	draining := engine.proxy.draining
	for _, conn := range []net.Conn{builtin, managed, dial("tcp")} {
		exercise(t, conn, 'x')
	}
	checkUDP()
	if !draining.running() {
		t.Fatal("HAProxy exited before its existing connection closed")
	}
	var in, out int64
	countProxyTraffic := func() {
		for _, report := range engine.Traffic() {
			if report.Ratio == 2000 {
				in += report.In
				out += report.Out
			}
		}
	}
	countProxyTraffic()
	exercise(t, managed, 'x')
	_ = managed.Close()
	select {
	case <-draining.done:
	case <-time.After(3 * time.Second):
		t.Fatal("idle HAProxy did not exit")
	}
	engine.Status()
	if engine.proxy.reserved != 0 {
		t.Fatal("idle HAProxy retained session capacity")
	}
	countProxyTraffic()
	if in != 3 || out != 6 {
		t.Fatalf("HAProxy reported %d B in and %d B out, want 3 B and 6 B", in, out)
	}
}
