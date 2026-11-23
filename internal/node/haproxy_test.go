package node

import (
	"context"
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

func TestManagedHAProxy(t *testing.T) {
	binary, err := exec.LookPath("haproxy")
	if err != nil || runtime.GOOS != "linux" {
		t.Skip("requires Linux with HAProxy installed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	engine := NewEngine("127.0.0.1", 1024, 2048)
	engine.proxy.binary = binary
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
