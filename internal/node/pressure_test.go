package node

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	"hopx/internal/wire"
)

func TestListenerDensityUnderLoad(t *testing.T) {
	if os.Getenv("HOPX_LOADTEST") != "1" {
		t.Skip("set HOPX_LOADTEST=1 to run the Linux capacity fixture")
	}
	if runtime.GOOS != "linux" {
		t.Skip("Linux memory sampler")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	engine := NewEngine("127.0.0.1", 1024, 2048)
	defer engine.Close()
	remote := tcpEcho(t, 'h')
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	_ = udp.SetReadBuffer(256 << 10)
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, e := udp.ReadFromUDP(buf)
			if e != nil {
				return
			}
			_, _ = udp.WriteToUDP(buf[:n], addr)
		}
	}()
	rules := make([]wire.Forward, 0, 1000)
	for i := range 999 {
		rules = append(rules, wire.Forward{Rule: wire.Rule{ID: int64(i + 1), Port: 20000 + i, Enabled: true, Protocol: "tcp", Targets: []string{remote}}})
	}
	rules = append(rules, wire.Forward{Rule: wire.Rule{ID: 1000, Port: 20999, Enabled: true, Protocol: "udp", Targets: []string{udp.LocalAddr().String()}}})
	config := wire.Config{Revision: "load", Rules: rules}
	started := time.Now()
	if err = engine.Apply(ctx, config, nil); err != nil {
		t.Fatal(err)
	}
	t.Logf("configured 1000 listeners in %s", time.Since(started))
	t.Cleanup(func() { cancel() })
	exercise := func(proto string, count int, port int, payload []byte) []net.Conn {
		t.Helper()
		var wg sync.WaitGroup
		outcomes := make(chan error, count)
		clients := make(chan net.Conn, count)
		for i := range count {
			if proto == "udp" && i > 0 && i%30 == 0 {
				time.Sleep(10 * time.Millisecond)
			}
			wg.Go(func() {
				addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
				c, e := net.DialTimeout(proto, addr, 5*time.Second)
				if e != nil {
					outcomes <- e
					return
				}
				clients <- c
				_ = c.SetDeadline(time.Now().Add(6 * time.Second))
				if _, e = c.Write(payload); e != nil {
					outcomes <- e
					return
				}
				size := len(payload)
				if proto == "tcp" {
					size++
				}
				response := make([]byte, size)
				_, e = io.ReadFull(c, response)
				if e != nil {
					outcomes <- fmt.Errorf("%s client %d: %w", proto, i, e)
				}
			})
		}
		wg.Wait()
		close(outcomes)
		close(clients)
		active := make([]net.Conn, 0, count)
		for c := range clients {
			active = append(active, c)
			t.Cleanup(func() { _ = c.Close() })
		}
		failed := 0
		for e := range outcomes {
			if failed == 0 {
				t.Logf("first %s error: %v", proto, e)
			}
			failed++
		}
		if failed > 0 {
			t.Fatalf("%d of %d %s requests failed", failed, count, proto)
		}
		return active
	}
	tcpClients := exercise("tcp", 400, 20001, []byte("z"))
	udpClients := exercise("udp", 600, 20999, []byte("synthetic datagram"))
	var gauge sampler
	sample := func() {
		metrics := gauge.sample(".")
		t.Logf("TCP %d, UDP %d, RSS %.2f MiB, UDP queue drops %d", engine.activeTCP.Load(), engine.activeUDP.Load(), float64(metrics.RSS)/(1<<20), engine.udpDropped.Load())
		if _, listeners, _ := engine.Status(); listeners != 1000 {
			t.Fatalf("active listeners: %d", listeners)
		}
	}
	sample()
	if value := os.Getenv("HOPX_LOADTEST_DURATION"); value != "" {
		duration, err := time.ParseDuration(value)
		if err != nil || duration <= 0 {
			t.Fatalf("invalid HOPX_LOADTEST_DURATION: %q", value)
		}
		alternate := tcpEcho(t, 'b')
		refresh := func(clients []net.Conn, payload, expected string) {
			t.Helper()
			reply := make([]byte, len(expected))
			for i, c := range clients {
				if err := c.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
					t.Fatal(err)
				}
				if _, err := io.WriteString(c, payload); err != nil {
					t.Fatalf("session %d write: %v", i, err)
				}
				if _, err := io.ReadFull(c, reply); err != nil || string(reply) != expected {
					t.Fatalf("session %d reply: %q, %v", i, reply, err)
				}
			}
		}
		deadline := time.NewTimer(duration)
		defer deadline.Stop()
		tick := time.NewTicker(5 * time.Second)
		defer tick.Stop()
		for round := 1; ; round++ {
			select {
			case <-deadline.C:
				sample()
				return
			case <-tick.C:
			}
			if round%12 == 0 {
				target := alternate
				if round%24 == 0 {
					target = remote
				}
				rules[0].Targets = []string{target}
				config.Revision = strconv.Itoa(round)
				if err := engine.Apply(ctx, config, nil); err != nil {
					t.Fatal(err)
				}
				sample()
			}
			refresh(tcpClients, "z", "hz")
			refresh(udpClients, "synthetic datagram", "synthetic datagram")
		}
	}
}
