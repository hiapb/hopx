package node

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/pires/go-proxyproto"
	"hopx/internal/certificate"
	"hopx/internal/relay"
	"hopx/internal/wire"
)

func tcpEcho(t *testing.T, prefix byte) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				buf := make([]byte, 1)
				for {
					if _, err := io.ReadFull(conn, buf); err != nil {
						return
					}
					if _, err := conn.Write([]byte{prefix, buf[0]}); err != nil {
						return
					}
				}
			}()
		}
	}()
	return listener.Addr().String()
}

func freeTCP(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := l.Addr().String()
	l.Close()
	return address
}

func nodeHop(t *testing.T, ctx context.Context, transport string) wire.Hop {
	t.Helper()
	address := freeTCP(t)
	cert, key, err := certificate.SelfSigned(address)
	if err != nil {
		t.Fatal(err)
	}
	auth := rand.Text()
	ln, err := relay.Listen(ctx, address, cert, key, auth, transport, 64)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return wire.Hop{Addr: address, Cert: cert, Token: auth, Transport: transport}
}

func exercise(t *testing.T, c net.Conn, expected byte) {
	t.Helper()
	_ = c.SetDeadline(time.Now().Add(4 * time.Second))
	if _, e := c.Write([]byte("z")); e != nil {
		t.Fatal(e)
	}
	reply := make([]byte, 2)
	if _, e := io.ReadFull(c, reply); e != nil {
		t.Fatal(e)
	}
	if reply[0] != expected || reply[1] != 'z' {
		t.Fatalf("got %q, want %q", reply, []byte{expected, 'z'})
	}
}

func TestTLSInboundHandshakePolicy(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	address := freeTCP(t)
	_, portText, _ := net.SplitHostPort(address)
	port, _ := strconv.Atoi(portText)
	cert, key, err := certificate.SelfSigned("relay.test:443")
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(cert)) {
		t.Fatal("cannot load test certificate")
	}
	e := NewEngine("127.0.0.1", 8, 16)
	rule := wire.Forward{Rule: wire.Rule{
		ID: 1, Enabled: true, Protocol: "tcp", Port: port,
		Targets: []string{tcpEcho(t, 'T')}, TLSCert: cert, TLSKey: key,
		TLSServerNames: []string{"relay.test"}, TLSALPN: []string{"http/1.1"},
	}}
	if err = e.Apply(ctx, wire.Config{Revision: "tls", Rules: []wire.Forward{rule}}, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	dialer := &net.Dialer{Timeout: time.Second}
	for _, tc := range []struct {
		name string
		alpn []string
		ok   bool
	}{
		{"relay.test", []string{"http/1.1"}, true},
		{"wrong.test", []string{"http/1.1"}, false},
		{"relay.test", nil, false},
		{"relay.test", []string{"h2"}, false},
	} {
		conn, err := tls.DialWithDialer(dialer, "tcp", address, &tls.Config{
			ServerName: tc.name, NextProtos: tc.alpn, RootCAs: roots,
		})
		if (err == nil) != tc.ok {
			t.Fatalf("TLS handshake with %s and %v: %v", tc.name, tc.alpn, err)
		}
		if conn != nil {
			exercise(t, conn, 'T')
			conn.Close()
		}
	}
}

func TestSharedTLSRoutesKeepOneListener(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	address := freeTCP(t)
	_, portText, _ := net.SplitHostPort(address)
	port, _ := strconv.Atoi(portText)
	cert, key, err := certificate.SelfSigned("shared.test:443")
	if err != nil {
		t.Fatal(err)
	}
	engine := NewEngine("127.0.0.1", 1, 16)
	t.Cleanup(engine.Close)
	parent := wire.Forward{Rule: wire.Rule{ID: 1, Enabled: true, Protocol: "tcp", Port: port, TLSShared: true, TLSCert: cert, TLSKey: key}}
	secondPort := port + 1
	if secondPort > 65534 {
		secondPort = port - 2
	}
	first := wire.Forward{Rule: wire.Rule{ID: 2, Enabled: true, Protocol: "tcp", Port: secondPort,
		TLSSharedPort: port, TLSServerNames: []string{"one.test"}, Targets: []string{tcpEcho(t, 'A')}}}
	second := wire.Forward{Rule: wire.Rule{ID: 3, Enabled: true, Protocol: "tcp", Port: secondPort + 1,
		TLSSharedPort: port, TLSServerNames: []string{"two.test"}, Targets: []string{tcpEcho(t, 'B')}}}
	if err = engine.Apply(ctx, wire.Config{Revision: "shared", Rules: []wire.Forward{parent, first, second}}, nil); err != nil {
		t.Fatal(err)
	}
	if _, listeners, _ := engine.Status(); listeners != 1 {
		t.Fatalf("expected one listener, got %d", listeners)
	}
	dial := func(host string) (net.Conn, error) {
		return tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", address, &tls.Config{
			ServerName: host, InsecureSkipVerify: true, // The test uses an ephemeral certificate.
		})
	}
	open := func(host string) net.Conn {
		t.Helper()
		conn, err := dial(host)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		return conn
	}
	a := open("one.test")
	exercise(t, a, 'A')
	exercise(t, open("two.test"), 'B')
	if conn, err := dial("unknown.test"); err == nil {
		conn.Close()
		t.Fatal("unknown SNI was accepted")
	}
	first.Targets = []string{tcpEcho(t, 'C')}
	if err = engine.Apply(ctx, wire.Config{Revision: "changed", Rules: []wire.Forward{parent, first}}, nil); err != nil {
		t.Fatal(err)
	}
	exercise(t, a, 'A')
	exercise(t, open("one.test"), 'C')
	if conn, err := dial("two.test"); err == nil {
		conn.Close()
		t.Fatal("removed SNI was accepted")
	}
}

func TestTwoHopHotUpdateAndFailedBind(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hops := []wire.Hop{nodeHop(t, ctx, "wss"), nodeHop(t, ctx, "tls")}
	address := freeTCP(t)
	_, portText, _ := net.SplitHostPort(address)
	port, _ := strconv.Atoi(portText)
	first, second := tcpEcho(t, 'a'), tcpEcho(t, 'b')
	engine := NewEngine("127.0.0.1", 4, 32)
	defer engine.Close()
	rule := wire.Rule{ID: 1, Port: port, Protocol: "tcp", Enabled: true, Targets: []string{first}, Path: []int64{1, 2}}
	config := wire.Config{Revision: "1", Rules: []wire.Forward{{Rule: rule, Routes: [][]wire.Hop{hops}}}}
	if e := engine.Apply(ctx, config, nil); e != nil {
		t.Fatal(e)
	}
	old, e := net.Dial("tcp", address)
	if e != nil {
		t.Fatal(e)
	}
	defer old.Close()
	exercise(t, old, 'a')
	config.Revision = "2"
	config.Rules[0].Targets = []string{second}
	if e = engine.Apply(ctx, config, nil); e != nil {
		t.Fatal(e)
	}
	next, e := net.Dial("tcp", address)
	if e != nil {
		t.Fatal(e)
	}
	defer next.Close()
	exercise(t, next, 'b')
	exercise(t, old, 'a')
	blocked, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer blocked.Close()
	rule.Port = blocked.Addr().(*net.TCPAddr).Port
	rule.ID = 2
	config.Revision = "3"
	config.Rules = append(config.Rules, wire.Forward{Rule: rule, Routes: [][]wire.Hop{hops}})
	if e = engine.Apply(ctx, config, nil); e == nil {
		t.Fatal("conflicting bind succeeded")
	}
	if applied, _, _ := engine.Status(); applied != "2" {
		t.Fatal(applied)
	}
	after, e := net.Dial("tcp", address)
	if e != nil {
		t.Fatal(e)
	}
	defer after.Close()
	exercise(t, after, 'b')
}

func TestTwoHopUDP(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hops := []wire.Hop{nodeHop(t, ctx, "wss"), nodeHop(t, ctx, "tls")}
	address, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udp, err := net.ListenUDP("udp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	go func() {
		buf := make([]byte, 128)
		for {
			n, peer, e := udp.ReadFromUDP(buf)
			if e != nil {
				return
			}
			_, _ = udp.WriteToUDP(buf[:n], peer)
		}
	}()
	route, err := relay.Prepare(hops)
	if err != nil {
		t.Fatal(err)
	}
	timed, stop := context.WithTimeout(ctx, 5*time.Second)
	defer stop()
	conn, err := route.Dial(timed, "udp", udp.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
	if _, err = conn.Write([]byte("udp-through-two-hops")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 100)
	n, err := conn.Read(buf)
	if err != nil || string(buf[:n]) != "udp-through-two-hops" {
		t.Fatalf("response %q: %v", buf[:n], err)
	}
}

func TestFallbackUsesBackupWhenPrimaryStalls(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stalled, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer stalled.Close()
	go func() {
		conn, err := stalled.Accept()
		if err == nil {
			defer conn.Close()
			<-ctx.Done()
		}
	}()
	cert, _, err := certificate.SelfSigned(stalled.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	backup := nodeHop(t, ctx, "tls")
	engine := NewEngine("127.0.0.1", 8, 16)
	t.Cleanup(engine.Close)
	_, portText, _ := net.SplitHostPort(freeTCP(t))
	port, _ := strconv.Atoi(portText)
	f := wire.Forward{
		Rule: wire.Rule{ID: 1, Enabled: true, Protocol: "tcp", Port: port,
			Path: []int64{2}, BackupPath: []int64{3}, Targets: []string{tcpEcho(t, 'R')}},
		Routes: [][]wire.Hop{{{Addr: stalled.Addr().String(), Cert: cert, Token: rand.Text()}}},
		Backup: [][]wire.Hop{{backup}},
	}
	if err := engine.Apply(ctx, wire.Config{Revision: "backup", Rules: []wire.Forward{f}}, nil); err != nil {
		t.Fatal(err)
	}
	result := engine.checkConnectivity(ctx, wire.DiagnosticTask{ID: "probe", RuleID: 1})
	if !result.Connected || !result.Backup {
		t.Fatalf("backup diagnostic: %+v", result)
	}
	if engine.activeRules[1].lastTCPRoute.Load() != 0 {
		t.Fatal("a diagnostic probe must not count as forwarded traffic")
	}
	_ = stalled.Close()
	client, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", portText), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = client.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 2)
	if _, err = io.ReadFull(client, payload); err != nil || string(payload) != "Rx" {
		t.Fatalf("backup forwarded %q: %v", payload, err)
	}
	result = engine.checkRuleRoutes(ctx, wire.DiagnosticTask{ID: "status", RuleID: 1, Revision: "backup"})
	if len(result.RecentRoutes) != 1 || !result.RecentRoutes[0].Backup || result.RecentRoutes[0].Network != "tcp" {
		t.Fatalf("last forwarded route: %+v", result.RecentRoutes)
	}
}

func TestReverseEgress(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reverseAddress := freeTCP(t)
	cert, key, err := certificate.SelfSigned(reverseAddress)
	if err != nil {
		t.Fatal(err)
	}
	hub := relay.NewReverseHub(true)
	ingressToken := rand.Text() + rand.Text()
	reverse, err := hub.Listen(ctx, reverseAddress, cert, key, ingressToken)
	if err != nil {
		t.Fatal(err)
	}
	defer reverse.Close()
	reverseID, egressToken := rand.Text(), rand.Text()+rand.Text()
	egress, err := relay.NewReverseClient(ctx, reverseID, egressToken, 32)
	if err != nil {
		t.Fatal(err)
	}
	egress.Update([]wire.ReverseEndpoint{{Address: reverseAddress, Certificate: cert, Token: wire.ReverseCredential(ingressToken, reverseID)}})
	target := tcpEcho(t, 'r')
	path, err := relay.PrepareWithReverse([]wire.Hop{{ReverseID: reverseID, Token: egressToken}}, hub)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(4 * time.Second)
	for {
		client, err := path.Dial(ctx, "tcp", target)
		if err == nil {
			defer client.Close()
			exercise(t, client, 'r')
			return
		}
		if time.Now().After(deadline) {
			t.Fatal(err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestUDPProxyProtocolV2PreservesPayload(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	target, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	probe, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	port := probe.LocalAddr().(*net.UDPAddr).Port
	probe.Close()
	engine := NewEngine("127.0.0.1", 8, 8)
	defer engine.Close()
	config := wire.Config{Revision: "udp-proxy", Rules: []wire.Forward{{Rule: wire.Rule{
		ID: 1, Port: port, Protocol: "udp", Enabled: true, ProxyOut: true, ProxyOutVersion: 2,
		Targets: []string{target.LocalAddr().String()},
	}}}}
	if err = engine.Apply(ctx, config, nil); err != nil {
		t.Fatal(err)
	}
	client, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = target.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err = client.Write([]byte("payload")); err != nil {
		t.Fatal(err)
	}
	var data [128]byte
	n, _, err := target.ReadFromUDP(data[:])
	if err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(bytes.NewReader(data[:n]))
	header, err := proxyproto.Read(reader)
	if err != nil {
		t.Fatal(err)
	}
	source, dest, ok := header.UDPAddrs()
	if !ok || source.Port != client.LocalAddr().(*net.UDPAddr).Port || dest.Port != port {
		t.Fatalf("incorrect datagram header: %+v", header)
	}
	payload, err := io.ReadAll(reader)
	if err != nil || string(payload) != "payload" {
		t.Fatalf("unexpected payload %q: %v", payload, err)
	}
}

func TestUDPSmartBindReturnsFromReceivingAddress(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux supports additional IPv4 addresses on loopback")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	target, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		var packet [65535]byte
		for {
			n, source, err := target.ReadFromUDP(packet[:])
			if err != nil {
				return
			}
			_, _ = target.WriteToUDP(packet[:n], source)
		}
	}()
	probe, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	port := probe.LocalAddr().(*net.UDPAddr).Port
	probe.Close()
	engine := NewEngine("127.0.0.1", 8, 8)
	defer engine.Close()
	engine.udpBind = []string{"127.0.0.1", "127.0.0.2"}
	cfg := wire.Config{Revision: "udp-smart-bind", Rules: []wire.Forward{{Rule: wire.Rule{
		ID: 1, Port: port, Protocol: "udp", Enabled: true, Targets: []string{target.LocalAddr().String()},
	}}}}
	if err = engine.Apply(ctx, cfg, nil); err != nil {
		t.Fatal(err)
	}
	large := bytes.Repeat([]byte("echo"), 15000)
	payloads := [][]byte{nil, []byte("echo"), large}
	for _, address := range []string{"127.0.0.1", "127.0.0.2"} {
		client, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.ParseIP(address), Port: port})
		if err != nil {
			t.Fatal(err)
		}
		_ = client.SetDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, len(large)+1)
		for _, payload := range payloads {
			if _, err = client.Write(payload); err != nil {
				client.Close()
				t.Fatal(err)
			}
			n, err := client.Read(buf)
			if err != nil || !bytes.Equal(buf[:n], payload) {
				client.Close()
				t.Fatalf("%s: sent %d bytes, received %d: %v", address, len(payload), n, err)
			}
		}
		client.Close()
	}
}
