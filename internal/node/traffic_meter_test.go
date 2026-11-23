package node

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net"
	"testing"
	"time"

	"hopx/internal/certificate"
	"hopx/internal/relay"
	"hopx/internal/wire"
)

func TestRelayExitMeasuresPayload(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cert, key, err := certificate.SelfSigned("127.0.0.1:443")
	if err != nil {
		t.Fatal(err)
	}
	pub, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	exit := NewEngine("127.0.0.1", 16, 32)
	exit.meter.Store(&meterVerifier{key: pub, group: 2})
	meter := wire.ExitMeter{Rule: 10, Owner: 1, Group: 2, Ratio: 500}
	ticket := meter.Sign(signer)
	startTarget := func(t *testing.T, network string) string {
		t.Helper()
		if network == "tcp" {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { listener.Close() })
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				if _, err := io.ReadFull(conn, make([]byte, 3)); err == nil {
					_, _ = io.WriteString(conn, "1234567")
				}
			}()
			return listener.Addr().String()
		}
		listener, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { listener.Close() })
		go func() {
			data := make([]byte, 32)
			if n, addr, err := listener.ReadFrom(data); err == nil && n == 3 {
				_, _ = listener.WriteTo([]byte("1234567"), addr)
			}
		}()
		return listener.LocalAddr().String()
	}
	for _, mode := range []string{"tls", "tls-mux", "ws", "wss", "wss-mux", "http", "https", "chain", "reverse", "native-udp", "legacy"} {
		t.Run(mode, func(t *testing.T) {
			run, stop := context.WithCancel(ctx)
			defer stop()
			secret := rand.Text() + rand.Text()
			var path []wire.Hop
			var hub *relay.ReverseHub
			pool := &relay.MuxPool{}
			defer pool.Close()
			switch mode {
			case "native-udp":
				secret = hex.EncodeToString([]byte(secret)[:32])
				ln, err := relay.ListenNativeUDP(run, "127.0.0.1:0", secret, exit.slots, exit.meterTarget)
				if err != nil {
					t.Fatal(err)
				}
				defer ln.Close()
				path = []wire.Hop{{Addr: ln.Addr().String(), Cert: cert, NativeUDPKey: secret, NativeUDPMeter: true}}
			case "reverse":
				hub = relay.NewReverseHub(true)
				hubListener, err := hub.Listen(run, "127.0.0.1:0", cert, key, secret)
				if err != nil {
					t.Fatal(err)
				}
				defer hubListener.Close()
				id := rand.Text()
				worker, err := relay.NewReverseClientWithSlots(run, id, secret, exit.slots, exit.meterTarget)
				if err != nil {
					t.Fatal(err)
				}
				worker.Update([]wire.ReverseEndpoint{{Address: hubListener.Addr().String(), Certificate: cert, Token: wire.ReverseCredential(secret, id)}})
				path = []wire.Hop{{ReverseID: id, Token: secret}}
				for until := time.Now().Add(3 * time.Second); ; {
					conn, err := hub.Open(id)
					if err == nil {
						conn.Close()
						break
					}
					if time.Now().After(until) {
						t.Fatal(err)
					}
					time.Sleep(10 * time.Millisecond)
				}
			default:
				transport := mode
				if mode == "chain" || mode == "legacy" {
					transport = "tls"
				}
				var target relay.MeterTarget
				if mode != "legacy" {
					target = exit.meterTarget
				}
				ln, err := relay.ListenWithSlots(run, "127.0.0.1:0", cert, key, secret, transport, exit.slots, target)
				if err != nil {
					t.Fatal(err)
				}
				defer ln.Close()
				path = []wire.Hop{{Addr: ln.Addr().String(), Cert: cert, Token: secret, Transport: transport}}
				if mode == "chain" {
					mid, err := relay.Listen(run, "127.0.0.1:0", cert, key, secret, "tls", 16)
					if err != nil {
						t.Fatal(err)
					}
					defer mid.Close()
					path = append([]wire.Hop{{Addr: mid.Addr().String(), Cert: cert, Token: secret, Transport: "tls"}}, path...)
				}
			}
			session, err := relay.PrepareWithMux(path, hub, pool)
			if err != nil {
				t.Fatal(err)
			}
			for _, network := range []string{"tcp", "udp"} {
				if network == "tcp" && mode == "native-udp" {
					continue
				}
				conn, accepted, err := session.DialMetered(run, network, startTarget(t, network), ticket)
				if err != nil || accepted != (mode != "legacy") {
					t.Fatalf("%s dial: accepted=%v, %v", network, accepted, err)
				}
				_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
				if _, err = io.WriteString(conn, "abc"); err != nil {
					t.Fatal(err)
				}
				var response [7]byte
				if _, err = io.ReadFull(conn, response[:]); err != nil || string(response[:]) != "1234567" {
					t.Fatalf("target response %q, %v", response, err)
				}
				conn.Close()
				if mode == "legacy" {
					if report := exit.Traffic(); len(report) != 0 {
						t.Fatalf("legacy exit unexpectedly recorded traffic: %+v", report)
					}
					continue
				}
				var in, out int64
				for until := time.Now().Add(time.Second); ; {
					for _, row := range exit.Traffic() {
						if row.ExitMeter != ticket {
							t.Fatal("traffic associated with the wrong rule")
						}
						in, out = in+row.In, out+row.Out
					}
					if in == 3 && out == 7 {
						break
					}
					if in > 3 || out > 7 || time.Now().After(until) {
						t.Fatalf("unexpected %s payload counts: in=%d out=%d", network, in, out)
					}
					time.Sleep(time.Millisecond)
				}
			}
		})
	}
}
