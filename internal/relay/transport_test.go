package relay

import (
	"context"
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"

	"hopx/internal/wire"

	"hopx/internal/certificate"
)

func TestRelayTransportsThroughTwoHops(t *testing.T) {
	cert, key, err := certificate.SelfSigned("127.0.0.1:443")
	if err != nil {
		t.Fatal(err)
	}
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	go func() {
		for {
			conn, err := tcp.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := udp.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = udp.WriteTo(buf[:n], addr)
		}
	}()

	for _, transports := range [][2]string{{"https", "ws"}, {"http", "wss"}, {"tls", "https"}, {"https", "wss-mux"}, {"ws", "http"}} {
		t.Run(transports[0]+"-"+transports[1], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			var hops []wire.Hop
			for _, transport := range transports {
				secret := rand.Text() + rand.Text()
				listener, err := Listen(ctx, "127.0.0.1:0", cert, key, secret, transport, 8)
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				hops = append(hops, wire.Hop{Addr: listener.Addr().String(), Cert: cert, Token: secret, Transport: transport})
			}
			route, err := Prepare(hops)
			if err != nil {
				t.Fatal(err)
			}
			for _, address := range []net.Addr{tcp.Addr(), udp.LocalAddr()} {
				conn, err := route.Dial(ctx, address.Network(), address.String())
				if err != nil {
					t.Fatalf("%s dial: %v", address.Network(), err)
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
				if _, err = io.WriteString(conn, "echo"); err != nil {
					t.Fatal(err)
				}
				var data [4]byte
				if _, err = io.ReadFull(conn, data[:]); err != nil || string(data[:]) != "echo" {
					t.Fatalf("%s echo: %q, %v", address.Network(), data, err)
				}
			}
		})
	}
}

func TestHTTPRelayCountsIncompleteHandshakes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cert, key, err := certificate.SelfSigned("127.0.0.1:443")
	if err != nil {
		t.Fatal(err)
	}
	slots := make(chan struct{}, 1)
	listener, err := ListenWithSlots(ctx, "127.0.0.1:0", cert, key, rand.Text()+rand.Text(), "http", slots)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	first, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	waitForSlots := func(want int) {
		t.Helper()
		for len(slots) != want {
			select {
			case <-ctx.Done():
				t.Fatalf("wanted %d allocated slots, got %d", want, len(slots))
			case <-time.After(time.Millisecond):
			}
		}
	}
	waitForSlots(1)
	second, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	_ = second.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if _, err := second.Read(b[:]); err == nil {
		t.Fatal("relay accepted a handshake after session capacity was exhausted")
	} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		t.Fatal("relay kept the excess connection open")
	}
	_ = first.Close()
	waitForSlots(0)
}

func TestEncryptedRelayChecksCertificateAndToken(t *testing.T) {
	cert, key, err := certificate.SelfSigned("127.0.0.1:443")
	if err != nil {
		t.Fatal(err)
	}
	otherCert, _, err := certificate.SelfSigned("127.0.0.1:443")
	if err != nil {
		t.Fatal(err)
	}
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()

	for _, transport := range []string{"tls", "tls-mux", "wss", "wss-mux", "https"} {
		t.Run(transport, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			token := rand.Text() + rand.Text()
			listener, err := Listen(ctx, "127.0.0.1:0", cert, key, token, transport, 16)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()

			original := wire.Hop{Addr: listener.Addr().String(), Cert: cert, Token: token, Transport: transport}
			var pool MuxPool
			defer pool.Close()
			for _, check := range []struct {
				name string
				hop  wire.Hop
				want bool
			}{
				{name: "trusted endpoint", hop: original, want: true},
				{name: "different certificate", hop: wire.Hop{Addr: original.Addr, Cert: otherCert, Token: token, Transport: transport}},
				{name: "different hostname", hop: wire.Hop{Addr: original.Addr, AdvertisedAddr: "wrong-name.test:443", Cert: cert, Token: token, Transport: transport}},
				{name: "different token", hop: wire.Hop{Addr: original.Addr, Cert: cert, Token: rand.Text() + rand.Text(), Transport: transport}},
			} {
				t.Run(check.name, func(t *testing.T) {
					session, err := PrepareWithMux([]wire.Hop{check.hop}, nil, &pool)
					if err != nil {
						t.Fatal(err)
					}
					deadline, stop := context.WithTimeout(ctx, time.Second)
					defer stop()
					conn, err := session.Dial(deadline, "tcp", target.Addr().String())
					if err == nil {
						defer conn.Close()
					}
					if (err == nil) != check.want {
						t.Fatalf("connection result = %v, want success=%t", err, check.want)
					}
				})
			}
		})
	}
}
