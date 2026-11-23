package relay

import (
	"context"
	"crypto/rand"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"hopx/internal/wire"

	"hopx/internal/certificate"
)

func TestMultiplexesForwardingStreams(t *testing.T) {
	for _, transport := range []string{"tls-mux", "wss-mux"} {
		t.Run(transport, func(t *testing.T) { testMultiplexing(t, transport) })
	}
}

func testMultiplexing(t *testing.T, transport string) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	cert, key, err := certificate.SelfSigned("127.0.0.1:443")
	if err != nil {
		t.Fatal(err)
	}
	token := rand.Text() + rand.Text()
	outlet, err := Listen(ctx, "127.0.0.1:0", cert, key, token, transport, 96)
	if err != nil {
		t.Fatal(err)
	}
	defer outlet.Close()
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	go func() {
		for {
			conn, err := backend.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	var pool MuxPool
	defer pool.Close()
	hop := wire.Hop{Addr: outlet.Addr().String(), Cert: cert, Token: token, Transport: transport}
	path, err := PrepareWithMux([]wire.Hop{hop}, nil, &pool)
	if err != nil {
		t.Fatal(err)
	}
	const streams = 56
	results := make(chan net.Conn, streams)
	var clients sync.WaitGroup
	for range streams {
		clients.Go(func() {
			conn, err := path.Dial(ctx, "tcp", backend.Addr().String())
			if err != nil {
				t.Error(err)
				return
			}
			if _, err = io.WriteString(conn, "ping"); err == nil {
				var response [4]byte
				_, err = io.ReadFull(conn, response[:])
				if err == nil && string(response[:]) != "ping" {
					t.Error("invalid stream response")
				}
			}
			if err != nil {
				t.Error(err)
			}
			results <- conn
		})
	}
	clients.Wait()
	close(results)
	for conn := range results {
		defer conn.Close()
	}
	peer := pool.peers[hop]
	if peer == nil || peer.session == nil || peer.session.NumStreams() != streams {
		t.Fatal("forwarding streams did not share one authenticated carrier")
	}
	plain, err := Prepare([]wire.Hop{hop})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := plain.Dial(ctx, "tcp", backend.Addr().String())
	if err != nil {
		t.Fatalf("client without multiplexing: %v", err)
	}
	conn.Close()
}
