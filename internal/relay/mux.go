package relay

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	gostdial "github.com/go-gost/core/dialer"
	"github.com/hashicorp/yamux"
	"hopx/internal/wire"
)

const muxProtocol = "hopx-relay-mux/1"

type MuxPool struct {
	mu     sync.Mutex
	peers  map[wire.Hop]*muxPeer
	closed bool
	sweep  time.Time
}

type muxPeer struct {
	gate    chan struct{}
	session *yamux.Session
	used    time.Time
	pins    int
	closed  bool
}

func (p *MuxPool) peer(hop wire.Hop) *muxPeer {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	if p.peers == nil {
		p.peers = make(map[wire.Hop]*muxPeer)
	}
	now := time.Now()
	if now.After(p.sweep) {
		p.sweep = now.Add(30 * time.Second)
		for key, peer := range p.peers {
			if peer.pins == 0 && now.Sub(peer.used) > 2*time.Minute && (peer.session == nil || peer.session.NumStreams() == 0) {
				if peer.session != nil {
					_ = peer.session.Close()
				}
				delete(p.peers, key)
			}
		}
	}
	peer := p.peers[hop]
	if peer == nil && len(p.peers) < 32 {
		peer = &muxPeer{gate: make(chan struct{}, 1)}
		p.peers[hop] = peer
	}
	if peer != nil {
		peer.pins++
		peer.used = now
	}
	return peer
}

func (p *MuxPool) Close() {
	p.mu.Lock()
	peers := p.peers
	p.peers, p.closed = nil, true
	p.mu.Unlock()
	for _, peer := range peers {
		peer.gate <- struct{}{}
		peer.closed = true
		if peer.session != nil {
			_ = peer.session.Close()
			peer.session = nil
		}
		<-peer.gate
	}
}

func (p *MuxPool) open(ctx context.Context, target endpoint) (net.Conn, error) {
	hop := target.hop
	peer := p.peer(hop)
	if peer == nil {
		return nil, errors.New("multiplexed relay connections exhausted")
	}
	defer func() {
		p.mu.Lock()
		peer.pins--
		p.mu.Unlock()
	}()
	select {
	case peer.gate <- struct{}{}:
		defer func() { <-peer.gate }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if peer.closed {
		return nil, net.ErrClosed
	}
	if peer.session == nil || peer.session.IsClosed() {
		conn, err := dialCarrier(ctx, target)
		if err != nil {
			return nil, err
		}
		if err = authenticateCarrier(ctx, conn, hop.Token, true); err != nil {
			conn.Close()
			return nil, err
		}
		peer.session, err = yamux.Client(conn, muxConfig())
		if err != nil {
			conn.Close()
			return nil, err
		}
	}
	return peer.session.OpenStream()
}

const websocketMuxPrefix byte = 0

func dialCarrier(ctx context.Context, target endpoint) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	if target.hop.Transport == "wss-mux" {
		raw, err := dialer.DialContext(ctx, "tcp", target.address)
		if err != nil {
			return nil, err
		}
		conn, err := target.websocket.Handshake(ctx, raw, gostdial.AddrHandshakeOption(target.address))
		if err != nil {
			raw.Close()
			return nil, err
		}
		_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		_, err = conn.Write([]byte{websocketMuxPrefix})
		_ = conn.SetWriteDeadline(time.Time{})
		if err != nil {
			conn.Close()
			return nil, err
		}
		return conn, nil
	}
	cfg := target.tls.Clone()
	cfg.NextProtos = []string{muxProtocol}
	tlsDialer := tls.Dialer{NetDialer: dialer, Config: cfg}
	conn, err := tlsDialer.DialContext(ctx, "tcp", target.address)
	if err != nil {
		return nil, err
	}
	if conn.(*tls.Conn).ConnectionState().NegotiatedProtocol != muxProtocol {
		conn.Close()
		return nil, errors.New("relay did not negotiate multiplexing")
	}
	return conn, nil
}

func serveWebsocketMux(ctx context.Context, ln net.Listener, h connectionHandler, token string, slots chan struct{}) {
	handshakes := make(chan struct{}, min(cap(slots), 32))
	carriers := make(chan struct{}, min(cap(slots), 32))
	for {
		raw, err := ln.Accept()
		if err != nil {
			return
		}
		select {
		case handshakes <- struct{}{}:
			go func() {
				defer raw.Close()
				_ = raw.SetReadDeadline(time.Now().Add(5 * time.Second))
				reader := bufio.NewReaderSize(raw, 4096)
				first, err := reader.Peek(1)
				<-handshakes
				if err != nil {
					return
				}
				_ = raw.SetReadDeadline(time.Time{})
				conn := &bufferedRelayConn{Conn: raw, reader: reader}
				if first[0] != websocketMuxPrefix {
					select {
					case slots <- struct{}{}:
						defer func() { <-slots }()
						handleRelay(ctx, h, conn)
					default:
					}
					return
				}
				_, _ = reader.Discard(1)
				select {
				case carriers <- struct{}{}:
					defer func() { <-carriers }()
					serveCarrier(ctx, conn, h, token, slots)
				default:
				}
			}()
		default:
			_ = raw.Close()
		}
	}
}

func serveCarrier(ctx context.Context, conn net.Conn, h connectionHandler, token string, slots chan struct{}) {
	defer conn.Close()
	if authenticateCarrier(ctx, conn, token, false) != nil {
		return
	}
	session, err := yamux.Server(conn, muxConfig())
	if err != nil {
		return
	}
	defer session.Close()
	stop := context.AfterFunc(ctx, func() { _ = session.Close() })
	defer stop()
	serve(session, slots, func(conn net.Conn) { handleRelay(ctx, h, conn) })
}

func authenticateCarrier(ctx context.Context, conn net.Conn, token string, client bool) error {
	if len(token) > 256 {
		return errors.New("relay token is too long")
	}
	deadline := time.Now().Add(5 * time.Second)
	if limit, ok := ctx.Deadline(); ok && limit.Before(deadline) {
		deadline = limit
	}
	_ = conn.SetDeadline(deadline)
	defer conn.SetDeadline(time.Time{})
	var header [2]byte
	if client {
		binary.BigEndian.PutUint16(header[:], uint16(len(token)))
		if _, err := conn.Write(append(header[:], []byte(token)...)); err != nil {
			return err
		}
		if _, err := io.ReadFull(conn, header[:1]); err != nil || header[0] != 1 {
			return errors.New("relay refused multiplexing authentication")
		}
		return nil
	}
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return err
	}
	size := int(binary.BigEndian.Uint16(header[:]))
	if size != len(token) {
		return errors.New("invalid multiplexing credentials")
	}
	var key [256]byte
	if _, err := io.ReadFull(conn, key[:size]); err != nil {
		return err
	}
	if !sameToken(string(key[:size]), token) {
		return errors.New("invalid multiplexing credentials")
	}
	_, err := conn.Write([]byte{1})
	return err
}

func serveMuxListener(ctx context.Context, ln net.Listener, h connectionHandler, token string, slots chan struct{}) {
	handshakes := make(chan struct{}, min(cap(slots), 32))
	carriers := make(chan struct{}, min(cap(slots), 32))
	for {
		raw, err := ln.Accept()
		if err != nil {
			return
		}
		select {
		case handshakes <- struct{}{}:
			go func() {
				defer raw.Close()
				conn := raw.(*tls.Conn)
				timeout, cancel := context.WithTimeout(ctx, 5*time.Second)
				err := conn.HandshakeContext(timeout)
				cancel()
				<-handshakes
				if err != nil {
					return
				}
				if conn.ConnectionState().NegotiatedProtocol != muxProtocol {
					select {
					case slots <- struct{}{}:
						defer func() { <-slots }()
						handleRelay(ctx, h, conn)
					default:
					}
					return
				}
				select {
				case carriers <- struct{}{}:
					defer func() { <-carriers }()
				default:
					return
				}
				serveCarrier(ctx, conn, h, token, slots)
			}()
		default:
			_ = raw.Close()
		}
	}
}
