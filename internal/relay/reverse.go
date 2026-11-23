package relay

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
	"hopx/internal/wire"
)

// ReverseHub registers authenticated egress sessions on an ingress node.
type ReverseHub struct {
	scoped   bool
	mu       sync.RWMutex
	sessions map[string]*yamux.Session
}

func NewReverseHub(scoped bool) *ReverseHub {
	return &ReverseHub{scoped: scoped, sessions: make(map[string]*yamux.Session)}
}

func muxConfig() *yamux.Config {
	cfg := yamux.DefaultConfig()
	cfg.AcceptBacklog = 64
	cfg.LogOutput = io.Discard
	cfg.StreamOpenTimeout = 4 * time.Second
	cfg.ConnectionWriteTimeout = 4 * time.Second
	cfg.KeepAliveInterval = 20 * time.Second
	return cfg
}

func sameToken(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }

func (h *ReverseHub) accept(ctx context.Context, conn net.Conn, token string) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(6 * time.Second))
	var input [78]byte
	if _, err := io.ReadFull(conn, input[:]); err != nil {
		return
	}
	key := string(input[52:])
	if h.scoped {
		token = wire.ReverseCredential(token, key)
	}
	if !sameToken(string(input[:52]), token) {
		return
	}
	if _, err := conn.Write([]byte{1}); err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})
	session, err := yamux.Client(conn, muxConfig())
	if err != nil {
		return
	}
	defer session.Close()
	h.mu.Lock()
	previous := h.sessions[key]
	if len(h.sessions) >= 256 && previous == nil {
		h.mu.Unlock()
		return
	}
	h.sessions[key] = session
	h.mu.Unlock()
	if previous != nil {
		_ = previous.Close()
	}
	select {
	case <-session.CloseChan():
	case <-ctx.Done():
	}
	h.mu.Lock()
	if h.sessions[key] == session {
		delete(h.sessions, key)
	}
	h.mu.Unlock()
}

func (h *ReverseHub) Open(key string) (net.Conn, error) {
	h.mu.RLock()
	session := h.sessions[key]
	h.mu.RUnlock()
	if session == nil {
		return nil, errors.New("reverse egress not connected")
	}
	return session.OpenStream()
}

func (h *ReverseHub) Listen(ctx context.Context, addr, cert, key, token string) (net.Listener, error) {
	pair, err := tls.X509KeyPair([]byte(cert), []byte(key))
	if err != nil {
		return nil, err
	}
	if len(token) != 52 {
		return nil, errors.New("invalid reverse ingress token")
	}
	ln, err := tls.Listen("tcp", addr, &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13})
	if err != nil {
		return nil, err
	}
	slots := make(chan struct{}, 256)
	go func() {
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			select {
			case slots <- struct{}{}:
				go func() { defer func() { <-slots }(); h.accept(ctx, c, token) }()
			default:
				c.Close()
			}
		}
	}()
	return ln, nil
}

func runReverse(ctx context.Context, endpoint wire.ReverseEndpoint, profile reverseProfile) error {
	if len(profile.ID) != 26 || len(endpoint.Token) != 52 {
		return errors.New("invalid reverse registration")
	}
	name, _, err := net.SplitHostPort(endpoint.Address)
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(endpoint.Certificate)) {
		return errors.New("invalid reverse certificate")
	}
	cfg := &tls.Config{ServerName: name, RootCAs: pool, MinVersion: tls.VersionTLS13}
	dialer := tls.Dialer{NetDialer: &net.Dialer{Timeout: 5 * time.Second}, Config: cfg}
	c, err := dialer.DialContext(ctx, "tcp", endpoint.Address)
	if err != nil {
		return err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(6 * time.Second))
	if _, err = io.WriteString(c, endpoint.Token+profile.ID); err != nil {
		return err
	}
	var ack [1]byte
	if _, err = io.ReadFull(c, ack[:]); err != nil || ack[0] != 1 {
		return errors.New("reverse ingress rejected registration")
	}
	_ = c.SetDeadline(time.Time{})
	mux, err := yamux.Server(c, muxConfig())
	if err != nil {
		return err
	}
	defer mux.Close()
	stop := context.AfterFunc(ctx, func() { _ = mux.Close() })
	defer stop()
	serve(mux, profile.Slots, func(conn net.Conn) { handleRelay(ctx, profile.Handler, conn) })
	return nil
}

type reverseProfile struct {
	ID      string
	Handler connectionHandler
	Slots   chan struct{}
}

type ReverseClient struct {
	ctx     context.Context
	profile reverseProfile
	streams map[string]context.CancelFunc
}

func NewReverseClient(ctx context.Context, id, token string, limit int) (*ReverseClient, error) {
	return NewReverseClientWithSlots(ctx, id, token, make(chan struct{}, limit))
}

func NewReverseClientWithSlots(ctx context.Context, id, token string, slots chan struct{}, meters ...MeterTarget) (*ReverseClient, error) {
	var meter MeterTarget
	if len(meters) > 0 {
		meter = meters[0]
	}
	handler, err := newHandler(token, meter)
	if err != nil {
		return nil, err
	}
	client := &ReverseClient{
		ctx:     ctx,
		profile: reverseProfile{ID: id, Handler: handler, Slots: slots},
		streams: make(map[string]context.CancelFunc),
	}
	context.AfterFunc(ctx, func() { _ = handler.Close() })
	return client, nil
}

func (c *ReverseClient) Update(endpoints []wire.ReverseEndpoint) {
	next := make(map[string]context.CancelFunc)
	for _, endpoint := range endpoints {
		key := endpoint.Address + "\x00" + endpoint.Token + "\x00" + endpoint.Certificate
		if next[key] != nil {
			continue
		}
		if existing := c.streams[key]; existing != nil {
			next[key] = existing
			delete(c.streams, key)
			continue
		}
		ctx, cancel := context.WithCancel(c.ctx)
		next[key] = cancel
		go func() {
			for ctx.Err() == nil {
				_ = runReverse(ctx, endpoint, c.profile)
				t := time.NewTimer(3 * time.Second)
				select {
				case <-ctx.Done():
					t.Stop()
					return
				case <-t.C:
				}
			}
		}()
	}
	for _, cancel := range c.streams {
		cancel()
	}
	c.streams = next
}
