package relay

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/url"
	"time"

	"github.com/go-gost/core/auth"
	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/connector"
	gostdial "github.com/go-gost/core/dialer"
	"github.com/go-gost/core/handler"
	gostlisten "github.com/go-gost/core/listener"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/relay"
	xchain "github.com/go-gost/x/chain"
	relayConnector "github.com/go-gost/x/connector/relay"
	wsDial "github.com/go-gost/x/dialer/ws"
	relayHandler "github.com/go-gost/x/handler/relay"
	wsListen "github.com/go-gost/x/listener/ws"
	xlogger "github.com/go-gost/x/logger"
	"github.com/go-gost/x/metadata"
	"hopx/internal/wire"
)

var log = xlogger.NewLogger(xlogger.LevelOption(logger.ErrorLevel), xlogger.OutputOption(io.Discard))

type authentication string

func (a authentication) Authenticate(_ context.Context, user, password string, _ ...auth.Option) (string, bool) {
	return user, user == "hopx" && subtle.ConstantTimeCompare([]byte(password), []byte(a)) == 1
}

type Session struct {
	reverse *ReverseHub
	pool    *MuxPool
	groups  []endpoint
}

type endpoint struct {
	hop       wire.Hop
	address   string
	tls       *tls.Config
	connector connector.Connector
	websocket gostdial.Handshaker
	reverseID string
	nativeKey []byte
}

func Prepare(path []wire.Hop) (*Session, error) { return PrepareWithReverse(path, nil) }

func PrepareWithReverse(path []wire.Hop, reverse *ReverseHub) (*Session, error) {
	return PrepareWithMux(path, reverse, nil)
}

func PrepareWithMux(path []wire.Hop, reverse *ReverseHub, pool *MuxPool) (*Session, error) {
	s := &Session{reverse: reverse, pool: pool}
	for _, hop := range path {
		c := relayConnector.NewConnector(connector.LoggerOption(log), connector.AuthOption(url.UserPassword("hopx", hop.Token)))
		if err := c.Init(metadata.NewMetadata(map[string]any{"noDelay": true, "connectTimeout": "5s"})); err != nil {
			return nil, err
		}
		target := endpoint{connector: c, reverseID: hop.ReverseID, address: hop.Addr, hop: hop}
		if len(path) == 1 && hop.NativeUDPKey != "" && hop.ReverseID == "" {
			var err error
			target.nativeKey, err = nativeUDPKey(hop.NativeUDPKey)
			if err != nil {
				return nil, err
			}
		}
		if hop.ReverseID != "" {
			if reverse == nil || len(s.groups) > 0 {
				return nil, errors.New("reverse egress must be the first hop and needs an ingress listener")
			}
		} else {
			certificateAddr := hop.Addr
			if hop.AdvertisedAddr != "" {
				certificateAddr = hop.AdvertisedAddr
			}
			host, _, err := net.SplitHostPort(certificateAddr)
			if err != nil {
				return nil, err
			}
			roots := x509.NewCertPool()
			if !roots.AppendCertsFromPEM([]byte(hop.Cert)) {
				return nil, errors.New("invalid relay certificate")
			}
			target.tls = &tls.Config{ServerName: host, RootCAs: roots, MinVersion: tls.VersionTLS13}
			if hop.Transport == "wss" || hop.Transport == "wss-mux" || hop.Transport == "ws" {
				ws := wsDial.NewDialer(gostdial.LoggerOption(log))
				if hop.Transport != "ws" {
					ws = wsDial.NewTLSDialer(gostdial.TLSConfigOption(target.tls), gostdial.LoggerOption(log))
				}
				if err = ws.Init(metadata.NewMetadata(map[string]any{"path": "/hopx-relay", "handshakeTimeout": "5s"})); err != nil {
					return nil, err
				}
				target.websocket = ws.(gostdial.Handshaker)
			}
		}
		s.groups = append(s.groups, target)
	}
	return s, nil
}

func (s *Session) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	return s.dial(ctx, network, addr, nil, "", nil)
}

func (s *Session) DialMetered(ctx context.Context, network, addr, ticket string) (net.Conn, bool, error) {
	var metered bool
	conn, err := s.dial(ctx, network, addr, nil, ticket, &metered)
	return conn, metered, err
}

func (s *Session) ProbeTCP(ctx context.Context, addr string) (wire.RouteTrace, error) {
	trace := wire.RouteTrace{Hops: len(s.groups)}
	conn, err := s.dial(ctx, "tcp", addr, &trace, "", nil)
	if err == nil {
		_ = conn.Close()
	}
	return trace, err
}

func (s *Session) Probe(ctx context.Context, network, addr string, udpEcho bool) wire.RouteTrace {
	trace := wire.RouteTrace{Hops: len(s.groups), Steps: make([]wire.ProbeStep, len(s.groups)+1), Target: addr}
	for i, hop := range s.groups {
		transport := hop.hop.Transport
		if transport == "" {
			transport = "tls"
		}
		if hop.reverseID != "" {
			transport = "reverse"
		} else if network == "udp" && len(hop.nativeKey) != 0 {
			transport = "dtls"
		}
		trace.Steps[i] = wire.ProbeStep{GroupID: hop.hop.GroupID, Transport: transport, Status: "skipped"}
	}
	target := &trace.Steps[len(s.groups)]
	target.Status = "skipped"
	start := time.Now()
	conn, err := s.dial(ctx, network, addr, &trace, "", nil)
	if err != nil {
		if len(s.groups) == 0 {
			recordProbeStep(target, start, "target_connect", err)
		}
		return trace
	}
	defer conn.Close()
	if network == "tcp" {
		if len(s.groups) == 0 {
			recordProbeStep(target, start, "tcp_connect", nil)
		}
		return trace
	}
	if !udpEcho {
		target.Status = "unknown"
		return trace
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	payload := []byte("hopx-probe:" + rand.Text())
	started := time.Now()
	if _, err = conn.Write(payload); err == nil {
		reply := make([]byte, len(payload)+1)
		var n int
		n, err = conn.Read(reply)
		if err == nil && (n != len(payload) || subtle.ConstantTimeCompare(reply[:n], payload) != 1) {
			err = errors.New("UDP echo reply did not match")
		}
	}
	recordProbeStep(target, started, "udp_echo", err)
	return trace
}

func recordProbeStep(step *wire.ProbeStep, started time.Time, phase string, err error) {
	step.Status = "ok"
	if err != nil {
		step.Status = "failed"
	}
	step.Phase, step.LatencyMS = phase, max(0, time.Since(started).Milliseconds())
}

func (s *Session) dial(ctx context.Context, network, addr string, trace *wire.RouteTrace, ticket string, metered *bool) (net.Conn, error) {
	dialer := net.Dialer{Timeout: 5 * time.Second}
	if len(s.groups) == 0 {
		return dialer.DialContext(ctx, network, addr)
	}
	var conn net.Conn
	var err error
	multiplexed := false
	first := s.groups[0]
	var steps []wire.ProbeStep
	var started time.Time
	if trace != nil {
		steps = trace.Steps
		if len(steps) != 0 {
			started = time.Now()
		}
	}
	if network == "udp" && len(first.nativeKey) != 0 {
		if len(steps) == 0 {
			if ticket != "" && first.hop.NativeUDPMeter {
				conn, accepted, err := dialNativeMetered(ctx, first.address, first.nativeKey, addr, ticket, nil)
				if err == nil {
					*metered = accepted
					return conn, nil
				}
			}
			return dialNativeUDP(ctx, first.address, first.nativeKey, addr)
		}
		var targetStart time.Time
		conn, err := dialNativeUDPWithHandshake(ctx, first.address, first.nativeKey, addr, func() {
			trace.Reached = 1
			recordProbeStep(&steps[0], started, "handshake", nil)
			targetStart = time.Now()
		})
		if trace.Reached == 0 {
			recordProbeStep(&steps[0], started, "handshake", err)
		} else if err != nil {
			recordProbeStep(&steps[1], targetStart, "target_connect", err)
		}
		return conn, err
	}
	if first.reverseID != "" && s.reverse != nil {
		conn, err = s.reverse.Open(first.reverseID)
	} else {
		if (first.hop.Transport == "tls-mux" || first.hop.Transport == "wss-mux") && s.pool != nil {
			conn, err = s.pool.open(ctx, first)
			multiplexed = err == nil
		}
		if !multiplexed {
			conn, err = dialer.DialContext(ctx, "tcp", first.address)
		}
	}
	if err != nil {
		if len(steps) != 0 {
			recordProbeStep(&steps[0], started, "relay_connect", err)
		}
		return nil, err
	}
	base := conn
	cancelDial := context.AfterFunc(ctx, func() { _ = base.Close() })
	defer cancelDial()
	for i, e := range s.groups {
		var transport net.Conn
		if i == 0 && (multiplexed || (e.reverseID != "" && s.reverse != nil)) {
			transport = conn
		} else if e.websocket != nil {
			transport, err = e.websocket.Handshake(ctx, conn, gostdial.AddrHandshakeOption(e.address))
		} else if e.hop.Transport == "http" || e.hop.Transport == "https" {
			transport, err = dialHTTPRelay(ctx, conn, e)
		} else {
			tlsConn := tls.Client(conn, e.tls)
			err = tlsConn.HandshakeContext(ctx)
			transport = tlsConn
		}
		if err != nil {
			if len(steps) != 0 {
				recordProbeStep(&steps[i], started, "handshake", err)
			}
			conn.Close()
			return nil, err
		}
		if trace != nil {
			trace.Reached = i + 1
		}
		if len(steps) != 0 {
			recordProbeStep(&steps[i], started, "handshake", nil)
			started = time.Now()
		}
		nextNetwork, nextAddr := network, addr
		if i+1 < len(s.groups) {
			nextNetwork, nextAddr = "tcp", s.groups[i+1].address
		}
		if ticket != "" && i+1 == len(s.groups) {
			negotiation := &meterNegotiation{Conn: transport, ticket: ticket}
			conn, err = e.connector.Connect(ctx, negotiation, nextNetwork, nextAddr)
			*metered = negotiation.metered
			if conn == negotiation {
				conn = transport
			}
		} else {
			conn, err = e.connector.Connect(ctx, transport, nextNetwork, nextAddr)
		}
		if len(steps) != 0 && i+1 == len(s.groups) {
			phase := "target_connect"
			if network == "tcp" {
				phase = "tcp_connect"
			}
			recordProbeStep(&steps[i+1], started, phase, err)
		}
		if err != nil {
			if len(steps) != 0 && i+1 < len(s.groups) {
				recordProbeStep(&steps[i+1], started, "relay_connect", err)
			}
			transport.Close()
			return nil, err
		}
	}
	if err := ctx.Err(); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// Allow only TCP and UDP CONNECT after the TLS handshake.
type guard struct {
	finishMeter func()
	net.Conn
	first   []byte
	checked bool
	ticket  string
	metered bool
}

func (c *guard) Read(p []byte) (int, error) {
	if !c.checked {
		c.checked = true
		var req relay.Request
		if _, err := req.ReadFrom(c.Conn); err != nil {
			return 0, err
		}
		if req.Version != relay.Version1 || req.Cmd&relay.CmdMask != relay.CmdConnect {
			return 0, errors.New("unsupported relay command")
		}
		for _, f := range req.Features {
			if n, ok := f.(*relay.NetworkFeature); ok && n.Network != relay.NetworkTCP && n.Network != relay.NetworkUDP {
				return 0, errors.New("unsupported relay network")
			}
		}
		c.ticket = trafficFeature(req.Features)
		var data appendWriter
		if _, err := req.WriteTo(&data); err != nil {
			return 0, err
		}
		c.first = data
	}
	if len(c.first) > 0 {
		n := copy(p, c.first)
		c.first = c.first[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

type appendWriter []byte

func (a *appendWriter) Write(p []byte) (int, error) { *a = append(*a, p...); return len(p), nil }

type connectionHandler interface {
	Handle(context.Context, net.Conn, ...handler.HandleOption) error
	Close() error
}

func newHandler(token string, meter MeterTarget) (connectionHandler, error) {
	var router chain.Router = xchain.NewRouter(chain.TimeoutRouterOption(5*time.Second), chain.LoggerRouterOption(log))
	if meter != nil {
		router = meterRouter{Router: router, target: meter}
	}
	h := relayHandler.NewHandler(handler.LoggerOption(log), handler.AutherOption(authentication(token)), handler.RouterOption(router))
	if err := h.Init(metadata.NewMetadata(map[string]any{"noDelay": true, "readTimeout": "8s"})); err != nil {
		return nil, err
	}
	return h.(connectionHandler), nil
}

type acceptor interface{ Accept() (net.Conn, error) }

func handleRelay(ctx context.Context, h connectionHandler, conn net.Conn) {
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	request := &guard{Conn: conn}
	_ = h.Handle(context.WithValue(ctx, relayGuardKey{}, request), request)
	if request.finishMeter != nil {
		request.finishMeter()
	}
}

func serve(listener acceptor, slots chan struct{}, handle func(net.Conn)) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		select {
		case slots <- struct{}{}:
			go func() {
				defer func() { <-slots }()
				handle(conn)
			}()
		default:
			_ = conn.Close()
		}
	}
}

func Listen(ctx context.Context, addr, cert, key, token, transport string, maxConns int) (net.Listener, error) {
	return ListenWithSlots(ctx, addr, cert, key, token, transport, make(chan struct{}, maxConns))
}

func ListenWithSlots(ctx context.Context, addr, cert, key, token, transport string, slots chan struct{}, meters ...MeterTarget) (net.Listener, error) {
	certPair, err := tls.X509KeyPair([]byte(cert), []byte(key))
	if err != nil {
		return nil, err
	}
	var meter MeterTarget
	if len(meters) > 0 {
		meter = meters[0]
	}
	h, err := newHandler(token, meter)
	if err != nil {
		return nil, err
	}
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{certPair}, MinVersion: tls.VersionTLS13}
	var ln net.Listener
	switch transport {
	case "", "tls", "tls-mux":
		if transport == "tls-mux" {
			tlsConfig.NextProtos = []string{muxProtocol}
		}
		ln, err = tls.Listen("tcp", addr, tlsConfig)
	case "wss", "wss-mux", "ws":
		ws := wsListen.NewListener(gostlisten.AddrOption(addr), gostlisten.LoggerOption(log))
		if transport != "ws" {
			ws = wsListen.NewTLSListener(gostlisten.AddrOption(addr), gostlisten.TLSConfigOption(tlsConfig), gostlisten.LoggerOption(log))
		}
		err = ws.Init(metadata.NewMetadata(map[string]any{
			"path": "/hopx-relay", "handshakeTimeout": "5s", "readHeaderTimeout": "5s", "backlog": min(cap(slots), 128),
		}))
		ln = ws
	case "http", "https":
		if transport == "https" {
			ln, err = tls.Listen("tcp", addr, tlsConfig)
		} else {
			ln, err = net.Listen("tcp", addr)
		}
	default:
		err = errors.New("unsupported relay transport")
	}
	if err != nil {
		_ = h.Close()
		return nil, err
	}
	go func() {
		defer h.Close()
		if transport == "tls-mux" {
			serveMuxListener(ctx, ln, h, token, slots)
		} else if transport == "wss-mux" {
			serveWebsocketMux(ctx, ln, h, token, slots)
		} else {
			serve(ln, slots, func(conn net.Conn) {
				if transport == "http" || transport == "https" {
					handleHTTPRelay(ctx, h, conn)
				} else {
					handleRelay(ctx, h, conn)
				}
			})
		}
	}()
	return ln, nil
}
