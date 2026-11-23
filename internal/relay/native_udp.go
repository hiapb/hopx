package relay

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/pion/dtls/v3"
)

const (
	nativeUDPIdentity   = "hopx-udp-v1"
	nativeUDPPayload    = 8000 // A datagram and its DTLS record fit Pion's 8192-byte receive buffer.
	nativeUDPIdle       = 50 * time.Second
	nativeUDPSetupLimit = 4 * time.Second
)

func nativeUDPKey(value string) ([]byte, error) {
	key, err := hex.DecodeString(value)
	if err != nil || len(key) != 32 {
		return nil, errors.New("invalid native UDP relay key")
	}
	return key, nil
}

func nativeUDPAuth(key []byte) dtls.Option {
	return dtls.WithPSK(func(identity []byte) ([]byte, error) {
		if subtle.ConstantTimeCompare(identity, []byte(nativeUDPIdentity)) != 1 {
			return nil, errors.New("invalid native UDP relay identity")
		}
		return key, nil
	})
}

// A connected kernel socket fixes the peer before DTLS processes packets.
type connectedPacket struct{ *net.UDPConn }

func (c connectedPacket) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := c.Read(p)
	return n, c.RemoteAddr(), err
}

func (c connectedPacket) WriteTo(p []byte, _ net.Addr) (int, error) { return c.Write(p) }

func dialNativeUDP(ctx context.Context, address string, key []byte, target string) (net.Conn, error) {
	return dialNativeUDPWithHandshake(ctx, address, key, target, nil)
}

func dialNativeUDPWithHandshake(ctx context.Context, address string, key []byte, target string, handshake func()) (net.Conn, error) {
	conn, _, err := dialNativeMetered(ctx, address, key, target, "", handshake)
	return conn, err
}

func dialNativeMetered(ctx context.Context, address string, key []byte, target, ticket string, handshake func()) (net.Conn, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, nativeUDPSetupLimit)
	defer cancel()
	socket, err := (&net.Dialer{}).DialContext(ctx, "udp", address)
	if err != nil {
		return nil, false, err
	}
	packet := connectedPacket{socket.(*net.UDPConn)}
	conn, err := dtls.ClientWithOptions(packet, packet.RemoteAddr(), nativeUDPAuth(key),
		dtls.WithPSKIdentityHint([]byte(nativeUDPIdentity)),
		dtls.WithCipherSuites(dtls.TLS_PSK_WITH_AES_128_GCM_SHA256),
		dtls.WithExtendedMasterSecret(dtls.RequireExtendedMasterSecret))
	if err != nil {
		packet.Close()
		return nil, false, err
	}
	if err = conn.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, false, err
	}
	if handshake != nil {
		handshake()
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	if ticket != "" {
		target += "\x00" + ticket
	}
	var metered bool
	if _, err = conn.Write([]byte(target)); err == nil {
		var reply [1]byte
		var size int
		size, err = conn.Read(reply[:])
		metered = size == 1 && reply[0] == 3 && ticket != ""
		if err == nil && (size != 1 || (reply[0] != 1 && !metered)) {
			err = errors.New("native UDP relay rejected target")
		}
	}
	if err != nil || ctx.Err() != nil {
		conn.Close()
		return nil, false, errors.Join(err, ctx.Err())
	}
	_ = conn.SetDeadline(time.Time{})
	return nativeDatagrams{Conn: conn}, metered, nil
}

type nativeDatagrams struct{ net.Conn }

var nativeUDPBuckets = sync.Pool{New: func() any { return new([nativeUDPPayload + 1]byte) }}

func (c nativeDatagrams) Write(p []byte) (int, error) {
	if len(p) > nativeUDPPayload {
		return 0, syscall.EMSGSIZE
	}
	if len(p) == 0 {
		if _, err := c.Conn.Write([]byte{0}); err != nil {
			return 0, err
		}
		return 0, nil
	}
	buf := nativeUDPBuckets.Get().(*[nativeUDPPayload + 1]byte)
	defer nativeUDPBuckets.Put(buf)
	buf[0] = 0
	copy(buf[1:], p)
	if _, err := c.Conn.Write(buf[:len(p)+1]); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c nativeDatagrams) Read(p []byte) (int, error) {
	buf := nativeUDPBuckets.Get().(*[nativeUDPPayload + 1]byte)
	defer nativeUDPBuckets.Put(buf)
	for {
		n, err := c.Conn.Read(buf[:])
		if err != nil {
			return 0, err
		}
		if n == 0 || buf[0] != 0 {
			continue
		}
		if n-1 > len(p) {
			return 0, io.ErrShortBuffer
		}
		return copy(p, buf[1:n]), nil
	}
}

func ListenNativeUDP(ctx context.Context, address, key string, slots chan struct{}, meters ...MeterTarget) (net.Listener, error) {
	secret, err := nativeUDPKey(key)
	if err != nil {
		return nil, err
	}
	addr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, err
	}
	listener, err := dtls.ListenWithOptions("udp", addr, nativeUDPAuth(secret),
		dtls.WithPSKIdentityHint([]byte(nativeUDPIdentity)),
		dtls.WithCipherSuites(dtls.TLS_PSK_WITH_AES_128_GCM_SHA256),
		dtls.WithExtendedMasterSecret(dtls.RequireExtendedMasterSecret))
	if err != nil {
		return nil, err
	}
	var meter MeterTarget
	if len(meters) > 0 {
		meter = meters[0]
	}
	handshakes := make(chan struct{}, min(32, cap(slots)))
	go func() {
		stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
		defer stop()
		for {
			accepted, err := listener.Accept()
			if err != nil {
				return
			}
			select {
			case handshakes <- struct{}{}:
				go func(conn *dtls.Conn) {
					defer conn.Close()
					handshakeCtx, cancel := context.WithTimeout(ctx, nativeUDPSetupLimit)
					err := conn.HandshakeContext(handshakeCtx)
					cancel()
					<-handshakes
					if err != nil {
						return
					}
					select {
					case slots <- struct{}{}:
						defer func() { <-slots }()
						forwardNativeUDP(ctx, conn, meter)
					default:
					}
				}(accepted.(*dtls.Conn))
			default:
				accepted.Close()
			}
		}
	}()
	return listener, nil
}

func forwardNativeUDP(ctx context.Context, conn net.Conn, meter MeterTarget) {
	setup, cancel := context.WithTimeout(ctx, nativeUDPSetupLimit)
	defer cancel()
	deadline, _ := setup.Deadline()
	_ = conn.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	var request [1024]byte
	n, err := conn.Read(request[:])
	if err != nil {
		return
	}
	address, ticket, _ := strings.Cut(string(request[:n]), "\x00")
	host, port, err := net.SplitHostPort(address)
	value, portErr := strconv.Atoi(port)
	if err != nil || portErr != nil || host == "" || value < 1 || value > 65535 {
		_, _ = conn.Write([]byte{2})
		return
	}
	target, err := (&net.Dialer{}).DialContext(setup, "udp", address)
	if err != nil {
		_, _ = conn.Write([]byte{2})
		return
	}
	reply := byte(1)
	if ticket != "" && meter != nil {
		var finish func()
		target, finish = meter(ctx, ticket, target)
		if finish != nil {
			defer finish()
			reply = 3
		}
	}
	defer target.Close()
	if _, err := conn.Write([]byte{reply}); err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})
	transport := nativeDatagrams{Conn: conn}
	done := make(chan struct{})
	go func() {
		defer close(done)
		copyNativeDatagrams(transport, target)
		_ = conn.Close()
	}()
	copyNativeDatagrams(target, transport)
	_ = target.Close()
	<-done
}

func copyNativeDatagrams(to, from net.Conn) {
	buf := nativeUDPBuckets.Get().(*[nativeUDPPayload + 1]byte)
	defer nativeUDPBuckets.Put(buf)
	for {
		_ = from.SetReadDeadline(time.Now().Add(nativeUDPIdle))
		n, err := from.Read(buf[:])
		if err != nil {
			return
		}
		_ = to.SetWriteDeadline(time.Now().Add(3 * time.Second))
		if _, err := to.Write(buf[:n]); err != nil && !errors.Is(err, syscall.EMSGSIZE) {
			return
		}
	}
}
