package node

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/pires/go-proxyproto"
	"golang.org/x/sys/unix"
)

const udpIdle = 45 * time.Second

type udpSession struct {
	packets chan []byte
}
type udpSessions struct {
	mu    sync.Mutex
	items map[netip.AddrPort]*udpSession
}

type udpBuffer [65535]byte

var udpBuffers = sync.Pool{New: func() any { return new(udpBuffer) }}

type udpSocketReader struct {
	raw  syscall.RawConn
	peer bool
}

func newUDPSocketReader(socket *net.UDPConn, peer bool) udpSocketReader {
	raw, _ := socket.SyscallConn()
	return udpSocketReader{raw: raw, peer: peer}
}

func (reader udpSocketReader) read(fallback net.Conn) (*udpBuffer, int, netip.AddrPort, error) {
	if reader.raw == nil {
		buffer := udpBuffers.Get().(*udpBuffer)
		if reader.peer {
			n, addr, err := fallback.(*net.UDPConn).ReadFromUDPAddrPort(buffer[:])
			return buffer, n, addr, err
		}
		n, err := fallback.Read(buffer[:])
		return buffer, n, netip.AddrPort{}, err
	}
	var buffer *udpBuffer
	var addr unix.Sockaddr
	var n int
	var readErr error
	err := reader.raw.Read(func(fd uintptr) bool {
		buffer = udpBuffers.Get().(*udpBuffer)
		for {
			if reader.peer {
				n, addr, readErr = unix.Recvfrom(int(fd), buffer[:], 0)
			} else {
				n, _, readErr = unix.Recvfrom(int(fd), buffer[:], 0)
			}
			if readErr != unix.EINTR {
				break
			}
		}
		if readErr == unix.EAGAIN || readErr == unix.EWOULDBLOCK {
			// The runtime waits for socket readiness without holding a packet buffer.
			udpBuffers.Put(buffer)
			buffer = nil
			return false
		}
		return true
	})
	if err != nil {
		return buffer, 0, netip.AddrPort{}, err
	}
	var source netip.AddrPort
	switch address := addr.(type) {
	case *unix.SockaddrInet4:
		source = netip.AddrPortFrom(netip.AddrFrom4(address.Addr), uint16(address.Port))
	case *unix.SockaddrInet6:
		ip := netip.AddrFrom16(address.Addr)
		if address.ZoneId != 0 {
			// net.UDPConn accepts the numeric interface index when sending a reply.
			ip = ip.WithZone(strconv.FormatUint(uint64(address.ZoneId), 10))
		}
		source = netip.AddrPortFrom(ip, uint16(address.Port))
	}
	return buffer, n, source, readErr
}

func (e *Engine) serveUDP(ctx context.Context, l *listener) {
	sessions := &udpSessions{items: make(map[netip.AddrPort]*udpSession)}
	reader := newUDPSocketReader(l.udp, true)
	for {
		buf, n, addr, err := reader.read(l.udp)
		if err != nil {
			if buf != nil {
				udpBuffers.Put(buf)
			}
			return
		}
		sessions.mu.Lock()
		s := sessions.items[addr]
		if s == nil {
			rr := l.route.Load()
			select {
			case e.slots <- struct{}{}:
				if rr.admit(addr.Addr().String()) {
					s = &udpSession{packets: make(chan []byte, 4)}
					sessions.items[addr] = s
					e.activeUDP.Add(1)
					e.workers.Go(func() {
						defer func() { e.activeUDP.Add(-1); <-e.slots; rr.leave(addr.Addr().String()) }()
						defer func() {
							sessions.mu.Lock()
							delete(sessions.items, addr)
							for len(s.packets) > 0 {
								p := <-s.packets
								e.udpQueued.Add(-int64(len(p)))
							}
							sessions.mu.Unlock()
						}()
						e.forwardUDP(ctx, l.udp, addr, s, rr)
					})
				} else {
					<-e.slots
				}
			default:
			}
		}
		if s != nil && len(s.packets) < cap(s.packets) {
			length := int64(n)
			if e.udpQueued.Add(length) <= 16<<20 {
				packet := make([]byte, n)
				copy(packet, buf[:n])
				s.packets <- packet
			} else {
				e.udpQueued.Add(-length)
				e.udpDropped.Add(1)
			}
		} else {
			e.udpDropped.Add(1)
		}
		udpBuffers.Put(buf)
		sessions.mu.Unlock()
	}
}

func (e *Engine) forwardUDP(ctx context.Context, listen *net.UDPConn, source netip.AddrPort, s *udpSession, rr *ruleRuntime) {
	if rr.lifetime != nil {
		ctx = rr.lifetime
	}
	if ctx.Err() != nil {
		return
	}
	target, backup, metered, err := rr.dialForward(ctx, "udp", source.Addr().String(), true)
	if err != nil {
		return
	}
	defer target.Close()
	var proxyPrefix []byte
	if rr.rule.ProxyOut && rr.rule.ProxyOutVersion == 2 {
		destination := listen.LocalAddr().(*net.UDPAddr)
		header := proxyproto.HeaderProxyFromAddrs(2, net.UDPAddrFromAddrPort(source), destination)
		if _, _, ok := header.UDPAddrs(); !ok {
			header = &proxyproto.Header{Version: 2, Command: proxyproto.LOCAL, TransportProtocol: proxyproto.UNSPEC}
		}
		proxyPrefix, err = header.Format()
		if err != nil {
			return
		}
	}
	var outgoing []byte
	rr.recordRoute(&rr.lastUDPRoute, backup)
	billing, counts := rr.billing(backup, metered)
	if !counts.retain() {
		return
	}
	defer counts.writers.Add(-1)
	stop := context.AfterFunc(ctx, func() { target.Close() })
	defer stop()
	finished := make(chan struct{})
	counts.writers.Add(1)
	go func() {
		defer close(finished)
		defer counts.writers.Add(-1)
		var reader udpSocketReader
		socket := target
		if tracked, ok := socket.(*loadConn); ok {
			socket = tracked.Conn
		}
		if udp, ok := socket.(*net.UDPConn); ok {
			reader = newUDPSocketReader(udp, false)
		}
		for {
			_ = target.SetReadDeadline(time.Now().Add(udpIdle))
			buf, n, _, err := reader.read(target)
			if err == nil && rr.admitPacket(n) {
				if finish, allowed := rr.quota.take(billing, n); allowed {
					var written int
					written, err = listen.WriteToUDPAddrPort(buf[:n], source)
					finish(written)
					if err == nil {
						counts.out.Add(int64(written))
					}
				}
			}
			if buf != nil {
				udpBuffers.Put(buf)
			}
			if err != nil {
				return
			}
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case <-finished:
			return
		case packet := <-s.packets:
			if rr.admitPacket(len(packet)) {
				finish, allowed := rr.quota.take(billing, len(packet))
				if allowed {
					_ = target.SetWriteDeadline(time.Now().Add(3 * time.Second))
					payload := packet
					if len(proxyPrefix) > 0 {
						outgoing = append(append(outgoing[:0], proxyPrefix...), packet...)
						payload = outgoing
					}
					n, e := target.Write(payload)
					n = min(len(packet), max(0, n-len(proxyPrefix)))
					finish(n)
					counts.in.Add(int64(n))
					err = e
				}
			}
			e.udpQueued.Add(-int64(len(packet)))
			if errors.Is(err, syscall.EMSGSIZE) {
				e.udpDropped.Add(1)
				err = nil
			}
			if err != nil {
				return
			}
		}
	}
}

func (rr *ruleRuntime) admitPacket(size int) bool {
	if rr.rule.Expires > 0 && time.Now().Unix() >= rr.rule.Expires {
		return false
	}
	now := time.Now()
	if rr.limit != nil && !rr.limit.AllowN(now, size) {
		return false
	}
	user := rr.userLimiter()
	return user == nil || user.AllowN(now, size)
}

// Bind separate UDP sockets so the source of a response matches the address of its request.
func interfaceUDPAddresses() ([]string, error) {
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool)
	var list []string
	for _, address := range addresses {
		network, ok := address.(*net.IPNet)
		if !ok || (!network.IP.IsGlobalUnicast() && !network.IP.IsLoopback()) {
			continue
		}
		host := network.IP.String()
		if !seen[host] {
			seen[host] = true
			list = append(list, host)
		}
	}
	if len(list) == 0 {
		return nil, errors.New("UDP smart bind requires at least one local IP address")
	}
	sort.Strings(list)
	return list, nil
}
