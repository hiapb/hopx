package node

import (
	"bytes"
	"context"
	"crypto/rand"
	"net"
	"net/netip"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"hopx/internal/wire"
)

func permittedPingAddress(address netip.Addr, publicOnly bool) bool {
	if publicOnly {
		return wire.PublicDestination(address)
	}
	return address.IsGlobalUnicast() || address.IsLoopback()
}

func pingHost(ctx context.Context, task wire.DiagnosticTask) *wire.DiagnosticResult {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	result := &wire.DiagnosticResult{ID: task.ID}
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", task.PingHost)
	if err != nil {
		result.Error = "目标名称解析失败"
		return result
	}
	for _, candidate := range addresses {
		address := candidate.Unmap()
		if !permittedPingAddress(address, task.PublicOnly) {
			continue
		}
		result.Address = address.String()
		network, bind, protocol := "udp4", "0.0.0.0", 1
		var request, reply icmp.Type = ipv4.ICMPTypeEcho, ipv4.ICMPTypeEchoReply
		if address.Is6() {
			network, bind, protocol = "udp6", "::", 58
			request, reply = ipv6.ICMPTypeEchoRequest, ipv6.ICMPTypeEchoReply
		}
		conn, err := icmp.ListenPacket(network, bind)
		if err != nil {
			result.Error = "该节点无法创建 ICMP 套接字"
			continue
		}
		defer conn.Close()
		deadline, _ := ctx.Deadline()
		_ = conn.SetDeadline(deadline)
		stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
		defer stop()
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			result.Error = "无法生成诊断请求"
			return result
		}
		frame, err := (&icmp.Message{Type: request, Body: &icmp.Echo{Data: nonce[:]}}).Marshal(nil)
		if err != nil {
			result.Error = "无法构造诊断请求"
			return result
		}
		started := time.Now()
		if _, err = conn.WriteTo(frame, net.UDPAddrFromAddrPort(netip.AddrPortFrom(address, 0))); err != nil {
			result.Error = "无法发送 Ping 请求"
			return result
		}
		var response [256]byte
		for {
			count, from, err := conn.ReadFrom(response[:])
			if err != nil {
				result.Error = "未收到 Ping 响应"
				return result
			}
			peer, ok := from.(*net.UDPAddr)
			if !ok || peer.AddrPort().Addr().Unmap() != address {
				continue
			}
			msg, err := icmp.ParseMessage(protocol, response[:count])
			if err != nil || msg.Type != reply {
				continue
			}
			if echo, ok := msg.Body.(*icmp.Echo); ok && bytes.Equal(echo.Data, nonce[:]) {
				result.Connected, result.LatencyMS, result.Error = true, time.Since(started).Milliseconds(), ""
				return result
			}
		}
	}
	if result.Error == "" {
		result.Error = "目标没有可探测的 IP 地址"
	}
	return result
}
