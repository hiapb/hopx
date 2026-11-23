package node

import (
	"context"
	"errors"
	"net"
	"strconv"
	"syscall"
	"time"

	"hopx/internal/wire"
)

func (e *Engine) checkPort(ctx context.Context, task wire.DiagnosticTask) *wire.DiagnosticResult {
	result := &wire.DiagnosticResult{ID: task.ID}
	check := task.PortCheck
	if check.Port < 1 || check.Port > 65535 || (check.Network != "tcp" && check.Network != "udp" && check.Network != "both") {
		return result
	}
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	e.mu.Lock()
	defer e.mu.Unlock()
	var listen net.ListenConfig
	for _, network := range []string{"tcp", "udp"} {
		if check.Network != network && check.Network != "both" {
			continue
		}
		proxy := check.HAProxy && network == "tcp"
		hosts := e.bind
		if network == "udp" && len(e.udpBind) != 0 {
			hosts = e.udpBind
		}
		for _, host := range hosts {
			address := net.JoinHostPort(host, strconv.Itoa(check.Port))
			binding := wire.PortBinding{Network: network, Address: address, Status: "available"}
			key := listenerKey{host: host, network: network, port: check.Port}
			if proxy && e.proxy.binary == "" {
				binding.Status = "no_haproxy"
			} else if existing := e.listeners[key]; existing != nil {
				if proxy || existing.route.Load().rule.ID != task.RuleID {
					binding.Status = "occupied"
				} else {
					binding.Status = "in_use_by_rule"
				}
			} else if active := e.activeRules[task.RuleID]; proxy && active != nil &&
				active.rule.HAProxy && active.rule.Port == check.Port && e.proxy.active.running() {
				binding.Status = "in_use_by_rule"
			} else {
				var socket interface{ Close() error }
				var err error
				if network == "tcp" {
					socket, err = listen.Listen(ctx, network, address)
				} else {
					socket, err = listen.ListenPacket(ctx, network, address)
				}
				switch {
				case err == nil:
					_ = socket.Close()
				case errors.Is(err, syscall.EADDRINUSE):
					binding.Status = "occupied"
				default:
					binding.Status = "unavailable"
				}
			}
			result.Bindings = append(result.Bindings, binding)
		}
	}
	return result
}
