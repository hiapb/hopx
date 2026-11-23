package node

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	"hopx/internal/relay"

	"hopx/internal/wire"
)

var errPrivateDestination = errors.New("forwarding to this address is restricted")

// Return an approved IP rather than resolving the same hostname again at the
// exit, where it could resolve to an internal address.
func resolvePublicTarget(ctx context.Context, target string) (primary, alternate string, err error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return "", "", err
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if wire.PublicDestination(ip) {
			return net.JoinHostPort(ip.Unmap().String(), port), "", nil
		}
		return "", "", errPrivateDestination
	}
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return "", "", err
	}
	var first netip.Addr
	for _, candidate := range addresses {
		ip := candidate.Unmap()
		if !wire.PublicDestination(ip) {
			continue
		}
		if !first.IsValid() {
			first = ip
			primary = net.JoinHostPort(ip.String(), port)
		} else if first.Is4() != ip.Is4() {
			alternate = net.JoinHostPort(ip.String(), port)
			break
		}
	}
	if primary == "" {
		return "", "", errPrivateDestination
	}
	return primary, alternate, nil
}

func dialRuleTarget(ctx context.Context, path *relay.Session, network, target, ticket string, publicOnly bool) (net.Conn, bool, error) {
	if !publicOnly {
		return path.DialMetered(ctx, network, target, ticket)
	}
	primary, alternate, err := resolvePublicTarget(ctx, target)
	if err != nil {
		return nil, false, err
	}
	if alternate == "" {
		return path.DialMetered(ctx, network, primary, ticket)
	}
	first, cancel := context.WithTimeout(ctx, 2*time.Second)
	conn, metered, err := path.DialMetered(first, network, primary, ticket)
	cancel()
	if err == nil || ctx.Err() != nil {
		return conn, metered, err
	}
	return path.DialMetered(ctx, network, alternate, ticket)
}
