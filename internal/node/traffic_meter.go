package node

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net"
	"time"

	"hopx/internal/wire"
)

type meterVerifier struct {
	key   ed25519.PublicKey
	group int64
}

type exitTraffic struct {
	counter
	meter wire.ExitMeter
	refs  int
}

func (e *Engine) meterTarget(ctx context.Context, ticket string, target net.Conn) (net.Conn, func()) {
	verifier := e.meter.Load()
	if verifier == nil {
		return target, nil
	}
	e.exitMu.Lock()
	if ctx.Err() != nil {
		e.exitMu.Unlock()
		return target, nil
	}
	traffic := e.exitCounters[ticket]
	if traffic == nil || traffic.meter.Rule == 0 {
		meter, ok := wire.VerifyExitMeter(verifier.key, ticket, verifier.group)
		if !ok {
			e.exitMu.Unlock()
			return target, nil
		}
		if traffic == nil {
			traffic = &exitTraffic{}
			e.exitCounters[ticket] = traffic
		}
		traffic.meter = meter
	}
	traffic.refs++
	e.exitWorkers.Add(1)
	e.exitMu.Unlock()

	meter := traffic.meter
	conn := &exitConn{Conn: target, ctx: ctx, traffic: traffic}
	if meter.Managed {
		conn.quota = &e.quota
		conn.billing = wire.Forward{Rule: wire.Rule{Owner: meter.Owner}, Ratio: meter.Ratio, QuotaEpoch: meter.Epoch, QuotaManaged: true}
		e.quota.attachExit(conn.billing, ticket)
	}
	return conn, func() {
		if conn.quota != nil {
			conn.quota.detachExit(conn.billing, ticket)
		}
		e.exitMu.Lock()
		traffic.refs--
		e.exitMu.Unlock()
		e.exitWorkers.Done()
	}
}

func (e *Engine) collectExitTraffic(values []wire.Traffic) []wire.Traffic {
	e.exitMu.Lock()
	defer e.exitMu.Unlock()
	for ticket, counters := range e.exitCounters {
		in, out := counters.in.Swap(0), counters.out.Swap(0)
		if in != 0 || out != 0 {
			values = append(values, wire.Traffic{ExitMeter: ticket, In: in, Out: out})
		}
		if counters.refs == 0 {
			delete(e.exitCounters, ticket)
		}
	}
	return values
}

var errRelayQuota = errors.New("egress quota allowance exhausted")

type exitConn struct {
	net.Conn
	ctx     context.Context
	traffic *exitTraffic
	quota   *quotaBook
	billing wire.Forward
}

func (c *exitConn) take(size int) (quotaReservation, error) {
	if c.quota == nil || size == 0 {
		return quotaReservation{}, nil
	}
	reservation, ok, changed := c.quota.reserve(c.billing, size, true)
	if ok {
		return reservation, nil
	}
	// Wake when the panel updates this user's lease, or when the wait ends.
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	for changed != nil {
		select {
		case <-c.ctx.Done():
			return quotaReservation{}, c.ctx.Err()
		case <-timer.C:
			return quotaReservation{}, errRelayQuota
		case <-changed:
			reservation, ok, changed = c.quota.reserve(c.billing, size, true)
			if ok {
				return reservation, nil
			}
		}
	}
	return quotaReservation{}, errRelayQuota
}

func (c *exitConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	reservation, quotaErr := c.take(n)
	if quotaErr != nil {
		return 0, quotaErr
	}
	reservation.finish(n)
	c.traffic.out.Add(int64(n))
	return n, err
}

func (c *exitConn) Write(p []byte) (int, error) {
	reservation, err := c.take(len(p))
	if err != nil {
		return 0, err
	}
	n, err := c.Conn.Write(p)
	reservation.finish(n)
	c.traffic.in.Add(int64(n))
	return n, err
}

func (c *exitConn) CloseWrite() error {
	if closer, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}
	return c.Close()
}
