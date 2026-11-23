package relay

import (
	"bytes"
	"context"
	"io"
	"net"

	"github.com/go-gost/core/chain"
	"github.com/go-gost/relay"
)

const meterFeature = "hopx-meter"

type MeterTarget func(ctx context.Context, ticket string, target net.Conn) (net.Conn, func())

type meterRouter struct {
	chain.Router
	target MeterTarget
}

type relayGuardKey struct{}

func (r meterRouter) Dial(ctx context.Context, network, address string, options ...chain.DialOption) (net.Conn, error) {
	target, err := r.Router.Dial(ctx, network, address, options...)
	guard, _ := ctx.Value(relayGuardKey{}).(*guard)
	if err == nil && guard != nil && guard.ticket != "" {
		target, guard.finishMeter = r.target(ctx, guard.ticket, target)
		guard.metered = guard.finishMeter != nil
	}
	return target, err
}

func trafficFeature(features []relay.Feature) string {
	for _, feature := range features {
		if metadata, ok := feature.(*relay.MetadataFeature); ok {
			if value := metadata.KVs[meterFeature]; value != "" {
				return value
			}
		}
	}
	return ""
}

type meterNegotiation struct {
	net.Conn
	ticket           string
	reply            bytes.Reader
	checked, metered bool
}

func (c *meterNegotiation) Write(p []byte) (int, error) {
	if c.ticket == "" {
		return c.Conn.Write(p)
	}
	var request relay.Request
	if _, err := request.ReadFrom(bytes.NewReader(p)); err != nil {
		return 0, err
	}
	request.Features = append(request.Features, &relay.MetadataFeature{KVs: map[string]string{meterFeature: c.ticket}})
	c.ticket = ""
	if _, err := request.WriteTo(c.Conn); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *meterNegotiation) Read(p []byte) (int, error) {
	if !c.checked {
		c.checked = true
		var response relay.Response
		if _, err := response.ReadFrom(c.Conn); err != nil {
			return 0, err
		}
		c.metered = response.Status == relay.StatusOK && trafficFeature(response.Features) == "1"
		var header appendWriter
		if _, err := response.WriteTo(&header); err != nil {
			return 0, err
		}
		c.reply.Reset(header)
	}
	if c.reply.Len() > 0 {
		return c.reply.Read(p)
	}
	return c.Conn.Read(p)
}

func (c *guard) Write(p []byte) (int, error) {
	if !c.metered {
		return c.Conn.Write(p)
	}
	// GOST writes a complete CONNECT response before starting either data pump.
	c.metered = false
	var response relay.Response
	if _, err := response.ReadFrom(bytes.NewReader(p)); err != nil {
		return 0, err
	}
	if response.Status != relay.StatusOK {
		return c.Conn.Write(p)
	}
	response.Features = append(response.Features, &relay.MetadataFeature{KVs: map[string]string{meterFeature: "1"}})
	var frame appendWriter
	if _, err := response.WriteTo(&frame); err != nil {
		return 0, err
	}
	n, err := c.Conn.Write(frame)
	if err == nil && n != len(frame) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return 0, err
	}
	return len(p), nil
}
