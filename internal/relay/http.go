package relay

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"strings"
	"time"
)

const httpRelayPath = "/hopx-relay"

type bufferedRelayConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedRelayConn) Read(p []byte) (int, error) { return c.reader.Read(p) }
func (c *bufferedRelayConn) CloseWrite() error {
	if c, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return c.CloseWrite()
	}
	return c.Conn.Close()
}

func dialHTTPRelay(ctx context.Context, conn net.Conn, endpoint endpoint) (net.Conn, error) {
	if endpoint.hop.Transport == "https" {
		tlsConn := tls.Client(conn, endpoint.tls)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return nil, err
		}
		conn = tlsConn
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	defer conn.SetDeadline(time.Time{})
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", httpRelayPath, endpoint.address); err != nil {
		return nil, err
	}
	reader := bufio.NewReaderSize(conn, 4096)
	for i := 0; i < 32; i++ {
		line, err := reader.ReadSlice('\n')
		if err != nil {
			return nil, err
		}
		if i == 0 && !strings.HasPrefix(string(line), "HTTP/1.1 200 ") {
			return nil, errors.New("HTTP relay rejected the CONNECT request")
		}
		if i > 0 && string(line) == "\r\n" {
			return &bufferedRelayConn{Conn: conn, reader: reader}, nil
		}
	}
	return nil, errors.New("HTTP relay response exceeds header limits")
}

func handleHTTPRelay(ctx context.Context, handler connectionHandler, conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	header := &io.LimitedReader{R: conn, N: 4096}
	reader := bufio.NewReaderSize(header, 4096)
	request, err := http.ReadRequest(reader)
	if err != nil || request.Method != http.MethodConnect || request.RequestURI != httpRelayPath ||
		request.ContentLength != 0 || len(request.TransferEncoding) > 0 {
		_, _ = io.WriteString(conn, "HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
		return
	}
	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	header.N = math.MaxInt64
	_ = conn.SetDeadline(time.Time{})
	handleRelay(ctx, handler, &bufferedRelayConn{Conn: conn, reader: reader})
}
