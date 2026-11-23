package node

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"slices"
	"time"

	dissector "github.com/go-gost/tls-dissector"
)

func filterResponse(conn net.Conn, clientIP string, filters, inherited []int) (net.Conn, error) {
	if len(filters) == 0 && len(inherited) == 0 {
		return conn, nil
	}
	has := func(code int) bool { return slices.Contains(filters, code) || slices.Contains(inherited, code) }
	if !has(1) && !has(2) && !has(3) && !has(4) {
		return conn, nil
	}
	if ip := net.ParseIP(clientIP); has(2000) && ip != nil && ip.To4() == nil {
		return conn, nil
	}
	reader := bufio.NewReaderSize(conn, 16<<10)
	_ = conn.SetReadDeadline(time.Now().Add(8 * time.Second))
	defer conn.SetReadDeadline(time.Time{})
	first, err := reader.Peek(1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(first) > 0 && first[0] == 'H' && (has(3) || has(4)) {
		head, _ := reader.Peek(12)
		if bytes.HasPrefix(head, []byte("HTTP/1.")) {
			upgrade := len(head) >= 12 && bytes.Equal(head[9:12], []byte("101"))
			if (upgrade && has(4)) || (!upgrade && has(3)) {
				return nil, errors.New("upstream HTTP/1 response rejected")
			}
		}
	}
	if len(first) > 0 && first[0] >= 20 && first[0] <= 23 && (has(1) || has(2)) {
		head, _ := reader.Peek(5)
		if len(head) == 5 && head[1] == 3 && head[2] <= 4 {
			if has(2) {
				return nil, errors.New("upstream TLS response rejected")
			}
			if head[0] == 22 {
				length := int(binary.BigEndian.Uint16(head[3:5]))
				record, _ := reader.Peek(5 + min(length, 16384-5))
				hello, err := dissector.ParseServerHello(bytes.NewReader(record))
				if err != nil || hello.Version < tls.VersionTLS13 {
					return nil, errors.New("upstream TLS response does not indicate TLS 1.3")
				}
			}
		}
	}
	return &prefixedConn{conn, reader}, nil
}
