package node

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"math/bits"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"

	dissector "github.com/go-gost/tls-dissector"
	"hopx/internal/wire"
)

func matchHost(host string, names []string) bool {
	if name, _, err := net.SplitHostPort(host); err == nil {
		host = name
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	return slices.ContainsFunc(names, func(pattern string) bool {
		pattern = strings.ToLower(pattern)
		return host == pattern || (strings.HasPrefix(pattern, ".") && strings.HasSuffix(host, pattern))
	})
}

func allowIngressHost(host string, policy *wire.IngressFilter) bool {
	if len(policy.AllowedHosts) > 0 {
		return matchHost(host, policy.AllowedHosts)
	}
	return !matchHost(host, policy.BlockedHosts)
}

// FET uses the first bytes of an unrecognized stream. Exempt readable
// prefixes and non-random bit distributions before classifying ciphertext.
func fullyEncryptedPrefix(data []byte) bool {
	if len(data) < 32 {
		return false
	}
	var ones, printable, run, longest int
	for _, octet := range data {
		ones += bits.OnesCount8(octet)
		if octet >= 0x20 && octet <= 0x7e {
			printable++
			run++
			longest = max(longest, run)
		} else {
			run = 0
		}
	}
	return 34*len(data) <= ones*10 && ones*10 <= 46*len(data) && printable*2 < len(data) && longest < 6
}

func inspectIngress(conn net.Conn, policy *wire.IngressFilter, serverName string, terminatedTLS bool) (net.Conn, error) {
	if !policy.InspectsTCP() {
		return conn, nil
	}
	if terminatedTLS && !policy.RejectEmptySNI && len(policy.BlockedPaths)+len(policy.BlockedTypes) == 0 {
		return conn, nil
	}
	const maxPreview = 16 << 10
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	defer conn.SetReadDeadline(time.Time{})
	reader := bufio.NewReaderSize(conn, maxPreview)
	first, _ := reader.Peek(1)
	var protocol, host, path string
	if len(first) != 0 {
		switch first[0] {
		case 4, 5:
			if head, _ := reader.Peek(2); len(head) == 2 && head[1] != 0 {
				protocol = "socks"
			}
		case 22:
			head, _ := reader.Peek(5)
			if len(head) == 5 && head[1] == 3 && head[2] <= 4 {
				protocol = "tls"
				size := int(binary.BigEndian.Uint16(head[3:5])) + 5
				if size <= maxPreview {
					if raw, e := reader.Peek(size); e == nil {
						if hello, e := dissector.ParseClientHello(bytes.NewReader(raw)); e == nil {
							host = hello.ServerName
						}
					}
				}
			}
		default:
			if first[0] >= 'A' && first[0] <= 'Z' {
				head, _ := reader.Peek(8)
				method, _, found := strings.Cut(string(head), " ")
				if found && slices.Contains([]string{"GET", "POST", "PUT", "HEAD", "DELETE", "OPTIONS", "TRACE", "CONNECT", "PATCH", "PRI"}, method) {
					protocol = "http"
					if !slices.Contains(policy.BlockedTypes, protocol) && len(policy.AllowedHosts)+len(policy.BlockedHosts)+len(policy.BlockedPaths) > 0 {
						var read bytes.Buffer
						parser := bufio.NewReader(io.TeeReader(io.LimitReader(reader, maxPreview), &read))
						if req, err := http.ReadRequest(parser); err == nil {
							host, path = req.Host, req.URL.Path
						}
						reader = bufio.NewReaderSize(io.MultiReader(&read, reader), maxPreview)
					}
				}
			}
		}
	}
	if len(first) != 0 && protocol == "" && slices.Contains(policy.BlockedTypes, "fet") {
		prefix, _ := reader.Peek(32)
		if fullyEncryptedPrefix(prefix) {
			protocol = "fet"
		}
	}
	if slices.Contains(policy.BlockedTypes, protocol) || (protocol == "tls" && policy.RejectEmptySNI && host == "") {
		return nil, errors.New("ingress protocol rejected")
	}
	if host == "" {
		host = serverName
	}
	if !allowIngressHost(host, policy) || (path != "" && slices.ContainsFunc(policy.BlockedPaths, func(p string) bool {
		return strings.HasSuffix(path, p)
	})) {
		return nil, errors.New("ingress host or path rejected")
	}
	return &prefixedConn{conn, reader}, nil
}
