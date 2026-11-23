package node

import (
	"io"
	"net"
	"testing"

	"hopx/internal/wire"
)

func TestIngressFilterPreservesInspectedRequest(t *testing.T) {
	for _, test := range []struct {
		name, payload string
		policy        wire.IngressFilter
		reject        bool
	}{
		{"allowed HTTP", "POST /api/items HTTP/1.1\r\nHost: API.example.test:443\r\nContent-Length: 5\r\n\r\nhello",
			wire.IngressFilter{AllowedHosts: []string{".example.test"}}, false},
		{"blocked host", "GET / HTTP/1.1\r\nHost: other.test\r\n\r\n",
			wire.IngressFilter{AllowedHosts: []string{".example.test"}}, true},
		{"blocked path", "GET /private.json HTTP/1.1\r\nHost: example.test\r\n\r\n",
			wire.IngressFilter{BlockedPaths: []string{".json"}}, true},
		{"blocked SOCKS", "\x05\x01\x00", wire.IngressFilter{BlockedTypes: []string{"socks"}}, true},
		{"blocked encrypted prefix", "\x97\xd2\x86\x59\x4b\xf6\x2a\xe6\xb1\x37\x0c\xae\x8b\x59\xc6\xdb\x20\x27\xf4\x9d\x65\x1b\xd0\x9f\x09\x78\xa3\x2c\xdf\x79\x52\x98", wire.IngressFilter{BlockedTypes: []string{"fet"}}, true},
		{"allowed text under FET filter", "SSH-2.0-OpenSSH_9.9 on a local test host\r\n", wire.IngressFilter{BlockedTypes: []string{"fet"}}, false},
		{"allowed short prefix under FET filter", "\x90\xb1\xd2\xc4", wire.IngressFilter{BlockedTypes: []string{"fet"}}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, peer := net.Pipe()
			defer client.Close()
			go func() {
				defer peer.Close()
				_, _ = io.WriteString(peer, test.payload)
			}()
			conn, err := inspectIngress(client, &test.policy, "", false)
			if (err != nil) != test.reject {
				t.Fatalf("unexpected error: %v", err)
			}
			if test.reject {
				return
			}
			data, err := io.ReadAll(conn)
			if err != nil || string(data) != test.payload {
				t.Fatalf("forwarded %q, %v", data, err)
			}
		})
	}
}
