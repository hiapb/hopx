package node

import (
	"io"
	"net"
	"testing"
)

func TestResponseFilterPreservesAllowedBytes(t *testing.T) {
	for _, test := range []struct {
		name     string
		response string
		ip       string
		filters  []int
		reject   bool
	}{
		{"HTTP 200 blocked", "HTTP/1.1 200 OK\r\n\r\n", "127.0.0.1", []int{3}, true},
		{"HTTP 101 allowed", "HTTP/1.1 101 Switching Protocols\r\n\r\n", "127.0.0.1", []int{3}, false},
		{"HTTP 101 blocked", "HTTP/1.1 101 Switching Protocols\r\n\r\n", "127.0.0.1", []int{4}, true},
		{"IPv6 bypass", "HTTP/1.1 200 OK\r\n\r\n", "::1", []int{3, 2000}, false},
		{"non-HTTP left intact", "Hello", "127.0.0.1", []int{3}, false},
		{"TLS record blocked", "\x16\x03\x03\x00\x01\x02", "127.0.0.1", []int{2}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			input, upstream := net.Pipe()
			defer input.Close()
			go func() {
				defer upstream.Close()
				_, _ = io.WriteString(upstream, test.response)
			}()
			conn, err := filterResponse(input, test.ip, test.filters, nil)
			if (err != nil) != test.reject {
				t.Fatalf("unexpected error: %v", err)
			}
			if !test.reject {
				body, err := io.ReadAll(conn)
				if err != nil || string(body) != test.response {
					t.Fatalf("got %q, %v", body, err)
				}
			}
		})
	}
}
