package wire

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
)

var reverseTokenEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// ReverseCredential binds an ingress's secret to a single egress registration.
func ReverseCredential(secret, egressID string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("hopx-reverse-v1\x00"))
	mac.Write([]byte(egressID))
	return reverseTokenEncoding.EncodeToString(mac.Sum(nil))
}
