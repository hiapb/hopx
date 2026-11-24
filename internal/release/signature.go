package release

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"strings"
)

func Verify(publicKey []byte, version, platform, checksum, signature string) error {
	block, _ := pem.Decode(publicKey)
	if block == nil || block.Type != "PUBLIC KEY" {
		return errors.New("invalid release public key")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return errors.New("invalid release public key")
	}
	key, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return errors.New("release public key must be Ed25519")
	}
	sig, err := base64.StdEncoding.Strict().DecodeString(signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return errors.New("invalid release signature format")
	}
	message := []byte(version + "\n" + platform + "\n" + strings.ToLower(checksum) + "\n")
	if !ed25519.Verify(key, message, sig) {
		return errors.New("release signature invalid")
	}
	return nil
}
