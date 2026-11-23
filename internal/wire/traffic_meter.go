package wire

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
)

// ExitMeter authorizes a physical terminal group to meter a rule. For a virtual
// chain the ratio comes from the virtual group and the terminal still measures it.
type ExitMeter struct {
	Rule, Owner, Group, Epoch, Ratio, VirtualGroup int64
	Managed                                        bool
}

const meterPayload = 6*8 + 1

func (m ExitMeter) Sign(key ed25519.PrivateKey) string {
	var raw [meterPayload + ed25519.SignatureSize]byte
	for i, value := range [...]int64{m.Rule, m.Owner, m.Group, m.Epoch, m.Ratio, m.VirtualGroup} {
		binary.BigEndian.PutUint64(raw[i*8:], uint64(value))
	}
	if m.Managed {
		raw[meterPayload-1] = 1
	}
	copy(raw[meterPayload:], ed25519.Sign(key, raw[:meterPayload]))
	return base64.RawURLEncoding.EncodeToString(raw[:])
}

func VerifyExitMeter(key ed25519.PublicKey, ticket string, group int64) (ExitMeter, bool) {
	var raw [meterPayload + ed25519.SignatureSize]byte
	if len(key) != ed25519.PublicKeySize || len(ticket) != base64.RawURLEncoding.EncodedLen(len(raw)) {
		return ExitMeter{}, false
	}
	n, err := base64.RawURLEncoding.Decode(raw[:], []byte(ticket))
	if err != nil || n != len(raw) {
		return ExitMeter{}, false
	}
	m := ExitMeter{
		Rule: int64(binary.BigEndian.Uint64(raw[0:])), Owner: int64(binary.BigEndian.Uint64(raw[8:])),
		Group: int64(binary.BigEndian.Uint64(raw[16:])), Epoch: int64(binary.BigEndian.Uint64(raw[24:])),
		Ratio: int64(binary.BigEndian.Uint64(raw[32:])), VirtualGroup: int64(binary.BigEndian.Uint64(raw[40:])), Managed: raw[meterPayload-1] == 1,
	}
	if m.Group != group || m.Rule <= 0 || m.Owner <= 0 || m.Epoch < 0 || m.Ratio < 0 || m.Ratio > 100000 {
		return ExitMeter{}, false
	}
	return m, ed25519.Verify(key, raw[:meterPayload], raw[meterPayload:])
}
