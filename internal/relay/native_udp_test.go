package relay

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"syscall"
	"testing"
	"time"

	"hopx/internal/wire"

	"hopx/internal/certificate"
)

func TestNativeUDPWithDTLS(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	target, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		buf := make([]byte, 9000)
		for {
			n, addr, err := target.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = target.WriteToUDP(buf[:n], addr)
		}
	}()

	key := hex.EncodeToString([]byte(rand.Text() + rand.Text())[:32])
	listener, err := ListenNativeUDP(ctx, "127.0.0.1:0", key, make(chan struct{}, 4))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if _, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second); err == nil {
		t.Fatal("native UDP unexpectedly has a TCP listener")
	}
	cert, _, err := certificate.SelfSigned(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	session, err := Prepare([]wire.Hop{{Addr: listener.Addr().String(), Cert: cert, NativeUDPKey: key}})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := session.Dial(ctx, "udp", target.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	for _, sent := range [][]byte{[]byte("UDP"), nil, bytes.Repeat([]byte("x"), nativeUDPPayload), []byte("second")} {
		if n, err := conn.Write(sent); err != nil || n != len(sent) {
			t.Fatalf("write %d bytes: %d, %v", len(sent), n, err)
		}
		got := make([]byte, nativeUDPPayload)
		if n, err := conn.Read(got); err != nil || !bytes.Equal(got[:n], sent) {
			t.Fatalf("read %d bytes: %d, %v", len(sent), n, err)
		}
	}
	if _, err := conn.Write(make([]byte, nativeUDPPayload+1)); !errors.Is(err, syscall.EMSGSIZE) {
		t.Fatalf("oversize datagram returned %v", err)
	}
	invalidKey := make([]byte, 32)
	rejectCtx, stop := context.WithTimeout(ctx, time.Second)
	defer stop()
	if other, err := dialNativeUDP(rejectCtx, listener.Addr().String(), invalidKey, target.LocalAddr().String()); err == nil {
		other.Close()
		t.Fatal("incorrect DTLS key was accepted")
	}
}
