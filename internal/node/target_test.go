package node

import (
	"context"
	"errors"
	"testing"
	"time"

	"hopx/internal/relay"
)

func TestSiteTargetPolicyPinsPublicAddresses(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for _, target := range []string{
		"127.0.0.1:443", "localhost:443", "[::ffff:127.0.0.1]:443",
		"10.0.0.1:443", "169.254.169.254:80", "[fc00::1]:443",
	} {
		_, _, err := dialRuleTarget(ctx, &relay.Session{}, "tcp", target, "", true)
		if !errors.Is(err, errPrivateDestination) {
			t.Fatalf("private target %s returned %v", target, err)
		}
	}
	for _, target := range []string{"8.8.8.8:53", "[2606:4700:4700::1111]:53"} {
		first, second, err := resolvePublicTarget(ctx, target)
		if err != nil || first != target || second != "" {
			t.Fatalf("public target %s returned %q and %q (%v)", target, first, second, err)
		}
	}
}
