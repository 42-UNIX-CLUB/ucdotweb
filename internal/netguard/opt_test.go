package netguard

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

// Finding N1: an IPv6 literal with a zone ("%lo") is not matched by any prefix of the blocked
// list, because netip.Prefix.Contains never matches an address that carries a zone.
func TestOptZonedAddressIsRefused(t *testing.T) {
	g := &Guard{}
	for _, s := range []string{"64:ff9b::a9fe:a9fe", "64:ff9b:1::1", "2002:7f00:1::1", "2001::1", "2001:db8::1", "100::1"} {
		if g.Allowed(netip.MustParseAddr(s)) {
			t.Errorf("%s is allowed without a zone", s)
		}
		if g.Allowed(netip.MustParseAddr(s + "%lo")) {
			t.Errorf("%s%%lo is allowed: the zone hides it from the blocked list", s)
		}
	}
	// the dialer: a context that is already cancelled, so nothing is sent whatever happens
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := g.DialContext(ctx, "tcp", "[64:ff9b::a9fe:a9fe%lo]:80")
	if !errors.Is(err, ErrBlocked) {
		t.Errorf("dialing [64:ff9b::a9fe:a9fe%%lo]:80: %v, want ErrBlocked", err)
	}
	_, err = g.DialContext(ctx, "tcp", "[64:ff9b::a9fe:a9fe]:80")
	if !errors.Is(err, ErrBlocked) {
		t.Errorf("control, no zone: %v, want ErrBlocked", err)
	}
}
