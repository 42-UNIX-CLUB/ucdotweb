// Package netguard decides which addresses the proxy and the relay may connect to, and
// provides a dialer that resolves a name, checks every address, and connects only to an
// address it checked (so a second DNS answer cannot redirect the connection: DNS rebinding).
package netguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"
)

var blocked = mustPrefixes(
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
	"192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15",
	"198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32",
	"::/128", "::1/128", "64:ff9b::/96", "64:ff9b:1::/48", "2002::/16", "100::/64", "2001::/23", "2001:db8::/32", "fc00::/7",
	"fe80::/10", "ff00::/8",
)

func mustPrefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

// ErrBlocked is returned for an address the platform refuses to reach.
var ErrBlocked = errors.New("destination address is not allowed")

// Guard checks addresses. AllowLoopback exists only for tests.
type Guard struct {
	AllowLoopback bool
	Resolver      *net.Resolver
	Timeout       time.Duration
}

// Allowed reports whether an address may be reached.
func (g *Guard) Allowed(a netip.Addr) bool {
	if a.Zone() != "" {
		return false // a zoned literal ("fe80::1%eth0") escapes the prefix list: never needed for the internet
	}
	a = a.Unmap() // IPv4-mapped IPv6 is checked as IPv4
	if g.AllowLoopback && a.IsLoopback() {
		return true
	}
	if !a.IsValid() || a.IsUnspecified() || a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() ||
		a.IsLinkLocalMulticast() || a.IsMulticast() {
		return false
	}
	for _, p := range blocked {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

// DialContext resolves host, refuses if any answer is blocked, and dials the first allowed
// address. It has the signature of net.Dialer.DialContext so it can be plugged into an
// http.Transport.
func (g *Guard) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	r := g.Resolver
	if r == nil {
		r = net.DefaultResolver
	}
	var addrs []netip.Addr
	if a, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{a}
	} else {
		addrs, err = r.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("%s: no addresses", host)
	}
	for _, a := range addrs {
		if !g.Allowed(a) { // one bad answer refuses the name: no mixing public and private
			return nil, fmt.Errorf("%s resolves to %s: %w", host, a, ErrBlocked)
		}
	}
	timeout := g.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	d := net.Dialer{Timeout: timeout}
	var last error
	for _, a := range addrs {
		c, err := d.DialContext(ctx, network, net.JoinHostPort(a.String(), port))
		if err == nil {
			return c, nil
		}
		last = err
	}
	return nil, last
}
