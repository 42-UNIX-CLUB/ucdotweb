package proxy

import (
	"math/rand"
	"net/url"
	"path"
	"strings"
	"testing"
)

// A search for a path that the proxy lets through under the prefix /debian/ but that a
// server which decodes percent escapes once and then resolves dot segments (what nginx and
// Apache do) would serve from outside /debian/. Random paths built from awkward pieces, a
// fixed seed, so the run repeats.
func TestOptNoPathLeavesThePrefix(t *testing.T) {
	rules := []Rule{{Host: "h.example", Prefixes: []string{"/debian/"}}}
	pieces := []string{"/", "/", "..", ".", "%2e", "%2E", "%2f", "%2F", "%5c", "%5C", "\\", "debian", "a", ";", "..;", "%00",
		"%252e", "%252f", "%c0%ae", "%u002e", "?", "#", "%3f", "%23", " ", "%20", "%09", "%0a", "%e3%80%82", "。", "．", "%", "%2", "+"}
	rng := rand.New(rand.NewSource(20261127))
	const tries = 2_000_000
	let, escapes, twice := 0, 0, 0
	var first, firstTwice string
	for i := 0; i < tries; i++ {
		var b strings.Builder
		b.WriteString("/proxy/h.example/debian/")
		for n := rng.Intn(8); n > 0; n-- {
			b.WriteString(pieces[rng.Intn(len(pieces))])
		}
		raw := b.String()
		if strings.ContainsAny(raw, " \t\n") {
			continue // not a request line a server would read as one target
		}
		// what the server does with the request target, then what ServeHTTP does with it
		in, err := url.ParseRequestURI(raw)
		if err != nil {
			continue
		}
		rest := strings.TrimPrefix(in.EscapedPath(), "/proxy/")
		host, p, _ := strings.Cut(rest, "/")
		p = "/" + p
		if host != "h.example" || badPath(p) || !allowed(rules, "GET", host, p, in.RawQuery, "") {
			continue
		}
		let++
		target := "https://" + host + p
		if in.RawQuery != "" {
			target += "?" + in.RawQuery
		}
		u, err := url.Parse(target) // http.NewRequest does this
		if err != nil {
			continue // the request is never made
		}
		sent := u.EscapedPath()
		once, err := url.PathUnescape(sent)
		if err != nil {
			continue
		}
		if !strings.HasPrefix(path.Clean(strings.ReplaceAll(once, "\\", "/"))+"/", "/debian/") {
			escapes++
			if first == "" {
				first = p + "  ->  sent " + sent + "  ->  " + path.Clean(once)
			}
		}
		if two, err := url.PathUnescape(once); err == nil && !strings.HasPrefix(path.Clean(strings.ReplaceAll(two, "\\", "/"))+"/", "/debian/") {
			twice++
			if firstTwice == "" {
				firstTwice = p + "  ->  " + path.Clean(two)
			}
		}
	}
	t.Logf("%d random paths, %d let through; outside the prefix after one decoding: %d; after two decodings: %d", tries, let, escapes, twice)
	if escapes > 0 {
		t.Errorf("a path the proxy lets through leaves /debian/ on a server that decodes once: %s", first)
	}
	if twice > 0 {
		t.Logf("leaves /debian/ only on a server that decodes twice (not what the listed mirrors do): %s", firstTwice)
	}
}
