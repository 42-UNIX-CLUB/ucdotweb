package proxy

import (
	"io"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/42-UNIX-CLUB/ucdotweb/internal/store"
)

func openDB(t testing.TB) *store.DB {
	t.Helper()
	db, err := store.Open(t.TempDir()+"/r.db", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func status(t *testing.T, r *rig, path string) int {
	t.Helper()
	resp := r.get(t, path, true)
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode
}

func TestAdminChangeTakesEffectLive(t *testing.T) {
	r := newRig(t, true)
	const added = "/proxy/mirror.example.net/debian/dists/stable/InRelease"
	const listed = "/proxy/deb.debian.org/debian/dists/stable/InRelease"
	if c := status(t, r, added); c != 403 {
		t.Fatalf("before the add: status %d, want 403", c)
	}
	if c := status(t, r, listed); c != 200 {
		t.Fatalf("seeded host: status %d, want 200", c)
	}
	if _, err := r.db.PutAllowRule("adm", store.AllowRule{Host: "mirror.example.net", Prefixes: []string{"/debian/"}}); err != nil {
		t.Fatal(err)
	}
	if c := status(t, r, added); c != 200 {
		t.Fatalf("after the add: status %d, want 200", c)
	}
	if c := status(t, r, "/proxy/mirror.example.net/other/x"); c != 403 {
		t.Fatalf("path outside the new prefix: status %d, want 403", c)
	}
	if err := r.db.RemoveAllowRule("adm", "deb.debian.org"); err != nil {
		t.Fatal(err)
	}
	if c := status(t, r, listed); c != 403 {
		t.Fatalf("after the remove: status %d, want 403", c)
	}
	// replacing a rule narrows it at once
	if _, err := r.db.PutAllowRule("adm", store.AllowRule{Host: "mirror.example.net", Prefixes: []string{"/ubuntu/"}}); err != nil {
		t.Fatal(err)
	}
	if c := status(t, r, added); c != 403 {
		t.Fatalf("after narrowing: status %d, want 403", c)
	}
}

func TestRedirectCheckedAgainstLiveList(t *testing.T) {
	r := newRig(t, true)
	if c := status(t, r, "/proxy/deb.debian.org/debian/redirect-in"); c != 200 {
		t.Fatalf("redirect inside the list: status %d", c)
	}
	// the redirect target is under /debian/ on the same host; drop /debian/dists/ from it
	if _, err := r.db.PutAllowRule("adm", store.AllowRule{Host: "deb.debian.org", Prefixes: []string{"/debian/redirect-in"}}); err != nil {
		t.Fatal(err)
	}
	if c := status(t, r, "/proxy/deb.debian.org/debian/redirect-in"); c != 502 {
		t.Fatalf("redirect to a path no longer listed: status %d, want 502", c)
	}
}

func TestSeedFromStartingRulesOnce(t *testing.T) {
	db := openDB(t)
	p := &Proxy{Rules: DefaultRules, DB: db}
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	got, err := p.rules()
	if err != nil {
		t.Fatal(err)
	}
	// the store's copy matches the defaults field for field (order is by host)
	want := append([]Rule(nil), DefaultRules...)
	sort.Slice(want, func(i, j int) bool { return want[i].Host < want[j].Host })
	if len(got) != len(want) {
		t.Fatalf("%d rules, want %d", len(got), len(want))
	}
	for i := range want {
		g, w := got[i], want[i]
		if g.Host != w.Host || g.Git != w.Git || g.Releases != w.Releases || strings.Join(g.Prefixes, " ") != strings.Join(w.Prefixes, " ") {
			t.Fatalf("rule %d: %+v, want %+v", i, g, w)
		}
	}
	// a second service start with other rules does not reseed
	p2 := &Proxy{Rules: []Rule{{Host: "other.org", Prefixes: []string{"/"}}}, DB: db}
	if err := p2.Start(); err != nil {
		t.Fatal(err)
	}
	got2, _ := p2.rules()
	if len(got2) != len(want) {
		t.Fatalf("reseeded: %d rules", len(got2))
	}
}

func TestBadStartingRulesRefused(t *testing.T) {
	for name, rs := range map[string][]Rule{
		"twice":     {{Host: "a.org", Prefixes: []string{"/"}}, {Host: "a.org", Prefixes: []string{"/x/"}}},
		"uppercase": {{Host: "A.org", Prefixes: []string{"/"}}},
		"no slash":  {{Host: "a.org", Prefixes: []string{"x/"}}},
	} {
		db := openDB(t)
		p := &Proxy{Rules: rs, DB: db}
		if err := p.Start(); err == nil {
			t.Errorf("%s: started", name)
		}
		if _, err := p.rules(); err == nil {
			t.Errorf("%s: rules served", name)
		}
		if got, _ := db.AllowRules(); len(got) != 0 {
			t.Errorf("%s: seeded %v", name, got)
		}
	}
}

func TestFailsClosedWhenTheStoreFails(t *testing.T) {
	db, err := store.Open(t.TempDir()+"/c.db", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	p := &Proxy{Rules: DefaultRules, DB: db}
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	db.Close()
	// any change anywhere moves the version; the reload then fails
	other := openDB(t)
	if _, err := other.PutAllowRule("adm", store.AllowRule{Host: "x.org", Prefixes: []string{"/"}}); err != nil {
		t.Fatal(err)
	}
	if rs, err := p.rules(); err == nil {
		t.Fatalf("served %d rules from a closed store", len(rs))
	}
}

func TestValidateRule(t *testing.T) {
	good := []Rule{
		{Host: "deb.debian.org", Prefixes: []string{"/debian/"}},
		{Host: "github.com", Git: true},
		{Host: "codeload.github.com", Prefixes: []string{"/"}},
		{Host: "a-b.c0.example.net", Prefixes: []string{"/x/y_z~1.2+3/", "/a%20b/"}},
		{Host: "xn--bcher-kva.de", Releases: true},
	}
	for _, r := range good {
		if err := ValidateRule(r); err != nil {
			t.Errorf("%+v refused: %v", r, err)
		}
	}
	if _, err := ValidateRules(DefaultRules); err != nil {
		t.Errorf("the defaults are refused: %v", err)
	}
	hosts := []string{"", "https://deb.debian.org", "deb.debian.org:443", "deb.debian.org/debian", "*.debian.org",
		"Deb.Debian.org", "deb.debian.org.", ".debian.org", "deb..org", "localhost", "foo.localhost", "printer.local",
		"db.internal", "router.lan", "nas.home.arpa", "1.2.3.4", "127.1", "[::1]", "::1", "2130706433", "0x7f000001",
		"-a.org", "a-.org", "a.b", "user@a.org", "a.org?x", "a .org", "Kernel.org", strings.Repeat("a", 64) + ".org",
		"site.test", "x.onion", "intranet", "a.invalid", "a.example", "4.3.2.1.in-addr.arpa"}
	for _, h := range hosts {
		if err := ValidateRule(Rule{Host: h, Prefixes: []string{"/"}}); err == nil {
			t.Errorf("host %q accepted", h)
		}
	}
	prefixes := []string{"", "debian/", "/debian/../etc/", "/debian/..", "/./x", "/x/.", "/%2e%2e/", "/a%2Fb", "/a%5cb",
		"/a\\b", "/a?b", "/a#b", "/a b", "/a\nb", "//x", "/a%zz", "/a%2", "/" + strings.Repeat("a", 200), "/é/"}
	for _, p := range prefixes {
		if err := ValidateRule(Rule{Host: "a.org", Prefixes: []string{p}}); err == nil {
			t.Errorf("prefix %q accepted", p)
		}
	}
	if err := ValidateRule(Rule{Host: "a.org"}); err == nil {
		t.Error("a rule that allows nothing was accepted")
	}
	many := make([]string, MaxPrefixes+1)
	for i := range many {
		many[i] = "/p/"
	}
	if err := ValidateRule(Rule{Host: "a.org", Prefixes: many}); err == nil {
		t.Error("too many prefixes accepted")
	}
}

// The matching rules, unchanged by the move to the store: checked against the list as the
// store returns it after the seed.
func TestMatchingUnchanged(t *testing.T) {
	p := &Proxy{Rules: DefaultRules, DB: openDB(t)}
	rules, err := p.rules()
	if err != nil {
		t.Fatal(err)
	}
	const pack = "application/x-git-upload-pack-request"
	cases := []struct {
		method, host, path, query, ctype string
		want                             bool
	}{
		{"GET", "deb.debian.org", "/debian/dists/stable/InRelease", "", "", true},
		{"HEAD", "deb.debian.org", "/debian/x", "", "", true},
		{"GET", "DEB.Debian.ORG", "/debian/x", "", "", true}, // host compared without case, as before
		{"POST", "deb.debian.org", "/debian/x", "", "", false},
		{"PUT", "deb.debian.org", "/debian/x", "", "", false},
		{"GET", "deb.debian.org", "/debianx", "", "", false},
		{"GET", "deb.debian.org.evil.org", "/debian/x", "", "", false},
		{"GET", "github.com", "/a/b.git/info/refs", "service=git-upload-pack", "", true},
		{"GET", "github.com", "/a/b.git/info/refs", "service=git-receive-pack", "", false},
		{"POST", "github.com", "/a/b.git/git-upload-pack", "", pack, true},
		{"POST", "github.com", "/a/b.git/git-upload-pack", "", "text/plain", false},
		{"POST", "github.com", "/a/b.git/git-receive-pack", "", pack, false},
		{"POST", "github.com", "/a/../b.git/git-upload-pack", "", pack, false},
		{"GET", "github.com", "/a/b/releases/download/v1/x.tar.gz", "", "", true},
		{"GET", "github.com", "/a/b/archive/v1.tar.gz", "", "", true},
		{"GET", "github.com", "/a/b/releases/latest", "", "", false},
		{"GET", "github.com", "/a/b/issues", "", "", false},
		{"HEAD", "github.com", "/a/b/archive/v1.tar.gz", "", "", true},
		{"POST", "github.com", "/a/b/archive/v1.tar.gz", "", "", false},
		{"GET", "gitlab.com", "/a/b/archive/v1.tar.gz", "", "", false}, // git only, no releases
		{"POST", "gitlab.com", "/a/b.git/git-upload-pack", "", pack, true},
		{"POST", "codeload.github.com", "/x", "", pack, false},
		{"GET", "codeload.github.com", "/anything", "", "", true},
		{"GET", "cdn.kernel.org", "/pub/linux/x", "", "", true},
		{"GET", "cdn.kernel.org", "/private/x", "", "", false},
		{"GET", "example.org", "/", "", "", false},
	}
	for _, c := range cases {
		if got := allowed(rules, c.method, c.host, c.path, c.query, c.ctype); got != c.want {
			t.Errorf("%s %s%s?%s: %v, want %v", c.method, c.host, c.path, c.query, got, c.want)
		}
		if got := allowed(DefaultRules, c.method, c.host, c.path, c.query, c.ctype); got != c.want {
			t.Errorf("defaults directly, %s %s%s: %v, want %v", c.method, c.host, c.path, got, c.want)
		}
	}
}

// Readers and an administrator at once; run with -race.
func TestRulesConcurrentWithChanges(t *testing.T) {
	db := openDB(t)
	p := &Proxy{Rules: DefaultRules, DB: db}
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				rs, err := p.rules()
				if err != nil {
					t.Error(err)
					return
				}
				_ = allowed(rs, "GET", "deb.debian.org", "/debian/x", "", "")
			}
		}()
	}
	for i := 0; i < 50; i++ {
		pre := []string{"/a/"}
		if i%2 == 1 {
			pre = []string{"/b/"}
		}
		if _, err := db.PutAllowRule("adm", store.AllowRule{Host: "flip.example.net", Prefixes: pre}); err != nil {
			t.Fatal(err)
		}
	}
	close(stop)
	wg.Wait()
	rs, _ := p.rules()
	if !allowed(rs, "GET", "flip.example.net", "/b/x", "", "") || allowed(rs, "GET", "flip.example.net", "/a/x", "", "") {
		t.Fatal("the last change is not the one in force")
	}
}

// The cost a request pays to get the list when nothing changed.
func BenchmarkRulesCached(b *testing.B) {
	p := &Proxy{Rules: DefaultRules, DB: openDB(b)}
	if err := p.Start(); err != nil {
		b.Fatal(err)
	}
	for b.Loop() {
		if _, err := p.rules(); err != nil {
			b.Fatal(err)
		}
	}
}

// The match itself, for comparison.
func BenchmarkAllowed(b *testing.B) {
	for b.Loop() {
		allowed(DefaultRules, "GET", "index.crates.io", "/config.json", "", "")
	}
}
