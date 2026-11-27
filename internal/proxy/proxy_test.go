package proxy

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/42-UNIX-CLUB/ucdotweb/internal/netguard"
	"github.com/42-UNIX-CLUB/ucdotweb/internal/store"
)

// rig: a fake upstream "mirror" over TLS, a proxy whose client resolves the listed host
// names to that upstream, and a store.
type rig struct {
	db       *store.DB
	upstream *httptest.Server
	front    *httptest.Server
	hits     atomic.Int64
}

func newRig(t *testing.T, signedIn bool) *rig {
	t.Helper()
	r := &rig{}
	r.upstream = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.hits.Add(1)
		switch {
		case req.URL.Path == "/debian/dists/stable/InRelease":
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("Set-Cookie", "upstream=1")
			io.WriteString(w, strings.Repeat("x", 1000))
		case req.URL.Path == "/debian/redirect-out":
			http.Redirect(w, req, "https://evil.example/debian/x", http.StatusFound)
		case req.URL.Path == "/debian/redirect-in":
			http.Redirect(w, req, "/debian/dists/stable/InRelease", http.StatusFound)
		case strings.HasSuffix(req.URL.Path, "/info/refs"):
			io.WriteString(w, "refs")
		default:
			http.NotFound(w, req)
		}
	}))
	db, err := store.Open(t.TempDir()+"/p.db", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.SeenUser("u1", "tester"); err != nil {
		t.Fatal(err)
	}
	r.db = db
	upAddr := r.upstream.Listener.Addr().String()
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // the test server's own certificate
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, upAddr) // every listed host is the fake mirror
		},
	}
	p := &Proxy{Rules: DefaultRules, DB: db, Client: &http.Client{Transport: tr},
		Who: func(*http.Request) (string, bool) { return "u1", signedIn }}
	r.front = httptest.NewServer(p)
	t.Cleanup(func() { r.front.Close(); r.upstream.Close(); db.Close() })
	return r
}

func (r *rig) get(t *testing.T, path string, hdr bool) *http.Response {
	t.Helper()
	req, _ := http.NewRequest("GET", r.front.URL+path, nil)
	if hdr {
		req.Header.Set("X-UCOS-Proxy", "1")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestAllowedFetch(t *testing.T) {
	r := newRig(t, true)
	resp := r.get(t, "/proxy/deb.debian.org/debian/dists/stable/InRelease", true)
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || len(b) != 1000 {
		t.Fatalf("status %d, %d bytes", resp.StatusCode, len(b))
	}
	if resp.Header.Get("Content-Security-Policy") != "sandbox" || resp.Header.Get("Content-Disposition") != "attachment" {
		t.Fatalf("proxied file not sandboxed: %q %q", resp.Header.Get("Content-Security-Policy"), resp.Header.Get("Content-Disposition"))
	}
	if resp.Header.Get("Set-Cookie") != "" {
		t.Fatal("an upstream cookie was passed to the browser")
	}
	r.front.Close() // waits for the handler, which records usage after the body is sent
	if used, reqs, _ := r.db.UsageToday("u1", "proxy"); used != 1000 || reqs != 1 {
		t.Fatalf("usage %d bytes %d requests", used, reqs)
	}
}

func TestRefusals(t *testing.T) {
	r := newRig(t, true)
	cases := map[string]struct {
		path string
		hdr  bool
		want int
	}{
		"no header":         {"/proxy/deb.debian.org/debian/dists/stable/InRelease", false, 403},
		"host not listed":   {"/proxy/example.org/", true, 403},
		"path not listed":   {"/proxy/deb.debian.org/other/x", true, 403},
		"dot segments":      {"/proxy/deb.debian.org/debian/../etc/passwd", true, 400},
		"encoded dots":      {"/proxy/deb.debian.org/debian/%2e%2e/x", true, 400},
		"encoded slash":     {"/proxy/deb.debian.org/debian%2f..%2fx", true, 400},
		"userinfo":          {"/proxy/x@deb.debian.org/debian/", true, 400},
		"git push refs":     {"/proxy/github.com/a/b/info/refs?service=git-receive-pack", true, 403},
		"github page":       {"/proxy/github.com/a/b/issues", true, 403},
		"redirect off list": {"/proxy/deb.debian.org/debian/redirect-out", true, 502},
	}
	for name, c := range cases {
		resp := r.get(t, c.path, c.hdr)
		resp.Body.Close()
		if resp.StatusCode != c.want {
			t.Errorf("%s: status %d, want %d", name, resp.StatusCode, c.want)
		}
	}
}

func TestGitAndRedirectAllowed(t *testing.T) {
	r := newRig(t, true)
	for _, p := range []string{"/proxy/github.com/a/b.git/info/refs?service=git-upload-pack", "/proxy/deb.debian.org/debian/redirect-in"} {
		resp := r.get(t, p, true)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Errorf("%s: status %d", p, resp.StatusCode)
		}
	}
}

func TestSignedOut(t *testing.T) {
	r := newRig(t, false)
	resp := r.get(t, "/proxy/deb.debian.org/debian/dists/stable/InRelease", true)
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("status %d, want 401", resp.StatusCode)
	}
}

func TestPanicSwitchAndBan(t *testing.T) {
	r := newRig(t, true)
	_ = r.db.SetFlag("admin", "proxy_off", true)
	resp := r.get(t, "/proxy/deb.debian.org/debian/dists/stable/InRelease", true)
	resp.Body.Close()
	if resp.StatusCode != 503 {
		t.Fatalf("switch off: status %d, want 503", resp.StatusCode)
	}
	_ = r.db.SetFlag("admin", "proxy_off", false)
	_ = r.db.SetGrant("admin", "u1", "banned", true, "test")
	resp = r.get(t, "/proxy/deb.debian.org/debian/dists/stable/InRelease", true)
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("banned: status %d, want 403", resp.StatusCode)
	}
}

func TestDailyQuotaCuts(t *testing.T) {
	r := newRig(t, true)
	if err := r.db.Exec(`UPDATE quotas SET bytes_per_day = 1500 WHERE tier = 'user'`); err != nil {
		t.Fatal(err)
	}
	for i, want := range []int{1000, 500} { // the second response is cut at the quota
		resp := r.get(t, "/proxy/deb.debian.org/debian/dists/stable/InRelease", true)
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if len(b) != want {
			t.Fatalf("request %d: %d bytes, want %d", i, len(b), want)
		}
	}
	resp := r.get(t, "/proxy/deb.debian.org/debian/dists/stable/InRelease", true)
	resp.Body.Close()
	if resp.StatusCode != 429 {
		t.Fatalf("over quota: status %d, want 429", resp.StatusCode)
	}
}

func TestRateLimit(t *testing.T) {
	r := newRig(t, true)
	_ = r.db.Exec(`UPDATE quotas SET reqs_per_min = 3 WHERE tier = 'user'`)
	codes := []int{}
	for i := 0; i < 4; i++ {
		resp := r.get(t, "/proxy/deb.debian.org/debian/dists/stable/InRelease", true)
		resp.Body.Close()
		codes = append(codes, resp.StatusCode)
	}
	if codes[2] != 200 || codes[3] != 429 {
		t.Fatalf("codes %v, want the 4th refused", codes)
	}
}

func TestLogKeepsHostOnly(t *testing.T) {
	r := newRig(t, true)
	resp := r.get(t, "/proxy/deb.debian.org/debian/dists/stable/InRelease?secret=1", true)
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	r.front.Close() // waits for the handler, which logs after the body is sent
	var host string
	if err := r.db.QueryRow(`SELECT host FROM conn_log`, &host); err != nil {
		t.Fatal(err)
	}
	if host != "deb.debian.org" {
		t.Fatalf("logged %q", host)
	}
}

func TestGuardRefusesPrivate(t *testing.T) {
	g := &netguard.Guard{}
	for _, s := range []string{"127.0.0.1", "10.1.2.3", "169.254.169.254", "192.168.1.1", "100.64.0.1", "::1",
		"fd00::1", "fe80::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1", "0.0.0.0", "224.0.0.1",
		"64:ff9b::a00:1", "64:ff9b::7f00:1", "2002:a00:1::1", "2002:c0a8:101::1"} { // NAT64 and 6to4 hold an IPv4 address
		if g.Allowed(netip.MustParseAddr(s)) {
			t.Errorf("%s allowed", s)
		}
	}
	for _, s := range []string{"151.101.2.132", "2a04:4e42::644"} {
		if !g.Allowed(netip.MustParseAddr(s)) {
			t.Errorf("%s refused", s)
		}
	}
	if _, err := g.DialContext(t.Context(), "tcp", "127.0.0.1:1"); err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Errorf("dial to loopback: %v", err)
	}
}

func TestConcurrentDownloadsShareQuota(t *testing.T) {
	r := newRig(t, true)
	if err := r.db.Exec(`UPDATE quotas SET bytes_per_day = 2500, reqs_per_min = 0 WHERE tier = 'user'`); err != nil {
		t.Fatal(err)
	}
	total := make(chan int, 5)
	for i := 0; i < 5; i++ { // 5 x 1000 bytes in parallel against a 2500-byte quota
		go func() {
			resp := r.get(t, "/proxy/deb.debian.org/debian/dists/stable/InRelease", true)
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				b = nil // refused at the start, after the others used the quota: the body is the error text
			}
			total <- len(b)
		}()
	}
	sum := 0
	for i := 0; i < 5; i++ {
		sum += <-total
	}
	if sum > 2500 {
		t.Fatalf("parallel downloads delivered %d bytes past a 2500-byte quota", sum)
	}
}

func TestPlatformCap(t *testing.T) {
	r := newRig(t, true)
	if err := r.db.SetCap("admin", "proxy", 500); err != nil {
		t.Fatal(err)
	}
	_ = r.db.AddUsage("someone-else", "proxy", 500, 1) // other users used the platform's day
	resp := r.get(t, "/proxy/deb.debian.org/debian/dists/stable/InRelease", true)
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable || r.hits.Load() != 0 {
		t.Fatalf("status %d, upstream hits %d: want 503 and no fetch", resp.StatusCode, r.hits.Load())
	}
	var outcome string
	if err := r.db.QueryRow(`SELECT outcome FROM conn_log`, &outcome); err != nil || outcome != "platform cap" {
		t.Fatalf("log %q %v", outcome, err)
	}
}

func TestZeroByteQuotaMeansNoLimit(t *testing.T) {
	r := newRig(t, true)
	if err := r.db.SetQuota("admin", "user", store.Quota{BytesPerDay: 0}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		resp := r.get(t, "/proxy/deb.debian.org/debian/dists/stable/InRelease", true)
		b, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil || resp.StatusCode != 200 || len(b) != 1000 {
			t.Fatalf("request %d: status %d, %d bytes, err %v", i, resp.StatusCode, len(b), err)
		}
	}
}

func TestPruneDropsIdleUsers(t *testing.T) {
	p := &Proxy{}
	old := time.Now().Add(-2 * time.Minute)
	p.windows = map[string][]time.Time{"idle": {old}, "busy": {time.Now()}}
	p.used = map[string]*dayUse{"yesterday": {day: "2000-01-01", bytes: 5}, "today": {day: store.Day(time.Now()), bytes: 7}}
	p.mu.Lock()
	p.prune(time.Now())
	p.mu.Unlock()
	if _, ok := p.windows["idle"]; ok || len(p.windows) != 1 {
		t.Fatalf("windows after prune: %v", p.windows)
	}
	if _, ok := p.used["yesterday"]; ok || len(p.used) != 1 {
		t.Fatalf("used after prune: %v", p.used)
	}
	if p.take("new", 10, 0) != 10 { // an entry that was never loaded must not crash take
		t.Fatal("take on a missing entry")
	}
}
