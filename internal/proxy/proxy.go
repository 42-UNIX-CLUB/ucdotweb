// Package proxy is the allow-listed proxy for signed-in users: it fetches files from package
// mirrors and source hosts over https for the UC.OS page, which cannot read them itself
// because those hosts send no CORS headers. Only listed hosts and path prefixes, only GET and
// HEAD (plus the POST that `git clone` over smart HTTP needs), every redirect hop checked,
// quotas per user, a panic switch, and a log that keeps the host and the byte count only.
//
// URL shape: GET /proxy/{host}/{path...}?{query}   (upstream is always https://{host}/{path})
package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/42-UNIX-CLUB/ucdotweb/internal/netguard"
	"github.com/42-UNIX-CLUB/ucdotweb/internal/store"
)

// Rule allows one host and the path prefixes under it.
type Rule struct {
	Host     string   `json:"host"`
	Prefixes []string `json:"prefixes"`           // "/" allows every path
	Git      bool     `json:"git,omitempty"`      // also the smart-HTTP clone paths of any repository
	Releases bool     `json:"releases,omitempty"` // also /{owner}/{repo}/releases/download/ and /archive/
}

// DefaultRules are the high-trust hosts named in the design. They seed the store's list the
// first time; administrators change the list after that (see rules.go).
var DefaultRules = []Rule{
	{Host: "deb.debian.org", Prefixes: []string{"/debian/", "/debian-security/", "/debian-ports/"}},
	{Host: "security.debian.org", Prefixes: []string{"/debian-security/"}},
	{Host: "archive.ubuntu.com", Prefixes: []string{"/ubuntu/"}},
	{Host: "security.ubuntu.com", Prefixes: []string{"/ubuntu/"}},
	{Host: "ports.ubuntu.com", Prefixes: []string{"/ubuntu-ports/"}},
	{Host: "github.com", Git: true, Releases: true},
	{Host: "codeload.github.com", Prefixes: []string{"/"}},
	{Host: "objects.githubusercontent.com", Prefixes: []string{"/"}},
	{Host: "release-assets.githubusercontent.com", Prefixes: []string{"/"}},
	{Host: "gitlab.com", Git: true},
	{Host: "codeberg.org", Git: true},
	{Host: "git.kernel.org", Git: true},
	{Host: "cdn.kernel.org", Prefixes: []string{"/pub/"}},
	{Host: "ftp.gnu.org", Prefixes: []string{"/gnu/"}},
	{Host: "files.pythonhosted.org", Prefixes: []string{"/packages/"}},
	{Host: "static.crates.io", Prefixes: []string{"/crates/"}},
	{Host: "index.crates.io", Prefixes: []string{"/"}},
}

// LoadRules reads a JSON list of rules, or returns the defaults if path is empty. The rules
// only seed the store's list, the first time (see Proxy.Start).
func LoadRules(path string) ([]Rule, error) {
	if path == "" {
		return DefaultRules, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rs []Rule
	return rs, json.Unmarshal(b, &rs)
}

// Who identifies the requester; the web package provides it from the session.
type Who func(r *http.Request) (subject string, ok bool)

// Proxy is the handler.
type Proxy struct {
	// Rules seed the store's allow-list if it was never seeded. After that the store's list
	// is the one in force, and this field is not read again.
	Rules  []Rule
	DB     *store.DB
	Who    Who
	Client *http.Client // nil: a client using the guard below
	Guard  *netguard.Guard

	mu      sync.Mutex
	windows map[string][]time.Time // requests in the last minute, per user
	limited map[string]bool        // users refused since their last allowed request
	used    map[string]*dayUse     // bytes today per user, counted per chunk across requests
	swept   time.Time              // last prune of windows and used, under mu
	once    sync.Once

	snap   atomic.Pointer[snapshot] // the store's list as last loaded
	loadMu sync.Mutex               // one reload at a time
	seeded bool                     // under loadMu
}

type dayUse struct {
	day   string
	bytes int64
}

// usedToday returns the user's bytes today, loading them from the database once a day.
func (p *Proxy) usedToday(subject string) int64 {
	day := store.Day(time.Now())
	p.mu.Lock()
	u := p.used[subject]
	p.mu.Unlock()
	if u == nil || u.day != day {
		b, _, _ := p.DB.UsageToday(subject, kind)
		p.mu.Lock()
		if p.used == nil {
			p.used = map[string]*dayUse{}
		}
		if cur := p.used[subject]; cur == nil || cur.day != day {
			p.used[subject] = &dayUse{day: day, bytes: b}
		}
		u = p.used[subject]
		p.mu.Unlock()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return u.bytes
}

// take records n bytes for the user and returns how many of them fit in the quota.
// Concurrent downloads of one user share the same counter, so together they stop at the limit.
func (p *Proxy) take(subject string, n, limit int64) int64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	u := p.used[subject]
	if u == nil { // usedToday normally made it; never dereference a missing entry
		if p.used == nil {
			p.used = map[string]*dayUse{}
		}
		u = &dayUse{day: store.Day(time.Now())}
		p.used[subject] = u
	}
	if limit > 0 && u.bytes+n > limit {
		n = limit - u.bytes
		if n < 0 {
			n = 0
		}
	}
	u.bytes += n
	return n
}

const kind = "proxy"

func (p *Proxy) client() *http.Client {
	p.once.Do(func() {
		if p.Client != nil {
			return
		}
		g := p.Guard
		if g == nil {
			g = &netguard.Guard{}
		}
		tr := &http.Transport{DialContext: g.DialContext, ForceAttemptHTTP2: true, MaxIdleConns: 64,
			IdleConnTimeout: 90 * time.Second, TLSHandshakeTimeout: 10 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second, DisableCompression: true}
		p.Client = &http.Client{Transport: tr}
	})
	return p.Client
}

// allowed checks host, method and path against the rules.
func allowed(rules []Rule, method, host, path, rawQuery, ctype string) bool {
	for _, r := range rules {
		if !strings.EqualFold(r.Host, host) {
			continue
		}
		if r.Git && isGit(method, path, rawQuery, ctype) {
			return true
		}
		if method != "GET" && method != "HEAD" {
			return false
		}
		if r.Releases && isRelease(path) {
			return true
		}
		for _, pre := range r.Prefixes {
			if strings.HasPrefix(path, pre) {
				return true
			}
		}
	}
	return false
}

// isGit allows the two requests of a clone or fetch over smart HTTP, and nothing that writes.
func isGit(method, path, rawQuery, ctype string) bool {
	if strings.Contains(path, "..") {
		return false
	}
	switch {
	case method == "GET" && strings.HasSuffix(path, "/info/refs"):
		q, _ := url.ParseQuery(rawQuery)
		return q.Get("service") == "git-upload-pack"
	case method == "POST" && strings.HasSuffix(path, "/git-upload-pack"):
		return ctype == "application/x-git-upload-pack-request"
	}
	return false
}

// badPath refuses dot segments and encoded slashes or dots, which could walk out of a prefix
// once the upstream server normalises the path.
func badPath(path string) bool {
	l := strings.ToLower(path)
	return strings.Contains(l, "/../") || strings.HasSuffix(l, "/..") || strings.Contains(l, "/./") ||
		strings.Contains(l, "%2e") || strings.Contains(l, "%2f") || strings.Contains(l, "%5c") || strings.Contains(l, "\\")
}

func isRelease(path string) bool {
	parts := strings.SplitN(strings.TrimPrefix(path, "/"), "/", 4)
	return len(parts) == 4 && (parts[2] == "releases" && strings.HasPrefix(parts[3], "download/") || parts[2] == "archive")
}

// rate records a request and reports whether the user is within requests per minute, and
// for a refusal whether it is the first since the user's last allowed request.
func (p *Proxy) rate(subject string, limit int) (ok, first bool) {
	now := time.Now()
	p.mu.Lock()
	defer p.mu.Unlock()
	p.prune(now)
	if limit <= 0 {
		return true, false
	}
	if p.windows == nil {
		p.windows = map[string][]time.Time{}
	}
	w := p.windows[subject]
	i := 0
	for i < len(w) && now.Sub(w[i]) > time.Minute {
		i++
	}
	w = w[i:]
	if len(w) >= limit {
		p.windows[subject] = w
		if p.limited == nil {
			p.limited = map[string]bool{}
		}
		first = !p.limited[subject]
		p.limited[subject] = true
		return false, first
	}
	p.windows[subject] = append(w, now)
	delete(p.limited, subject)
	return true, false
}

// prune drops, at most once a minute, the windows of users with no request in the last
// minute and the byte counts of earlier days, so the maps do not grow with every user ever
// seen. A dropped count is loaded again from the database when needed. Called under mu.
func (p *Proxy) prune(now time.Time) {
	if now.Sub(p.swept) < time.Minute {
		return
	}
	p.swept = now
	for s, w := range p.windows {
		if len(w) == 0 || now.Sub(w[len(w)-1]) > time.Minute {
			delete(p.windows, s)
			delete(p.limited, s)
		}
	}
	day := store.Day(now)
	for s, u := range p.used {
		if u.day != day {
			delete(p.used, s)
		}
	}
}

var passReq = []string{"Accept", "Range", "If-Modified-Since", "If-None-Match", "If-Range", "Git-Protocol", "Content-Type"}
var passResp = []string{"Content-Type", "Content-Length", "Content-Range", "Accept-Ranges", "Last-Modified", "ETag",
	"Content-Encoding", "Cache-Control", "Expires"}

func fail(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	fmt.Fprintln(w, msg)
}

// ServeHTTP handles /proxy/{host}/{path...}.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// A header a cross-site page cannot send without a CORS preflight, which we never answer.
	if r.Header.Get("X-UCOS-Proxy") != "1" {
		fail(w, http.StatusForbidden, "Missing X-UCOS-Proxy header.")
		return
	}
	subject, ok := p.Who(r)
	if !ok {
		fail(w, http.StatusUnauthorized, "Sign in to use the proxy.")
		return
	}
	if p.DB.Flag("proxy_off") || p.DB.Flag("all_off") {
		fail(w, http.StatusServiceUnavailable, "The proxy is switched off by the administrators.")
		return
	}
	u, err := p.DB.GetUser(subject)
	if err != nil || u.Banned {
		fail(w, http.StatusForbidden, "This account may not use the proxy.")
		return
	}
	rest := strings.TrimPrefix(r.URL.EscapedPath(), "/proxy/")
	host, path, _ := strings.Cut(rest, "/")
	path = "/" + path
	if host == "" || len(host) > 253 || strings.Contains(host, "@") || badPath(path) {
		fail(w, http.StatusBadRequest, "Bad host or path.")
		return
	}
	q, err := p.DB.GetQuota("user")
	if err != nil {
		fail(w, http.StatusInternalServerError, "Quota unavailable.")
		return
	}
	// the rate limit comes before anything is logged, so refused requests are limited too,
	// and only the first refusal of a burst writes a row
	if ok, first := p.rate(subject, q.ReqsPerMin); !ok {
		if first {
			_ = p.DB.LogConn(subject, kind, host, 0, "rate limited")
		}
		fail(w, http.StatusTooManyRequests, "Too many requests. Wait a minute.")
		return
	}
	rules, err := p.rules()
	if err != nil {
		fail(w, http.StatusServiceUnavailable, "The proxy's list is unavailable. Try again later.")
		return
	}
	if !allowed(rules, r.Method, host, path, r.URL.RawQuery, r.Header.Get("Content-Type")) {
		_ = p.DB.LogConn(subject, kind, host, 0, "not allowed")
		fail(w, http.StatusForbidden, "This host or path is not on the proxy's list.")
		return
	}
	if p.DB.CapReached(kind) {
		_ = p.DB.LogConn(subject, kind, host, 0, "platform cap")
		fail(w, http.StatusServiceUnavailable, "The platform's daily proxy limit is reached. It resets at 00:00 UTC.")
		return
	}
	if used := p.usedToday(subject); q.BytesPerDay > 0 && used >= q.BytesPerDay {
		_ = p.DB.LogConn(subject, kind, host, 0, "daily quota")
		fail(w, http.StatusTooManyRequests, "Daily proxy quota reached. It resets at 00:00 UTC.")
		return
	}

	target := "https://" + host + path
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	var body io.Reader
	if r.Method == "POST" {
		body = io.LimitReader(r.Body, 8<<20) // a clone negotiation is small
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()
	up, _ := http.NewRequestWithContext(ctx, r.Method, target, body)
	for _, h := range passReq {
		if v := r.Header.Get(h); v != "" {
			up.Header.Set(h, v)
		}
	}
	up.Header.Set("User-Agent", "ucdotweb-proxy")
	c := *p.client()
	c.CheckRedirect = func(next *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("too many redirects")
		}
		rules, err := p.rules() // the list in force now: a host removed mid-request is refused
		if err != nil || next.URL.Scheme != "https" || badPath(next.URL.EscapedPath()) || !allowed(rules, next.Method, next.URL.Host, next.URL.EscapedPath(), next.URL.RawQuery, "") {
			return fmt.Errorf("redirect to %s is not on the list", next.URL.Host)
		}
		return nil
	}
	resp, err := c.Do(up)
	if err != nil {
		outcome := "upstream error"
		if errors.Is(err, netguard.ErrBlocked) {
			outcome = "blocked address"
		}
		_ = p.DB.LogConn(subject, kind, host, 0, outcome)
		fail(w, http.StatusBadGateway, "The upstream request failed.")
		return
	}
	defer resp.Body.Close()
	for _, h := range passResp {
		if v := resp.Header.Get(h); v != "" {
			w.Header().Set(h, v)
		}
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// the file is served from our own origin: it must never run as a page there, even if a
	// browser is somehow led to open it (the X-UCOS-Proxy header already stops plain navigation)
	w.Header().Set("Content-Security-Policy", "sandbox")
	w.Header().Set("Content-Disposition", "attachment")
	w.WriteHeader(resp.StatusCode)
	n, cut := p.copyQuota(w, resp.Body, subject, q.BytesPerDay)
	outcome := fmt.Sprint(resp.StatusCode)
	if cut {
		outcome += " cut at quota"
	}
	_ = p.DB.AddUsage(subject, kind, n, 1)
	_ = p.DB.LogConn(subject, kind, host, n, outcome)
}

// copyQuota copies the body, taking each chunk from the user's daily quota, and says if it
// stopped because the quota ran out.
func (p *Proxy) copyQuota(w http.ResponseWriter, r io.Reader, subject string, limit int64) (int64, bool) {
	buf := make([]byte, 64<<10)
	var n int64
	fl, _ := w.(http.Flusher)
	for {
		k, err := r.Read(buf)
		if k > 0 {
			ok := p.take(subject, int64(k), limit)
			if ok > 0 {
				if _, werr := w.Write(buf[:ok]); werr != nil {
					return n, false
				}
				n += ok
				if fl != nil {
					fl.Flush()
				}
			}
			if ok < int64(k) {
				return n, true
			}
		}
		if err != nil {
			return n, false
		}
	}
}
