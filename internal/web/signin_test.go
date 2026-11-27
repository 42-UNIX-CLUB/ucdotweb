package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/42-UNIX-CLUB/ucdotweb/internal/session"
)

// started is a sign-in begun by a browser with no cookie jar: the sealed cookie GET
// /auth/login set, the provider's authorize URL, and the callback URL the provider answered.
type started struct {
	cookie    *http.Cookie
	authorize string
	callback  string
}

func startSignIn(t *testing.T, r *rig) started {
	t.Helper()
	c := noFollow(&http.Client{})
	resp, err := c.Get(r.app.URL + "/auth/login")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	var st started
	for _, ck := range resp.Cookies() {
		if ck.Name == r.srv.pendingCookie() {
			st.cookie = ck
		}
	}
	if st.cookie == nil {
		t.Fatalf("no pending sign-in cookie in %q", resp.Header.Values("Set-Cookie"))
	}
	st.authorize = resp.Header.Get("Location")
	st.callback = providerAnswer(t, st.authorize)
	return st
}

// providerAnswer asks the stand-in provider to authorize and returns the callback URL it
// redirects to, with a fresh code.
func providerAnswer(t *testing.T, authorize string) string {
	t.Helper()
	resp, err := noFollow(&http.Client{}).Get(authorize)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.Header.Get("Location")
}

// callbackWith sends the callback with exactly the given cookies.
func callbackWith(t *testing.T, cb string, cookies ...*http.Cookie) *http.Response {
	t.Helper()
	req, _ := http.NewRequest("GET", cb, nil)
	for _, ck := range cookies {
		req.AddCookie(&http.Cookie{Name: ck.Name, Value: ck.Value})
	}
	resp, err := noFollow(&http.Client{}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp
}

func setCookieFor(resp *http.Response, name string) string {
	for _, sc := range resp.Header.Values("Set-Cookie") {
		if strings.HasPrefix(sc, name+"=") {
			return sc
		}
	}
	return ""
}

func TestLoginWritesNoRowAndSealsACookie(t *testing.T) {
	r := newRig(t, map[string]any{"login": "x", "status": "active"})
	resp, err := noFollow(&http.Client{}).Get(r.app.URL + "/auth/login")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if n := r.sessions.Count(); n != 0 {
		t.Fatalf("GET /auth/login stored %d session rows, want 0", n)
	}
	sc := setCookieFor(resp, "ucdotweb-signin")
	for _, want := range []string{"HttpOnly", "SameSite=Lax", "Path=/;", "Max-Age=600"} {
		if !strings.Contains(sc, want) {
			t.Fatalf("pending cookie %q lacks %s", sc, want)
		}
	}
	if strings.Contains(sc, "Secure") {
		t.Fatalf("pending cookie %q is Secure with insecure cookies on", sc)
	}
	if strings.Contains(sc, "verifier") || strings.Contains(sc, `"s"`) {
		t.Fatalf("pending cookie %q is not sealed", sc)
	}
	// with secure cookies: the Secure flag and the __Secure- prefix
	sec := &Server{Sessions: session.New(time.Minute, time.Hour, true), DB: r.db}
	rec := httptest.NewRecorder()
	sec.setPendingCookie(rec, "v", int(pendingLife.Seconds()))
	if sc := rec.Header().Get("Set-Cookie"); !strings.HasPrefix(sc, "__Host-ucdotweb-signin=") || !strings.Contains(sc, "; Secure") {
		t.Fatalf("secure mode: pending cookie %q", sc)
	}
}

func TestFullSignInClearsThePendingCookie(t *testing.T) {
	r := newRig(t, map[string]any{"login": "x", "status": "active"})
	st := startSignIn(t, r)
	resp := callbackWith(t, st.callback, st.cookie)
	if resp.StatusCode != http.StatusFound || r.sessions.Count() != 1 {
		t.Fatalf("callback: status %d, sessions %d", resp.StatusCode, r.sessions.Count())
	}
	if sc := setCookieFor(resp, st.cookie.Name); !strings.Contains(sc, "Max-Age=0") || !strings.Contains(sc, "Path=/;") {
		t.Fatalf("pending cookie not cleared: %q", sc)
	}
}

func TestTamperedPendingCookieRefused(t *testing.T) {
	r := newRig(t, map[string]any{"login": "x", "status": "active"})
	st := startSignIn(t, r)
	v := []byte(st.cookie.Value)
	i := len(v) / 2
	if v[i] == 'A' {
		v[i] = 'B'
	} else {
		v[i] = 'A'
	}
	bad := &http.Cookie{Name: st.cookie.Name, Value: string(v)}
	resp := callbackWith(t, st.callback, bad)
	if resp.StatusCode != http.StatusBadRequest || r.sessions.Count() != 0 {
		t.Fatalf("tampered cookie: status %d, sessions %d, want 400 and 0", resp.StatusCode, r.sessions.Count())
	}
	if sc := setCookieFor(resp, st.cookie.Name); !strings.Contains(sc, "Max-Age=0") {
		t.Fatalf("tampered cookie not cleared: %q", sc)
	}
}

func TestExpiredPendingCookieRefused(t *testing.T) {
	r := newRig(t, map[string]any{"login": "x", "status": "active"})
	st := startSignIn(t, r)
	p, err := r.srv.openPending(st.cookie.Value, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.srv.openPending(st.cookie.Value, time.Now().Add(pendingLife+time.Second)); err == nil {
		t.Fatal("the cookie still opens after its expiry")
	}
	p.Expires = time.Now().Add(-time.Second)
	v, err := r.srv.sealPending(p)
	if err != nil {
		t.Fatal(err)
	}
	resp := callbackWith(t, st.callback, &http.Cookie{Name: st.cookie.Name, Value: v})
	if resp.StatusCode != http.StatusBadRequest || r.sessions.Count() != 0 {
		t.Fatalf("expired cookie: status %d, sessions %d, want 400 and 0", resp.StatusCode, r.sessions.Count())
	}
}

func TestCallbackWithoutPendingCookieRefused(t *testing.T) {
	r := newRig(t, map[string]any{"login": "x", "status": "active"})
	st := startSignIn(t, r) // a real state and code, but the browser that answers has no cookie
	resp := callbackWith(t, st.callback)
	if resp.StatusCode != http.StatusBadRequest || r.sessions.Count() != 0 {
		t.Fatalf("no cookie: status %d, sessions %d, want 400 and 0", resp.StatusCode, r.sessions.Count())
	}
}

func TestPendingCookieWorksOnce(t *testing.T) {
	r := newRig(t, map[string]any{"login": "x", "status": "active"})
	st := startSignIn(t, r)
	if resp := callbackWith(t, st.callback, st.cookie); resp.StatusCode != http.StatusFound {
		t.Fatalf("first use: status %d", resp.StatusCode)
	}
	// the same sealed cookie with a new, valid code for the same state and PKCE challenge
	again := providerAnswer(t, st.authorize)
	if resp := callbackWith(t, again, st.cookie); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("reused cookie: status %d, want 403", resp.StatusCode)
	}
	if n := r.sessions.Count(); n != 1 {
		t.Fatalf("sessions: %d, want 1", n)
	}
}

func sessionValue(t *testing.T, r *rig, c *http.Client) string {
	t.Helper()
	u, _ := url.Parse(r.app.URL + "/")
	for _, ck := range c.Jar.Cookies(u) {
		if ck.Name == "ucdotweb" {
			return ck.Value
		}
	}
	return ""
}

func signedIn(t *testing.T, r *rig, c *http.Client) bool {
	t.Helper()
	resp, err := c.Get(r.app.URL + "/api/me")
	if err != nil {
		t.Fatal(err)
	}
	return strings.Contains(body(t, resp), `"signed_in":true`)
}

// Finding 15: a link to /auth/login must not sign the visitor out.
func TestLoginKeepsTheCurrentSessionUntilTheCallback(t *testing.T) {
	r := newRig(t, map[string]any{"login": "x", "status": "active"})
	c, code := signIn(t, r)
	if code != http.StatusOK {
		t.Fatalf("first sign-in: %d", code)
	}
	first := sessionValue(t, r, c)
	stop := noFollow(&http.Client{Jar: c.Jar})
	resp, err := stop.Get(r.app.URL + "/auth/login")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	authorize := resp.Header.Get("Location")
	if !signedIn(t, r, c) || sessionValue(t, r, c) != first || r.sessions.Count() != 1 {
		t.Fatalf("GET /auth/login changed the current session (sessions %d)", r.sessions.Count())
	}
	// the provider refuses: still signed in, same session
	cb, _ := url.Parse(providerAnswer(t, authorize))
	q := cb.Query()
	q.Del("code")
	q.Set("error", "access_denied")
	cb.RawQuery = q.Encode()
	resp, err = stop.Get(cb.String())
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || !signedIn(t, r, c) || sessionValue(t, r, c) != first {
		t.Fatalf("a refused sign-in changed the current session: status %d", resp.StatusCode)
	}
	// a new sign-in that succeeds replaces the session, with a new id
	resp, err = stop.Get(r.app.URL + "/auth/login")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	resp, err = stop.Get(providerAnswer(t, resp.Header.Get("Location")))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	second := sessionValue(t, r, c)
	if resp.StatusCode != http.StatusFound || !signedIn(t, r, c) || second == "" || second == first || r.sessions.Count() != 1 {
		t.Fatalf("after the new sign-in: status %d, rotated %v, sessions %d", resp.StatusCode, second != first, r.sessions.Count())
	}
}

// Finding 8: the maintainers' exemption from the sign-in switches needs a linked 42 account,
// as the bootstrap does.
func TestMaintainerExemptionNeedsA42Link(t *testing.T) {
	m := newRig(t, map[string]any{"login": "maintainer", "status": "active", "ft_linked": false})
	_ = m.db.SetFlag("test", "signin_off", true)
	if _, code := signIn(t, m); code != http.StatusServiceUnavailable {
		t.Fatalf("unlinked maintainer login with signin_off: status %d, want 503", code)
	}
	_ = m.db.SetFlag("test", "signin_off", false)
	_ = m.db.SetFlag("test", "signup_off", true)
	if _, code := signIn(t, m); code != http.StatusServiceUnavailable {
		t.Fatalf("unlinked maintainer login with signup_off: status %d, want 503", code)
	}
	if _, err := m.db.GetUser("clubroom-user-42"); err == nil {
		t.Fatal("the refused account was recorded")
	}
}

// A sign-in refused because this very account is banned also ends the browser's current
// session for that account; it does not linger until the 12-hour limit.
func TestRefusedSigninDropsThatAccountsSession(t *testing.T) {
	r := newRig(t, map[string]any{"login": "someone", "status": "active"})
	c, code := signIn(t, r)
	if code != http.StatusOK {
		t.Fatalf("sign-in: %d", code)
	}
	if n := r.sessions.Count(); n != 1 {
		t.Fatalf("%d sessions, want 1", n)
	}
	if err := r.db.SetGrant("test", "clubroom-user-42", "banned", true, "test"); err != nil {
		t.Fatal(err)
	}
	resp, err := c.Get(r.app.URL + "/auth/login")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if n := r.sessions.Count(); n != 0 {
		t.Fatalf("%d sessions after a refused sign-in of the banned account, want 0", n)
	}
}

// Without a "login" claim (an account with no 42 link), the Clubroom's preferred_username is
// shown, and it never makes anyone an administrator.
func TestPreferredUsernameForDisplayOnly(t *testing.T) {
	r := newRig(t, map[string]any{"preferred_username": "Maintainer", "status": "active"})
	c, code := signIn(t, r)
	if code != http.StatusOK {
		t.Fatalf("sign-in: %d", code)
	}
	resp, err := c.Get(r.app.URL + "/api/me")
	if err != nil {
		t.Fatal(err)
	}
	me := body(t, resp)
	if !strings.Contains(me, `"login":"Maintainer"`) || !strings.Contains(me, `"admin":false`) {
		t.Fatalf("/api/me: %s", me)
	}
}
