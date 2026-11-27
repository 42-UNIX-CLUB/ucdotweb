package web

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/42-UNIX-CLUB/ucdotweb/internal/oidc"
	"github.com/42-UNIX-CLUB/ucdotweb/internal/relay"
	"github.com/42-UNIX-CLUB/ucdotweb/internal/session"
	"github.com/42-UNIX-CLUB/ucdotweb/internal/standin"
	"github.com/42-UNIX-CLUB/ucdotweb/internal/store"
)

type rig struct {
	idp      *standin.Provider
	idpSrv   *httptest.Server
	app      *httptest.Server
	sessions *session.Store
	db       *store.DB
	srv      *Server
	verifier *relay.Verifier
}

func newRig(t *testing.T, claims map[string]any) *rig {
	t.Helper()
	r := &rig{}
	// the provider's issuer must be known before it starts: use an unstarted server
	r.idpSrv = httptest.NewUnstartedServer(nil)
	r.idpSrv.Start()
	appSrv := httptest.NewUnstartedServer(nil)
	appSrv.Start()
	r.app = appSrv
	r.idp = standin.New(r.idpSrv.URL, "uc-os", "test-secret", appSrv.URL+"/auth/callback",
		standin.User{Subject: "clubroom-user-42", Claims: claims})
	r.idpSrv.Config.Handler = r.idp.Handler()
	prov, err := oidc.Discover(t.Context(), oidc.Config{Issuer: r.idpSrv.URL, ClientID: "uc-os",
		ClientSecret: "test-secret", RedirectURL: appSrv.URL + "/auth/callback", Scopes: []string{"uc-os:connect"}}, nil)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	db, err := store.Open(t.TempDir()+"/test.db", make([]byte, 32))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	r.db = db
	r.sessions = session.NewWith(db, 30*time.Minute, 12*time.Hour, false)
	srv := &Server{Provider: prov, Sessions: r.sessions, Origin: appSrv.URL, Log: log.New(io.Discard, "", 0),
		DB: db, AdminLogins: []string{"Maintainer"}, BundleDir: t.TempDir()}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	srv.Minter = &relay.Minter{Issuer: appSrv.URL, Kid: "k", Key: priv}
	r.verifier, _ = relay.NewVerifier(appSrv.URL, "k", pub)
	srv.Relay = http.NotFoundHandler()
	r.srv = srv
	appSrv.Config.Handler = srv.Handler()
	t.Cleanup(func() { r.idpSrv.Close(); appSrv.Close() })
	return r
}

func client(t *testing.T) *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar}
}

func body(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

func TestSignInAndMe(t *testing.T) {
	r := newRig(t, map[string]any{"login": "rucosta", "status": "active", "ft_linked": true})
	c := client(t)
	resp, err := c.Get(r.app.URL + "/api/me")
	if err != nil || !strings.Contains(body(t, resp), `"signed_in":false`) {
		t.Fatalf("before sign-in: %v", err)
	}
	resp, err = c.Get(r.app.URL + "/auth/login") // follows: login -> provider -> callback -> /
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	resp, _ = c.Get(r.app.URL + "/api/me")
	got := body(t, resp)
	if !strings.Contains(got, `"signed_in":true`) || !strings.Contains(got, `"member":true`) || strings.Contains(got, "clubroom-user-42") {
		t.Fatalf("after sign-in: %s", got)
	}
	if r.sessions.Count() != 1 {
		t.Fatalf("sessions: %d, want 1 (the pre-login session must be replaced)", r.sessions.Count())
	}
}

func TestDisabledAccountRefused(t *testing.T) {
	r := newRig(t, map[string]any{"login": "x", "status": "disabled"})
	c := client(t)
	resp, _ := c.Get(r.app.URL + "/auth/login")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d, want 403", resp.StatusCode)
	}
	resp.Body.Close()
	resp, _ = c.Get(r.app.URL + "/api/me")
	if !strings.Contains(body(t, resp), `"signed_in":false`) {
		t.Fatal("disabled account got a session")
	}
}

// noFollow stops at the first redirect so a test can tamper with the callback.
func noFollow(c *http.Client) *http.Client {
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return c
}

func authorizeRedirect(t *testing.T, r *rig, c *http.Client) *url.URL {
	t.Helper()
	resp, err := c.Get(r.app.URL + "/auth/login")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	resp, err = c.Get(resp.Header.Get("Location")) // the provider answers with the callback URL
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	u, _ := url.Parse(resp.Header.Get("Location"))
	return u
}

func TestWrongStateRefused(t *testing.T) {
	r := newRig(t, map[string]any{"status": "active"})
	c := noFollow(client(t))
	cb := authorizeRedirect(t, r, c)
	q := cb.Query()
	q.Set("state", "forged")
	cb.RawQuery = q.Encode()
	resp, _ := c.Get(cb.String())
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("forged state: status %d, want 403", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestCodeWorksOnce(t *testing.T) {
	r := newRig(t, map[string]any{"status": "active"})
	c := noFollow(client(t))
	cb := authorizeRedirect(t, r, c)
	resp, _ := c.Get(cb.String())
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("first use: status %d", resp.StatusCode)
	}
	resp.Body.Close()
	// a second browser replaying the same callback has no pending sign-in
	c2 := noFollow(client(t))
	resp, _ = c2.Get(cb.String())
	if resp.StatusCode == http.StatusFound {
		t.Fatal("a replayed callback signed someone in")
	}
	resp.Body.Close()
}

func TestCallbackWithoutLoginRefused(t *testing.T) {
	r := newRig(t, map[string]any{"status": "active"})
	resp, _ := noFollow(client(t)).Get(r.app.URL + "/auth/callback?code=x&state=y")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestLogoutNeedsOrigin(t *testing.T) {
	r := newRig(t, map[string]any{"status": "active"})
	c := client(t)
	resp, _ := c.Get(r.app.URL + "/auth/login")
	resp.Body.Close()
	resp, _ = c.Post(r.app.URL+"/auth/logout", "text/plain", nil) // no Origin: as a cross-site form could
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("logout without Origin: status %d, want 403", resp.StatusCode)
	}
	resp.Body.Close()
	req, _ := http.NewRequest("POST", r.app.URL+"/auth/logout", nil)
	req.Header.Set("Origin", r.app.URL)
	resp, _ = c.Do(req)
	if resp.StatusCode != http.StatusNoContent || r.sessions.Count() != 0 {
		t.Fatalf("logout: status %d, sessions %d", resp.StatusCode, r.sessions.Count())
	}
	resp.Body.Close()
}

func TestCookieFlags(t *testing.T) {
	r := newRig(t, map[string]any{"status": "active"})
	resp, _ := noFollow(client(t)).Get(r.app.URL + "/auth/login")
	resp.Body.Close()
	sc := resp.Header.Get("Set-Cookie")
	for _, want := range []string{"HttpOnly", "SameSite=Lax", "Path=/"} {
		if !strings.Contains(sc, want) {
			t.Fatalf("cookie %q lacks %s", sc, want)
		}
	}
}

func TestMaintainerBecomesAdmin(t *testing.T) {
	r := newRig(t, map[string]any{"login": "maintainer", "status": "active"})
	c := client(t)
	resp, _ := c.Get(r.app.URL + "/auth/login")
	resp.Body.Close()
	resp, _ = c.Get(r.app.URL + "/api/me")
	if got := body(t, resp); !strings.Contains(got, `"admin":true`) {
		t.Fatalf("maintainer not admin: %s", got)
	}
	if r.db.AuditCount() != 1 {
		t.Fatalf("audit entries: %d, want 1", r.db.AuditCount())
	}
}

func TestBannedUserRefused(t *testing.T) {
	r := newRig(t, map[string]any{"login": "x", "status": "active"})
	c := client(t)
	resp, _ := c.Get(r.app.URL + "/auth/login")
	resp.Body.Close()
	if err := r.db.SetGrant("test", "clubroom-user-42", "banned", true, "test"); err != nil {
		t.Fatal(err)
	}
	resp, _ = c.Get(r.app.URL + "/api/me") // an existing session stops working at once
	if !strings.Contains(body(t, resp), `"signed_in":false`) {
		t.Fatal("banned user still signed in")
	}
	resp, _ = client(t).Get(r.app.URL + "/auth/login") // and a new sign-in is refused
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("banned sign-in: status %d, want 403", resp.StatusCode)
	}
	resp.Body.Close()
}

func flagReq(t *testing.T, c *http.Client, r *rig, origin string) int {
	req, _ := http.NewRequest("POST", r.app.URL+"/api/admin/flag", strings.NewReader(`{"name":"proxy_off","on":true}`))
	req.Header.Set("Content-Type", "application/json")
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func TestPanicSwitchAdminsOnly(t *testing.T) {
	r := newRig(t, map[string]any{"login": "someone", "status": "active"})
	c := client(t)
	resp, _ := c.Get(r.app.URL + "/auth/login")
	resp.Body.Close()
	if code := flagReq(t, c, r, r.app.URL); code != http.StatusForbidden || r.db.Flag("proxy_off") {
		t.Fatalf("non-admin flipped the switch: status %d", code)
	}
	if err := r.db.SetGrant("test", "clubroom-user-42", "admin", true, ""); err != nil {
		t.Fatal(err)
	}
	if code := flagReq(t, c, r, ""); code != http.StatusForbidden {
		t.Fatalf("admin without Origin: status %d, want 403", code)
	}
	if code := flagReq(t, c, r, r.app.URL); code != http.StatusNoContent || !r.db.Flag("proxy_off") {
		t.Fatalf("admin: status %d, flag %v", code, r.db.Flag("proxy_off"))
	}
}

func TestSessionIDNotStoredInClear(t *testing.T) {
	r := newRig(t, map[string]any{"login": "x", "status": "active"})
	c := client(t)
	resp, _ := c.Get(r.app.URL + "/auth/login")
	resp.Body.Close()
	u, _ := url.Parse(r.app.URL)
	var id string
	for _, ck := range c.Jar.Cookies(u) {
		id = ck.Value
	}
	if id == "" {
		t.Fatal("no session cookie")
	}
	if _, _, _, ok, _ := r.db.SessionGet(id); ok {
		t.Fatal("the session id is the database key: a leaked database would give live sessions")
	}
	if _, _, _, ok, _ := r.db.SessionGet(store.HashID(id)); !ok {
		t.Fatal("session not found by hash")
	}
}

func relayTokenReq(t *testing.T, c *http.Client, r *rig) (int, string) {
	req, _ := http.NewRequest("POST", r.app.URL+"/api/relay-token", nil)
	req.Header.Set("Origin", r.app.URL)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, body(t, resp)
}

func TestRelayTokenMembersOnly(t *testing.T) {
	r := newRig(t, map[string]any{"login": "x", "status": "active", "ft_linked": false})
	c := client(t)
	if code, _ := relayTokenReq(t, c, r); code != http.StatusUnauthorized {
		t.Fatalf("signed out: %d, want 401", code)
	}
	resp, _ := c.Get(r.app.URL + "/auth/login")
	resp.Body.Close()
	if code, _ := relayTokenReq(t, c, r); code != http.StatusForbidden {
		t.Fatalf("not a member: %d, want 403", code)
	}
	r.db.SetGrant("admin", "clubroom-user-42", "member", true, "")
	code, got := relayTokenReq(t, c, r)
	if code != 200 || !strings.Contains(got, `"expires_in":300`) {
		t.Fatalf("member: %d %s", code, got)
	}
	// the token carries the session's hash, so the relay's check follows the session
	tok := got[strings.Index(got, `"token":"`)+9:]
	tok = tok[:strings.Index(tok, `"`)]
	cl, err := r.verifier.Verify(tok, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := r.srv.CheckRelay(cl.Sub, cl.Sid); err != nil {
		t.Fatalf("check while signed in: %v", err)
	}
	req, _ := http.NewRequest("POST", r.app.URL+"/auth/logout", nil)
	req.Header.Set("Origin", r.app.URL)
	resp, _ = c.Do(req)
	resp.Body.Close()
	if err := r.srv.CheckRelay(cl.Sub, cl.Sid); err == nil {
		t.Fatal("relay check passes after sign-out")
	}
}
