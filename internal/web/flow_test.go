package web

import (
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
	"github.com/42-UNIX-CLUB/ucdotweb/internal/session"
	"github.com/42-UNIX-CLUB/ucdotweb/internal/standin"
)

type rig struct {
	idp      *standin.Provider
	idpSrv   *httptest.Server
	app      *httptest.Server
	sessions *session.Store
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
	r.sessions = session.New(30*time.Minute, 12*time.Hour, false)
	srv := &Server{Provider: prov, Sessions: r.sessions, Origin: appSrv.URL, Log: log.New(io.Discard, "", 0)}
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
