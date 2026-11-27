package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func signIn(t *testing.T, r *rig) (*http.Client, int) {
	t.Helper()
	c := client(t)
	resp, err := c.Get(r.app.URL + "/auth/login")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusServiceUnavailable {
		return c, resp.StatusCode
	}
	// a sign-in ends on "/", which this test server does not serve: ask /api/me instead
	me, err := c.Get(r.app.URL + "/api/me")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(body(t, me), `"signed_in":true`) {
		return c, http.StatusOK
	}
	return c, http.StatusForbidden
}

func TestSignupOff(t *testing.T) {
	r := newRig(t, map[string]any{"login": "someone", "status": "active"})
	_ = r.db.SetFlag("test", "signup_off", true)
	if _, code := signIn(t, r); code != http.StatusServiceUnavailable {
		t.Fatalf("new user with signup_off: status %d, want 503", code)
	}
	if _, err := r.db.GetUser("clubroom-user-42"); err == nil {
		t.Fatal("the refused user was recorded")
	}
	_ = r.db.SetFlag("test", "signup_off", false)
	if _, code := signIn(t, r); code != http.StatusOK {
		t.Fatalf("signup open: status %d", code)
	}
	_ = r.db.SetFlag("test", "signup_off", true)
	if _, code := signIn(t, r); code != http.StatusOK {
		t.Fatalf("known user with signup_off: status %d, want 200", code)
	}
}

func TestSigninOffSparesAdministrators(t *testing.T) {
	r := newRig(t, map[string]any{"login": "someone", "status": "active"})
	if _, code := signIn(t, r); code != http.StatusOK {
		t.Fatal(code)
	}
	_ = r.db.SetFlag("test", "signin_off", true)
	if _, code := signIn(t, r); code != http.StatusServiceUnavailable {
		t.Fatalf("user with signin_off: status %d, want 503", code)
	}
	_ = r.db.SetGrant("test", "clubroom-user-42", "admin", true, "")
	if _, code := signIn(t, r); code != http.StatusOK {
		t.Fatalf("administrator with signin_off: status %d, want 200", code)
	}
	m := newRig(t, map[string]any{"login": "maintainer", "status": "active", "ft_linked": true}) // in AdminLogins, never seen
	_ = m.db.SetFlag("test", "signin_off", true)
	_ = m.db.SetFlag("test", "signup_off", true)
	if _, code := signIn(t, m); code != http.StatusOK {
		t.Fatalf("maintainer with both switches on: status %d, want 200", code)
	}
}

func TestAdminChangeNeedsRecentSignIn(t *testing.T) {
	old := float64(time.Now().Add(-time.Hour).Unix())
	r := newRig(t, map[string]any{"login": "someone", "status": "active", "auth_time": old})
	c, _ := signIn(t, r)
	_ = r.db.SetGrant("test", "clubroom-user-42", "admin", true, "")
	var v any
	if code := getJSON(t, c, r, "/api/admin/flags", &v); code != http.StatusOK {
		t.Fatalf("read with an old sign-in: status %d, want 200", code)
	}
	code, b := post(t, c, r, "/api/admin/flag", `{"name":"proxy_off","on":true}`)
	if code != http.StatusUnauthorized || !strings.Contains(b, `"reauth"`) || !strings.Contains(b, "/auth/login?reauth=1") || r.db.Flag("proxy_off") {
		t.Fatalf("change with an hour-old sign-in: %d %s", code, b)
	}
	r.srv.AdminFresh = 2 * time.Hour
	if code, b := post(t, c, r, "/api/admin/flag", `{"name":"proxy_off","on":true}`); code != http.StatusNoContent {
		t.Fatalf("within AdminFresh: %d %s", code, b)
	}
}

func TestReauthAsksProviderForRealSignIn(t *testing.T) {
	r := newRig(t, map[string]any{"status": "active"})
	c := noFollow(client(t))
	resp, err := c.Get(r.app.URL + "/auth/login?reauth=1")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	u, _ := url.Parse(resp.Header.Get("Location"))
	if q := u.Query(); q.Get("prompt") != "login" || q.Get("max_age") != "0" || q.Get("code_challenge_method") != "S256" {
		t.Fatalf("authorize URL %s", u)
	}
	resp, _ = c.Get(r.app.URL + "/auth/login")
	resp.Body.Close()
	if u, _ := url.Parse(resp.Header.Get("Location")); u.Query().Has("prompt") {
		t.Fatalf("plain login asked for prompt: %s", u)
	}
}

func TestMemberFollowsFtActive(t *testing.T) {
	for _, c := range []struct {
		claims map[string]any
		member bool
	}{
		{map[string]any{"login": "x", "status": "active", "ft_linked": true, "ft_active": true}, true},
		{map[string]any{"login": "x", "status": "active", "ft_linked": true, "ft_active": false}, false}, // blackholed, for example
		{map[string]any{"login": "x", "status": "active", "ft_linked": true}, true},                      // no claim yet: active
		{map[string]any{"login": "x", "status": "active", "ft_active": true}, false},                     // not linked
	} {
		r := newRig(t, c.claims)
		cl, _ := signIn(t, r)
		resp, _ := cl.Get(r.app.URL + "/api/me")
		got := strings.Contains(body(t, resp), `"member":true`)
		if got != c.member {
			t.Errorf("claims %v: member %v, want %v", c.claims, got, c.member)
		}
	}
	r := newRig(t, map[string]any{"login": "x", "status": "active", "ft_linked": true, "ft_active": false})
	cl, _ := signIn(t, r)
	_ = r.db.SetGrant("test", "clubroom-user-42", "member", true, "") // an administrator's grant still counts
	resp, _ := cl.Get(r.app.URL + "/api/me")
	if !strings.Contains(body(t, resp), `"member":true`) {
		t.Fatal("an administrator's member grant lost to ft_active false")
	}
}

func TestAdminCaps(t *testing.T) {
	r, c := adminRig(t)
	if code, _ := post(t, c, r, "/api/admin/caps", `{"service":"relay"}`); code != http.StatusBadRequest {
		t.Fatal("cap without bytes_per_day accepted")
	}
	if code, b := post(t, c, r, "/api/admin/caps", `{"service":"relay","bytes_per_day":50000000000}`); code != http.StatusNoContent {
		t.Fatalf("set cap: %d %s", code, b)
	}
	var out struct {
		Caps map[string]float64 `json:"caps"`
	}
	if getJSON(t, c, r, "/api/admin/caps", &out); out.Caps["relay"] != 5e10 || out.Caps["proxy"] != 0 {
		t.Fatalf("caps %v", out.Caps)
	}
}

func TestCheckOrigin(t *testing.T) {
	for _, s := range []string{"https://dux.ensui.dev", "http://127.0.0.1:8090", "https://example.org:8443"} {
		if err := CheckOrigin(s); err != nil {
			t.Errorf("%q refused: %v", s, err)
		}
	}
	for _, s := range []string{"https://dux.ensui.dev/", "https://dux.ensui.dev/app", "dux.ensui.dev", "ftp://x.org",
		"https://", "https://x.org?", "https://x.org#", "https://user@x.org", "https://Dux.Ensui.dev", ""} {
		if err := CheckOrigin(s); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
}
