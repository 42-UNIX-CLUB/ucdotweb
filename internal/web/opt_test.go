package web

import (
	"net/http"
	"testing"
)

// Finding S2: GET /auth/login needs no session and no other credential, and each call stores
// a new row in the sessions table (the pending sign-in). Nothing limits how many.
func TestOptLoginStoresARowPerAnonymousRequest(t *testing.T) {
	r := newRig(t, map[string]any{"login": "x", "status": "active"})
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }} // no cookie jar
	before := r.sessions.Count()
	const n = 300
	for i := 0; i < n; i++ {
		resp, err := c.Get(r.app.URL + "/auth/login")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusFound {
			t.Fatalf("request %d: status %d", i, resp.StatusCode)
		}
	}
	rows := r.sessions.Count() - before
	t.Logf("%d anonymous requests to /auth/login: %d new rows in sessions", n, rows)
	if rows > 10 {
		t.Errorf("%d session rows stored for %d requests that carried nothing", rows, n)
	}
}

// Finding S3: the admin bootstrap compares the "login" claim with the maintainers' list and
// does not look at ft_linked. An account whose login claim equals a maintainer's name becomes
// an administrator even when the provider says no 42 account is linked.
func TestOptBootstrapDoesNotNeedA42Link(t *testing.T) {
	r := newRig(t, map[string]any{"login": "maintainer", "status": "active", "ft_linked": false})
	c := client(t)
	resp, err := c.Get(r.app.URL + "/auth/login")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	resp, err = c.Get(r.app.URL + "/api/me")
	if err != nil {
		t.Fatal(err)
	}
	me := body(t, resp)
	t.Logf("login claim \"maintainer\", ft_linked false: /api/me says %s", me)
	u, _ := r.db.GetUser("clubroom-user-42")
	if u.AdminGrant {
		t.Errorf("admin grant given to an account with no linked 42 account, by its login claim alone")
	}
}
