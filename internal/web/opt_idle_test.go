package web

import (
	"net/url"
	"testing"

	"github.com/42-UNIX-CLUB/ucdotweb/internal/session"
)

// Second read: a session ends after 30 idle minutes, and "idle" is measured by HTTP requests
// that carry the cookie (session.Get touches it). The relay's re-check every 5 seconds reads
// the session with GetByHash, which does not touch it. So a member whose only activity is an
// open relay socket, however busy, is cut off 30 minutes after their last API request.
// The test stands in for the half hour by moving last_seen back in the table, while the
// re-check has been running all along.
func TestOptRelayActivityKeepsTheSessionAlive(t *testing.T) {
	r := newRig(t, map[string]any{"login": "x", "status": "active", "ft_linked": true})
	c, _ := signIn(t, r)
	u, _ := url.Parse(r.app.URL)
	var sid string
	for _, ck := range c.Jar.Cookies(u) {
		if ck.Name == "ucdotweb" {
			sid = session.IDHash(ck.Value)
		}
	}
	if sid == "" {
		t.Fatal("no session cookie")
	}
	// two stretches of 29 minutes with no API request, the re-check running in between: an
	// open socket keeps the session alive, though 58 minutes passed without a request
	for i := 0; i < 2; i++ {
		r.db.Exec(`UPDATE sessions SET last_seen = last_seen - 1740`)
		if err := r.srv.CheckRelay("clubroom-user-42", sid); err != nil {
			t.Fatalf("re-check after stretch %d: %v", i+1, err)
		}
	}
	// and a session really idle for 31 minutes (no socket re-checking it) is ended
	r.db.Exec(`UPDATE sessions SET last_seen = last_seen - 1860`)
	if err := r.srv.CheckRelay("clubroom-user-42", sid); err == nil {
		t.Errorf("a session idle for 31 minutes was kept")
	}
}
