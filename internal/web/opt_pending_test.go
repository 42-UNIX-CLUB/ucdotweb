package web

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// Review of the sealed sign-in cookie. With Secure set it is named "__Secure-..." with
// Path=/auth/callback. The __Secure- prefix only demands the Secure attribute: a page on a
// sibling or parent domain (another name under the same registered domain) can still set a
// cookie of that name with a Domain attribute, and the browser sends it to /auth/callback.
// The session cookie uses "__Host-" for exactly that reason (session.go: "no subdomain can
// set it"); __Host- needs Path=/ and no Domain. The pending sign-in holds the state that
// ties a callback to this browser, so it wants the same protection.
func TestOptPendingCookieCannotBeSetBySiblingDomains(t *testing.T) {
	r := newRig(t, map[string]any{"login": "x", "status": "active"})
	r.srv.Sessions.Secure = true
	rec := httptest.NewRecorder()
	r.srv.setPendingCookie(rec, "value", 600)
	c := rec.Result().Cookies()[0]
	t.Logf("pending sign-in cookie: name %q, path %q, domain %q, secure %v", c.Name, c.Path, c.Domain, c.Secure)
	if !strings.HasPrefix(c.Name, "__Host-") || c.Path != "/" || c.Domain != "" {
		t.Errorf("the cookie %q with path %q is not a __Host- cookie: another site under the same domain can plant its own", c.Name, c.Path)
	}
}
