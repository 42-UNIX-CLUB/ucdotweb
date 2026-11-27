package web

import (
	"net/http"
	"strings"
	"testing"
)

// allowRig is newRig with the allow-list routes in front, set before any request, then a
// signed-in user. admin makes that user an administrator.
func allowRig(t *testing.T, admin bool) (*rig, *http.Client) {
	t.Helper()
	r := newRig(t, map[string]any{"login": "someone", "status": "active"})
	mux := http.NewServeMux()
	r.srv.allowlistRoutes(mux)
	mux.Handle("/", r.app.Config.Handler)
	r.app.Config.Handler = mux
	c := client(t)
	resp, err := c.Get(r.app.URL + "/auth/login")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if admin {
		if err := r.db.SetGrant("test", "clubroom-user-42", "admin", true, ""); err != nil {
			t.Fatal(err)
		}
	}
	return r, c
}

type allowList struct {
	Rules []struct {
		Host      string   `json:"host"`
		Prefixes  []string `json:"prefixes"`
		Git       bool     `json:"git"`
		Releases  bool     `json:"releases"`
		UpdatedAt int64    `json:"updated_at"`
		UpdatedBy string   `json:"updated_by"`
	} `json:"rules"`
}

func TestAllowlistAdminsOnly(t *testing.T) {
	r, _ := allowRig(t, false)
	var v allowList
	if code := getJSON(t, client(t), r, "/api/admin/allowlist", &v); code != http.StatusUnauthorized {
		t.Fatalf("signed out: status %d, want 401", code)
	}
	if code, _ := post(t, client(t), r, "/api/admin/allowlist", `{"host":"a.org","prefixes":["/"]}`); code != http.StatusUnauthorized {
		t.Fatalf("signed out add: status %d, want 401", code)
	}
	r2, c := allowRig(t, false) // a signed-in user who is not an administrator
	if code := getJSON(t, c, r2, "/api/admin/allowlist", &v); code != http.StatusForbidden {
		t.Fatalf("user read: status %d, want 403", code)
	}
	n := r2.db.AuditCount()
	for _, p := range []struct{ path, js string }{
		{"/api/admin/allowlist", `{"host":"a.org","prefixes":["/"]}`},
		{"/api/admin/allowlist/remove", `{"host":"a.org"}`},
	} {
		if code, _ := post(t, c, r2, p.path, p.js); code != http.StatusForbidden {
			t.Fatalf("user %s: status %d, want 403", p.path, code)
		}
	}
	if rs, _ := r2.db.AllowRules(); len(rs) != 0 || r2.db.AuditCount() != n {
		t.Fatalf("a user changed the list: %v", rs)
	}
}

func TestAllowlistSameOriginAndJSON(t *testing.T) {
	r, c := allowRig(t, true)
	n := r.db.AuditCount()
	send := func(path, origin, ctype string) int {
		req, _ := http.NewRequest("POST", r.app.URL+path, strings.NewReader(`{"host":"a.org","prefixes":["/"]}`))
		if ctype != "" {
			req.Header.Set("Content-Type", ctype)
		}
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
	for _, path := range []string{"/api/admin/allowlist", "/api/admin/allowlist/remove"} {
		if code := send(path, "", "application/json"); code != http.StatusForbidden {
			t.Errorf("%s without Origin: %d, want 403", path, code)
		}
		if code := send(path, "https://evil.example", "application/json"); code != http.StatusForbidden {
			t.Errorf("%s from another origin: %d, want 403", path, code)
		}
		if code := send(path, r.app.URL, "text/plain"); code != http.StatusBadRequest {
			t.Errorf("%s as a simple request: %d, want 400", path, code)
		}
	}
	if rs, _ := r.db.AllowRules(); len(rs) != 0 || r.db.AuditCount() != n {
		t.Fatalf("a refused request changed the list: %v", rs)
	}
}

func TestAllowlistAddReplaceRemove(t *testing.T) {
	r, c := allowRig(t, true)
	var v allowList
	if code := getJSON(t, c, r, "/api/admin/allowlist", &v); code != 200 || v.Rules == nil || len(v.Rules) != 0 {
		t.Fatalf("empty list: %d %+v", code, v)
	}
	if code, b := post(t, c, r, "/api/admin/allowlist", `{"host":"ftp.gnu.org","prefixes":["/gnu/"]}`); code != http.StatusNoContent {
		t.Fatalf("add: %d %s", code, b)
	}
	var audit struct {
		Audit []map[string]any `json:"audit"`
	}
	getJSON(t, c, r, "/api/admin/audit?limit=1", &audit)
	if a := audit.Audit[0]; a["action"] != "allowlist add" || a["actor"] != "clubroom-user-42" || a["target"] != "ftp.gnu.org" || a["detail"] != "prefixes /gnu/" {
		t.Fatalf("add audit: %v", a)
	}
	if code, b := post(t, c, r, "/api/admin/allowlist", `{"host":"ftp.gnu.org","prefixes":["/gnu/","/old-gnu/"],"git":true,"releases":true}`); code != http.StatusNoContent {
		t.Fatalf("replace: %d %s", code, b)
	}
	getJSON(t, c, r, "/api/admin/audit?limit=1", &audit)
	if a := audit.Audit[0]; a["action"] != "allowlist replace" || !strings.Contains(a["detail"].(string), "now: prefixes /gnu/ /old-gnu/; git; releases") {
		t.Fatalf("replace audit: %v", a)
	}
	getJSON(t, c, r, "/api/admin/allowlist", &v)
	if len(v.Rules) != 1 || v.Rules[0].Host != "ftp.gnu.org" || len(v.Rules[0].Prefixes) != 2 || !v.Rules[0].Git ||
		!v.Rules[0].Releases || v.Rules[0].UpdatedBy != "clubroom-user-42" || v.Rules[0].UpdatedAt == 0 {
		t.Fatalf("list after replace: %+v", v.Rules)
	}
	if code, _ := post(t, c, r, "/api/admin/allowlist/remove", `{"host":"nope.org"}`); code != http.StatusNotFound {
		t.Fatalf("remove unknown: %d, want 404", code)
	}
	if code, b := post(t, c, r, "/api/admin/allowlist/remove", `{"host":"ftp.gnu.org"}`); code != http.StatusNoContent {
		t.Fatalf("remove: %d %s", code, b)
	}
	getJSON(t, c, r, "/api/admin/audit?limit=1", &audit)
	if a := audit.Audit[0]; a["action"] != "allowlist remove" || a["actor"] != "clubroom-user-42" || a["target"] != "ftp.gnu.org" {
		t.Fatalf("remove audit: %v", a)
	}
	if getJSON(t, c, r, "/api/admin/allowlist", &v); len(v.Rules) != 0 {
		t.Fatalf("list after remove: %+v", v.Rules)
	}
}

func TestAllowlistBadInputRefused(t *testing.T) {
	r, c := allowRig(t, true)
	n := r.db.AuditCount()
	for _, js := range []string{
		`{"host":"https://a.org","prefixes":["/"]}`,
		`{"host":"a.org:8080","prefixes":["/"]}`,
		`{"host":"*.a.org","prefixes":["/"]}`,
		`{"host":"A.org","prefixes":["/"]}`,
		`{"host":"127.0.0.1","prefixes":["/"]}`,
		`{"host":"[::1]","prefixes":["/"]}`,
		`{"host":"localhost","prefixes":["/"]}`,
		`{"host":"metadata.google.internal","prefixes":["/"]}`,
		`{"host":"a.org","prefixes":["debian/"]}`,
		`{"host":"a.org","prefixes":["/a/../b/"]}`,
		`{"host":"a.org","prefixes":[]}`,
		`{"host":"a.org"}`,
		`{"host":"a.org","prefixes":["/"],"push":true}`,
		`{"host":"a.org","prefixes":"/"}`,
		`not json`,
		`{"host":"a.org","prefixes":["/` + strings.Repeat("a", 5000) + `"]}`,
	} {
		if code, b := post(t, c, r, "/api/admin/allowlist", js); code != http.StatusBadRequest {
			t.Errorf("%.60s: %d %s, want 400", js, code, b)
		}
	}
	if rs, _ := r.db.AllowRules(); len(rs) != 0 || r.db.AuditCount() != n {
		t.Fatalf("bad input changed the list: %v", rs)
	}
}
