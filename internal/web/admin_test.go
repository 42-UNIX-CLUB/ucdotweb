package web

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// adminRig signs one user in and makes them an administrator.
func adminRig(t *testing.T) (*rig, *http.Client) {
	t.Helper()
	r := newRig(t, map[string]any{"login": "someone", "status": "active"})
	c := client(t)
	resp, _ := c.Get(r.app.URL + "/auth/login")
	resp.Body.Close()
	if err := r.db.SetGrant("test", "clubroom-user-42", "admin", true, ""); err != nil {
		t.Fatal(err)
	}
	return r, c
}

func post(t *testing.T, c *http.Client, r *rig, path, js string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest("POST", r.app.URL+path, strings.NewReader(js))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", r.app.URL)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, body(t, resp)
}

func getJSON(t *testing.T, c *http.Client, r *rig, path string, v any) int {
	t.Helper()
	resp, err := c.Get(r.app.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
			t.Fatalf("%s: Cache-Control %q, want no-store", path, cc)
		}
	}
	return resp.StatusCode
}

func TestAdminReadsRefusedToOthers(t *testing.T) {
	r := newRig(t, map[string]any{"login": "someone", "status": "active"})
	var v any
	for _, p := range []string{"/api/admin/users", "/api/admin/quotas", "/api/admin/flags", "/api/admin/audit", "/api/admin/conns", "/api/admin/users/clubroom-user-42"} {
		if code := getJSON(t, client(t), r, p, &v); code != http.StatusUnauthorized {
			t.Fatalf("%s signed out: status %d, want 401", p, code)
		}
	}
	c := client(t)
	resp, _ := c.Get(r.app.URL + "/auth/login")
	resp.Body.Close()
	for _, p := range []string{"/api/admin/users", "/api/admin/audit", "/api/admin/conns"} {
		if code := getJSON(t, c, r, p, &v); code != http.StatusForbidden {
			t.Fatalf("%s as a user: status %d, want 403", p, code)
		}
	}
	if code, _ := post(t, c, r, "/api/admin/users/clubroom-user-42/grant", `{"grant":"admin","on":true}`); code != http.StatusForbidden {
		t.Fatalf("self-grant as a user: status %d, want 403", code)
	}
}

func TestAdminUsersAndGrants(t *testing.T) {
	r, c := adminRig(t)
	if _, err := r.db.SeenUser("other-subject", "otherlogin"); err != nil {
		t.Fatal(err)
	}
	var list struct {
		Users []map[string]any `json:"users"`
	}
	if code := getJSON(t, c, r, "/api/admin/users?q=OTHER", &list); code != 200 || len(list.Users) != 1 || list.Users[0]["login"] != "otherlogin" {
		t.Fatalf("search: status %d, %v", code, list.Users)
	}
	if code, b := post(t, c, r, "/api/admin/users/other-subject/grant", `{"grant":"banned","on":true}`); code != http.StatusBadRequest {
		t.Fatalf("ban without reason: %d %s", code, b)
	}
	if code, b := post(t, c, r, "/api/admin/users/other-subject/grant", `{"grant":"banned","on":true,"reason":"spam"}`); code != http.StatusNoContent {
		t.Fatalf("ban: %d %s", code, b)
	}
	if code, _ := post(t, c, r, "/api/admin/users/other-subject/grant", `{"grant":"root","on":true}`); code != http.StatusBadRequest {
		t.Fatal("unknown grant accepted")
	}
	if code, _ := post(t, c, r, "/api/admin/users/nobody/grant", `{"grant":"member","on":true}`); code != http.StatusNotFound {
		t.Fatal("grant to an unknown user accepted")
	}
	if code, _ := post(t, c, r, "/api/admin/users/other-subject/grant", `{"grant":"member","on":true,"extra":1}`); code != http.StatusBadRequest {
		t.Fatal("unknown field accepted")
	}
	var one struct {
		User map[string]any `json:"user"`
	}
	if code := getJSON(t, c, r, "/api/admin/users/other-subject", &one); code != 200 || one.User["banned"] != true || one.User["ban_reason"] != "spam" {
		t.Fatalf("user view: %d %v", code, one.User)
	}
	var audit struct {
		Audit []map[string]any `json:"audit"`
	}
	getJSON(t, c, r, "/api/admin/audit?limit=1", &audit)
	if len(audit.Audit) != 1 || audit.Audit[0]["action"] != "set banned" || audit.Audit[0]["actor"] != "clubroom-user-42" {
		t.Fatalf("audit: %v", audit.Audit)
	}
	// paging: the entry before the newest is the test's own admin grant
	id := int64(audit.Audit[0]["id"].(float64))
	getJSON(t, c, r, "/api/admin/audit?limit=1&before="+itoa(id), &audit)
	if len(audit.Audit) != 1 || audit.Audit[0]["action"] != "set admin" {
		t.Fatalf("audit page 2: %v", audit.Audit)
	}
}

func itoa(n int64) string { b, _ := json.Marshal(n); return string(b) }

func TestAdminQuotas(t *testing.T) {
	r, c := adminRig(t)
	if code, _ := post(t, c, r, "/api/admin/quotas", `{"tier":"member","bytes_per_day":1000}`); code != http.StatusBadRequest {
		t.Fatal("partial quota accepted (missing limits would become 'no limit')")
	}
	if code, _ := post(t, c, r, "/api/admin/quotas", `{"tier":"member","bytes_per_day":-1,"conns":1,"dests_per_min":1,"reqs_per_min":1}`); code != http.StatusBadRequest {
		t.Fatal("negative quota accepted")
	}
	if code, _ := post(t, c, r, "/api/admin/quotas", `{"tier":"gold","bytes_per_day":1,"conns":1,"dests_per_min":1,"reqs_per_min":1}`); code != http.StatusBadRequest {
		t.Fatal("unknown tier accepted")
	}
	if code, b := post(t, c, r, "/api/admin/quotas", `{"tier":"member","bytes_per_day":1000,"conns":4,"dests_per_min":10,"reqs_per_min":60}`); code != http.StatusNoContent {
		t.Fatalf("set quota: %d %s", code, b)
	}
	q, err := r.db.GetQuota("member")
	if err != nil || q.BytesPerDay != 1000 || q.Conns != 4 || q.DestsPerMin != 10 || q.ReqsPerMin != 60 {
		t.Fatalf("stored quota %+v %v", q, err)
	}
	var out struct {
		Quotas map[string]map[string]float64 `json:"quotas"`
	}
	if getJSON(t, c, r, "/api/admin/quotas", &out); out.Quotas["member"]["conns"] != 4 || out.Quotas["user"]["reqs_per_min"] != 120 {
		t.Fatalf("quota view: %v", out.Quotas)
	}
}

func TestAdminFlagsAndConns(t *testing.T) {
	r, c := adminRig(t)
	if code, _ := post(t, c, r, "/api/admin/flag", `{"name":"relay_off","on":true}`); code != http.StatusNoContent {
		t.Fatal("flag")
	}
	var f struct {
		Flags map[string]map[string]any `json:"flags"`
	}
	getJSON(t, c, r, "/api/admin/flags", &f)
	if f.Flags["relay_off"]["on"] != true || f.Flags["relay_off"]["by"] != "clubroom-user-42" || f.Flags["all_off"]["on"] != false {
		t.Fatalf("flags: %v", f.Flags)
	}
	_ = r.db.LogConn("a", "proxy", "deb.debian.org", 10, "ok")
	_ = r.db.LogConn("b", "relay", "example.com", 20, "ok")
	var cs struct {
		Conns []map[string]any `json:"conns"`
	}
	if getJSON(t, c, r, "/api/admin/conns?subject=b", &cs); len(cs.Conns) != 1 || cs.Conns[0]["host"] != "example.com" {
		t.Fatalf("conns for b: %v", cs.Conns)
	}
	if getJSON(t, c, r, "/api/admin/conns", &cs); len(cs.Conns) != 2 {
		t.Fatalf("all conns: %v", cs.Conns)
	}
}

func TestAdminContentTypeParameters(t *testing.T) {
	r, c := adminRig(t)
	for ct, want := range map[string]int{
		"application/json; charset=utf-8": http.StatusNoContent,
		"Application/JSON":                http.StatusNoContent,
		"text/plain":                      http.StatusBadRequest,
		"application/json; =":             http.StatusBadRequest,
	} {
		req, _ := http.NewRequest("POST", r.app.URL+"/api/admin/flag", strings.NewReader(`{"name":"relay_off","on":true}`))
		req.Header.Set("Content-Type", ct)
		req.Header.Set("Origin", r.app.URL)
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Errorf("Content-Type %q: status %d, want %d", ct, resp.StatusCode, want)
		}
	}
}
