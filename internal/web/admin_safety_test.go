package web

import (
	"context"
	"io"
	"log"
	"net/http"
	"sync"
	"testing"

	"github.com/42-UNIX-CLUB/ucdotweb/internal/safety"
)

type countNotifier struct {
	mu sync.Mutex
	n  int
}

func (c *countNotifier) Name() string { return "count" }

func (c *countNotifier) Notify(context.Context, string, string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n++
	return nil
}

func (c *countNotifier) count() int { c.mu.Lock(); defer c.mu.Unlock(); return c.n }

func safetyRig(t *testing.T) (*rig, *http.Client, *countNotifier) {
	t.Helper()
	r, c := adminRig(t)
	n := &countNotifier{}
	w, err := safety.New(r.db, safety.DefaultConfig(), n, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	r.srv.Safety = w
	return r, c, n
}

func TestSafetyRoutesAdminsOnly(t *testing.T) {
	r := newRig(t, map[string]any{"login": "someone", "status": "active"})
	var v any
	for _, p := range []string{"/api/admin/reports", "/api/admin/safety"} {
		if code := getJSON(t, client(t), r, p, &v); code != http.StatusUnauthorized {
			t.Fatalf("%s signed out: %d, want 401", p, code)
		}
	}
	c := client(t)
	resp, _ := c.Get(r.app.URL + "/auth/login")
	resp.Body.Close()
	for _, p := range []string{"/api/admin/reports", "/api/admin/safety"} {
		if code := getJSON(t, c, r, p, &v); code != http.StatusForbidden {
			t.Fatalf("%s as a user: %d, want 403", p, code)
		}
	}
	if code, _ := post(t, c, r, "/api/admin/reports", `{"severity":"critical","summary":"x"}`); code != http.StatusForbidden {
		t.Fatalf("report as a user: %d, want 403", code)
	}
	if r.db.Flag("relay_off") {
		t.Fatal("a user's report changed a switch")
	}
}

func TestSafetyReportValidation(t *testing.T) {
	r, c, _ := safetyRig(t)
	for _, js := range []string{`{"severity":"urgent","summary":"x"}`, `{"severity":"low","summary":"  "}`,
		`{"severity":"low","summary":"x","extra":1}`, `{"severity":"low"}`} {
		if code, b := post(t, c, r, "/api/admin/reports", js); code != http.StatusBadRequest {
			t.Fatalf("%s: %d %s", js, code, b)
		}
	}
	req, _ := http.NewRequest("POST", r.app.URL+"/api/admin/reports", nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://evil.example")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-site report: %d, want 403", resp.StatusCode)
	}
}

func TestSafetyReportsAndCriticalSuspends(t *testing.T) {
	r, c, n := safetyRig(t)
	code, b := post(t, c, r, "/api/admin/reports", `{"severity":"low","subject":"user-9","source":"member","summary":"slow mirror"}`)
	if code != http.StatusCreated || r.db.Flag("relay_off") {
		t.Fatalf("low report: %d %s", code, b)
	}
	code, b = post(t, c, r, "/api/admin/reports", `{"severity":"critical","source":"host provider","summary":"abuse complaint"}`)
	if code != http.StatusCreated || !r.db.Flag("relay_off") || n.count() != 1 {
		t.Fatalf("critical report: %d %s, notified %d", code, b, n.count())
	}
	var list struct {
		Reports []map[string]any `json:"reports"`
	}
	if code := getJSON(t, c, r, "/api/admin/reports", &list); code != 200 || len(list.Reports) != 2 ||
		list.Reports[0]["severity"] != "critical" || list.Reports[1]["subject"] != "user-9" || list.Reports[0]["actor"] != "clubroom-user-42" {
		t.Fatalf("reports: %d %v", code, list.Reports)
	}
	var st struct {
		Switch      string           `json:"switch"`
		Suspended   bool             `json:"suspended"`
		SuspendedBy string           `json:"suspended_by"`
		Checks      []map[string]any `json:"checks"`
		LastTrip    map[string]any   `json:"last_trip"`
	}
	if code := getJSON(t, c, r, "/api/admin/safety", &st); code != 200 || !st.Suspended || st.Switch != "relay_off" ||
		st.SuspendedBy != "safety" || len(st.Checks) != 3 || st.LastTrip == nil {
		t.Fatalf("safety view: %d %+v", code, st)
	}
	// only an administrator lifts it, through the existing switch endpoint
	if code, _ := post(t, c, r, "/api/admin/flag", `{"name":"relay_off","on":false}`); code != http.StatusNoContent {
		t.Fatal("lift")
	}
	r.srv.Safety.Check(t.Context())
	if r.db.Flag("relay_off") || n.count() != 1 {
		t.Fatal("the report that was already handled suspended again after the lift")
	}
}

func TestSafetyWithoutWatcher(t *testing.T) {
	r, c := adminRig(t)
	var v any
	if code := getJSON(t, c, r, "/api/admin/safety", &v); code != http.StatusServiceUnavailable {
		t.Fatalf("safety view without a watcher: %d, want 503", code)
	}
	if code, b := post(t, c, r, "/api/admin/reports", `{"severity":"critical","summary":"x"}`); code != http.StatusCreated {
		t.Fatalf("report without a watcher: %d %s", code, b)
	}
}
