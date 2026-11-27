package web

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/42-UNIX-CLUB/ucdotweb/internal/store"
)

func bundleReq(t *testing.T, c *http.Client, r *rig, method, path, ct, origin string, body []byte) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(method, r.app.URL+path, bytes.NewReader(body))
	if ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func upload(t *testing.T, c *http.Client, r *rig, data []byte, secs string) (int, string) {
	t.Helper()
	return bundleReq(t, c, r, "POST", "/api/bundles?expires_in="+secs, "application/octet-stream", r.app.URL, data)
}

func TestBundleRoundTrip(t *testing.T) {
	r := newRig(t, map[string]any{"login": "someone", "status": "active"})
	c, _ := signIn(t, r)
	data := bytes.Repeat([]byte{0, 1, 2, 0xff}, 1000)
	code, b := upload(t, c, r, data, "3600")
	if code != http.StatusCreated {
		t.Fatalf("upload: %d %s", code, b)
	}
	var up struct {
		ID        string `json:"id"`
		Size      int64  `json:"size"`
		ExpiresAt int64  `json:"expires_at"`
	}
	if err := json.Unmarshal([]byte(b), &up); err != nil || len(up.ID) != 32 || up.Size != 4000 {
		t.Fatalf("upload answer %s %v", b, err)
	}
	if d := time.Until(time.Unix(up.ExpiresAt, 0)); d < 59*time.Minute || d > 61*time.Minute {
		t.Fatalf("expires in %v", d)
	}
	resp, err := c.Get(r.app.URL + "/api/bundles/" + up.ID)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !bytes.Equal(got, data) {
		t.Fatalf("download: %d, %d bytes", resp.StatusCode, len(got))
	}
	for k, want := range map[string]string{"Content-Type": "application/octet-stream", "Content-Disposition": "attachment",
		"Content-Security-Policy": "sandbox", "Cache-Control": "no-store"} {
		if resp.Header.Get(k) != want {
			t.Errorf("%s: %q, want %q", k, resp.Header.Get(k), want)
		}
	}
	var list struct {
		Bundles []map[string]any `json:"bundles"`
		Used    int64            `json:"used"`
		Limit   int64            `json:"limit"`
	}
	if code := getJSON(t, c, r, "/api/bundles", &list); code != 200 || len(list.Bundles) != 1 || list.Used != 4000 || list.Limit != store.DefaultBundleBytes {
		t.Fatalf("list: %d %+v", code, list)
	}
	if code, _ := bundleReq(t, c, r, "DELETE", "/api/bundles/"+up.ID, "", "https://evil.example", nil); code != http.StatusForbidden {
		t.Fatalf("cross-site delete: %d", code)
	}
	if code, _ := bundleReq(t, c, r, "DELETE", "/api/bundles/"+up.ID, "", r.app.URL, nil); code != http.StatusNoContent {
		t.Fatalf("delete: %d", code)
	}
	if _, err := os.Stat(filepath.Join(r.srv.BundleDir, up.ID)); !os.IsNotExist(err) {
		t.Fatalf("file still there after delete: %v", err)
	}
	if code, _ := bundleReq(t, c, r, "GET", "/api/bundles/"+up.ID, "", "", nil); code != http.StatusNotFound {
		t.Fatalf("download after delete: %d", code)
	}
}

func TestBundleOnlyForTheSameAccount(t *testing.T) {
	r := newRig(t, map[string]any{"login": "someone", "status": "active"})
	c, _ := signIn(t, r)
	id := strings.Repeat("ab", 16)
	if err := os.WriteFile(filepath.Join(r.srv.BundleDir, id), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := r.db.AddBundle(id, "someone-else", 6, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if code, _ := bundleReq(t, c, r, "GET", "/api/bundles/"+id, "", "", nil); code != http.StatusNotFound {
		t.Fatalf("another account's bundle: %d, want 404", code)
	}
	if code, _ := bundleReq(t, c, r, "DELETE", "/api/bundles/"+id, "", r.app.URL, nil); code != http.StatusNotFound {
		t.Fatalf("deleting another account's bundle: %d, want 404", code)
	}
	if code, _ := bundleReq(t, client(t), r, "GET", "/api/bundles/"+id, "", "", nil); code != http.StatusUnauthorized {
		t.Fatalf("signed out: %d, want 401", code)
	}
	if code, _ := bundleReq(t, c, r, "GET", "/api/bundles/..%2f..%2fetc", "", "", nil); code != http.StatusNotFound {
		t.Fatalf("bad id: %d", code)
	}
}

func TestBundleUploadRefusals(t *testing.T) {
	r := newRig(t, map[string]any{"login": "someone", "status": "active"})
	c, _ := signIn(t, r)
	data := []byte("ciphertext")
	cases := []struct {
		name, ct, origin, secs string
		body                   []byte
		want                   int
	}{
		{"cross-site", "application/octet-stream", "https://evil.example", "3600", data, http.StatusForbidden},
		{"no origin", "application/octet-stream", "", "3600", data, http.StatusForbidden},
		{"form post", "application/x-www-form-urlencoded", r.app.URL, "3600", data, http.StatusBadRequest},
		{"no expiry", "application/octet-stream", r.app.URL, "", data, http.StatusBadRequest},
		{"too short", "application/octet-stream", r.app.URL, "59", data, http.StatusBadRequest},
		{"too long", "application/octet-stream", r.app.URL, "2592001", data, http.StatusBadRequest},
		{"empty", "application/octet-stream", r.app.URL, "3600", nil, http.StatusBadRequest},
		{"30 days", "application/octet-stream", r.app.URL, "2592000", data, http.StatusCreated},
	}
	for _, k := range cases {
		if code, b := bundleReq(t, c, r, "POST", "/api/bundles?expires_in="+k.secs, k.ct, k.origin, k.body); code != k.want {
			t.Errorf("%s: %d %s, want %d", k.name, code, b, k.want)
		}
	}
	if code, _ := upload(t, client(t), r, data, "3600"); code != http.StatusUnauthorized {
		t.Errorf("signed out: %d, want 401", code)
	}
	entries, _ := os.ReadDir(r.srv.BundleDir)
	if len(entries) != 1 {
		t.Fatalf("%d files in the bundle directory, want 1 (refused uploads leave nothing)", len(entries))
	}
}

func TestBundleQuota(t *testing.T) {
	r := newRig(t, map[string]any{"login": "someone", "status": "active"})
	c, _ := signIn(t, r)
	q, _ := r.db.GetQuota("user")
	q.BundleBytes = 100
	if err := r.db.SetQuota("admin", "user", q); err != nil {
		t.Fatal(err)
	}
	if code, b := upload(t, c, r, make([]byte, 60), "3600"); code != http.StatusCreated {
		t.Fatalf("first: %d %s", code, b)
	}
	if code, _ := upload(t, c, r, make([]byte, 41), "3600"); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("over the limit: %d, want 413", code)
	}
	// a body without a length, larger than the room left, is cut off by the reader
	pr, pw := io.Pipe()
	go func() { pw.Write(make([]byte, 50)); pw.Close() }()
	req, _ := http.NewRequest("POST", r.app.URL+"/api/bundles?expires_in=3600", pr)
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Origin", r.app.URL)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("chunked over the limit: %d, want 413", resp.StatusCode)
	}
	if code, b := upload(t, c, r, make([]byte, 40), "3600"); code != http.StatusCreated {
		t.Fatalf("exactly the room left: %d %s", code, b)
	}
	if used, _ := r.db.BundleBytes("clubroom-user-42"); used != 100 {
		t.Fatalf("used %d, want 100", used)
	}
}

func TestPurgeBundles(t *testing.T) {
	r := newRig(t, map[string]any{"login": "someone", "status": "active"})
	dir := r.srv.BundleDir
	expired, live, orphan := strings.Repeat("01", 16), strings.Repeat("02", 16), strings.Repeat("03", 16)
	for _, n := range []string{expired, live, orphan, orphan + ".tmp", "README"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	old := time.Now().Add(-2 * time.Hour)
	for _, n := range []string{expired, live, orphan, orphan + ".tmp", "README"} {
		_ = os.Chtimes(filepath.Join(dir, n), old, old)
	}
	_ = r.db.AddBundle(expired, "u", 1, time.Now().Add(-time.Second))
	_ = r.db.AddBundle(live, "u", 1, time.Now().Add(time.Hour))
	n, err := r.srv.PurgeBundles()
	if err != nil || n != 3 {
		t.Fatalf("purged %d, %v; want 3", n, err)
	}
	left, _ := os.ReadDir(dir)
	var names []string
	for _, e := range left {
		names = append(names, e.Name())
	}
	if strings.Join(names, ",") != live+",README" {
		t.Fatalf("left: %v", names)
	}
	if r.db.KnownBundle(expired) {
		t.Fatal("expired record kept")
	}
}
