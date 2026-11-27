package web

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// The bundle limits decided on 2026-11-27 (findings B4 and B5): a daily quota and a platform
// daily cap on bundle traffic, a ceiling on one upload, and a platform storage cap.

const bundleUser = "clubroom-user-42"

// setUserQuota sets the "user" tier's daily bytes and bundle space, keeping the rest.
func setUserQuota(t *testing.T, r *rig, perDay, space int64) {
	t.Helper()
	q, err := r.db.GetQuota("user")
	if err != nil {
		t.Fatal(err)
	}
	q.BytesPerDay, q.BundleBytes = perDay, space
	if err := r.db.SetQuota("admin", "user", q); err != nil {
		t.Fatal(err)
	}
}

func uploadID(t *testing.T, c *http.Client, r *rig, n int) string {
	t.Helper()
	code, b := upload(t, c, r, bytes.Repeat([]byte{9}, n), "3600")
	if code != http.StatusCreated {
		t.Fatalf("upload of %d: %d %s", n, code, b)
	}
	var up struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal([]byte(b), &up)
	return up.ID
}

// chunked uploads n bytes with no Content-Length, so only the body reader can stop it.
func chunked(t *testing.T, c *http.Client, r *rig, n int) (int, string) {
	t.Helper()
	pr, pw := io.Pipe()
	go func() { pw.Write(make([]byte, n)); pw.Close() }()
	req, _ := http.NewRequest("POST", r.app.URL+"/api/bundles?expires_in=3600", pr)
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Origin", r.app.URL)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func bundleUsage(t *testing.T, r *rig) int64 {
	t.Helper()
	b, _, err := r.db.UsageToday(bundleUser, "bundle")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestBundleUploadCeiling(t *testing.T) {
	old := maxUpload
	maxUpload = 100
	t.Cleanup(func() { maxUpload = old })
	r := newRig(t, map[string]any{"login": "someone", "status": "active"})
	c, _ := signIn(t, r)
	setUserQuota(t, r, 0, 0) // no daily quota and no space limit: the ceiling still holds
	if code, b := upload(t, c, r, make([]byte, 101), "3600"); code != http.StatusRequestEntityTooLarge || !strings.Contains(b, "at most") {
		t.Fatalf("over the ceiling: %d %s, want 413", code, b)
	}
	if code, b := chunked(t, c, r, 150); code != http.StatusRequestEntityTooLarge || !strings.Contains(b, "at most") {
		t.Fatalf("chunked over the ceiling: %d %s, want 413", code, b)
	}
	uploadID(t, c, r, 100)
	var list struct {
		MaxUpload int64 `json:"max_upload"`
	}
	if getJSON(t, c, r, "/api/bundles", &list); list.MaxUpload != BundleMaxUpload {
		t.Fatalf("max_upload %d", list.MaxUpload)
	}
	if BundleMaxUpload != 200_000_000 {
		t.Fatalf("the decided ceiling is 200 MB, not %d", BundleMaxUpload)
	}
}

func TestBundleDailyQuota(t *testing.T) {
	r := newRig(t, map[string]any{"login": "someone", "status": "active"})
	c, _ := signIn(t, r)
	setUserQuota(t, r, 100, 0)
	_ = r.db.AddUsage(bundleUser, "proxy", 5000, 1) // proxy traffic does not count against bundles
	id := uploadID(t, c, r, 60)
	if got := bundleUsage(t, r); got != 60 {
		t.Fatalf("usage after upload %d, want 60", got)
	}
	if code, b := upload(t, c, r, make([]byte, 41), "3600"); code != http.StatusTooManyRequests || !strings.Contains(b, "Daily bundle quota") {
		t.Fatalf("upload passing the quota: %d %s, want 429", code, b)
	}
	if code, _ := chunked(t, c, r, 41); code != http.StatusTooManyRequests {
		t.Fatalf("chunked upload passing the quota: %d, want 429", code)
	}
	// the chunked upload moved 40 bytes before it was cut: they count
	if got := bundleUsage(t, r); got != 100 {
		t.Fatalf("usage %d, want 100", got)
	}
	if code, _ := upload(t, c, r, make([]byte, 1), "3600"); code != http.StatusTooManyRequests {
		t.Fatalf("upload at the quota: %d, want 429", code)
	}
	if code, b := bundleReq(t, c, r, "GET", "/api/bundles/"+id, "", "", nil); code != http.StatusTooManyRequests || !strings.Contains(b, "Daily bundle quota") {
		t.Fatalf("download passing the quota: %d %s, want 429", code, b)
	}
}

func TestBundleDownloadCountsItsSize(t *testing.T) {
	r := newRig(t, map[string]any{"login": "someone", "status": "active"})
	c, _ := signIn(t, r)
	setUserQuota(t, r, 250, 0)
	id := uploadID(t, c, r, 100)
	if code, _ := bundleReq(t, c, r, "HEAD", "/api/bundles/"+id, "", "", nil); code != http.StatusOK {
		t.Fatalf("head: %d", code)
	}
	if got := bundleUsage(t, r); got != 100 {
		t.Fatalf("a HEAD counted: usage %d, want 100", got)
	}
	if code, _ := bundleReq(t, c, r, "GET", "/api/bundles/"+id, "", "", nil); code != http.StatusOK {
		t.Fatalf("download: %d", code)
	}
	if got := bundleUsage(t, r); got != 200 {
		t.Fatalf("usage after download %d, want 200", got)
	}
	// 200 used of 250: a 100-byte download would pass the quota, so it does not start
	if code, _ := bundleReq(t, c, r, "GET", "/api/bundles/"+id, "", "", nil); code != http.StatusTooManyRequests {
		t.Fatalf("second download: %d, want 429", code)
	}
	if got := bundleUsage(t, r); got != 200 {
		t.Fatalf("a refused download counted: usage %d", got)
	}
}

func TestBundlePlatformDailyCap(t *testing.T) {
	r, c := adminRig(t)
	setUserQuota(t, r, 0, 0)
	if code, b := post(t, c, r, "/api/admin/caps", `{"service":"bundle","bytes_per_day":150}`); code != http.StatusNoContent {
		t.Fatalf("set the bundle cap: %d %s", code, b)
	}
	var out struct {
		Caps map[string]float64 `json:"caps"`
	}
	if getJSON(t, c, r, "/api/admin/caps", &out); out.Caps["bundle"] != 150 {
		t.Fatalf("caps %v", out.Caps)
	}
	_ = r.db.AddUsage("another-user", "bundle", 40, 1) // the cap is for all users together
	id := uploadID(t, c, r, 60)
	if code, b := upload(t, c, r, make([]byte, 51), "3600"); code != http.StatusServiceUnavailable || !strings.Contains(b, "platform's daily bundle limit") {
		t.Fatalf("upload passing the cap: %d %s, want 503", code, b)
	}
	if code, _ := bundleReq(t, c, r, "GET", "/api/bundles/"+id, "", "", nil); code != http.StatusServiceUnavailable {
		t.Fatalf("download passing the cap: %d, want 503", code)
	}
	if code, _ := chunked(t, c, r, 80); code != http.StatusServiceUnavailable {
		t.Fatalf("chunked upload passing the cap: %d, want 503", code)
	}
	if code, _ := upload(t, c, r, make([]byte, 1), "3600"); code != http.StatusServiceUnavailable {
		t.Fatalf("upload at the cap: %d, want 503", code)
	}
}

func TestBundleStorageCap(t *testing.T) {
	r, c := adminRig(t)
	setUserQuota(t, r, 0, 0)
	if code, _ := post(t, c, r, "/api/admin/storage", `{"name":"bundles"}`); code != http.StatusBadRequest {
		t.Fatal("storage cap without bytes accepted")
	}
	if code, _ := post(t, c, r, "/api/admin/storage", `{"name":"bundles","bytes":-1}`); code != http.StatusBadRequest {
		t.Fatal("negative storage cap accepted")
	}
	if code, _ := post(t, c, r, "/api/admin/storage", `{"name":"disk","bytes":1}`); code != http.StatusBadRequest {
		t.Fatal("unknown storage accepted")
	}
	if code, b := post(t, c, r, "/api/admin/storage", `{"name":"bundles","bytes":100}`); code != http.StatusNoContent {
		t.Fatalf("set the storage cap: %d %s", code, b)
	}
	// another user's bundle, expired but its file not yet removed: it still takes room
	if err := r.db.AddBundle(strings.Repeat("cd", 16), "another-user", 70, time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	var st struct {
		Storage map[string]int64 `json:"storage"`
		Used    map[string]int64 `json:"used"`
	}
	if getJSON(t, c, r, "/api/admin/storage", &st); st.Storage["bundles"] != 100 || st.Used["bundles"] != 70 {
		t.Fatalf("storage %+v", st)
	}
	if code, b := upload(t, c, r, make([]byte, 31), "3600"); code != http.StatusInsufficientStorage || !strings.Contains(b, "storage is full") {
		t.Fatalf("upload passing the storage cap: %d %s, want 507", code, b)
	}
	if code, _ := chunked(t, c, r, 31); code != http.StatusInsufficientStorage {
		t.Fatalf("chunked upload passing the storage cap: %d, want 507", code)
	}
	uploadID(t, c, r, 30)
	if code, _ := upload(t, c, r, make([]byte, 1), "3600"); code != http.StatusInsufficientStorage {
		t.Fatalf("upload at the storage cap: %d, want 507", code)
	}
	if n, _ := r.db.AllBundleBytes(); n != 100 {
		t.Fatalf("stored %d, want 100", n)
	}
	var audit int
	_ = r.db.QueryRow(`SELECT count(*) FROM audit WHERE action = 'set storage cap'`, &audit)
	if audit != 1 {
		t.Fatalf("audit entries %d, want 1", audit)
	}
}

// With every limit at 0 (none) uploads still work: no limit is applied by default except the
// ceiling.
func TestBundleNoLimitsByDefault(t *testing.T) {
	r := newRig(t, map[string]any{"login": "someone", "status": "active"})
	c, _ := signIn(t, r)
	setUserQuota(t, r, 0, 0)
	id := uploadID(t, c, r, 1000)
	if code, _ := bundleReq(t, c, r, "GET", "/api/bundles/"+id, "", "", nil); code != http.StatusOK {
		t.Fatalf("download: %d", code)
	}
	caps, _ := r.db.Caps()
	if c, ok := caps["bundle"]; !ok || c != 0 {
		t.Fatalf("bundle cap %v %v, want 0", c, ok)
	}
	if s, _ := r.db.StorageCaps(); s["bundles"] != 0 {
		t.Fatalf("storage cap %v", s)
	}
	if got := bundleUsage(t, r); got != 2000 {
		t.Fatalf("usage %d, want 2000", got)
	}
}
