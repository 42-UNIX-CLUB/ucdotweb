package store

import (
	"strings"
	"testing"
	"time"
)

func open(t *testing.T) *DB {
	d, err := Open(t.TempDir()+"/s.db", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func TestAuditAppendOnly(t *testing.T) {
	d := open(t)
	d.SeenUser("u", "l")
	if err := d.SetGrant("a", "u", "member", true, ""); err != nil {
		t.Fatal(err)
	}
	if err := d.Exec(`UPDATE audit SET actor = 'x'`); err == nil || !strings.Contains(err.Error(), "append-only") {
		t.Fatalf("update allowed: %v", err)
	}
	if err := d.Exec(`DELETE FROM audit`); err == nil {
		t.Fatal("delete allowed")
	}
}

func TestSessionEncryptedAtRest(t *testing.T) {
	d := open(t)
	if err := d.SessionPut("h", []byte(`{"RefreshToken":"very-secret-token"}`), time.Now()); err != nil {
		t.Fatal(err)
	}
	var raw []byte
	if err := d.QueryRow(`SELECT data FROM sessions`, &raw); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "very-secret-token") {
		t.Fatal("session data stored in clear")
	}
	got, _, _, ok, err := d.SessionGet("h")
	if !ok || err != nil || !strings.Contains(string(got), "very-secret-token") {
		t.Fatalf("round trip: %v %v", ok, err)
	}
}

func TestWrongKeyCannotRead(t *testing.T) {
	path := t.TempDir() + "/k.db"
	d, _ := Open(path, make([]byte, 32))
	d.SessionPut("h", []byte("x"), time.Now())
	d.Close()
	k := make([]byte, 32)
	k[0] = 1
	d2, _ := Open(path, k)
	defer d2.Close()
	if _, _, _, ok, err := d2.SessionGet("h"); ok || err == nil {
		t.Fatal("read with the wrong key")
	}
}

func TestLogPurge(t *testing.T) {
	d := open(t)
	d.now = func() time.Time { return time.Now().Add(-31 * 24 * time.Hour) }
	d.LogConn("u", "proxy", "h", 1, "200")
	d.now = time.Now
	d.LogConn("u", "proxy", "h", 1, "200")
	if n, _ := d.PurgeLogs(30 * 24 * time.Hour); n != 1 {
		t.Fatalf("purged %d, want 1", n)
	}
}

func TestDefaultQuotas(t *testing.T) {
	d := open(t)
	m, _ := d.GetQuota("member")
	if m.BytesPerDay != 2_500_000_000 || m.Conns != 8 || m.DestsPerMin != 15 {
		t.Fatalf("member quota %+v", m)
	}
	u, _ := d.GetQuota("user")
	if u.BytesPerDay != 2_000_000_000 || u.ReqsPerMin != 120 {
		t.Fatalf("user quota %+v", u)
	}
}
