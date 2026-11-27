package store

import (
	"database/sql"
	"testing"
	"time"
)

func TestBundleRecords(t *testing.T) {
	d := open(t)
	if q, err := d.GetQuota("member"); err != nil || q.BundleBytes != DefaultBundleBytes {
		t.Fatalf("default bundle quota %d %v", q.BundleBytes, err)
	}
	_ = d.AddBundle("a", "u", 10, time.Now().Add(time.Hour))
	_ = d.AddBundle("b", "u", 20, time.Now().Add(-time.Second)) // expired: not served, but counted until its file is gone
	_ = d.AddBundle("c", "v", 40, time.Now().Add(time.Hour))
	if n, _ := d.BundleBytes("u"); n != 30 {
		t.Fatalf("used %d, want 30", n)
	}
	if ids, _ := d.ExpiredBundlesOf("u"); len(ids) != 1 || ids[0] != "b" {
		t.Fatalf("u's expired %v", ids)
	}
	if _, err := d.Bundle("u", "b"); err != ErrNoBundle {
		t.Fatal("expired bundle served")
	}
	if _, err := d.Bundle("u", "c"); err != ErrNoBundle {
		t.Fatal("another subject's bundle served")
	}
	if err := d.DeleteBundle("u", "c"); err != ErrNoBundle {
		t.Fatal("another subject's bundle deleted")
	}
	if ids, _ := d.ExpiredBundles(); len(ids) != 1 || ids[0] != "b" {
		t.Fatalf("expired %v", ids)
	}
}

// A database made before bundles existed gains the column with the default, keeping its
// other limits.
func TestBundleMigration(t *testing.T) {
	path := t.TempDir() + "/old.db"
	raw, err := sql.Open("sqlite3", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`CREATE TABLE quotas (tier TEXT PRIMARY KEY, bytes_per_day INTEGER NOT NULL, conns INTEGER NOT NULL,
		dests_per_min INTEGER NOT NULL, reqs_per_min INTEGER NOT NULL);
		INSERT INTO quotas VALUES ('member', 123, 4, 5, 6);`); err != nil {
		t.Fatal(err)
	}
	raw.Close()
	d, err := Open(path, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	q, err := d.GetQuota("member")
	if err != nil || q.BytesPerDay != 123 || q.ReqsPerMin != 6 || q.BundleBytes != DefaultBundleBytes {
		t.Fatalf("migrated quota %+v %v", q, err)
	}
	d.Close()
	if d, err = Open(path, make([]byte, 32)); err != nil { // a second open finds the column and adds nothing
		t.Fatal(err)
	}
}
