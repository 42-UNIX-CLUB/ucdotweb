package web

import (
	"bytes"
	"net/http"
	"os"
	"testing"
)

// Finding B1: the space check counts only bundles that have not expired, but an expired
// bundle's file stays on disk until the hourly housekeeping. With the shortest expiry (60 s)
// a user can upload the full limit again every minute, so the disk can hold many times the
// limit. Here the expiry is moved into the past in the database to stand in for the wait.
func TestOptExpiredBundlesStillFillTheDisk(t *testing.T) {
	r := newRig(t, map[string]any{"login": "someone", "status": "active"})
	c, _ := signIn(t, r)
	r.db.Exec(`UPDATE quotas SET bundle_bytes = 100`)
	data := bytes.Repeat([]byte{7}, 80)
	const rounds = 10
	for i := 0; i < rounds; i++ {
		if code, b := upload(t, c, r, data, "60"); code != http.StatusCreated {
			t.Fatalf("upload %d: %d %s", i, code, b)
		}
		r.db.Exec(`UPDATE bundles SET expires = 1`) // the 60 seconds have passed
	}
	entries, _ := os.ReadDir(r.srv.BundleDir)
	var onDisk int64
	for _, e := range entries {
		if info, err := e.Info(); err == nil {
			onDisk += info.Size()
		}
	}
	t.Logf("limit 100 bytes, %d uploads of 80 bytes each after the one before expired: %d files, %d bytes on disk", rounds, len(entries), onDisk)
	if onDisk > 100 {
		t.Errorf("%d bytes on disk for a user whose limit is 100", onDisk)
	}
}
