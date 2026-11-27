package store

import (
	"testing"
	"time"
)

func TestCaps(t *testing.T) {
	d := open(t)
	if d.CapReached("proxy") {
		t.Fatal("cap reached with no cap set")
	}
	if err := d.SetCap("admin", "proxy", 1000); err != nil {
		t.Fatal(err)
	}
	if err := d.SetCap("admin", "gold", 1); err == nil {
		t.Fatal("unknown service accepted")
	}
	if err := d.SetCap("admin", "proxy", -1); err == nil {
		t.Fatal("negative cap accepted")
	}
	_ = d.AddUsage("a", "proxy", 600, 1)
	_ = d.AddUsage("b", "relay", 5000, 1) // another service does not count
	if d.CapReached("proxy") {
		t.Fatal("600 of 1000 reached the cap")
	}
	_ = d.AddUsage("b", "proxy", 400, 1)
	if d.CapReached("proxy") {
		t.Fatal("the answer should be cached for 10 s")
	}
	d.now = func() time.Time { return time.Now().Add(11 * time.Second) } // the cache runs out
	if !d.CapReached("proxy") {
		t.Fatal("two users together at 1000 of 1000 did not reach the cap")
	}
	d.now = time.Now
	caps, err := d.Caps()
	if err != nil || caps["proxy"] != 1000 || caps["relay"] != 0 {
		t.Fatalf("caps %v %v", caps, err)
	}
	if err := d.SetCap("admin", "proxy", 0); err != nil || d.CapReached("proxy") {
		t.Fatalf("removing the cap: %v", err)
	}
}

func TestEraseOldReportSummaries(t *testing.T) {
	d := open(t)
	if err := d.EnsureSafety(); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-400 * 24 * time.Hour).Unix()
	if err := d.Exec(`INSERT INTO reports (at, actor, severity, subject, source, summary) VALUES (?, 'a', 'low', 's', 'mail', 'old text')`, old); err != nil {
		t.Fatal(err)
	}
	if err := d.Exec(`INSERT INTO reports (at, actor, severity, subject, source, summary) VALUES (?, 'a', 'low', 's', 'mail', 'new text')`, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	n, err := d.EraseOldReportSummaries(365 * 24 * time.Hour)
	if err != nil || n != 1 {
		t.Fatalf("erased %d, %v", n, err)
	}
	var kept int
	if err := d.QueryRow(`SELECT count(*) FROM reports WHERE summary = 'new text'`, &kept); err != nil || kept != 1 {
		t.Fatalf("the recent summary was touched: %d %v", kept, err)
	}
	var rows int
	_ = d.QueryRow(`SELECT count(*) FROM reports`, &rows)
	if rows != 2 {
		t.Fatalf("reports deleted: %d left", rows)
	}
}
