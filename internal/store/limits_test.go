package store

import (
	"sync"
	"testing"
	"time"
)

func TestUsageLeftAndTakeUsage(t *testing.T) {
	d := open(t)
	if u, p, err := d.UsageLeft("a", "bundle", 0); err != nil || u != -1 || p != -1 {
		t.Fatalf("no limits: %d %d %v", u, p, err)
	}
	_ = d.AddUsage("a", "proxy", 900, 1) // another kind does not count
	if r, err := d.TakeUsage("a", "bundle", 60, 100); err != nil || r != "" {
		t.Fatalf("take 60 of 100: %q %v", r, err)
	}
	if r, _ := d.TakeUsage("a", "bundle", 41, 100); r != OverQuota {
		t.Fatalf("take 41 more: %q, want %q", r, OverQuota)
	}
	if u, _, _ := d.UsageLeft("a", "bundle", 100); u != 40 {
		t.Fatalf("left %d, want 40", u)
	}
	_ = d.AddUsage("a", "bundle", 50, 1) // past the limit: left is 0, never below
	if u, _, _ := d.UsageLeft("a", "bundle", 100); u != 0 {
		t.Fatalf("left past the limit %d, want 0", u)
	}
	if err := d.SetCap("admin", "bundle", 200); err != nil {
		t.Fatal(err)
	}
	if _, p, _ := d.UsageLeft("b", "bundle", 0); p != 90 {
		t.Fatalf("platform left %d, want 90 (200 minus a's 110)", p)
	}
	if r, _ := d.TakeUsage("b", "bundle", 91, 0); r != OverCap {
		t.Fatalf("take past the cap: %q, want %q", r, OverCap)
	}
	if r, _ := d.TakeUsage("b", "bundle", 90, 0); r != "" {
		t.Fatalf("take exactly the cap: %q", r)
	}
	if b, n, _ := d.UsageToday("b", "bundle"); b != 90 || n != 1 {
		t.Fatalf("b's usage %d bytes %d requests", b, n)
	}
	if r, _ := d.TakeUsage("c", "proxy", 5, 0); r != "" { // proxy has no cap set
		t.Fatalf("proxy: %q", r)
	}
}

// Many takes at once never pass the limit together.
func TestTakeUsageIsExact(t *testing.T) {
	d := open(t)
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if r, err := d.TakeUsage("a", "bundle", 10, 55); err == nil && r == "" {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if b, _, _ := d.UsageToday("a", "bundle"); ok != 5 || b != 50 {
		t.Fatalf("%d takes passed, %d bytes; want 5 and 50", ok, b)
	}
}

func TestStorageCaps(t *testing.T) {
	d := open(t)
	if c, err := d.StorageCap("bundles"); err != nil || c != 0 {
		t.Fatalf("default %d %v", c, err)
	}
	if err := d.SetStorageCap("admin", "bundles", -1); err == nil {
		t.Fatal("negative cap accepted")
	}
	if err := d.SetStorageCap("admin", "disk", 1); err == nil {
		t.Fatal("unknown storage accepted")
	}
	before := d.AuditCount()
	if err := d.SetStorageCap("admin", "bundles", 1000); err != nil {
		t.Fatal(err)
	}
	if d.AuditCount() != before+1 {
		t.Fatal("no audit entry")
	}
	if all, _ := d.StorageCaps(); all["bundles"] != 1000 {
		t.Fatalf("caps %v", all)
	}
	_ = d.AddBundle("x", "u", 10, time.Now().Add(time.Hour))
	_ = d.AddBundle("y", "v", 20, time.Now().Add(-time.Second)) // expired, file not gone yet: counts
	if n, _ := d.AllBundleBytes(); n != 30 {
		t.Fatalf("all bundle bytes %d, want 30", n)
	}
}

func TestLimitSubjectsByKind(t *testing.T) {
	d := open(t)
	_ = d.LogConn("a", "relay", "h", 0, "rate limited")
	_ = d.LogConn("b", "proxy", "h", 0, "rate limited")
	_ = d.LogConn("c", "proxy", "h", 0, "200 cut at quota")
	since := time.Now().Add(-time.Minute)
	exact, suffixes := []string{"rate limited"}, []string{" cut at quota"}
	for _, k := range []struct {
		kinds []string
		want  string
	}{{[]string{"relay"}, "a"}, {[]string{"proxy"}, "b,c"}, {[]string{"relay", "proxy"}, "a,b,c"}, {nil, "a,b,c"}} {
		got, err := d.LimitSubjects(since, k.kinds, exact, suffixes)
		if err != nil {
			t.Fatal(err)
		}
		s := ""
		for i, x := range got {
			if i > 0 {
				s += ","
			}
			s += x
		}
		if s != k.want {
			t.Errorf("kinds %v: %q, want %q", k.kinds, s, k.want)
		}
	}
	_ = d.AddUsage("a", "relay", 1, 0)
	_ = d.AddUsage("a", "proxy", 10, 0)
	_ = d.AddUsage("a", "bundle", 100, 0)
	day := Day(time.Now())
	for _, k := range []struct {
		kinds []string
		want  int64
	}{{[]string{"relay"}, 1}, {[]string{"relay", "proxy"}, 11}, {nil, 111}} {
		m, err := d.TrafficByDay(k.kinds, day, day)
		if err != nil || m[day] != k.want {
			t.Errorf("traffic %v: %d %v, want %d", k.kinds, m[day], err, k.want)
		}
	}
}
