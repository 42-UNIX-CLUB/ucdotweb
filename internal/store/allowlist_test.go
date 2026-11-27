package store

import (
	"errors"
	"strings"
	"testing"
)

func lastAudit(t *testing.T, d *DB) AuditRow {
	t.Helper()
	a, err := d.Audit(0, 1)
	if err != nil || len(a) != 1 {
		t.Fatalf("audit: %v %v", a, err)
	}
	return a[0]
}

func TestAllowlistSeedOnce(t *testing.T) {
	d := open(t)
	if rs, err := d.AllowRules(); err != nil || len(rs) != 0 {
		t.Fatalf("fresh list: %v %v", rs, err)
	}
	seed := []AllowRule{{Host: "deb.debian.org", Prefixes: []string{"/debian/"}}, {Host: "github.com", Git: true, Releases: true}}
	v := AllowlistVersion()
	if ok, err := d.SeedAllowlist(seed); err != nil || !ok {
		t.Fatalf("seed: %v %v", ok, err)
	}
	if AllowlistVersion() == v {
		t.Fatal("the version did not move after the seed")
	}
	a := lastAudit(t, d)
	if a.Actor != "seed" || a.Action != "allowlist seed" || !strings.Contains(a.Detail, "2 rules") {
		t.Fatalf("seed audit: %+v", a)
	}
	rs, _ := d.AllowRules()
	if len(rs) != 2 || rs[0].Host != "deb.debian.org" || rs[0].Prefixes[0] != "/debian/" || rs[0].UpdatedBy != "seed" ||
		!rs[1].Git || !rs[1].Releases || rs[1].Prefixes == nil || len(rs[1].Prefixes) != 0 {
		t.Fatalf("seeded rules: %+v", rs)
	}
	// remove everything: a second seed must not refill the list
	for _, r := range rs {
		if err := d.RemoveAllowRule("admin", r.Host); err != nil {
			t.Fatal(err)
		}
	}
	n := d.AuditCount()
	if ok, err := d.SeedAllowlist(seed); err != nil || ok {
		t.Fatalf("second seed: %v %v", ok, err)
	}
	if rs, _ := d.AllowRules(); len(rs) != 0 {
		t.Fatalf("the list was seeded twice: %+v", rs)
	}
	if d.AuditCount() != n {
		t.Fatal("a skipped seed wrote the audit log")
	}
}

func TestAllowlistSeedRefusesDuplicates(t *testing.T) {
	d := open(t)
	_, err := d.SeedAllowlist([]AllowRule{{Host: "a.org", Prefixes: []string{"/"}}, {Host: "a.org", Prefixes: []string{"/x/"}}})
	if err == nil {
		t.Fatal("a host given twice was seeded")
	}
	if rs, _ := d.AllowRules(); len(rs) != 0 {
		t.Fatalf("a failed seed left rows: %+v", rs)
	}
	// the failed seed was rolled back, so a good one still runs
	if ok, err := d.SeedAllowlist([]AllowRule{{Host: "a.org", Prefixes: []string{"/"}}}); err != nil || !ok {
		t.Fatalf("seed after a failed one: %v %v", ok, err)
	}
}

func TestAllowlistPutReplaceRemove(t *testing.T) {
	d := open(t)
	v := AllowlistVersion()
	replaced, err := d.PutAllowRule("adm", AllowRule{Host: "ftp.gnu.org", Prefixes: []string{"/gnu/"}})
	if err != nil || replaced {
		t.Fatalf("add: %v %v", replaced, err)
	}
	if AllowlistVersion() == v {
		t.Fatal("the version did not move after an add")
	}
	if a := lastAudit(t, d); a.Actor != "adm" || a.Action != "allowlist add" || a.Target != "ftp.gnu.org" || a.Detail != "prefixes /gnu/" {
		t.Fatalf("add audit: %+v", a)
	}
	replaced, err = d.PutAllowRule("adm2", AllowRule{Host: "ftp.gnu.org", Prefixes: []string{"/gnu/", "/old-gnu/"}, Git: true})
	if err != nil || !replaced {
		t.Fatalf("replace: %v %v", replaced, err)
	}
	a := lastAudit(t, d)
	if a.Action != "allowlist replace" || a.Detail != "was: prefixes /gnu/. now: prefixes /gnu/ /old-gnu/; git" {
		t.Fatalf("replace audit: %+v", a)
	}
	rs, _ := d.AllowRules()
	if len(rs) != 1 || len(rs[0].Prefixes) != 2 || !rs[0].Git || rs[0].UpdatedBy != "adm2" {
		t.Fatalf("after replace: %+v", rs)
	}
	if err := d.RemoveAllowRule("adm", "nope.org"); !errors.Is(err, ErrNoAllowRule) {
		t.Fatalf("remove unknown: %v", err)
	}
	if err := d.RemoveAllowRule("adm", "ftp.gnu.org"); err != nil {
		t.Fatal(err)
	}
	if a := lastAudit(t, d); a.Action != "allowlist remove" || a.Target != "ftp.gnu.org" || !strings.HasPrefix(a.Detail, "was: ") {
		t.Fatalf("remove audit: %+v", a)
	}
	if rs, _ := d.AllowRules(); len(rs) != 0 {
		t.Fatalf("after remove: %+v", rs)
	}
}

func TestAllowlistStoreChecks(t *testing.T) {
	d := open(t)
	n := d.AuditCount()
	for _, r := range []AllowRule{{Host: ""}, {Host: "Deb.Debian.org", Prefixes: []string{"/"}}, {Host: "a.org", Prefixes: []string{"debian/"}}} {
		if _, err := d.PutAllowRule("adm", r); err == nil {
			t.Errorf("%+v accepted", r)
		}
	}
	if d.AuditCount() != n {
		t.Fatal("a refused change wrote the audit log")
	}
}
