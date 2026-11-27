package safety

import (
	"context"
	"io"
	"log"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/42-UNIX-CLUB/ucdotweb/internal/store"
)

// fakeNotifier records what it was asked to send.
type fakeNotifier struct {
	mu   sync.Mutex
	msgs []string
	err  error
}

func (f *fakeNotifier) Name() string { return "fake" }

func (f *fakeNotifier) Notify(_ context.Context, subject, text string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.msgs = append(f.msgs, subject+"\n"+text)
	return f.err
}

func (f *fakeNotifier) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.msgs)
}

type rig struct {
	db  *store.DB
	w   *Watcher
	n   *fakeNotifier
	now time.Time
}

func newRig(t *testing.T, cfg Config) *rig {
	t.Helper()
	db, err := store.Open(t.TempDir()+"/s.db", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	r := &rig{db: db, n: &fakeNotifier{}, now: time.Now().Truncate(time.Second)}
	w, err := New(db, cfg, r.n, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	w.now = func() time.Time { return r.now }
	r.w = w
	return r
}

// conn writes a connection log line at an exact time.
func (r *rig) conn(t *testing.T, at time.Time, subject, outcome string) {
	t.Helper()
	if err := r.db.Exec(`INSERT INTO conn_log VALUES (?, ?, 'relay', 'example.com', 0, ?)`, at.Unix(), subject, outcome); err != nil {
		t.Fatal(err)
	}
}

// usage writes a day's bytes for one user.
func (r *rig) usage(t *testing.T, daysAgo int, bytes int64) {
	t.Helper()
	if err := r.db.Exec(`INSERT INTO usage VALUES ('u', ?, 'relay', ?, 0)
		ON CONFLICT(subject, day, kind) DO UPDATE SET bytes = bytes + excluded.bytes`,
		store.Day(r.now.AddDate(0, 0, -daysAgo)), bytes); err != nil {
		t.Fatal(err)
	}
}

// lift turns the switch off as an administrator at an exact time.
func (r *rig) lift(t *testing.T, at time.Time) {
	t.Helper()
	if err := r.db.Exec(`INSERT OR REPLACE INTO flags VALUES ('relay_off', 0, ?, 'admin-subject')`, at.Unix()); err != nil {
		t.Fatal(err)
	}
}

func (r *rig) safetyFlagEntries(t *testing.T) int {
	t.Helper()
	var n int
	if err := r.db.QueryRow(`SELECT count(*) FROM audit WHERE actor = 'safety' AND action = 'flag'`, &n); err != nil {
		t.Fatal(err)
	}
	return n
}

func check(t *testing.T, s Status, name string) CheckResult {
	t.Helper()
	for _, c := range s.Checks {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no check %q in %+v", name, s.Checks)
	return CheckResult{}
}

func TestLimitsTripAtThreeUsers(t *testing.T) {
	r := newRig(t, DefaultConfig())
	r.conn(t, r.now.Add(-time.Minute), "a", "too many destinations")
	r.conn(t, r.now.Add(-time.Minute), "a", "too many connections") // same user twice counts once
	r.conn(t, r.now.Add(-2*time.Minute), "b", "200 cut at quota")
	r.conn(t, r.now.Add(-11*time.Minute), "c", "daily quota") // outside the window
	r.conn(t, r.now.Add(-time.Minute), "d", "not allowed")    // not a limit
	r.conn(t, r.now.Add(-time.Minute), "e", "200")
	s := r.w.Check(t.Context())
	if s.Suspended || r.db.Flag("relay_off") || r.n.count() != 0 {
		t.Fatalf("tripped with two users: %+v", s)
	}
	if c := check(t, s, "limits"); c.Tripped || !strings.HasPrefix(c.Detail, "2 users") {
		t.Fatalf("limits: %+v", c)
	}
	r.conn(t, r.now.Add(-30*time.Second), "c", "rate limited")
	s = r.w.Check(t.Context())
	if !s.Suspended || !r.db.Flag("relay_off") || s.SuspendedBy != Actor {
		t.Fatalf("not suspended with three users: %+v", s)
	}
	if r.db.Flag("proxy_off") || r.db.Flag("all_off") {
		t.Fatal("the default suspension must touch relay_off only")
	}
	if r.safetyFlagEntries(t) != 1 {
		t.Fatal("the switch must be set through store.SetFlag with actor safety")
	}
	if r.n.count() != 1 {
		t.Fatalf("notifications: %d, want 1", r.n.count())
	}
	msg := r.n.msgs[0]
	for _, want := range []string{"relay", "relay_off", "3 users", "a, b, c", "administrator"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("message lacks %q: %s", want, msg)
		}
	}
	if strings.ContainsAny(msg, "\u2014\u2013") {
		t.Fatalf("message has a dash it must not have: %s", msg)
	}
	if s.LastTrip == nil || s.LastTrip.Switch != "relay_off" || len(s.LastTrip.Reasons) != 1 {
		t.Fatalf("last trip: %+v", s.LastTrip)
	}
	var reason string
	if err := r.db.QueryRow(`SELECT detail FROM audit WHERE action = 'safety trip'`, &reason); err != nil || !strings.Contains(reason, "3 users") {
		t.Fatalf("trip reason in the audit log: %q %v", reason, err)
	}
}

func TestNoRenotifyWhileOn(t *testing.T) {
	r := newRig(t, DefaultConfig())
	for _, u := range []string{"a", "b", "c"} {
		r.conn(t, r.now.Add(-time.Minute), u, "daily quota")
	}
	r.w.Check(t.Context())
	for i := 0; i < 10; i++ {
		r.now = r.now.Add(time.Minute)
		r.conn(t, r.now, "x", "daily quota") // more evidence keeps coming
		r.w.Check(t.Context())
	}
	if r.n.count() != 1 || r.safetyFlagEntries(t) != 1 {
		t.Fatalf("notified %d times, set %d times; want once each", r.n.count(), r.safetyFlagEntries(t))
	}
}

func TestNeverLifts(t *testing.T) {
	r := newRig(t, DefaultConfig())
	for _, u := range []string{"a", "b", "c"} {
		r.conn(t, r.now.Add(-time.Minute), u, "daily quota")
	}
	r.w.Check(t.Context())
	// the evidence ages out of the window: the switch stays on
	r.now = r.now.Add(48 * time.Hour)
	s := r.w.Check(t.Context())
	if !s.Suspended || !r.db.Flag("relay_off") {
		t.Fatal("the watcher lifted a suspension")
	}
	if c := check(t, s, "limits"); c.Tripped {
		t.Fatalf("old evidence still counted: %+v", c)
	}
	// a switch an administrator turned on stays on too, and the watcher does not notify for it
	r2 := newRig(t, DefaultConfig())
	if err := r2.db.SetFlag("admin-subject", "relay_off", true); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		r2.now = r2.now.Add(time.Hour)
		r2.w.Check(t.Context())
	}
	f, _, _ := r2.db.SafetyFlag("relay_off")
	if !f.On || f.By != "admin-subject" || r2.n.count() != 0 {
		t.Fatalf("admin switch: %+v, notifications %d", f, r2.n.count())
	}
	var offs int
	_ = r.db.QueryRow(`SELECT count(*) FROM audit WHERE actor = 'safety' AND detail = 'false'`, &offs)
	if offs != 0 {
		t.Fatal("the watcher wrote a switch-off")
	}
}

func TestAfterLiftOnlyNewEvidence(t *testing.T) {
	r := newRig(t, DefaultConfig())
	for _, u := range []string{"a", "b", "c"} {
		r.conn(t, r.now.Add(-time.Minute), u, "daily quota")
	}
	r.w.Check(t.Context())
	r.now = r.now.Add(time.Minute)
	r.lift(t, r.now)
	r.conn(t, r.now, "d", "daily quota") // same second as the lift: excluded
	s := r.w.Check(t.Context())
	if s.Suspended || r.db.Flag("relay_off") {
		t.Fatalf("suspended again on the evidence the administrator already saw: %+v", s)
	}
	if s.ArmedSince != r.now.Unix() {
		t.Fatalf("armed since %d, want %d", s.ArmedSince, r.now.Unix())
	}
	r.now = r.now.Add(2 * time.Minute)
	for _, u := range []string{"a", "b"} {
		r.conn(t, r.now, u, "daily quota")
	}
	if s := r.w.Check(t.Context()); s.Suspended {
		t.Fatal("two new users after the lift tripped")
	}
	r.conn(t, r.now, "e", "too many connections")
	if s := r.w.Check(t.Context()); !s.Suspended {
		t.Fatal("three new users after the lift did not trip")
	}
	if r.n.count() != 2 {
		t.Fatalf("notifications %d, want 2 (one per suspension)", r.n.count())
	}
}

func TestTrafficNoHistory(t *testing.T) {
	r := newRig(t, DefaultConfig())
	s := r.w.Check(t.Context())
	if c := check(t, s, "traffic"); c.Tripped || !strings.HasPrefix(c.Detail, "skipped") {
		t.Fatalf("empty database: %+v", c)
	}
	r.usage(t, 0, 500_000_000_000) // a huge first day
	r.usage(t, 3, 1)               // and history of only 3 days
	s = r.w.Check(t.Context())
	if c := check(t, s, "traffic"); c.Tripped || s.Suspended || !strings.Contains(c.Detail, "less than 7 days") {
		t.Fatalf("short history tripped: %+v", c)
	}
}

func TestTrafficFarAboveNorm(t *testing.T) {
	r := newRig(t, DefaultConfig())
	for d := 1; d <= 7; d++ {
		r.usage(t, d, 2_000_000_000) // 2 GB a day: average 2 GB
	}
	r.usage(t, 30, 1) // older rows do not count in the average
	r.usage(t, 0, 9_000_000_000)
	s := r.w.Check(t.Context())
	if c := check(t, s, "traffic"); c.Tripped {
		t.Fatalf("4.5 times the norm tripped (factor 5): %+v", c)
	}
	r.usage(t, 0, 2_000_000_000) // 11 GB: above 5 times 2 GB and above the 10 GB floor
	s = r.w.Check(t.Context())
	if c := check(t, s, "traffic"); !c.Tripped || !s.Suspended || r.n.count() != 1 {
		t.Fatalf("11 GB against a 2 GB norm did not trip: %+v", c)
	}
	if !strings.Contains(r.n.msgs[0], "traffic far above the 7-day norm") {
		t.Fatalf("message: %s", r.n.msgs[0])
	}
}

func TestTrafficFloor(t *testing.T) {
	r := newRig(t, DefaultConfig())
	r.usage(t, 7, 1)             // history exists, the norm is almost zero
	r.usage(t, 0, 9_999_999_999) // far above the norm, just under the floor
	if s := r.w.Check(t.Context()); s.Suspended {
		t.Fatal("tripped under the floor")
	}
	cfg := DefaultConfig()
	cfg.TrafficFloor = 1_000_000
	r2 := newRig(t, cfg)
	r2.usage(t, 7, 1)
	r2.usage(t, 0, 2_000_000)
	if s := r2.w.Check(t.Context()); !s.Suspended {
		t.Fatal("did not trip above a lowered floor")
	}
}

func TestTrafficSkippedOnLiftDay(t *testing.T) {
	r := newRig(t, DefaultConfig())
	r.usage(t, 7, 1)
	r.usage(t, 0, 20_000_000_000)
	r.w.Check(t.Context())
	r.now = r.now.Add(time.Second)
	r.lift(t, r.now)
	r.now = r.now.Add(time.Minute)
	if s := r.w.Check(t.Context()); s.Suspended {
		t.Fatal("the same day's traffic suspended again after the lift")
	}
}

func TestCriticalReport(t *testing.T) {
	r := newRig(t, DefaultConfig())
	for _, sev := range []string{"low", "medium", "high"} {
		if _, err := r.db.AddReport("admin-subject", store.Report{Severity: sev, Summary: "x"}); err != nil {
			t.Fatal(err)
		}
	}
	if s := r.w.Check(t.Context()); s.Suspended {
		t.Fatal("a non-critical report suspended")
	}
	if _, err := r.db.AddReport("admin-subject", store.Report{Severity: "bad", Summary: "x"}); err == nil {
		t.Fatal("unknown severity stored")
	}
	id, err := r.db.AddReport("admin-subject", store.Report{Severity: "critical", Subject: "user-7",
		Source: "host provider", Summary: "complaint about scanning"})
	if err != nil {
		t.Fatal(err)
	}
	s := r.w.Check(t.Context())
	if !s.Suspended || r.n.count() != 1 {
		t.Fatalf("critical report did not suspend: %+v", s)
	}
	if strings.Contains(r.n.msgs[0], "complaint") || !strings.Contains(r.n.msgs[0], "report") {
		t.Fatalf("the summary must stay out of notifications: %s", r.n.msgs[0])
	}
	var detail string
	if err := r.db.QueryRow(`SELECT detail FROM audit WHERE action = 'file report' ORDER BY id DESC LIMIT 1`, &detail); err != nil ||
		!strings.Contains(detail, "critical") || strings.Contains(detail, "complaint") {
		t.Fatalf("report audit: %q %v", detail, err)
	}
	// after a lift (a second later), that report no longer counts
	r.now = time.Now().Add(time.Second).Truncate(time.Second)
	r.lift(t, r.now)
	r.now = r.now.Add(time.Second)
	if s := r.w.Check(t.Context()); s.Suspended {
		t.Fatalf("report %d suspended again after the lift", id)
	}
	rs, err := r.db.Reports(0, 10)
	if err != nil || len(rs) != 4 || rs[0].ID != id || rs[0].Subject != "user-7" {
		t.Fatalf("reports: %+v %v", rs, err)
	}
}

func TestNotifyErrorShownOnce(t *testing.T) {
	r := newRig(t, DefaultConfig())
	r.n.err = io.ErrUnexpectedEOF
	if _, err := r.db.AddReport("a", store.Report{Severity: "critical", Summary: "x"}); err != nil {
		t.Fatal(err)
	}
	s := r.w.Check(t.Context())
	if !s.Suspended || !strings.Contains(s.LastNotifyError, "unexpected EOF") {
		t.Fatalf("status: %+v", s)
	}
	r.w.Check(t.Context())
	if r.n.count() != 1 {
		t.Fatal("a failed notification is retried every pass")
	}
}

func TestConfigurableSwitch(t *testing.T) {
	cfg, err := ConfigFromEnv(func(k string) string {
		return map[string]string{"UCDOTWEB_SAFETY_SWITCH": "all_off", "UCDOTWEB_SAFETY_INTERVAL": "30s",
			"UCDOTWEB_SAFETY_TRAFFIC_FACTOR": "3", "UCDOTWEB_SAFETY_TRAFFIC_FLOOR": "123"}[k]
	})
	if err != nil || cfg.Switch != "all_off" || cfg.Interval != 30*time.Second || cfg.TrafficFactor != 3 || cfg.TrafficFloor != 123 {
		t.Fatalf("config %+v %v", cfg, err)
	}
	r := newRig(t, cfg)
	if _, err := r.db.AddReport("a", store.Report{Severity: "critical", Summary: "x"}); err != nil {
		t.Fatal(err)
	}
	if s := r.w.Check(t.Context()); !s.Suspended || !r.db.Flag("all_off") || r.db.Flag("relay_off") {
		t.Fatalf("all_off suspension: %+v", s)
	}
	for _, bad := range []map[string]string{{"UCDOTWEB_SAFETY_SWITCH": "signin_off"}, {"UCDOTWEB_SAFETY_INTERVAL": "10ms"},
		{"UCDOTWEB_SAFETY_TRAFFIC_FACTOR": "0.5"}, {"UCDOTWEB_SAFETY_TRAFFIC_FLOOR": "x"}} {
		if _, err := ConfigFromEnv(func(k string) string { return bad[k] }); err == nil {
			t.Fatalf("accepted %v", bad)
		}
	}
	d, err := ConfigFromEnv(func(string) string { return "" })
	if err != nil || d.Switch != "relay_off" || d.MinUsers != 3 || d.Window != 10*time.Minute {
		t.Fatalf("defaults %+v %v", d, err)
	}
}

func TestRunStopsAndChecks(t *testing.T) {
	r := newRig(t, DefaultConfig())
	r.w.cfg.Interval = 5 * time.Millisecond
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { r.w.Run(ctx); close(done) }()
	deadline := time.Now().Add(2 * time.Second)
	for r.w.Status().LastRun == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop")
	}
	s := r.w.Status()
	if s.LastRun == 0 || len(s.Checks) != 3 || s.LastError != "" {
		t.Fatalf("status after Run: %+v", s)
	}
}

func TestTrafficCountsOnlyTheSwitchedService(t *testing.T) {
	r := newRig(t, DefaultConfig()) // relay_off: only relay traffic counts
	for d := 1; d <= 7; d++ {
		r.usage(t, d, 2_000_000_000)
	}
	if err := r.db.Exec(`INSERT INTO usage VALUES ('u', ?, 'proxy', 50000000000, 0)`, store.Day(r.now)); err != nil {
		t.Fatal(err)
	}
	s := r.w.Check(t.Context())
	if c := check(t, s, "traffic"); c.Tripped || s.Suspended {
		t.Fatalf("a proxy surge suspended the relay: %+v", c)
	}
	cfg := DefaultConfig()
	cfg.Switch = "all_off" // every service counts
	r2 := newRig(t, cfg)
	for d := 1; d <= 7; d++ {
		r2.usage(t, d, 2_000_000_000)
	}
	if err := r2.db.Exec(`INSERT INTO usage VALUES ('u', ?, 'proxy', 50000000000, 0)`, store.Day(r2.now)); err != nil {
		t.Fatal(err)
	}
	if c := check(t, r2.w.Check(t.Context()), "traffic"); !c.Tripped {
		t.Fatalf("all_off: a 50 GB proxy day did not trip: %+v", c)
	}
}

// connKind writes a connection log line of one kind ("relay" or "proxy").
func (r *rig) connKind(t *testing.T, at time.Time, subject, kind, outcome string) {
	t.Helper()
	if err := r.db.LogConn(subject, kind, "example.com", 0, outcome); err != nil {
		t.Fatal(err)
	}
	if err := r.db.Exec(`UPDATE conn_log SET at = ? WHERE subject = ? AND kind = ?`, at.Unix(), subject, kind); err != nil {
		t.Fatal(err)
	}
}

// The limit check counts only trips of the service the switch stops (owner, 2026-11-27).
func TestLimitsCountOnlyTheSwitchedService(t *testing.T) {
	at := func(r *rig) time.Time { return r.now.Add(-time.Minute) }

	// relay_off: three relay users still suspend the relay
	r := newRig(t, DefaultConfig())
	for _, u := range []string{"a", "b", "c"} {
		r.connKind(t, at(r), u, "relay", "too many destinations")
	}
	if s := r.w.Check(t.Context()); !s.Suspended || !r.db.Flag("relay_off") {
		t.Fatalf("three relay users did not suspend the relay: %+v", s)
	}

	// relay_off: two relay users and one proxy user are two
	r = newRig(t, DefaultConfig())
	r.connKind(t, at(r), "a", "relay", "rate limited")
	r.connKind(t, at(r), "b", "relay", "daily quota")
	r.connKind(t, at(r), "c", "proxy", "rate limited")
	s := r.w.Check(t.Context())
	if c := check(t, s, "limits"); c.Tripped || s.Suspended || !strings.HasPrefix(c.Detail, "2 users hit a relay limit") {
		t.Fatalf("a proxy trip counted for the relay: %+v", c)
	}

	// proxy_off: proxy trips count, relay trips do not
	cfg := DefaultConfig()
	cfg.Switch = "proxy_off"
	r = newRig(t, cfg)
	for _, u := range []string{"a", "b", "c"} {
		r.connKind(t, at(r), u, "relay", "too many connections")
	}
	if s := r.w.Check(t.Context()); s.Suspended || r.db.Flag("proxy_off") {
		t.Fatalf("relay trips suspended the proxy: %+v", s)
	}
	for _, u := range []string{"d", "e", "f"} {
		r.connKind(t, at(r), u, "proxy", "200 cut at quota")
	}
	if s := r.w.Check(t.Context()); !s.Suspended || !r.db.Flag("proxy_off") || r.db.Flag("relay_off") {
		t.Fatalf("three proxy users did not suspend the proxy: %+v", s)
	}

	// all_off: both services count together
	cfg.Switch = "all_off"
	r = newRig(t, cfg)
	r.connKind(t, at(r), "a", "relay", "rate limited")
	r.connKind(t, at(r), "b", "proxy", "rate limited")
	r.connKind(t, at(r), "c", "proxy", "daily quota")
	if s := r.w.Check(t.Context()); !s.Suspended || !r.db.Flag("all_off") {
		t.Fatalf("all_off: three users across both services did not suspend: %+v", s)
	}
}

// No switch stops bundles, so bundle traffic never trips the traffic check, even for all_off.
func TestTrafficIgnoresBundles(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Switch = "all_off"
	r := newRig(t, cfg)
	for d := 1; d <= 7; d++ {
		r.usage(t, d, 2_000_000_000)
	}
	if err := r.db.Exec(`INSERT INTO usage VALUES ('u', ?, 'bundle', 50000000000, 0)`, store.Day(r.now)); err != nil {
		t.Fatal(err)
	}
	if c := check(t, r.w.Check(t.Context()), "traffic"); c.Tripped {
		t.Fatalf("a bundle surge tripped the traffic check: %+v", c)
	}
}
