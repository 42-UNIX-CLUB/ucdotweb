// Package safety is the automatic global suspension the owners decided: "automatic global
// suspension on three or more users tripping limits within 10 minutes, traffic far above the
// 7-day norm, or a critical abuse report; lifted only by an administrator; e-mail plus a club
// chat webhook".
//
// A Watcher runs the three checks on a timer. When one trips and the configured switch is
// off, it turns the switch on as actor "safety" (audited by store.SetFlag) and notifies.
// It never turns a switch off. While the switch is on it does nothing more, so it does not
// notify again. Once an administrator lifts the switch, only evidence newer than the lift
// counts, so the same evidence cannot suspend again.
package safety

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/42-UNIX-CLUB/ucdotweb/internal/store"
)

// Actor is the name the watcher writes in the audit log and the flags table.
const Actor = "safety"

// Switches are the panic switches a suspension may turn on.
var Switches = []string{"relay_off", "proxy_off", "all_off"}

// Config holds the thresholds. DefaultConfig gives the decided and the assumed values.
type Config struct {
	Switch   string        // the panic switch a suspension turns on
	Interval time.Duration // time between passes

	// Check (a): MinUsers distinct users with a limit outcome within Window (decided: 3, 10 min).
	MinUsers      int
	Window        time.Duration
	LimitOutcomes []string // connection log outcomes that mean a limit was hit, exactly
	LimitSuffixes []string // and outcomes that end with one of these

	// Check (b): today's bytes above TrafficFactor times the daily average of the previous
	// 7 days, and at least TrafficFloor bytes. Skipped until the oldest usage row is at
	// least HistoryDays old.
	TrafficFactor float64
	TrafficFloor  int64
	HistoryDays   int
}

// The outcomes the proxy and the relay log, or should log, when a user hits a limit.
var (
	// DefaultLimitOutcomes: the relay logs the first four today; "rate limited" and the
	// proxy's and the relay upgrade's "daily quota" are proposed for the call sites that
	// refuse without logging yet.
	DefaultLimitOutcomes = []string{"too many connections", "too many destinations", "daily quota",
		"cut at daily quota", "rate limited"}
	// DefaultLimitSuffixes: the proxy logs "{status} cut at quota" when a download stops at the quota.
	DefaultLimitSuffixes = []string{" cut at quota"}
)

// DefaultConfig returns the decided values (3 users, 10 minutes) and the assumed ones
// (relay_off, 1-minute passes, 5 times the norm, a 10 GB floor, 7 days of history).
func DefaultConfig() Config {
	return Config{
		Switch:        "relay_off",
		Interval:      time.Minute,
		MinUsers:      3,
		Window:        10 * time.Minute,
		LimitOutcomes: DefaultLimitOutcomes,
		LimitSuffixes: DefaultLimitSuffixes,
		TrafficFactor: 5,
		TrafficFloor:  10_000_000_000,
		HistoryDays:   7,
	}
}

// ConfigFromEnv starts from DefaultConfig and applies these optional variables:
//
//	UCDOTWEB_SAFETY_SWITCH          relay_off (default), proxy_off or all_off
//	UCDOTWEB_SAFETY_INTERVAL        time between passes, a Go duration (default 1m)
//	UCDOTWEB_SAFETY_TRAFFIC_FACTOR  how many times the 7-day daily average counts as far above (default 5)
//	UCDOTWEB_SAFETY_TRAFFIC_FLOOR   bytes today below which traffic never trips (default 10000000000)
func ConfigFromEnv(getenv func(string) string) (Config, error) {
	c := DefaultConfig()
	if v := getenv("UCDOTWEB_SAFETY_SWITCH"); v != "" {
		c.Switch = v
	}
	if v := getenv("UCDOTWEB_SAFETY_INTERVAL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return c, fmt.Errorf("UCDOTWEB_SAFETY_INTERVAL: %v", err)
		}
		c.Interval = d
	}
	if v := getenv("UCDOTWEB_SAFETY_TRAFFIC_FACTOR"); v != "" {
		f, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return c, fmt.Errorf("UCDOTWEB_SAFETY_TRAFFIC_FACTOR: %v", err)
		}
		c.TrafficFactor = f
	}
	if v := getenv("UCDOTWEB_SAFETY_TRAFFIC_FLOOR"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return c, fmt.Errorf("UCDOTWEB_SAFETY_TRAFFIC_FLOOR: %v", err)
		}
		c.TrafficFloor = n
	}
	return c, c.validate()
}

func (c Config) validate() error {
	known := false
	for _, s := range Switches {
		known = known || s == c.Switch
	}
	switch {
	case !known:
		return fmt.Errorf("safety: unknown switch %q (want relay_off, proxy_off or all_off)", c.Switch)
	case c.Interval < time.Second:
		return errors.New("safety: the interval must be at least one second")
	case c.MinUsers < 1 || c.Window <= 0:
		return errors.New("safety: the limit check needs at least one user and a window")
	case c.TrafficFactor < 1:
		return errors.New("safety: the traffic factor must be at least 1")
	case c.TrafficFloor < 0 || c.HistoryDays < 1:
		return errors.New("safety: the traffic floor cannot be negative and history needs a day")
	}
	return nil
}

// CheckResult is the outcome of one check in one pass.
type CheckResult struct {
	Name    string `json:"name"` // "limits", "traffic" or "reports"
	Tripped bool   `json:"tripped"`
	Detail  string `json:"detail"`
}

// Trip records one suspension made by the watcher.
type Trip struct {
	At      int64    `json:"at"`
	Switch  string   `json:"switch"`
	Reasons []string `json:"reasons"`
}

// Status is what the admin API shows. Times are Unix seconds, 0 for never.
type Status struct {
	Switch          string        `json:"switch"`
	Suspended       bool          `json:"suspended"`
	SuspendedBy     string        `json:"suspended_by,omitempty"`
	SuspendedAt     int64         `json:"suspended_at,omitempty"`
	ArmedSince      int64         `json:"armed_since"` // evidence before this does not count (the last lift)
	LastRun         int64         `json:"last_run"`
	Checks          []CheckResult `json:"checks"`
	LastTrip        *Trip         `json:"last_trip,omitempty"`
	LastError       string        `json:"last_error,omitempty"`
	LastNotifyError string        `json:"last_notify_error,omitempty"`
	Notifiers       []string      `json:"notifiers"`
	Config          StatusConfig  `json:"config"`
}

// StatusConfig is the part of Config the admin API shows.
type StatusConfig struct {
	IntervalSeconds int64   `json:"interval_seconds"`
	MinUsers        int     `json:"min_users"`
	WindowSeconds   int64   `json:"window_seconds"`
	TrafficFactor   float64 `json:"traffic_factor"`
	TrafficFloor    int64   `json:"traffic_floor"`
	HistoryDays     int     `json:"history_days"`
}

// Watcher runs the checks.
type Watcher struct {
	db     *store.DB
	cfg    Config
	notify Notifier
	log    *log.Logger
	now    func() time.Time

	pass      sync.Mutex // one pass at a time: a timer pass and a report's pass never overlap
	mu        sync.Mutex // guards status
	status    Status
	setFailed bool // the last attempt to set the switch failed and was already notified
}

// New makes a watcher and creates the reports table if needed. n may be nil (no
// notifications); lg may be nil.
func New(db *store.DB, cfg Config, n Notifier, lg *log.Logger) (*Watcher, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if err := db.EnsureSafety(); err != nil {
		return nil, err
	}
	if lg == nil {
		lg = log.New(os.Stderr, "", 0)
	}
	w := &Watcher{db: db, cfg: cfg, notify: n, log: lg, now: time.Now}
	w.status = Status{Switch: cfg.Switch, Checks: []CheckResult{}, Notifiers: names(n), Config: StatusConfig{
		IntervalSeconds: int64(cfg.Interval / time.Second), MinUsers: cfg.MinUsers,
		WindowSeconds: int64(cfg.Window / time.Second), TrafficFactor: cfg.TrafficFactor,
		TrafficFloor: cfg.TrafficFloor, HistoryDays: cfg.HistoryDays}}
	return w, nil
}

// Run checks at once and then every Interval until ctx ends.
func (w *Watcher) Run(ctx context.Context) {
	t := time.NewTicker(w.cfg.Interval)
	defer t.Stop()
	for {
		w.Check(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Status returns a copy of the last pass's state.
func (w *Watcher) Status() Status {
	w.mu.Lock()
	defer w.mu.Unlock()
	s := w.status
	s.Checks = append([]CheckResult{}, s.Checks...)
	s.Notifiers = append([]string{}, s.Notifiers...)
	if s.LastTrip != nil {
		t := *s.LastTrip
		t.Reasons = append([]string{}, t.Reasons...)
		s.LastTrip = &t
	}
	return s
}

// Check runs one pass: reads the switch, runs the three checks, and suspends and notifies
// if one tripped while the switch is off. It returns the new status.
func (w *Watcher) Check(ctx context.Context) Status {
	w.pass.Lock()
	defer w.pass.Unlock()
	now := w.now()
	var errs []string

	f, set, err := w.db.SafetyFlag(w.cfg.Switch)
	if err != nil {
		w.finish(now, f, time.Time{}, nil, []string{"reading the switch: " + err.Error()}, nil, "")
		return w.Status()
	}
	// The switch was lifted (or set off) at f.At: only newer evidence counts.
	var armed time.Time
	if set && !f.On {
		armed = f.At
	}
	checks := []CheckResult{w.checkLimits(now, armed, &errs), w.checkTraffic(now, armed, &errs), w.checkReports(armed, &errs)}

	if f.On {
		w.setFailed = false
		w.finish(now, f, armed, checks, errs, nil, "")
		return w.Status()
	}
	var reasons []string
	for _, c := range checks {
		if c.Tripped {
			reasons = append(reasons, c.Detail)
		}
	}
	if len(reasons) == 0 {
		w.setFailed = false
		w.finish(now, f, armed, checks, errs, nil, "")
		return w.Status()
	}

	if err := w.db.SetFlag(Actor, w.cfg.Switch, true); err != nil {
		errs = append(errs, "setting the switch: "+err.Error())
		w.log.Printf("safety: could not set %s: %v", w.cfg.Switch, err)
		nerr := ""
		if !w.setFailed { // tell the administrators once, not on every pass
			w.setFailed = true
			nerr = w.send(ctx, "UC.OS safety: suspension FAILED",
				fmt.Sprintf("A safety check tripped but %s could not be turned on. Check the service now.\nReason: %s",
					w.cfg.Switch, strings.Join(reasons, " ")))
		}
		w.finish(now, f, armed, checks, errs, nil, nerr)
		return w.Status()
	}
	w.setFailed = false
	_ = w.db.SafetyAudit(Actor, "safety trip", w.cfg.Switch, strings.Join(reasons, " "))
	w.log.Printf("safety: %s turned on: %s", w.cfg.Switch, strings.Join(reasons, " "))
	f2, _, err := w.db.SafetyFlag(w.cfg.Switch)
	if err != nil {
		f2 = store.FlagRow{Name: w.cfg.Switch, On: true, At: now, By: Actor}
	}
	trip := &Trip{At: now.Unix(), Switch: w.cfg.Switch, Reasons: reasons}
	nerr := w.send(ctx, "UC.OS safety: "+what(w.cfg.Switch)+" suspended", message(w.cfg.Switch, now, reasons))
	w.finish(now, f2, armed, checks, errs, trip, nerr)
	return w.Status()
}

func (w *Watcher) send(ctx context.Context, subject, text string) string {
	if w.notify == nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	if err := w.notify.Notify(ctx, subject, text); err != nil {
		w.log.Printf("safety: notification failed: %v", err)
		return err.Error()
	}
	return ""
}

func (w *Watcher) finish(now time.Time, f store.FlagRow, armed time.Time, checks []CheckResult, errs []string, trip *Trip, notifyErr string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	s := &w.status
	s.LastRun = now.Unix()
	s.Suspended = f.On
	s.SuspendedBy, s.SuspendedAt = "", 0
	if f.On {
		s.SuspendedBy, s.SuspendedAt = f.By, f.At.Unix()
	}
	s.ArmedSince = 0
	if !armed.IsZero() {
		s.ArmedSince = armed.Unix()
	}
	if checks == nil {
		checks = []CheckResult{}
	}
	s.Checks = checks
	s.LastError = strings.Join(errs, "; ")
	if trip != nil {
		s.LastTrip = trip
	}
	if trip != nil || notifyErr != "" {
		s.LastNotifyError = notifyErr
	}
}

// checkLimits is check (a): distinct users with a limit outcome in the window, after the lift.
// Only limits of the service the switch stops count, as for traffic: three users at the
// proxy's rate limit do not suspend the relay (owner, 2026-11-27).
func (w *Watcher) checkLimits(now, armed time.Time, errs *[]string) CheckResult {
	c := CheckResult{Name: "limits"}
	since := now.Add(-w.cfg.Window)
	if !armed.IsZero() && !armed.Add(time.Second).Before(since) {
		since = armed.Add(time.Second) // log times are whole seconds: the lift's second is excluded
	}
	subs, err := w.db.LimitSubjects(since, switchKinds(w.cfg.Switch), w.cfg.LimitOutcomes, w.cfg.LimitSuffixes)
	if err != nil {
		*errs = append(*errs, "limits: "+err.Error())
		c.Detail = "could not read the connection log"
		return c
	}
	c.Tripped = len(subs) >= w.cfg.MinUsers
	c.Detail = fmt.Sprintf("%d users hit a %s limit in the last %s (threshold %d)", len(subs), strings.Join(switchKinds(w.cfg.Switch), " or "), minutes(w.cfg.Window), w.cfg.MinUsers)
	if c.Tripped {
		c.Detail += ": " + strings.Join(subs, ", ") + "."
	}
	return c
}

// switchKinds are the kinds of usage and connection log lines that both checks (a) and (b)
// read: those of the services the switch stops, so trouble on one service never suspends
// another (owner, 2026-11-26 for traffic, 2026-11-27 for limits). all_off stops the relay
// and the proxy. No switch stops device-transfer bundles, so bundle traffic never counts.
func switchKinds(sw string) []string {
	switch sw {
	case "relay_off":
		return []string{"relay"}
	case "proxy_off":
		return []string{"proxy"}
	}
	return []string{"relay", "proxy"} // all_off
}

// checkTraffic is check (b): today's bytes of the switched service against the previous
// 7 days' daily average.
func (w *Watcher) checkTraffic(now, armed time.Time, errs *[]string) CheckResult {
	c := CheckResult{Name: "traffic"}
	today := store.Day(now)
	if !armed.IsZero() && store.Day(armed) == today {
		c.Detail = "skipped: an administrator lifted a suspension today (UTC)"
		return c
	}
	first, ok, err := w.db.FirstUsageDay()
	if err != nil {
		*errs = append(*errs, "traffic: "+err.Error())
		c.Detail = "could not read the usage"
		return c
	}
	if !ok || first > store.Day(now.AddDate(0, 0, -w.cfg.HistoryDays)) {
		c.Detail = fmt.Sprintf("skipped: less than %d days of history", w.cfg.HistoryDays)
		return c
	}
	days, err := w.db.TrafficByDay(switchKinds(w.cfg.Switch), store.Day(now.AddDate(0, 0, -7)), today)
	if err != nil {
		*errs = append(*errs, "traffic: "+err.Error())
		c.Detail = "could not read the usage"
		return c
	}
	var sum int64
	for d, b := range days {
		if d != today {
			sum += b
		}
	}
	avg := float64(sum) / 7
	cur := days[today]
	c.Tripped = cur >= w.cfg.TrafficFloor && float64(cur) > w.cfg.TrafficFactor*avg
	c.Detail = fmt.Sprintf("%s today, 7-day daily average %s (trips above %g times that and at least %s)",
		size(float64(cur)), size(avg), w.cfg.TrafficFactor, size(float64(w.cfg.TrafficFloor)))
	if c.Tripped {
		c.Detail = "traffic far above the 7-day norm: " + c.Detail + "."
	}
	return c
}

// checkReports is check (c): a critical report filed after the lift.
func (w *Watcher) checkReports(armed time.Time, errs *[]string) CheckResult {
	c := CheckResult{Name: "reports"}
	rs, err := w.db.CriticalReportsAfter(armed)
	if err != nil {
		*errs = append(*errs, "reports: "+err.Error())
		c.Detail = "could not read the reports"
		return c
	}
	if len(rs) == 0 {
		c.Detail = "no critical report since the last lift"
		return c
	}
	c.Tripped = true
	ids := make([]string, len(rs))
	for i, r := range rs {
		ids[i] = strconv.FormatInt(r.ID, 10)
	}
	c.Detail = "critical abuse report " + strings.Join(ids, ", ") + "."
	return c
}

func what(sw string) string {
	switch sw {
	case "relay_off":
		return "relay"
	case "proxy_off":
		return "proxy"
	}
	return "relay and proxy"
}

// message is the notification text: short, plain, pseudonymous ids only.
func message(sw string, at time.Time, reasons []string) string {
	return fmt.Sprintf("The %s was suspended automatically at %s (switch %s).\nReason: %s\n"+
		"It stays off until an administrator lifts it (POST /api/admin/flag). See GET /api/admin/safety.",
		what(sw), at.UTC().Format("2006-01-02 15:04 UTC"), sw, strings.Join(reasons, " "))
}

func minutes(d time.Duration) string {
	if d%time.Minute == 0 {
		return fmt.Sprintf("%d min", int(d/time.Minute))
	}
	return d.String()
}

func size(b float64) string {
	switch {
	case b >= 1e9:
		return fmt.Sprintf("%.1f GB", b/1e9)
	case b >= 1e6:
		return fmt.Sprintf("%.1f MB", b/1e6)
	}
	return fmt.Sprintf("%.0f bytes", b)
}
