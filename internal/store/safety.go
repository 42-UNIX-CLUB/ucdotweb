package store

// The safety automation's part of the database: abuse reports filed by administrators, and
// the read queries the watcher (internal/safety) needs. The reports table is created by
// EnsureSafety, which is safe to call any number of times.

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

const safetySchema = `
CREATE TABLE IF NOT EXISTS reports (
	id       INTEGER PRIMARY KEY AUTOINCREMENT,
	at       INTEGER NOT NULL,
	actor    TEXT NOT NULL,
	severity TEXT NOT NULL,
	subject  TEXT NOT NULL DEFAULT '',
	source   TEXT NOT NULL DEFAULT '',
	summary  TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS reports_at ON reports(at);
CREATE INDEX IF NOT EXISTS usage_day ON usage(day);
`

// EnsureSafety creates the reports table and the indexes the watcher reads by. Idempotent.
func (d *DB) EnsureSafety() error {
	if _, err := d.sql.Exec(safetySchema); err != nil {
		return fmt.Errorf("store: safety schema: %w", err)
	}
	return nil
}

// ReportSeverities are the severities a report may have, mildest first. A critical report
// suspends the configured service at once.
var ReportSeverities = []string{"low", "medium", "high", "critical"}

// ReportSeverityValid says whether s is one of ReportSeverities.
func ReportSeverityValid(s string) bool {
	for _, v := range ReportSeverities {
		if v == s {
			return true
		}
	}
	return false
}

// Report is one abuse report, entered by an administrator.
type Report struct {
	ID       int64
	At       time.Time
	Actor    string // the administrator who filed it (pseudonymous subject)
	Severity string
	Subject  string // the user it is about, if known (pseudonymous subject), or empty
	Source   string // where it came from, for example "host provider"
	Summary  string
}

// AddReport stores a report and writes the audit log in the same transaction. The summary
// stays out of the audit log: the audit log cannot be edited, the reports table can.
func (d *DB) AddReport(actor string, r Report) (int64, error) {
	if !ReportSeverityValid(r.Severity) {
		return 0, fmt.Errorf("store: unknown severity %q", r.Severity)
	}
	tx, err := d.sql.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	now := d.now().Unix()
	res, err := tx.Exec(`INSERT INTO reports (at, actor, severity, subject, source, summary) VALUES (?, ?, ?, ?, ?, ?)`,
		now, actor, r.Severity, r.Subject, r.Source, r.Summary)
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	if _, err := tx.Exec(`INSERT INTO audit (at, actor, action, target, detail) VALUES (?, ?, 'file report', ?, ?)`,
		now, actor, fmt.Sprintf("report %d", id), fmt.Sprintf("severity %s, about %q, source %q", r.Severity, r.Subject, r.Source)); err != nil {
		return 0, err
	}
	return id, tx.Commit()
}

func scanReports(rows *sql.Rows) ([]Report, error) {
	defer rows.Close()
	out := []Report{}
	for rows.Next() {
		var r Report
		var at int64
		if err := rows.Scan(&r.ID, &at, &r.Actor, &r.Severity, &r.Subject, &r.Source, &r.Summary); err != nil {
			return nil, err
		}
		r.At = time.Unix(at, 0)
		out = append(out, r)
	}
	return out, rows.Err()
}

// Reports returns reports with an id below before (0 for the newest), newest first.
func (d *DB) Reports(before int64, limit int) ([]Report, error) {
	if before <= 0 {
		before = 1 << 62
	}
	rows, err := d.sql.Query(`SELECT id, at, actor, severity, subject, source, summary FROM reports
		WHERE id < ? ORDER BY id DESC LIMIT ?`, before, limit)
	if err != nil {
		return nil, err
	}
	return scanReports(rows)
}

// CriticalReportsAfter returns the critical reports filed strictly after t, oldest first.
func (d *DB) CriticalReportsAfter(t time.Time) ([]Report, error) {
	after := int64(-1)
	if !t.IsZero() {
		after = t.Unix()
	}
	rows, err := d.sql.Query(`SELECT id, at, actor, severity, subject, source, summary FROM reports
		WHERE severity = 'critical' AND at > ? ORDER BY id`, after)
	if err != nil {
		return nil, err
	}
	return scanReports(rows)
}

// LimitSubjects returns the distinct users with a connection log line at or after since whose
// outcome is one of exact, or ends with one of suffixes. Sorted. Only lines of the given kinds
// ("relay", "proxy") count; no kinds means every kind.
func (d *DB) LimitSubjects(since time.Time, kinds, exact, suffixes []string) ([]string, error) {
	var cond []string
	args := []any{since.Unix()}
	for _, e := range exact {
		cond = append(cond, "outcome = ?")
		args = append(args, e)
	}
	for _, s := range suffixes {
		cond = append(cond, `outcome LIKE ? ESCAPE '\'`)
		args = append(args, "%"+likeEscape(s))
	}
	if len(cond) == 0 {
		return []string{}, nil
	}
	kindCond, kindArgs := kindsIn(kinds)
	rows, err := d.sql.Query(`SELECT DISTINCT subject FROM conn_log WHERE at >= ? AND (`+
		strings.Join(cond, " OR ")+`)`+kindCond+` ORDER BY subject`, append(args, kindArgs...)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// kindsIn is the SQL condition " AND kind IN (?, ...)" and its arguments; empty for no kinds.
func kindsIn(kinds []string) (string, []any) {
	if len(kinds) == 0 {
		return "", nil
	}
	args := make([]any, len(kinds))
	for i, k := range kinds {
		args[i] = k
	}
	return " AND kind IN (?" + strings.Repeat(", ?", len(kinds)-1) + ")", args
}

func likeEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

// TrafficByDay returns the bytes added up per day, for the days from from to to (inclusive),
// for the given kinds of usage ("relay", "proxy", "bundle"), or for every kind when kinds is
// empty.
func (d *DB) TrafficByDay(kinds []string, from, to string) (map[string]int64, error) {
	kindCond, kindArgs := kindsIn(kinds)
	rows, err := d.sql.Query(`SELECT day, sum(bytes) FROM usage WHERE day >= ? AND day <= ?`+kindCond+` GROUP BY day`,
		append([]any{from, to}, kindArgs...)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var day string
		var b int64
		if err := rows.Scan(&day, &b); err != nil {
			return nil, err
		}
		out[day] = b
	}
	return out, rows.Err()
}

// FirstUsageDay returns the oldest day with any usage row; ok is false when there is none.
func (d *DB) FirstUsageDay() (day string, ok bool, err error) {
	var v sql.NullString
	if err := d.sql.QueryRow(`SELECT min(day) FROM usage`).Scan(&v); err != nil {
		return "", false, err
	}
	return v.String, v.Valid, nil
}

// SafetyFlag reads one panic switch with who set it and when; set is false when it was
// never set.
func (d *DB) SafetyFlag(name string) (f FlagRow, set bool, err error) {
	var on int
	var at int64
	err = d.sql.QueryRow(`SELECT name, on_, at, by FROM flags WHERE name = ?`, name).Scan(&f.Name, &on, &at, &f.By)
	if errors.Is(err, sql.ErrNoRows) {
		return FlagRow{Name: name}, false, nil
	}
	if err != nil {
		return f, false, err
	}
	f.On, f.At = on != 0, time.Unix(at, 0)
	return f, true, nil
}

// SafetyAudit writes one audit entry for the safety automation (for example why it tripped).
func (d *DB) SafetyAudit(actor, action, target, detail string) error {
	_, err := d.sql.Exec(`INSERT INTO audit (at, actor, action, target, detail) VALUES (?, ?, ?, ?, ?)`,
		d.now().Unix(), actor, action, target, detail)
	return err
}
