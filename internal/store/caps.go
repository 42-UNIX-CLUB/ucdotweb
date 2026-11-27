package store

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// Platform caps: a daily byte limit for a whole service (all users together), kept below the
// server's traffic allowance. 0 means no cap, the default until the provider is chosen.
// The check reads the day's total from the usage table at most every capRefresh, so the cap
// stops new requests and connections a little after it is reached; transfers already running
// finish under their users' own quotas.

const capsSchema = `
CREATE TABLE IF NOT EXISTS caps (
	service       TEXT PRIMARY KEY,
	bytes_per_day INTEGER NOT NULL
);
INSERT OR IGNORE INTO caps VALUES ('proxy', 0);
INSERT OR IGNORE INTO caps VALUES ('relay', 0);
`

const capRefresh = 10 * time.Second

type capState struct {
	mu      sync.Mutex
	ensured bool
	at      map[string]time.Time
	reached map[string]bool
}

func (d *DB) ensureCaps() error {
	d.caps.mu.Lock()
	defer d.caps.mu.Unlock()
	if d.caps.ensured {
		return nil
	}
	if _, err := d.sql.Exec(capsSchema); err != nil {
		return err
	}
	d.caps.ensured = true
	return nil
}

// Caps returns every service's daily cap in bytes.
func (d *DB) Caps() (map[string]int64, error) {
	if err := d.ensureCaps(); err != nil {
		return nil, err
	}
	rows, err := d.sql.Query(`SELECT service, bytes_per_day FROM caps`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var s string
		var b int64
		if err := rows.Scan(&s, &b); err != nil {
			return nil, err
		}
		out[s] = b
	}
	return out, rows.Err()
}

// SetCap changes a service's daily cap, with an audit entry. 0 removes the cap.
func (d *DB) SetCap(actor, service string, bytesPerDay int64) error {
	if bytesPerDay < 0 {
		return errors.New("store: a cap cannot be negative")
	}
	if err := d.ensureCaps(); err != nil {
		return err
	}
	tx, err := d.sql.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	r, err := tx.Exec(`UPDATE caps SET bytes_per_day = ? WHERE service = ?`, bytesPerDay, service)
	if err != nil {
		return err
	}
	if n, _ := r.RowsAffected(); n == 0 {
		return errors.New("store: no such service")
	}
	if _, err := tx.Exec(`INSERT INTO audit (at, actor, action, target, detail) VALUES (?, ?, 'set cap', ?, ?)`,
		d.now().Unix(), actor, service, fmt.Sprintf("bytes/day %d", bytesPerDay)); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	d.caps.mu.Lock()
	delete(d.caps.at, service) // the next check reads again
	d.caps.mu.Unlock()
	return nil
}

// CapReached says whether a service's total bytes today have reached its cap. On a read
// error it answers false: the users' own quotas still apply.
func (d *DB) CapReached(service string) bool {
	now := d.now()
	d.caps.mu.Lock()
	if t, ok := d.caps.at[service]; ok && now.Sub(t) < capRefresh && Day(t) == Day(now) {
		r := d.caps.reached[service]
		d.caps.mu.Unlock()
		return r
	}
	d.caps.mu.Unlock()
	reached := false
	if d.ensureCaps() == nil {
		var limit, total int64
		if d.sql.QueryRow(`SELECT bytes_per_day FROM caps WHERE service = ?`, service).Scan(&limit) == nil && limit > 0 {
			_ = d.sql.QueryRow(`SELECT coalesce(sum(bytes), 0) FROM usage WHERE day = ? AND kind = ?`, Day(now), service).Scan(&total)
			reached = total >= limit
		}
	}
	d.caps.mu.Lock()
	if d.caps.at == nil {
		d.caps.at, d.caps.reached = map[string]time.Time{}, map[string]bool{}
	}
	d.caps.at[service], d.caps.reached[service] = now, reached
	d.caps.mu.Unlock()
	return reached
}

// EraseOldReportSummaries empties the summary of abuse reports older than retention (decided:
// 12 months), where personal data would sit. The rest of the report, and the audit log, stay.
func (d *DB) EraseOldReportSummaries(retention time.Duration) (int64, error) {
	if err := d.EnsureSafety(); err != nil {
		return 0, err
	}
	r, err := d.sql.Exec(`UPDATE reports SET summary = '' WHERE at < ? AND summary != ''`, d.now().Add(-retention).Unix())
	if err != nil {
		return 0, err
	}
	return r.RowsAffected()
}
