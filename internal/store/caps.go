package store

import (
	"database/sql"
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
//
// The 'bundle' row caps device-transfer bundle traffic (uploads and downloads). Bundles do
// not use CapReached: they read the cap and the day's total fresh, with UsageLeft and
// TakeUsage, so that a bundle's whole size can be checked against what is left.
//
// Storage caps (storage_caps) are different: a limit on bytes kept, not on bytes moved in a
// day. The 'bundles' row is the total size of every user's stored bundles together.

const capsSchema = `
CREATE TABLE IF NOT EXISTS caps (
	service       TEXT PRIMARY KEY,
	bytes_per_day INTEGER NOT NULL
);
INSERT OR IGNORE INTO caps VALUES ('proxy', 0);
INSERT OR IGNORE INTO caps VALUES ('relay', 0);
INSERT OR IGNORE INTO caps VALUES ('bundle', 0);
CREATE TABLE IF NOT EXISTS storage_caps (
	name  TEXT PRIMARY KEY,
	bytes INTEGER NOT NULL
);
INSERT OR IGNORE INTO storage_caps VALUES ('bundles', 0);
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

// UsageLeft says how many more bytes of one kind the subject may move today: user under
// their own daily limit (userLimit, from their tier; 0 means none), platform under the
// service's daily cap. -1 means no limit; 0 means the limit is reached (never below 0).
// Unlike CapReached it reads fresh and answers an error on a read error.
func (d *DB) UsageLeft(subject, kind string, userLimit int64) (user, platform int64, err error) {
	if err := d.ensureCaps(); err != nil {
		return 0, 0, err
	}
	day := Day(d.now())
	user, platform = -1, -1
	if userLimit > 0 {
		var used int64
		if err := d.sql.QueryRow(`SELECT coalesce(sum(bytes), 0) FROM usage WHERE subject = ? AND day = ? AND kind = ?`,
			subject, day, kind).Scan(&used); err != nil {
			return 0, 0, err
		}
		user = max(userLimit-used, 0)
	}
	limit, err := capOf(d.sql.QueryRow, kind)
	if err != nil {
		return 0, 0, err
	}
	if limit > 0 {
		var total int64
		if err := d.sql.QueryRow(`SELECT coalesce(sum(bytes), 0) FROM usage WHERE day = ? AND kind = ?`, day, kind).Scan(&total); err != nil {
			return 0, 0, err
		}
		platform = max(limit-total, 0)
	}
	return user, platform, nil
}

// capOf reads a service's daily cap; a service without a row has none (0).
func capOf(query func(string, ...any) *sql.Row, service string) (int64, error) {
	var limit int64
	err := query(`SELECT bytes_per_day FROM caps WHERE service = ?`, service).Scan(&limit)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return limit, err
}

// Usage refusals from TakeUsage.
const (
	OverQuota = "quota" // the user's own daily limit
	OverCap   = "cap"   // the platform's daily cap for the service
)

// TakeUsage adds n bytes and one request of one kind to the subject's day, but only if they
// fit both the user's daily limit (userLimit, 0 for none) and the service's platform cap.
// Otherwise it adds nothing and answers OverQuota or OverCap. The check and the addition are
// one transaction, and the store has one connection, so two calls at once cannot both pass.
func (d *DB) TakeUsage(subject, kind string, n, userLimit int64) (refusal string, err error) {
	if err := d.ensureCaps(); err != nil {
		return "", err
	}
	tx, err := d.sql.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	day := Day(d.now())
	if userLimit > 0 {
		var used int64
		if err := tx.QueryRow(`SELECT coalesce(sum(bytes), 0) FROM usage WHERE subject = ? AND day = ? AND kind = ?`,
			subject, day, kind).Scan(&used); err != nil {
			return "", err
		}
		if used+n > userLimit {
			return OverQuota, nil
		}
	}
	limit, err := capOf(tx.QueryRow, kind)
	if err != nil {
		return "", err
	}
	if limit > 0 {
		var total int64
		if err := tx.QueryRow(`SELECT coalesce(sum(bytes), 0) FROM usage WHERE day = ? AND kind = ?`, day, kind).Scan(&total); err != nil {
			return "", err
		}
		if total+n > limit {
			return OverCap, nil
		}
	}
	if _, err := tx.Exec(`INSERT INTO usage VALUES (?, ?, ?, ?, 1)
		ON CONFLICT(subject, day, kind) DO UPDATE SET bytes = bytes + excluded.bytes, requests = requests + 1`,
		subject, day, kind, n); err != nil {
		return "", err
	}
	return "", tx.Commit()
}

// StorageCaps returns every storage cap in bytes (0: none).
func (d *DB) StorageCaps() (map[string]int64, error) {
	if err := d.ensureCaps(); err != nil {
		return nil, err
	}
	rows, err := d.sql.Query(`SELECT name, bytes FROM storage_caps`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var n string
		var b int64
		if err := rows.Scan(&n, &b); err != nil {
			return nil, err
		}
		out[n] = b
	}
	return out, rows.Err()
}

// StorageCap returns one storage cap in bytes (0: none).
func (d *DB) StorageCap(name string) (int64, error) {
	if err := d.ensureCaps(); err != nil {
		return 0, err
	}
	var b int64
	err := d.sql.QueryRow(`SELECT bytes FROM storage_caps WHERE name = ?`, name).Scan(&b)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return b, err
}

// SetStorageCap changes a storage cap, with an audit entry. 0 removes the cap.
func (d *DB) SetStorageCap(actor, name string, bytes int64) error {
	if bytes < 0 {
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
	r, err := tx.Exec(`UPDATE storage_caps SET bytes = ? WHERE name = ?`, bytes, name)
	if err != nil {
		return err
	}
	if n, _ := r.RowsAffected(); n == 0 {
		return errors.New("store: no such storage")
	}
	if _, err := tx.Exec(`INSERT INTO audit (at, actor, action, target, detail) VALUES (?, ?, 'set storage cap', ?, ?)`,
		d.now().Unix(), actor, name, fmt.Sprintf("bytes %d", bytes)); err != nil {
		return err
	}
	return tx.Commit()
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
