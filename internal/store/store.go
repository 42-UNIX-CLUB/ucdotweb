// Package store is the platform's database: SQLite in one file. It holds sessions (only a
// hash of each session id, and the session data encrypted), the users the platform has seen
// (by their pseudonymous Clubroom id), grants and bans, quotas per tier, daily usage,
// panic switches, connection logs (kept 30 days) and the audit log of admin actions.
package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// DB is an open store.
type DB struct {
	sql  *sql.DB
	aead cipher.AEAD
	now  func() time.Time
	caps capState
}

const schema = `
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS sessions (
	id_hash   TEXT PRIMARY KEY,
	data      BLOB NOT NULL,
	created   INTEGER NOT NULL,
	last_seen INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
	subject      TEXT PRIMARY KEY,
	login        TEXT NOT NULL DEFAULT '',
	first_seen   INTEGER NOT NULL,
	last_seen    INTEGER NOT NULL,
	member_grant INTEGER NOT NULL DEFAULT 0,
	member_until INTEGER NOT NULL DEFAULT 0,
	admin_grant  INTEGER NOT NULL DEFAULT 0,
	banned       INTEGER NOT NULL DEFAULT 0,
	ban_reason   TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS quotas (
	tier          TEXT PRIMARY KEY,
	bytes_per_day INTEGER NOT NULL,
	conns         INTEGER NOT NULL,
	dests_per_min INTEGER NOT NULL,
	reqs_per_min  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS usage (
	subject  TEXT NOT NULL,
	day      TEXT NOT NULL,
	kind     TEXT NOT NULL,
	bytes    INTEGER NOT NULL DEFAULT 0,
	requests INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY (subject, day, kind)
);
CREATE TABLE IF NOT EXISTS flags (
	name  TEXT PRIMARY KEY,
	on_   INTEGER NOT NULL,
	at    INTEGER NOT NULL,
	by    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS conn_log (
	at      INTEGER NOT NULL,
	subject TEXT NOT NULL,
	kind    TEXT NOT NULL,
	host    TEXT NOT NULL,
	bytes   INTEGER NOT NULL,
	outcome TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS conn_log_at ON conn_log(at);
CREATE TABLE IF NOT EXISTS audit (
	id     INTEGER PRIMARY KEY AUTOINCREMENT,
	at     INTEGER NOT NULL,
	actor  TEXT NOT NULL,
	action TEXT NOT NULL,
	target TEXT NOT NULL,
	detail TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT, 'audit is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT, 'audit is append-only'); END;
INSERT OR IGNORE INTO quotas VALUES ('user',   2000000000, 0, 0, 120);
INSERT OR IGNORE INTO quotas VALUES ('member', 2500000000, 8, 15, 120);
`

// Open opens or creates the database file. key encrypts session data at rest (32 bytes,
// read by the caller from a secret file outside the repository).
func Open(path string, key []byte) (*DB, error) {
	if len(key) != 32 {
		return nil, errors.New("store: the encryption key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite3", "file:"+path+"?_busy_timeout=5000")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // SQLite has one writer; one connection keeps it simple and safe
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: schema: %w", err)
	}
	return &DB{sql: db, aead: aead, now: time.Now}, nil
}

// Close closes the database.
func (d *DB) Close() error { return d.sql.Close() }

// HashID turns a session id into the key stored: a leaked database gives no usable cookie.
func HashID(id string) string {
	h := sha256.Sum256([]byte(id))
	return hex.EncodeToString(h[:])
}

func (d *DB) seal(plain []byte) []byte {
	nonce := make([]byte, d.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic("crypto/rand: " + err.Error())
	}
	return d.aead.Seal(nonce, nonce, plain, nil)
}

func (d *DB) open(box []byte) ([]byte, error) {
	n := d.aead.NonceSize()
	if len(box) < n {
		return nil, errors.New("store: sealed data too short")
	}
	return d.aead.Open(nil, box[:n], box[n:], nil)
}

// ---- sessions (used by the session package) ----

// SessionGet returns the decrypted data and the times of a session.
func (d *DB) SessionGet(idHash string) (data []byte, created, lastSeen time.Time, ok bool, err error) {
	var box []byte
	var c, l int64
	err = d.sql.QueryRow(`SELECT data, created, last_seen FROM sessions WHERE id_hash = ?`, idHash).Scan(&box, &c, &l)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, time.Time{}, time.Time{}, false, nil
	}
	if err != nil {
		return nil, time.Time{}, time.Time{}, false, err
	}
	data, err = d.open(box)
	if err != nil {
		return nil, time.Time{}, time.Time{}, false, err
	}
	return data, time.Unix(c, 0), time.Unix(l, 0), true, nil
}

// SessionPut stores a session.
func (d *DB) SessionPut(idHash string, data []byte, created time.Time) error {
	now := d.now().Unix()
	_, err := d.sql.Exec(`INSERT OR REPLACE INTO sessions VALUES (?, ?, ?, ?)`, idHash, d.seal(data), created.Unix(), now)
	return err
}

// SessionTouch records use.
func (d *DB) SessionTouch(idHash string) error {
	_, err := d.sql.Exec(`UPDATE sessions SET last_seen = ? WHERE id_hash = ?`, d.now().Unix(), idHash)
	return err
}

// SessionDelete ends a session.
func (d *DB) SessionDelete(idHash string) error {
	_, err := d.sql.Exec(`DELETE FROM sessions WHERE id_hash = ?`, idHash)
	return err
}

// SessionPurge drops sessions idle or old beyond the limits.
func (d *DB) SessionPurge(idle, absolute time.Duration) (int64, error) {
	now := d.now()
	r, err := d.sql.Exec(`DELETE FROM sessions WHERE last_seen < ? OR created < ?`,
		now.Add(-idle).Unix(), now.Add(-absolute).Unix())
	if err != nil {
		return 0, err
	}
	return r.RowsAffected()
}

// SessionCount returns the number of stored sessions.
func (d *DB) SessionCount() int {
	var n int
	_ = d.sql.QueryRow(`SELECT count(*) FROM sessions`).Scan(&n)
	return n
}

// ---- users ----

// User is what the platform keeps about a person.
type User struct {
	Subject     string
	Login       string
	MemberGrant bool      // granted by an administrator
	MemberUntil time.Time // a 42 link's member role lasts until here (end of the school year)
	AdminGrant  bool
	Banned      bool
	BanReason   string
}

// SeenUser records a sign-in and returns the user's row.
func (d *DB) SeenUser(subject, login string) (User, error) {
	now := d.now().Unix()
	if _, err := d.sql.Exec(`INSERT INTO users (subject, login, first_seen, last_seen) VALUES (?, ?, ?, ?)
		ON CONFLICT(subject) DO UPDATE SET login = excluded.login, last_seen = excluded.last_seen`,
		subject, login, now, now); err != nil {
		return User{}, err
	}
	return d.GetUser(subject)
}

// GetUser reads a user.
func (d *DB) GetUser(subject string) (User, error) {
	var u User
	var mg, ag, b int
	var mu int64
	err := d.sql.QueryRow(`SELECT subject, login, member_grant, member_until, admin_grant, banned, ban_reason
		FROM users WHERE subject = ?`, subject).Scan(&u.Subject, &u.Login, &mg, &mu, &ag, &b, &u.BanReason)
	if err != nil {
		return u, err
	}
	u.MemberGrant, u.AdminGrant, u.Banned = mg != 0, ag != 0, b != 0
	if mu != 0 {
		u.MemberUntil = time.Unix(mu, 0)
	}
	return u, nil
}

// SetGrant changes a grant or a ban and writes the audit log in the same transaction.
func (d *DB) SetGrant(actor, subject, field string, on bool, reason string) error {
	col := map[string]string{"member": "member_grant", "admin": "admin_grant", "banned": "banned"}[field]
	if col == "" {
		return fmt.Errorf("store: unknown grant %q", field)
	}
	tx, err := d.sql.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	v := 0
	if on {
		v = 1
	}
	r, err := tx.Exec(`UPDATE users SET `+col+` = ?, ban_reason = CASE WHEN ? = 'banned' THEN ? ELSE ban_reason END
		WHERE subject = ?`, v, field, reason, subject)
	if err != nil {
		return err
	}
	if n, _ := r.RowsAffected(); n == 0 {
		return errors.New("store: no such user")
	}
	if _, err := tx.Exec(`INSERT INTO audit (at, actor, action, target, detail) VALUES (?, ?, ?, ?, ?)`,
		d.now().Unix(), actor, "set "+field, subject, fmt.Sprintf("%v %s", on, reason)); err != nil {
		return err
	}
	return tx.Commit()
}

// ---- quotas and usage ----

// Quota is the limits of a tier. Zero means no limit of that kind.
type Quota struct {
	BytesPerDay int64
	Conns       int
	DestsPerMin int
	ReqsPerMin  int
}

// GetQuota reads a tier's limits.
func (d *DB) GetQuota(tier string) (Quota, error) {
	var q Quota
	err := d.sql.QueryRow(`SELECT bytes_per_day, conns, dests_per_min, reqs_per_min FROM quotas WHERE tier = ?`, tier).
		Scan(&q.BytesPerDay, &q.Conns, &q.DestsPerMin, &q.ReqsPerMin)
	return q, err
}

// Day is the usage day for a time, in UTC.
func Day(t time.Time) string { return t.UTC().Format("2006-01-02") }

// AddUsage adds to a user's counters for today.
func (d *DB) AddUsage(subject, kind string, bytes, requests int64) error {
	_, err := d.sql.Exec(`INSERT INTO usage VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(subject, day, kind) DO UPDATE SET bytes = bytes + excluded.bytes, requests = requests + excluded.requests`,
		subject, Day(d.now()), kind, bytes, requests)
	return err
}

// UsageToday returns a user's bytes and requests of one kind today.
func (d *DB) UsageToday(subject, kind string) (bytes, requests int64, err error) {
	err = d.sql.QueryRow(`SELECT bytes, requests FROM usage WHERE subject = ? AND day = ? AND kind = ?`,
		subject, Day(d.now()), kind).Scan(&bytes, &requests)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, 0, nil
	}
	return bytes, requests, err
}

// ---- panic switches ----

// SetFlag turns a panic switch on or off, with an audit entry.
func (d *DB) SetFlag(actor, name string, on bool) error {
	tx, err := d.sql.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	v := 0
	if on {
		v = 1
	}
	now := d.now().Unix()
	if _, err := tx.Exec(`INSERT OR REPLACE INTO flags VALUES (?, ?, ?, ?)`, name, v, now, actor); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO audit (at, actor, action, target, detail) VALUES (?, ?, 'flag', ?, ?)`,
		now, actor, name, fmt.Sprint(on)); err != nil {
		return err
	}
	return tx.Commit()
}

// Flag reads a panic switch; unknown switches are off.
func (d *DB) Flag(name string) bool {
	var v int
	_ = d.sql.QueryRow(`SELECT on_ FROM flags WHERE name = ?`, name).Scan(&v)
	return v != 0
}

// ---- logs ----

// LogConn records one proxied request or relayed connection: who (pseudonymous), what
// kind, the destination host only (never a URL), bytes and the outcome.
func (d *DB) LogConn(subject, kind, host string, bytes int64, outcome string) error {
	_, err := d.sql.Exec(`INSERT INTO conn_log VALUES (?, ?, ?, ?, ?, ?)`, d.now().Unix(), subject, kind, host, bytes, outcome)
	return err
}

// PurgeLogs deletes connection logs older than the retention period (30 days by decision).
func (d *DB) PurgeLogs(retention time.Duration) (int64, error) {
	r, err := d.sql.Exec(`DELETE FROM conn_log WHERE at < ?`, d.now().Add(-retention).Unix())
	if err != nil {
		return 0, err
	}
	return r.RowsAffected()
}

// AuditCount returns the number of audit entries (for tests and the admin view).
func (d *DB) AuditCount() int {
	var n int
	_ = d.sql.QueryRow(`SELECT count(*) FROM audit`).Scan(&n)
	return n
}

// ---- admin views ----

// UserRow is one line of the admin's user list.
type UserRow struct {
	User
	FirstSeen, LastSeen time.Time
}

// ListUsers returns users, most recently seen first. query filters on the login (substring).
func (d *DB) ListUsers(query string, limit, offset int) ([]UserRow, error) {
	rows, err := d.sql.Query(`SELECT subject, login, member_grant, member_until, admin_grant, banned, ban_reason,
		first_seen, last_seen FROM users WHERE instr(lower(login), lower(?)) > 0
		ORDER BY last_seen DESC LIMIT ? OFFSET ?`, query, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []UserRow{}
	for rows.Next() {
		var u UserRow
		var mg, ag, b int
		var mu, fs, ls int64
		if err := rows.Scan(&u.Subject, &u.Login, &mg, &mu, &ag, &b, &u.BanReason, &fs, &ls); err != nil {
			return nil, err
		}
		u.MemberGrant, u.AdminGrant, u.Banned = mg != 0, ag != 0, b != 0
		if mu != 0 {
			u.MemberUntil = time.Unix(mu, 0)
		}
		u.FirstSeen, u.LastSeen = time.Unix(fs, 0), time.Unix(ls, 0)
		out = append(out, u)
	}
	return out, rows.Err()
}

// SetQuota changes a tier's limits, with an audit entry. Only existing tiers can change.
func (d *DB) SetQuota(actor, tier string, q Quota) error {
	if q.BytesPerDay < 0 || q.Conns < 0 || q.DestsPerMin < 0 || q.ReqsPerMin < 0 {
		return errors.New("store: limits cannot be negative")
	}
	tx, err := d.sql.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	r, err := tx.Exec(`UPDATE quotas SET bytes_per_day = ?, conns = ?, dests_per_min = ?, reqs_per_min = ? WHERE tier = ?`,
		q.BytesPerDay, q.Conns, q.DestsPerMin, q.ReqsPerMin, tier)
	if err != nil {
		return err
	}
	if n, _ := r.RowsAffected(); n == 0 {
		return errors.New("store: no such tier")
	}
	if _, err := tx.Exec(`INSERT INTO audit (at, actor, action, target, detail) VALUES (?, ?, 'set quota', ?, ?)`,
		d.now().Unix(), actor, tier, fmt.Sprintf("bytes/day %d, connections %d, destinations/min %d, requests/min %d",
			q.BytesPerDay, q.Conns, q.DestsPerMin, q.ReqsPerMin)); err != nil {
		return err
	}
	return tx.Commit()
}

// Quotas returns every tier's limits.
func (d *DB) Quotas() (map[string]Quota, error) {
	rows, err := d.sql.Query(`SELECT tier, bytes_per_day, conns, dests_per_min, reqs_per_min FROM quotas`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]Quota{}
	for rows.Next() {
		var t string
		var q Quota
		if err := rows.Scan(&t, &q.BytesPerDay, &q.Conns, &q.DestsPerMin, &q.ReqsPerMin); err != nil {
			return nil, err
		}
		out[t] = q
	}
	return out, rows.Err()
}

// FlagRow is a panic switch's state and who set it last.
type FlagRow struct {
	Name string
	On   bool
	At   time.Time
	By   string
}

// Flags returns the switches that were ever set.
func (d *DB) Flags() ([]FlagRow, error) {
	rows, err := d.sql.Query(`SELECT name, on_, at, by FROM flags ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []FlagRow{}
	for rows.Next() {
		var f FlagRow
		var on int
		var at int64
		if err := rows.Scan(&f.Name, &on, &at, &f.By); err != nil {
			return nil, err
		}
		f.On, f.At = on != 0, time.Unix(at, 0)
		out = append(out, f)
	}
	return out, rows.Err()
}

// AuditRow is one administrative action.
type AuditRow struct {
	ID                            int64
	At                            time.Time
	Actor, Action, Target, Detail string
}

// Audit returns entries older than before (0 for the newest), newest first.
func (d *DB) Audit(before int64, limit int) ([]AuditRow, error) {
	if before <= 0 {
		before = 1 << 62
	}
	rows, err := d.sql.Query(`SELECT id, at, actor, action, target, detail FROM audit WHERE id < ? ORDER BY id DESC LIMIT ?`, before, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AuditRow{}
	for rows.Next() {
		var a AuditRow
		var at int64
		if err := rows.Scan(&a.ID, &at, &a.Actor, &a.Action, &a.Target, &a.Detail); err != nil {
			return nil, err
		}
		a.At = time.Unix(at, 0)
		out = append(out, a)
	}
	return out, rows.Err()
}

// ConnRow is one line of the connection log.
type ConnRow struct {
	At                           time.Time
	Subject, Kind, Host, Outcome string
	Bytes                        int64
}

// Conns returns connection log lines older than before (zero time for the newest), newest
// first, for one subject or for everyone when subject is empty.
func (d *DB) Conns(subject string, before time.Time, limit int) ([]ConnRow, error) {
	b := before.Unix()
	if before.IsZero() {
		b = 1 << 62
	}
	rows, err := d.sql.Query(`SELECT at, subject, kind, host, bytes, outcome FROM conn_log
		WHERE at < ? AND (? = '' OR subject = ?) ORDER BY at DESC LIMIT ?`, b, subject, subject, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ConnRow{}
	for rows.Next() {
		var c ConnRow
		var at int64
		if err := rows.Scan(&at, &c.Subject, &c.Kind, &c.Host, &c.Bytes, &c.Outcome); err != nil {
			return nil, err
		}
		c.At = time.Unix(at, 0)
		out = append(out, c)
	}
	return out, rows.Err()
}

// UsageRow is a user's counters for one day and kind.
type UsageRow struct {
	Day, Kind       string
	Bytes, Requests int64
}

// Usage returns a user's counters for the last days days, newest first.
func (d *DB) Usage(subject string, days int) ([]UsageRow, error) {
	from := Day(d.now().AddDate(0, 0, -(days - 1)))
	rows, err := d.sql.Query(`SELECT day, kind, bytes, requests FROM usage WHERE subject = ? AND day >= ?
		ORDER BY day DESC, kind`, subject, from)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []UsageRow{}
	for rows.Next() {
		var u UsageRow
		if err := rows.Scan(&u.Day, &u.Kind, &u.Bytes, &u.Requests); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// Exec runs a statement; for tests only.
func (d *DB) Exec(q string, args ...any) error { _, err := d.sql.Exec(q, args...); return err }

// QueryRow scans one row into dest; for tests only.
func (d *DB) QueryRow(q string, dest ...any) error { return d.sql.QueryRow(q).Scan(dest...) }
