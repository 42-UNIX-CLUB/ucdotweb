package store

// The proxy's allow-list, edited by administrators. One row per host. The proxy checks the
// input (see proxy.ValidateRule) before it reaches these functions; the store only refuses
// what would break its own rows.

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"
)

const allowSchema = `
CREATE TABLE IF NOT EXISTS allow_rules (
	host       TEXT PRIMARY KEY,
	prefixes   TEXT NOT NULL,
	git        INTEGER NOT NULL DEFAULT 0,
	releases   INTEGER NOT NULL DEFAULT 0,
	updated_at INTEGER NOT NULL,
	updated_by TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS allow_seeded (
	id        INTEGER PRIMARY KEY CHECK (id = 1),
	seeded_at INTEGER NOT NULL
);
`

// AllowRule is one host of the proxy's allow-list and what it allows there.
type AllowRule struct {
	Host      string
	Prefixes  []string
	Git       bool
	Releases  bool
	UpdatedAt time.Time // set by the store
	UpdatedBy string    // set by the store
}

// ErrNoAllowRule is returned when a host is not on the list.
var ErrNoAllowRule = errors.New("store: no such allow-list rule")

// allowVersion grows after every committed change to any allow-list. A reader compares it
// with the value it loaded at, which costs one atomic read. It is shared by every open DB in
// the process: a change in one only makes the others reload once more.
var allowVersion atomic.Uint64

// AllowlistVersion returns the change counter. Read it before reading the rules.
func AllowlistVersion() uint64 { return allowVersion.Load() }

// ensureAllowlist creates the tables if they are missing. Safe to run many times.
func (d *DB) ensureAllowlist() error {
	if _, err := d.sql.Exec(allowSchema); err != nil {
		return fmt.Errorf("store: allow-list schema: %w", err)
	}
	return nil
}

func checkAllowRule(r AllowRule) error {
	if r.Host == "" || r.Host != strings.ToLower(r.Host) {
		return errors.New("store: an allow-list host must be lowercase and not empty")
	}
	for _, p := range r.Prefixes {
		if !strings.HasPrefix(p, "/") {
			return errors.New("store: an allow-list prefix must start with /")
		}
	}
	return nil
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// describe is the audit text for a rule.
func (r AllowRule) describe() string {
	parts := []string{"prefixes " + strings.Join(r.Prefixes, " ")}
	if len(r.Prefixes) == 0 {
		parts[0] = "no prefixes"
	}
	if r.Git {
		parts = append(parts, "git")
	}
	if r.Releases {
		parts = append(parts, "releases")
	}
	return strings.Join(parts, "; ")
}

func scanRule(row interface{ Scan(...any) error }) (AllowRule, error) {
	var r AllowRule
	var pre string
	var git, rel int
	var at int64
	if err := row.Scan(&r.Host, &pre, &git, &rel, &at, &r.UpdatedBy); err != nil {
		return r, err
	}
	if err := json.Unmarshal([]byte(pre), &r.Prefixes); err != nil {
		return r, fmt.Errorf("store: allow-list prefixes of %s: %w", r.Host, err)
	}
	if r.Prefixes == nil {
		r.Prefixes = []string{}
	}
	r.Git, r.Releases, r.UpdatedAt = git != 0, rel != 0, time.Unix(at, 0)
	return r, nil
}

// AllowRules returns the whole list, sorted by host.
func (d *DB) AllowRules() ([]AllowRule, error) {
	if err := d.ensureAllowlist(); err != nil {
		return nil, err
	}
	rows, err := d.sql.Query(`SELECT host, prefixes, git, releases, updated_at, updated_by FROM allow_rules ORDER BY host`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AllowRule{}
	for rows.Next() {
		r, err := scanRule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// PutAllowRule adds a rule, or replaces the rule for the same host, with an audit entry in
// the same transaction. It reports whether a rule was replaced.
func (d *DB) PutAllowRule(actor string, r AllowRule) (replaced bool, err error) {
	if err := checkAllowRule(r); err != nil {
		return false, err
	}
	if r.Prefixes == nil {
		r.Prefixes = []string{}
	}
	pre, _ := json.Marshal(r.Prefixes)
	if err := d.ensureAllowlist(); err != nil {
		return false, err
	}
	tx, err := d.sql.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	old, err := scanRule(tx.QueryRow(`SELECT host, prefixes, git, releases, updated_at, updated_by FROM allow_rules WHERE host = ?`, r.Host))
	switch {
	case err == nil:
		replaced = true
	case errors.Is(err, sql.ErrNoRows):
	default:
		return false, err
	}
	now := d.now().Unix()
	if _, err := tx.Exec(`INSERT OR REPLACE INTO allow_rules VALUES (?, ?, ?, ?, ?, ?)`,
		r.Host, string(pre), b2i(r.Git), b2i(r.Releases), now, actor); err != nil {
		return false, err
	}
	action, detail := "allowlist add", r.describe()
	if replaced {
		action, detail = "allowlist replace", "was: "+old.describe()+". now: "+r.describe()
	}
	if _, err := tx.Exec(`INSERT INTO audit (at, actor, action, target, detail) VALUES (?, ?, ?, ?, ?)`,
		now, actor, action, r.Host, detail); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	allowVersion.Add(1)
	return replaced, nil
}

// RemoveAllowRule takes a host off the list, with an audit entry in the same transaction.
func (d *DB) RemoveAllowRule(actor, host string) error {
	if err := d.ensureAllowlist(); err != nil {
		return err
	}
	tx, err := d.sql.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	old, err := scanRule(tx.QueryRow(`SELECT host, prefixes, git, releases, updated_at, updated_by FROM allow_rules WHERE host = ?`, host))
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNoAllowRule
	}
	if err != nil {
		return err
	}
	now := d.now().Unix()
	if _, err := tx.Exec(`DELETE FROM allow_rules WHERE host = ?`, host); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO audit (at, actor, action, target, detail) VALUES (?, ?, 'allowlist remove', ?, ?)`,
		now, actor, host, "was: "+old.describe()); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	allowVersion.Add(1)
	return nil
}

// SeedAllowlist fills the list from the rules the service starts with, the first time only.
// It runs once per database: after that, an empty list stays empty (an administrator may
// have removed every rule). It reports whether it seeded. The audit actor is "seed".
func (d *DB) SeedAllowlist(rules []AllowRule) (bool, error) {
	for _, r := range rules {
		if err := checkAllowRule(r); err != nil {
			return false, err
		}
	}
	if err := d.ensureAllowlist(); err != nil {
		return false, err
	}
	tx, err := d.sql.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var n int
	if err := tx.QueryRow(`SELECT count(*) FROM allow_seeded`).Scan(&n); err != nil {
		return false, err
	}
	if n > 0 {
		return false, nil
	}
	now := d.now().Unix()
	if _, err := tx.Exec(`INSERT INTO allow_seeded VALUES (1, ?)`, now); err != nil {
		return false, err
	}
	if err := tx.QueryRow(`SELECT count(*) FROM allow_rules`).Scan(&n); err != nil {
		return false, err
	}
	seeded := false
	if n == 0 {
		hosts := make([]string, 0, len(rules))
		for _, r := range rules {
			pre := r.Prefixes
			if pre == nil {
				pre = []string{}
			}
			b, _ := json.Marshal(pre)
			// a plain INSERT: a host given twice is an error, not a silent choice
			if _, err := tx.Exec(`INSERT INTO allow_rules VALUES (?, ?, ?, ?, ?, 'seed')`,
				r.Host, string(b), b2i(r.Git), b2i(r.Releases), now); err != nil {
				return false, fmt.Errorf("store: seeding %s: %w", r.Host, err)
			}
			hosts = append(hosts, r.Host)
		}
		if _, err := tx.Exec(`INSERT INTO audit (at, actor, action, target, detail) VALUES (?, 'seed', 'allowlist seed', 'allowlist', ?)`,
			now, fmt.Sprintf("%d rules: %s", len(rules), strings.Join(hosts, " "))); err != nil {
			return false, err
		}
		seeded = true
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	allowVersion.Add(1)
	return seeded, nil
}
