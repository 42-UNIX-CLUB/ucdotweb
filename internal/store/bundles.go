package store

import (
	"errors"
	"fmt"
	"time"
)

// Device-transfer bundles (decided: QR option b). The browser encrypts the bundle with a
// random key that never reaches the server; the server keeps only the ciphertext, as a file,
// and this table says whose it is and when it expires. Only the uploader's own account may
// download it (decided 2026-11-27). The bytes a user may keep in pending bundles are a
// per-tier limit in the quotas table, bundle_bytes (decided: an admin setting, default 50 MB).

const bundleSchema = `
CREATE TABLE IF NOT EXISTS bundles (
	id      TEXT PRIMARY KEY,
	subject TEXT NOT NULL,
	size    INTEGER NOT NULL,
	created INTEGER NOT NULL,
	expires INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS bundles_subject ON bundles(subject);
CREATE INDEX IF NOT EXISTS bundles_expires ON bundles(expires);
`

// DefaultBundleBytes is the starting bundle limit for every tier (50 MB).
const DefaultBundleBytes = 50_000_000

// ensureBundles makes the bundles table and adds quotas.bundle_bytes to a database made
// before bundles existed. Called from Open.
func (d *DB) ensureBundles() error {
	if _, err := d.sql.Exec(bundleSchema); err != nil {
		return fmt.Errorf("store: bundle schema: %w", err)
	}
	var n int
	if err := d.sql.QueryRow(`SELECT count(*) FROM pragma_table_info('quotas') WHERE name = 'bundle_bytes'`).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		if _, err := d.sql.Exec(fmt.Sprintf(`ALTER TABLE quotas ADD COLUMN bundle_bytes INTEGER NOT NULL DEFAULT %d`, DefaultBundleBytes)); err != nil {
			return fmt.Errorf("store: add bundle_bytes: %w", err)
		}
	}
	return nil
}

// BundleRow is one pending bundle.
type BundleRow struct {
	ID, Subject      string
	Size             int64
	Created, Expires time.Time
}

// ErrNoBundle is returned for a bundle that does not exist, has expired, or is someone else's.
var ErrNoBundle = errors.New("store: no such bundle")

// AddBundle records a bundle whose file is already in place.
func (d *DB) AddBundle(id, subject string, size int64, expires time.Time) error {
	_, err := d.sql.Exec(`INSERT INTO bundles (id, subject, size, created, expires) VALUES (?, ?, ?, ?, ?)`,
		id, subject, size, d.now().Unix(), expires.Unix())
	return err
}

// Bundle returns the subject's bundle id, if it has not expired.
func (d *DB) Bundle(subject, id string) (BundleRow, error) {
	var b BundleRow
	var created, expires int64
	err := d.sql.QueryRow(`SELECT id, subject, size, created, expires FROM bundles WHERE id = ? AND subject = ? AND expires > ?`,
		id, subject, d.now().Unix()).Scan(&b.ID, &b.Subject, &b.Size, &created, &expires)
	if err != nil {
		return BundleRow{}, ErrNoBundle
	}
	b.Created, b.Expires = time.Unix(created, 0), time.Unix(expires, 0)
	return b, nil
}

// Bundles lists the subject's pending bundles, soonest to expire first.
func (d *DB) Bundles(subject string) ([]BundleRow, error) {
	rows, err := d.sql.Query(`SELECT id, subject, size, created, expires FROM bundles WHERE subject = ? AND expires > ? ORDER BY expires`,
		subject, d.now().Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []BundleRow
	for rows.Next() {
		var b BundleRow
		var created, expires int64
		if err := rows.Scan(&b.ID, &b.Subject, &b.Size, &created, &expires); err != nil {
			return nil, err
		}
		b.Created, b.Expires = time.Unix(created, 0), time.Unix(expires, 0)
		out = append(out, b)
	}
	return out, rows.Err()
}

// BundleBytes is the total size of the subject's bundles that still have a file on disk:
// expired ones count until housekeeping or the user's next upload removes them, so the limit
// bounds the disk and not only what can be downloaded.
func (d *DB) BundleBytes(subject string) (int64, error) {
	var n int64
	err := d.sql.QueryRow(`SELECT coalesce(sum(size), 0) FROM bundles WHERE subject = ?`, subject).Scan(&n)
	return n, err
}

// AllBundleBytes is the total size of every user's bundles that still have a file on disk,
// expired or not, for the platform's storage cap.
func (d *DB) AllBundleBytes() (int64, error) {
	var n int64
	err := d.sql.QueryRow(`SELECT coalesce(sum(size), 0) FROM bundles`).Scan(&n)
	return n, err
}

// ExpiredBundlesOf returns the ids of the subject's expired bundles.
func (d *DB) ExpiredBundlesOf(subject string) ([]string, error) {
	return d.bundleIDs(`SELECT id FROM bundles WHERE subject = ? AND expires <= ?`, subject, d.now().Unix())
}

// DeleteBundle removes the subject's bundle record. The caller removes the file.
func (d *DB) DeleteBundle(subject, id string) error {
	r, err := d.sql.Exec(`DELETE FROM bundles WHERE id = ? AND subject = ?`, id, subject)
	if err != nil {
		return err
	}
	if n, _ := r.RowsAffected(); n == 0 {
		return ErrNoBundle
	}
	return nil
}

// ExpiredBundles returns the ids of bundles past their expiry, for housekeeping to remove
// their files and then call ForgetBundles.
func (d *DB) ExpiredBundles() ([]string, error) {
	return d.bundleIDs(`SELECT id FROM bundles WHERE expires <= ?`, d.now().Unix())
}

func (d *DB) bundleIDs(query string, args ...any) ([]string, error) {
	rows, err := d.sql.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// ForgetBundles removes the records of the given bundles.
func (d *DB) ForgetBundles(ids []string) error {
	for _, id := range ids {
		if _, err := d.sql.Exec(`DELETE FROM bundles WHERE id = ?`, id); err != nil {
			return err
		}
	}
	return nil
}

// KnownBundle reports whether a bundle record exists, expired or not (housekeeping uses it
// to find files that have no record). On an error the caller must keep the file.
func (d *DB) KnownBundle(id string) (bool, error) {
	var n int
	err := d.sql.QueryRow(`SELECT count(*) FROM bundles WHERE id = ?`, id).Scan(&n)
	return n > 0, err
}
