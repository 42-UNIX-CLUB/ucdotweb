package web

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Device-transfer bundles (decided: QR option b). The OS encrypts a bundle in the browser
// with a random key, uploads only the ciphertext with an expiry the user picks, and shows a
// QR code holding the bundle id and the key. The new device, signed in as the same account,
// downloads and decrypts it. The server never sees the key.
//
//	POST   /api/bundles?expires_in=SECONDS   body: the ciphertext (application/octet-stream)
//	GET    /api/bundles                      the user's pending bundles, used and limit
//	GET    /api/bundles/{id}                 the ciphertext; only to the uploader's account
//	DELETE /api/bundles/{id}
//
// Decided 2026-11-27: same account only; the bytes a user may keep pending are the tier's
// bundle_bytes (admin setting, default 50 MB; 0 means no limit, as for every quota); the
// longest expiry is 30 days.

const (
	BundleMaxExpiry = 30 * 24 * time.Hour
	BundleMinExpiry = time.Minute
	bundleIDBytes   = 16 // 128 random bits: an id cannot be guessed
)

type bundleState struct {
	mu        sync.Mutex
	uploading map[string]bool // subjects with an upload in progress: one at a time each
}

func (s *Server) bundleRoutes(mux *http.ServeMux) {
	if s.BundleDir == "" {
		return
	}
	mux.HandleFunc("POST /api/bundles", s.bundleUpload)
	mux.HandleFunc("GET /api/bundles", s.bundleList)
	mux.HandleFunc("GET /api/bundles/{id}", s.bundleGet)
	mux.HandleFunc("DELETE /api/bundles/{id}", s.bundleDelete)
}

func tierOf(v Viewer) string {
	if v.Member {
		return "member"
	}
	return "user"
}

func validBundleID(id string) bool {
	if len(id) != 2*bundleIDBytes {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil && strings.ToLower(id) == id
}

func (s *Server) bundlePath(id string) string { return filepath.Join(s.BundleDir, id) }

// beginUpload marks the subject as uploading; false if an upload of theirs is running. One
// at a time per user keeps the "used plus this one" check true without a lock around I/O.
func (s *Server) beginUpload(subject string) bool {
	s.bundles.mu.Lock()
	defer s.bundles.mu.Unlock()
	if s.bundles.uploading == nil {
		s.bundles.uploading = map[string]bool{}
	}
	if s.bundles.uploading[subject] {
		return false
	}
	s.bundles.uploading[subject] = true
	return true
}

func (s *Server) endUpload(subject string) {
	s.bundles.mu.Lock()
	delete(s.bundles.uploading, subject)
	s.bundles.mu.Unlock()
}

func (s *Server) bundleUpload(w http.ResponseWriter, r *http.Request) {
	if !s.sameOrigin(r) {
		http.Error(w, "Cross-site request refused.", http.StatusForbidden)
		return
	}
	v, ok := s.viewer(r)
	if !ok {
		http.Error(w, "Sign in first.", http.StatusUnauthorized)
		return
	}
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/octet-stream" {
		http.Error(w, "Send the bundle as application/octet-stream.", http.StatusBadRequest)
		return
	}
	secs, err := strconv.Atoi(r.URL.Query().Get("expires_in"))
	if err != nil || secs < int(BundleMinExpiry/time.Second) || secs > int(BundleMaxExpiry/time.Second) {
		http.Error(w, "Give expires_in in seconds, from 60 to 2592000 (30 days).", http.StatusBadRequest)
		return
	}
	if !s.beginUpload(v.Subject) {
		http.Error(w, "Another upload of yours is in progress.", http.StatusConflict)
		return
	}
	defer s.endUpload(v.Subject)
	ttl := time.Duration(secs) * time.Second
	// the user's expired bundles still count against the space until their files are gone:
	// remove them now, so the limit bounds the disk and does not block the user
	if expired, err := s.DB.ExpiredBundlesOf(v.Subject); err == nil {
		_, _ = s.removeBundles(expired)
	}

	q, err := s.DB.GetQuota(tierOf(v))
	if err != nil {
		http.Error(w, "Quota unavailable.", http.StatusInternalServerError)
		return
	}
	used, err := s.DB.BundleBytes(v.Subject)
	if err != nil {
		http.Error(w, "Quota unavailable.", http.StatusInternalServerError)
		return
	}
	room := int64(-1) // no limit
	if q.BundleBytes > 0 {
		room = q.BundleBytes - used
		if room <= 0 || r.ContentLength > room {
			http.Error(w, "Not enough bundle space. Delete a pending bundle or wait for one to expire.", http.StatusRequestEntityTooLarge)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, room)
	}

	idb := make([]byte, bundleIDBytes)
	if _, err := rand.Read(idb); err != nil {
		http.Error(w, "Could not make an id.", http.StatusInternalServerError)
		return
	}
	id := hex.EncodeToString(idb)
	tmp := s.bundlePath(id) + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		s.Log.Printf("bundles: %v", err)
		http.Error(w, "Could not store the bundle.", http.StatusInternalServerError)
		return
	}
	fw := &fileWriter{f: f}
	n, err := io.Copy(fw, r.Body)
	if err == nil && fw.err == nil {
		fw.err = f.Sync()
	}
	if cerr := f.Close(); fw.err == nil {
		fw.err = cerr
	}
	switch {
	case fw.err != nil: // our side: a full disk, for one
		os.Remove(tmp)
		s.Log.Printf("bundles: writing %s: %v", tmp, fw.err)
		http.Error(w, "Could not store the bundle.", http.StatusInternalServerError)
		return
	case err != nil:
		os.Remove(tmp)
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			http.Error(w, "Not enough bundle space. Delete a pending bundle or wait for one to expire.", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "The upload was cut off.", http.StatusBadRequest)
		return
	case n == 0:
		os.Remove(tmp)
		http.Error(w, "The bundle is empty.", http.StatusBadRequest)
		return
	}
	if err := os.Rename(tmp, s.bundlePath(id)); err != nil {
		os.Remove(tmp)
		s.Log.Printf("bundles: %v", err)
		http.Error(w, "Could not store the bundle.", http.StatusInternalServerError)
		return
	}
	expires := time.Now().Add(ttl)
	if err := s.DB.AddBundle(id, v.Subject, n, expires); err != nil {
		os.Remove(s.bundlePath(id))
		http.Error(w, "Could not store the bundle.", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{"id": id, "size": n, "expires_at": expires.Unix()})
}

func (s *Server) bundleList(w http.ResponseWriter, r *http.Request) {
	v, ok := s.viewer(r)
	if !ok {
		http.Error(w, "Sign in first.", http.StatusUnauthorized)
		return
	}
	rows, err := s.DB.Bundles(v.Subject)
	if err != nil {
		http.Error(w, "Could not read your bundles.", http.StatusInternalServerError)
		return
	}
	q, err := s.DB.GetQuota(tierOf(v))
	if err != nil {
		http.Error(w, "Quota unavailable.", http.StatusInternalServerError)
		return
	}
	list := []map[string]any{}
	var used int64
	for _, b := range rows {
		used += b.Size
		list = append(list, map[string]any{"id": b.ID, "size": b.Size, "created_at": b.Created.Unix(), "expires_at": b.Expires.Unix()})
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, map[string]any{"bundles": list, "used": used, "limit": q.BundleBytes})
}

func (s *Server) bundleGet(w http.ResponseWriter, r *http.Request) {
	v, ok := s.viewer(r)
	if !ok {
		http.Error(w, "Sign in first.", http.StatusUnauthorized)
		return
	}
	id := r.PathValue("id")
	if !validBundleID(id) {
		http.NotFound(w, r)
		return
	}
	// someone else's bundle answers exactly like a missing one
	b, err := s.DB.Bundle(v.Subject, id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	f, err := os.Open(s.bundlePath(b.ID))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	h := w.Header()
	h.Set("Content-Type", "application/octet-stream")
	h.Set("Content-Disposition", "attachment")
	h.Set("Content-Security-Policy", "sandbox")
	h.Set("Cache-Control", "no-store")
	http.ServeContent(w, r, "", time.Time{}, f)
}

func (s *Server) bundleDelete(w http.ResponseWriter, r *http.Request) {
	if !s.sameOrigin(r) {
		http.Error(w, "Cross-site request refused.", http.StatusForbidden)
		return
	}
	v, ok := s.viewer(r)
	if !ok {
		http.Error(w, "Sign in first.", http.StatusUnauthorized)
		return
	}
	id := r.PathValue("id")
	if !validBundleID(id) {
		http.NotFound(w, r)
		return
	}
	if err := s.DB.DeleteBundle(v.Subject, id); err != nil {
		http.NotFound(w, r)
		return
	}
	if err := os.Remove(s.bundlePath(id)); err != nil && !errors.Is(err, os.ErrNotExist) {
		s.Log.Printf("bundles: %v", err)
	}
	w.WriteHeader(http.StatusNoContent)
}

// fileWriter remembers a write error, so a failure on our disk is told apart from a
// failure reading the client's body.
type fileWriter struct {
	f   *os.File
	err error
}

func (w *fileWriter) Write(p []byte) (int, error) {
	n, err := w.f.Write(p)
	if err != nil {
		w.err = err
	}
	return n, err
}

// removeBundles removes the files of the given bundles, then the records of those whose file
// is gone. A file that cannot be removed keeps its record (and keeps counting against the
// owner's space); the others go on. It returns how many files it removed and the first error.
func (s *Server) removeBundles(ids []string) (int, error) {
	var gone []string
	var first error
	removed := 0
	for _, id := range ids {
		err := os.Remove(s.bundlePath(id))
		switch {
		case err == nil:
			removed++
			gone = append(gone, id)
		case errors.Is(err, os.ErrNotExist):
			gone = append(gone, id)
		case first == nil:
			first = err
		}
	}
	if err := s.DB.ForgetBundles(gone); err != nil && first == nil {
		first = err
	}
	return removed, first
}

// PurgeBundles removes expired bundles, and files left by an upload that never finished or
// that have no record. Housekeeping calls it; it returns how many files it removed.
func (s *Server) PurgeBundles() (int, error) {
	if s.BundleDir == "" {
		return 0, nil
	}
	ids, err := s.DB.ExpiredBundles()
	if err != nil {
		return 0, err
	}
	removed, first := s.removeBundles(ids) // one file that cannot go does not stop the rest
	entries, err := os.ReadDir(s.BundleDir)
	if err != nil {
		return removed, err
	}
	for _, e := range entries {
		name := e.Name()
		if !e.Type().IsRegular() {
			continue
		}
		info, err := e.Info()
		if err != nil || time.Since(info.ModTime()) < time.Hour {
			continue // a running upload, or one just finished and not yet recorded
		}
		id := strings.TrimSuffix(name, ".tmp")
		if !validBundleID(id) {
			continue // not ours
		}
		if name == id {
			known, err := s.DB.KnownBundle(id)
			if err != nil || known {
				continue // a live bundle, or we cannot tell: keep it
			}
		}
		if os.Remove(filepath.Join(s.BundleDir, name)) == nil {
			removed++
		}
	}
	return removed, first
}
