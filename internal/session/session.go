// Package session keeps browser sessions on the server. The browser holds only a random
// id in a cookie that scripts cannot read; everything else stays here. In memory for now:
// a restart signs everyone out. A database-backed store can replace it behind the same API.
package session

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"sync"
	"time"
)

// CookieName uses the __Host- prefix: Secure, Path=/, no Domain, so no subdomain can set it.
const CookieName = "__Host-ucdotweb"

// Data is what a session holds.
type Data struct {
	// Before sign-in: the values of the pending authorization request.
	PendingState, PendingNonce, PendingVerifier string
	PendingCreated                              time.Time
	// After sign-in.
	Subject      string
	Claims       map[string]any
	RefreshToken string // provider refresh token; encrypted at rest once a database is used
	SignedInAt   time.Time
}

type entry struct {
	data     Data
	created  time.Time
	lastSeen time.Time
}

// Store holds sessions.
type Store struct {
	mu       sync.Mutex
	m        map[string]*entry
	Idle     time.Duration // a session unused for this long ends
	Absolute time.Duration // a session older than this ends
	Secure   bool          // false only for local tests over plain http
	now      func() time.Time
}

// New returns a store with the given limits.
func New(idle, absolute time.Duration, secure bool) *Store {
	return &Store{m: map[string]*entry{}, Idle: idle, Absolute: absolute, Secure: secure, now: time.Now}
}

func newID() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *Store) name() string {
	if s.Secure {
		return CookieName
	}
	return "ucdotweb" // the __Host- prefix requires Secure
}

// Get returns the session of the request, if any and still valid.
func (s *Store) Get(r *http.Request) (string, *Data) {
	c, err := r.Cookie(s.name())
	if err != nil {
		return "", nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.m[c.Value]
	if !ok {
		return "", nil
	}
	now := s.now()
	if now.Sub(e.lastSeen) > s.Idle || now.Sub(e.created) > s.Absolute {
		delete(s.m, c.Value)
		return "", nil
	}
	e.lastSeen = now
	d := e.data
	return c.Value, &d
}

// Put stores data under a NEW id (rotation at every change of privilege), drops the old
// id if given, and sets the cookie.
func (s *Store) Put(w http.ResponseWriter, oldID string, d Data) string {
	id := newID()
	now := s.now()
	s.mu.Lock()
	if oldID != "" {
		delete(s.m, oldID)
	}
	s.m[id] = &entry{data: d, created: now, lastSeen: now}
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: s.name(), Value: id, Path: "/", HttpOnly: true, Secure: s.Secure,
		SameSite: http.SameSiteLaxMode, MaxAge: int(s.Absolute.Seconds())})
	return id
}

// Delete ends a session and clears the cookie.
func (s *Store) Delete(w http.ResponseWriter, id string) {
	s.mu.Lock()
	delete(s.m, id)
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: s.name(), Value: "", Path: "/", HttpOnly: true, Secure: s.Secure,
		SameSite: http.SameSiteLaxMode, MaxAge: -1})
}

// Count returns the number of live sessions (for tests and the admin view).
func (s *Store) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.m)
}
