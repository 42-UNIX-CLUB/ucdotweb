// Package session keeps browser sessions on the server. The browser holds only a random
// id in a cookie that scripts cannot read; everything else stays here. The backend is the
// database in production (only a hash of the id is stored, the data encrypted) and memory
// in tests.
package session

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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
	RefreshToken string // provider refresh token; encrypted at rest by the database backend
	SignedInAt   time.Time
}

// Backend stores sessions by the hash of their id.
type Backend interface {
	SessionGet(idHash string) (data []byte, created, lastSeen time.Time, ok bool, err error)
	SessionPut(idHash string, data []byte, created time.Time) error
	SessionTouch(idHash string) error
	SessionDelete(idHash string) error
	SessionCount() int
}

// Store holds sessions.
type Store struct {
	b        Backend
	Idle     time.Duration // a session unused for this long ends
	Absolute time.Duration // a session older than this ends
	Secure   bool          // false only for local tests over plain http
	now      func() time.Time
}

// New returns a store in memory, for tests.
func New(idle, absolute time.Duration, secure bool) *Store {
	return NewWith(&memory{m: map[string]memEntry{}}, idle, absolute, secure)
}

// NewWith returns a store on the given backend.
func NewWith(b Backend, idle, absolute time.Duration, secure bool) *Store {
	return &Store{b: b, Idle: idle, Absolute: absolute, Secure: secure, now: time.Now}
}

func newID() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func hashID(id string) string {
	h := sha256.Sum256([]byte(id))
	return hex.EncodeToString(h[:])
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
	if err != nil || c.Value == "" {
		return "", nil
	}
	h := hashID(c.Value)
	raw, created, last, ok, err := s.b.SessionGet(h)
	if err != nil || !ok {
		return "", nil
	}
	now := s.now()
	if now.Sub(last) > s.Idle || now.Sub(created) > s.Absolute {
		_ = s.b.SessionDelete(h)
		return "", nil
	}
	var d Data
	if json.Unmarshal(raw, &d) != nil {
		return "", nil
	}
	if now.Sub(last) > time.Minute { // touch at most once a minute: fewer writes
		_ = s.b.SessionTouch(h)
	}
	return c.Value, &d
}

// IDHash is the stored form of a session id. It is what relay tokens carry: never the id.
func IDHash(id string) string { return hashID(id) }

// GetByHash returns a live session by the hash of its id (for the relay's re-checks).
func (s *Store) GetByHash(h string) (*Data, bool) {
	raw, created, last, ok, err := s.b.SessionGet(h)
	if err != nil || !ok {
		return nil, false
	}
	now := s.now()
	if now.Sub(last) > s.Idle || now.Sub(created) > s.Absolute {
		return nil, false
	}
	var d Data
	if json.Unmarshal(raw, &d) != nil {
		return nil, false
	}
	return &d, true
}

// Put stores data under a NEW id (rotation at every change of privilege), drops the old
// id if given, and sets the cookie.
func (s *Store) Put(w http.ResponseWriter, oldID string, d Data) string {
	id := newID()
	if oldID != "" {
		_ = s.b.SessionDelete(hashID(oldID))
	}
	raw, _ := json.Marshal(d)
	if err := s.b.SessionPut(hashID(id), raw, s.now()); err != nil {
		return ""
	}
	http.SetCookie(w, &http.Cookie{Name: s.name(), Value: id, Path: "/", HttpOnly: true, Secure: s.Secure,
		SameSite: http.SameSiteLaxMode, MaxAge: int(s.Absolute.Seconds())})
	return id
}

// Delete ends a session and clears the cookie.
func (s *Store) Delete(w http.ResponseWriter, id string) {
	_ = s.b.SessionDelete(hashID(id))
	http.SetCookie(w, &http.Cookie{Name: s.name(), Value: "", Path: "/", HttpOnly: true, Secure: s.Secure,
		SameSite: http.SameSiteLaxMode, MaxAge: -1})
}

// Count returns the number of live sessions (for tests and the admin view).
func (s *Store) Count() int { return s.b.SessionCount() }

// ---- memory backend ----

type memEntry struct {
	data          []byte
	created, last time.Time
}

type memory struct {
	mu sync.Mutex
	m  map[string]memEntry
}

func (m *memory) SessionGet(h string) ([]byte, time.Time, time.Time, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.m[h]
	return e.data, e.created, e.last, ok, nil
}
func (m *memory) SessionPut(h string, d []byte, created time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.m[h] = memEntry{d, created, time.Now()}
	return nil
}
func (m *memory) SessionTouch(h string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e, ok := m.m[h]; ok {
		e.last = time.Now()
		m.m[h] = e
	}
	return nil
}
func (m *memory) SessionDelete(h string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.m, h)
	return nil
}
func (m *memory) SessionCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.m)
}
