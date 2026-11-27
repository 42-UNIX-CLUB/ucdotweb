package web

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/42-UNIX-CLUB/ucdotweb/internal/oidc"
)

// The pending sign-in is what must survive between GET /auth/login and the provider's
// callback: state, nonce, PKCE verifier and when it began. It lives in a short-lived cookie
// sealed with AES-GCM, so a visit to /auth/login writes nothing to the database. A session
// row is written only when the callback succeeds (decided 2026-11-27, DESIGN.md 15.12).

const (
	// pendingLabel derives the cookie's key from the database key, and is also the
	// additional data of every seal, so a value sealed for another purpose never opens here.
	pendingLabel = "ucdotweb pending sign-in v1"
	// pendingLife matches the 10 minutes oidc.Finish allows for a sign-in.
	pendingLife = 10 * time.Minute
	// pendingPath is "/" because __Host- cookies require it (see pendingCookie).
	pendingPath = "/"
)

// pendingSignIn is the sealed content. It carries its own expiry, checked when opened.
type pendingSignIn struct {
	State    string    `json:"s"`
	Nonce    string    `json:"n"`
	Verifier string    `json:"v"`
	Created  time.Time `json:"c"`
	Expires  time.Time `json:"e"`
}

func (p pendingSignIn) oidc() oidc.Pending {
	return oidc.Pending{State: p.State, Nonce: p.Nonce, Verifier: p.Verifier, Created: p.Created}
}

// pendingCookie is the cookie's name. With Secure it takes the __Host- prefix, like the
// session cookie: no other site under the same domain can plant it (a __Secure- cookie can
// be set with a Domain attribute by a sibling name). __Host- requires Path=/, so the cookie
// travels with every request to the origin for the few minutes of a sign-in.
func (s *Server) pendingCookie() string {
	if s.Sessions.Secure {
		return "__Host-ucdotweb-signin"
	}
	return "ucdotweb-signin"
}

func (s *Server) pendingAEAD() (cipher.AEAD, error) {
	block, err := aes.NewCipher(s.DB.DeriveKey(pendingLabel))
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// sealPending turns a pending sign-in into a cookie value: base64url of nonce and ciphertext.
func (s *Server) sealPending(p pendingSignIn) (string, error) {
	aead, err := s.pendingAEAD()
	if err != nil {
		return "", err
	}
	plain, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(aead.Seal(nonce, nonce, plain, []byte(pendingLabel))), nil
}

// openPending checks and opens a cookie value. Anything tampered, expired or incomplete is
// refused.
func (s *Server) openPending(v string, now time.Time) (pendingSignIn, error) {
	var p pendingSignIn
	box, err := base64.RawURLEncoding.DecodeString(v)
	if err != nil {
		return p, errors.New("pending sign-in: not base64url")
	}
	aead, err := s.pendingAEAD()
	if err != nil {
		return p, err
	}
	n := aead.NonceSize()
	if len(box) < n+aead.Overhead() {
		return p, errors.New("pending sign-in: too short")
	}
	plain, err := aead.Open(nil, box[:n], box[n:], []byte(pendingLabel))
	if err != nil {
		return p, errors.New("pending sign-in: does not authenticate")
	}
	if err := json.Unmarshal(plain, &p); err != nil {
		return p, errors.New("pending sign-in: bad content")
	}
	if p.State == "" || p.Nonce == "" || p.Verifier == "" {
		return p, errors.New("pending sign-in: incomplete")
	}
	if !now.Before(p.Expires) {
		return p, errors.New("pending sign-in: expired")
	}
	return p, nil
}

func (s *Server) setPendingCookie(w http.ResponseWriter, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: s.pendingCookie(), Value: value, Path: pendingPath, HttpOnly: true,
		Secure: s.Sessions.Secure, SameSite: http.SameSiteLaxMode, MaxAge: maxAge})
}

// takePending reads the pending sign-in of the request and clears its cookie, so each one
// is offered once. ok is false when it is missing or does not pass openPending.
func (s *Server) takePending(w http.ResponseWriter, r *http.Request) (pendingSignIn, bool) {
	c, err := r.Cookie(s.pendingCookie())
	if err != nil {
		return pendingSignIn{}, false
	}
	s.setPendingCookie(w, "", -1)
	p, err := s.openPending(c.Value, time.Now())
	if err != nil {
		s.Log.Printf("sign-in: %v", err)
		return pendingSignIn{}, false
	}
	return p, true
}

// usedStates remembers the state of each pending sign-in that completed, until it expires,
// so the same sealed cookie cannot complete a second sign-in. Only successful sign-ins are
// recorded, so its size follows real sign-ins. It is in memory: a restart forgets it, which
// leaves at most 10 minutes in which a stolen cookie and a new code for the same state at
// the provider could be used again.
type usedStates struct {
	mu sync.Mutex
	m  map[string]time.Time
}

// use records state as used until "until". It is false when state was already used.
func (u *usedStates) use(state string, until, now time.Time) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.m == nil {
		u.m = map[string]time.Time{}
	}
	for k, exp := range u.m {
		if !now.Before(exp) {
			delete(u.m, k)
		}
	}
	if _, seen := u.m[state]; seen {
		return false
	}
	u.m[state] = until
	return true
}
