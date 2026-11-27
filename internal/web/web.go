// Package web is the platform's HTTP surface for the browser: sign-in through the identity
// provider (backend for frontend), sign-out, and the current user. The proxy, the relay and
// the admin API attach here too.
package web

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/42-UNIX-CLUB/ucdotweb/internal/oidc"
	"github.com/42-UNIX-CLUB/ucdotweb/internal/relay"
	"github.com/42-UNIX-CLUB/ucdotweb/internal/safety"
	"github.com/42-UNIX-CLUB/ucdotweb/internal/session"
	"github.com/42-UNIX-CLUB/ucdotweb/internal/store"
)

// Server holds what the handlers need.
type Server struct {
	Provider *oidc.Provider
	Sessions *session.Store
	Origin   string // our own origin, for example https://dux.ensui.dev; checked on state changes
	Log      *log.Logger
	DB       *store.DB
	// AdminLogins are the 42 logins of the maintainers, who are administrators from their
	// first sign-in ("The admins are the maintainers"). Compared case-insensitively.
	AdminLogins []string
	// Proxy handles /proxy/; nil leaves the route out.
	Proxy http.Handler
	// Relay handles /relay and Minter signs its tokens; nil leaves both out.
	Relay  http.Handler
	Minter *relay.Minter
	// AdminFresh is how recently an administrator must have signed in to make a change
	// (decided: 15 minutes, the default when zero).
	AdminFresh time.Duration
	// Safety is the safety watcher; nil makes GET /api/admin/safety answer 503.
	Safety *safety.Watcher
}

// Handler returns the routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /auth/login", s.login)
	mux.HandleFunc("GET /auth/callback", s.callback)
	mux.HandleFunc("POST /auth/logout", s.logout)
	mux.HandleFunc("GET /api/me", s.me)
	s.adminRoutes(mux)
	s.allowlistRoutes(mux)
	s.safetyRoutes(mux)
	if s.Proxy != nil {
		mux.Handle("/proxy/", s.Proxy)
	}
	if s.Relay != nil && s.Minter != nil {
		mux.HandleFunc("POST /api/relay-token", s.relayToken)
		mux.Handle("GET /relay", s.Relay)
	}
	return securityHeaders(mux)
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	oldID, _ := s.Sessions.Get(r)
	var extra url.Values
	if r.URL.Query().Get("reauth") == "1" {
		// ask the provider for a real new sign-in, not a silent one from its own session
		extra = url.Values{"prompt": {"login"}, "max_age": {"0"}}
	}
	to, pd := s.Provider.StartWith(extra)
	s.Sessions.Put(w, oldID, session.Data{PendingState: pd.State, PendingNonce: pd.Nonce,
		PendingVerifier: pd.Verifier, PendingCreated: pd.Created})
	http.Redirect(w, r, to, http.StatusFound)
}

func (s *Server) callback(w http.ResponseWriter, r *http.Request) {
	id, d := s.Sessions.Get(r)
	if d == nil || d.PendingState == "" {
		http.Error(w, "No sign-in in progress. Start again.", http.StatusBadRequest)
		return
	}
	if e := r.URL.Query().Get("error"); e != "" {
		s.Sessions.Delete(w, id)
		http.Error(w, "The identity provider refused the sign-in.", http.StatusForbidden)
		return
	}
	pd := oidc.Pending{State: d.PendingState, Nonce: d.PendingNonce, Verifier: d.PendingVerifier, Created: d.PendingCreated}
	ident, err := s.Provider.Finish(r.Context(), pd, r.URL.Query().Get("state"), r.URL.Query().Get("code"))
	if err != nil {
		s.Sessions.Delete(w, id)
		s.Log.Printf("sign-in failed: %v", err)
		http.Error(w, "Sign-in failed. Start again.", http.StatusForbidden)
		return
	}
	if status, _ := ident.Claims["status"].(string); status != "" && status != "active" {
		s.Sessions.Delete(w, id)
		http.Error(w, "This account is not active.", http.StatusForbidden)
		return
	}
	login, _ := ident.Claims["login"].(string)
	prev, errPrev := s.DB.GetUser(ident.Subject)
	isNew := errPrev != nil
	if s.DB.Flag("signin_off") && !s.isMaintainer(login) && (isNew || !prev.AdminGrant) {
		// administrators stay exempt, or nobody could turn the switch back off
		s.Sessions.Delete(w, id)
		http.Error(w, "Sign-in is switched off for now. Try again later.", http.StatusServiceUnavailable)
		return
	}
	if isNew && s.DB.Flag("signup_off") && !s.isMaintainer(login) {
		s.Sessions.Delete(w, id)
		http.Error(w, "This platform is not taking new accounts for now. Try again later.", http.StatusServiceUnavailable)
		return
	}
	u, err := s.DB.SeenUser(ident.Subject, login)
	if err != nil {
		s.Sessions.Delete(w, id)
		s.Log.Printf("sign-in: recording the user failed: %v", err)
		http.Error(w, "Sign-in failed. Try again later.", http.StatusInternalServerError)
		return
	}
	if u.Banned {
		s.Sessions.Delete(w, id)
		http.Error(w, "This account is suspended on this platform.", http.StatusForbidden)
		return
	}
	if s.isMaintainer(login) && !u.AdminGrant {
		if err := s.DB.SetGrant("bootstrap", u.Subject, "admin", true, "maintainer by 42 login"); err != nil {
			s.Log.Printf("admin bootstrap failed: %v", err)
		}
	}
	// a new session id at the change of privilege (no fixation)
	s.Sessions.Put(w, id, session.Data{Subject: ident.Subject, Claims: ident.Claims,
		RefreshToken: ident.RefreshToken, SignedInAt: time.Now()})
	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if !s.sameOrigin(r) {
		http.Error(w, "Cross-site request refused.", http.StatusForbidden)
		return
	}
	if id, _ := s.Sessions.Get(r); id != "" {
		s.Sessions.Delete(w, id)
	}
	w.WriteHeader(http.StatusNoContent)
}

// Me answers what the page needs to know: signed in or not, and the role flags.
// The pseudonymous subject is not sent: the page does not need it.
func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{"signed_in": false}
	if v, ok := s.viewer(r); ok {
		out = map[string]any{"signed_in": true, "login": v.Login, "member": v.Member, "admin": v.Admin}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(out)
}

// sameOrigin requires a state-changing request to come from our own pages: an Origin header
// equal to ours (browsers send it on POST), plus the SameSite cookie as a second line.
func (s *Server) sameOrigin(r *http.Request) bool {
	return r.Header.Get("Origin") == s.Origin
}

func truthy(v any) bool { b, _ := v.(bool); return b }

// Viewer is the signed-in user with the roles that apply now.
type Viewer struct {
	Subject, Login string
	Member, Admin  bool
	// AuthAt is when the user last really signed in: the provider's auth_time when it sends
	// one, otherwise when this platform's session began.
	AuthAt time.Time
}

// fromData computes the viewer of a session's data.
func (s *Server) fromData(d *session.Data) (Viewer, bool) {
	if d == nil || d.Subject == "" {
		return Viewer{}, false
	}
	u, err := s.DB.GetUser(d.Subject)
	if err != nil || u.Banned {
		return Viewer{}, false
	}
	linked := truthy(d.Claims["ft_linked"])
	if linked && !u.MemberUntil.IsZero() && time.Now().After(u.MemberUntil) {
		linked = false
	}
	if linked && !ftActive(d.Claims) {
		linked = false // the member role from a 42 link lasts while the 42 account is active
	}
	authAt := d.SignedInAt
	if at, ok := d.Claims["auth_time"].(float64); ok && at > 0 {
		authAt = time.Unix(int64(at), 0)
	}
	return Viewer{Subject: u.Subject, Login: u.Login, Member: u.MemberGrant || linked, Admin: u.AdminGrant, AuthAt: authAt}, true
}

// ftActive reads the Clubroom's claim ft_active: whether the linked 42 account is still
// active (decided: the member role from a 42 link follows the 42 account's own state, since
// 42 has no fixed school year). The Clubroom decides it from 42's data (cursus, blackhole).
// A missing claim counts as active until the Clubroom sends it, so nobody loses the role
// before then; change the last line to "return false" to refuse instead.
// The claim is read at sign-in: a change at 42 shows at the next sign-in (12 hours at most).
func ftActive(claims map[string]any) bool {
	v, ok := claims["ft_active"].(bool)
	if ok {
		return v
	}
	return true
}

// CheckRelay is the relay's re-check: the session still exists, belongs to the subject,
// and the user is a member and not banned.
func (s *Server) CheckRelay(subject, sidHash string) error {
	d, ok := s.Sessions.GetByHash(sidHash)
	if !ok {
		return errors.New("signed out")
	}
	v, ok := s.fromData(d)
	switch {
	case !ok:
		return errors.New("account not allowed")
	case v.Subject != subject:
		return errors.New("token does not match the session")
	case !v.Member:
		return errors.New("members only")
	}
	return nil
}

// relayToken mints a 5-minute relay token for a member. POST from our own pages only.
func (s *Server) relayToken(w http.ResponseWriter, r *http.Request) {
	if !s.sameOrigin(r) {
		http.Error(w, "Cross-site request refused.", http.StatusForbidden)
		return
	}
	id, d := s.Sessions.Get(r)
	v, ok := s.fromData(d)
	if !ok {
		http.Error(w, "Sign in first.", http.StatusUnauthorized)
		return
	}
	if !v.Member {
		http.Error(w, "The relay is for members.", http.StatusForbidden)
		return
	}
	tok, err := s.Minter.Mint(v.Subject, session.IDHash(id), time.Now())
	if err != nil {
		http.Error(w, "Could not make a token.", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{"token": tok, "expires_in": int(relay.Lifetime.Seconds())})
}

// viewer combines the Clubroom's claims (identity, status, 42 link) with this platform's
// own grants (decision: roles are split). A banned user has no viewer.
func (s *Server) viewer(r *http.Request) (Viewer, bool) {
	_, d := s.Sessions.Get(r)
	return s.fromData(d)
}

// Who is what the proxy asks: the signed-in user's subject.
func (s *Server) Who(r *http.Request) (string, bool) {
	v, ok := s.viewer(r)
	return v.Subject, ok
}

func (s *Server) isMaintainer(login string) bool {
	for _, a := range s.AdminLogins {
		if login != "" && strings.EqualFold(a, login) {
			return true
		}
	}
	return false
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}
