// Package web is the platform's HTTP surface for the browser: sign-in through the identity
// provider (backend for frontend), sign-out, and the current user. The proxy, the relay and
// the admin API attach here later.
package web

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/42-UNIX-CLUB/ucdotweb/internal/oidc"
	"github.com/42-UNIX-CLUB/ucdotweb/internal/session"
)

// Server holds what the handlers need.
type Server struct {
	Provider *oidc.Provider
	Sessions *session.Store
	Origin   string // our own origin, for example https://dux.ensui.dev; checked on state changes
	Log      *log.Logger
}

// Handler returns the routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /auth/login", s.login)
	mux.HandleFunc("GET /auth/callback", s.callback)
	mux.HandleFunc("POST /auth/logout", s.logout)
	mux.HandleFunc("GET /api/me", s.me)
	return securityHeaders(mux)
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	oldID, _ := s.Sessions.Get(r)
	to, pd := s.Provider.Start()
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
	_, d := s.Sessions.Get(r)
	out := map[string]any{"signed_in": false}
	if d != nil && d.Subject != "" {
		out = map[string]any{"signed_in": true, "login": d.Claims["login"],
			"member": truthy(d.Claims["uc_os_member"]) || truthy(d.Claims["ft_linked"]),
			"admin":  truthy(d.Claims["uc_os_admin"])}
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

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}
