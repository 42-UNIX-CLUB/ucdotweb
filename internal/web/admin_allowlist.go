package web

import (
	"errors"
	"net/http"

	"github.com/42-UNIX-CLUB/ucdotweb/internal/proxy"
	"github.com/42-UNIX-CLUB/ucdotweb/internal/store"
)

// The proxy's allow-list, edited by administrators. A change takes effect on the next proxy
// request, without a restart. Same rules as the rest of the admin API (see admin.go).
//
//	GET  /api/admin/allowlist          every rule, sorted by host
//	POST /api/admin/allowlist          {"host": "deb.debian.org", "prefixes": ["/debian/"], "git": bool, "releases": bool}
//	                                   adds the rule, or replaces the rule for that host
//	POST /api/admin/allowlist/remove   {"host": "deb.debian.org"}
//
// A host is a plain lowercase public DNS name; prefixes start with "/" (at most 16, each at
// most 200 characters). "git" allows the clone paths of any repository on the host;
// "releases" allows /{owner}/{repo}/releases/download/ and /{owner}/{repo}/archive/.
func (s *Server) allowlistRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/admin/allowlist", s.admin(s.adminAllowlist))
	mux.HandleFunc("POST /api/admin/allowlist", s.adminChange(s.adminAllowPut))
	mux.HandleFunc("POST /api/admin/allowlist/remove", s.adminChange(s.adminAllowRemove))
}

func (s *Server) adminAllowlist(w http.ResponseWriter, r *http.Request, _ Viewer) {
	rows, err := s.DB.AllowRules()
	if err != nil {
		http.Error(w, "Could not read the allow-list.", http.StatusInternalServerError)
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, a := range rows {
		out = append(out, map[string]any{"host": a.Host, "prefixes": a.Prefixes, "git": a.Git, "releases": a.Releases,
			"updated_at": a.UpdatedAt.Unix(), "updated_by": a.UpdatedBy})
	}
	writeJSON(w, map[string]any{"rules": out})
}

func (s *Server) adminAllowPut(w http.ResponseWriter, r *http.Request, v Viewer) {
	var in struct {
		Host     string   `json:"host"`
		Prefixes []string `json:"prefixes"`
		Git      bool     `json:"git"`
		Releases bool     `json:"releases"`
	}
	if err := decode(r, &in); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	rule := proxy.Rule{Host: in.Host, Prefixes: in.Prefixes, Git: in.Git, Releases: in.Releases}
	if err := proxy.ValidateRule(rule); err != nil {
		http.Error(w, "Rule refused: "+err.Error()+".", http.StatusBadRequest)
		return
	}
	if _, err := s.DB.PutAllowRule(v.Subject, rule.ToStore()); err != nil {
		http.Error(w, "Could not change the allow-list.", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) adminAllowRemove(w http.ResponseWriter, r *http.Request, v Viewer) {
	var in struct {
		Host string `json:"host"`
	}
	if err := decode(r, &in); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	err := s.DB.RemoveAllowRule(v.Subject, in.Host)
	if errors.Is(err, store.ErrNoAllowRule) {
		http.Error(w, "No rule for that host.", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "Could not change the allow-list.", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
