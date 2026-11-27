package web

import (
	"encoding/json"
	"errors"
	"mime"
	"net/http"
	"strconv"
	"time"

	"github.com/42-UNIX-CLUB/ucdotweb/internal/store"
)

// The admin API, as JSON under /api/admin/. Administrators only. Reads are GET; changes are
// POST with a JSON body from our own origin, and every change writes the audit log in the
// same transaction. Users are identified by their pseudonymous Clubroom subject.
//
//	GET  /api/admin/users?q=LOGIN&limit=N&offset=N   list, most recently seen first
//	GET  /api/admin/users/{subject}                  one user, 7 days of usage, 50 last connections
//	POST /api/admin/users/{subject}/grant            {"grant": "member"|"admin"|"banned", "on": bool, "reason": "..."}
//	GET  /api/admin/quotas                           every tier's limits
//	POST /api/admin/quotas                           {"tier": "user"|"member", "bytes_per_day": N, "conns": N, "dests_per_min": N, "reqs_per_min": N}
//	GET  /api/admin/flags                            panic switches
//	POST /api/admin/flag                             {"name": "proxy_off"|"relay_off"|"all_off"|"signin_off"|"signup_off", "on": bool}
//	GET  /api/admin/caps                             platform caps: bytes a day per service, all users together (0: none)
//	POST /api/admin/caps                             {"service": "proxy"|"relay", "bytes_per_day": N}
//	GET  /api/admin/audit?before=ID&limit=N          audit log, newest first
//	GET  /api/admin/conns?subject=S&before=UNIX&limit=N   connection log (host only), newest first
//	GET  /api/admin/allowlist                        the proxy's allow-list, by host (admin_allowlist.go)
//	POST /api/admin/allowlist                        {"host": "...", "prefixes": ["/..."], "git": bool, "releases": bool} add or replace
//	POST /api/admin/allowlist/remove                 {"host": "..."}
//	POST /api/admin/reports                          file an abuse report; a critical one suspends at once (admin_safety.go)
//	GET  /api/admin/reports                          reports, newest first
//	GET  /api/admin/safety                           the safety watcher's state and last checks
//
// A maintainer listed in AdminLogins whose admin grant is removed gets it back at the next
// sign-in: the list is the source of truth for maintainers ("The admins are the maintainers").
func (s *Server) adminRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/admin/users", s.admin(s.adminUsers))
	mux.HandleFunc("GET /api/admin/users/{subject}", s.admin(s.adminUser))
	mux.HandleFunc("POST /api/admin/users/{subject}/grant", s.adminChange(s.adminGrant))
	mux.HandleFunc("GET /api/admin/quotas", s.admin(s.adminQuotas))
	mux.HandleFunc("POST /api/admin/quotas", s.adminChange(s.adminSetQuota))
	mux.HandleFunc("GET /api/admin/flags", s.admin(s.adminFlags))
	mux.HandleFunc("POST /api/admin/flag", s.adminChange(s.adminFlag))
	mux.HandleFunc("GET /api/admin/caps", s.admin(s.adminCaps))
	mux.HandleFunc("POST /api/admin/caps", s.adminChange(s.adminSetCap))
	mux.HandleFunc("GET /api/admin/audit", s.admin(s.adminAudit))
	mux.HandleFunc("GET /api/admin/conns", s.admin(s.adminConns))
}

type adminHandler func(w http.ResponseWriter, r *http.Request, v Viewer)

// admin lets only administrators through.
func (s *Server) admin(h adminHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		v, ok := s.viewer(r)
		if !ok {
			http.Error(w, "Sign in first.", http.StatusUnauthorized)
			return
		}
		if !v.Admin {
			http.Error(w, "Administrators only.", http.StatusForbidden)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		h(w, r, v)
	}
}

// adminChange is admin plus the checks for a change: our own origin, a JSON body, and a
// recent sign-in (AdminFresh). A stale one gets 401 with {"error": "reauth", "login": URL}:
// the admin program sends the person through that URL and retries.
func (s *Server) adminChange(h adminHandler) http.HandlerFunc {
	inner := s.admin(func(w http.ResponseWriter, r *http.Request, v Viewer) {
		fresh := s.AdminFresh
		if fresh == 0 {
			fresh = 15 * time.Minute
		}
		if time.Since(v.AuthAt) > fresh {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "reauth", "login": "/auth/login?reauth=1",
				"message": "Sign in again to make changes."})
			return
		}
		h(w, r, v)
	})
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.sameOrigin(r) {
			http.Error(w, "Cross-site request refused.", http.StatusForbidden)
			return
		}
		if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
			http.Error(w, "Expected a JSON body.", http.StatusBadRequest)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		inner(w, r)
	}
}

func decode(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return errors.New("Expected a JSON body with the documented fields.")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// intParam reads a whole number from the query, with a default and an upper bound.
func intParam(r *http.Request, name string, def, max int64) int64 {
	n, err := strconv.ParseInt(r.URL.Query().Get(name), 10, 64)
	if err != nil || n < 0 {
		return def
	}
	if n > max {
		return max
	}
	return n
}

func unix(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

func userJSON(u store.User) map[string]any {
	return map[string]any{"subject": u.Subject, "login": u.Login, "member_grant": u.MemberGrant,
		"member_until": unix(u.MemberUntil), "admin": u.AdminGrant, "banned": u.Banned, "ban_reason": u.BanReason}
}

func (s *Server) adminUsers(w http.ResponseWriter, r *http.Request, _ Viewer) {
	rows, err := s.DB.ListUsers(r.URL.Query().Get("q"), int(intParam(r, "limit", 50, 500)), int(intParam(r, "offset", 0, 1<<31)))
	if err != nil {
		http.Error(w, "Could not read the users.", http.StatusInternalServerError)
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, u := range rows {
		m := userJSON(u.User)
		m["first_seen"], m["last_seen"] = u.FirstSeen.Unix(), u.LastSeen.Unix()
		out = append(out, m)
	}
	writeJSON(w, map[string]any{"users": out})
}

func (s *Server) adminUser(w http.ResponseWriter, r *http.Request, _ Viewer) {
	sub := r.PathValue("subject")
	u, err := s.DB.GetUser(sub)
	if err != nil {
		http.Error(w, "No such user.", http.StatusNotFound)
		return
	}
	usage, err1 := s.DB.Usage(sub, 7)
	conns, err2 := s.DB.Conns(sub, time.Time{}, 50)
	if err1 != nil || err2 != nil {
		http.Error(w, "Could not read the user's activity.", http.StatusInternalServerError)
		return
	}
	us := make([]map[string]any, 0, len(usage))
	for _, x := range usage {
		us = append(us, map[string]any{"day": x.Day, "kind": x.Kind, "bytes": x.Bytes, "requests": x.Requests})
	}
	writeJSON(w, map[string]any{"user": userJSON(u), "usage": us, "conns": connsJSON(conns)})
}

func (s *Server) adminGrant(w http.ResponseWriter, r *http.Request, v Viewer) {
	var in struct {
		Grant  string `json:"grant"`
		On     bool   `json:"on"`
		Reason string `json:"reason"`
	}
	if err := decode(r, &in); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	switch in.Grant {
	case "member", "admin", "banned":
	default:
		http.Error(w, "Unknown grant.", http.StatusBadRequest)
		return
	}
	if in.Grant == "banned" && in.On && in.Reason == "" {
		http.Error(w, "A ban needs a reason.", http.StatusBadRequest)
		return
	}
	if len(in.Reason) > 500 {
		http.Error(w, "The reason is too long (500 characters at most).", http.StatusBadRequest)
		return
	}
	sub := r.PathValue("subject")
	if _, err := s.DB.GetUser(sub); err != nil {
		http.Error(w, "No such user.", http.StatusNotFound)
		return
	}
	if err := s.DB.SetGrant(v.Subject, sub, in.Grant, in.On, in.Reason); err != nil {
		http.Error(w, "Could not change the grant.", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func quotaJSON(q store.Quota) map[string]any {
	return map[string]any{"bytes_per_day": q.BytesPerDay, "conns": q.Conns, "dests_per_min": q.DestsPerMin, "reqs_per_min": q.ReqsPerMin}
}

func (s *Server) adminQuotas(w http.ResponseWriter, r *http.Request, _ Viewer) {
	qs, err := s.DB.Quotas()
	if err != nil {
		http.Error(w, "Could not read the quotas.", http.StatusInternalServerError)
		return
	}
	out := map[string]any{}
	for t, q := range qs {
		out[t] = quotaJSON(q)
	}
	writeJSON(w, map[string]any{"quotas": out})
}

func (s *Server) adminSetQuota(w http.ResponseWriter, r *http.Request, v Viewer) {
	var in struct {
		Tier        string `json:"tier"`
		BytesPerDay *int64 `json:"bytes_per_day"`
		Conns       *int   `json:"conns"`
		DestsPerMin *int   `json:"dests_per_min"`
		ReqsPerMin  *int   `json:"reqs_per_min"`
	}
	if err := decode(r, &in); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// every limit must be given: a forgotten field must not silently become "no limit" (0)
	if in.BytesPerDay == nil || in.Conns == nil || in.DestsPerMin == nil || in.ReqsPerMin == nil {
		http.Error(w, "Give all four limits (0 means no limit of that kind).", http.StatusBadRequest)
		return
	}
	q := store.Quota{BytesPerDay: *in.BytesPerDay, Conns: *in.Conns, DestsPerMin: *in.DestsPerMin, ReqsPerMin: *in.ReqsPerMin}
	if q.BytesPerDay < 0 || q.Conns < 0 || q.DestsPerMin < 0 || q.ReqsPerMin < 0 {
		http.Error(w, "Limits cannot be negative.", http.StatusBadRequest)
		return
	}
	if err := s.DB.SetQuota(v.Subject, in.Tier, q); err != nil {
		http.Error(w, "Unknown tier, or the change failed.", http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) adminFlags(w http.ResponseWriter, r *http.Request, _ Viewer) {
	rows, err := s.DB.Flags()
	if err != nil {
		http.Error(w, "Could not read the switches.", http.StatusInternalServerError)
		return
	}
	// every known switch is listed, set or not
	out := map[string]any{}
	for _, n := range switches {
		out[n] = map[string]any{"on": false}
	}
	for _, f := range rows {
		out[f.Name] = map[string]any{"on": f.On, "at": f.At.Unix(), "by": f.By}
	}
	writeJSON(w, map[string]any{"flags": out})
}

// switches are the panic switches. signin_off never stops administrators; signup_off refuses
// the first sign-in of someone this platform has not seen.
var switches = []string{"proxy_off", "relay_off", "all_off", "signin_off", "signup_off"}

// adminFlag turns a panic switch on or off.
func (s *Server) adminFlag(w http.ResponseWriter, r *http.Request, v Viewer) {
	var in struct {
		Name string `json:"name"`
		On   bool   `json:"on"`
	}
	if err := decode(r, &in); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	known := false
	for _, n := range switches {
		known = known || n == in.Name
	}
	if !known {
		http.Error(w, "Unknown switch.", http.StatusBadRequest)
		return
	}
	if err := s.DB.SetFlag(v.Subject, in.Name, in.On); err != nil {
		http.Error(w, "Could not change the switch.", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) adminAudit(w http.ResponseWriter, r *http.Request, _ Viewer) {
	rows, err := s.DB.Audit(intParam(r, "before", 0, 1<<62), int(intParam(r, "limit", 100, 1000)))
	if err != nil {
		http.Error(w, "Could not read the audit log.", http.StatusInternalServerError)
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, a := range rows {
		out = append(out, map[string]any{"id": a.ID, "at": a.At.Unix(), "actor": a.Actor, "action": a.Action,
			"target": a.Target, "detail": a.Detail})
	}
	writeJSON(w, map[string]any{"audit": out})
}

func connsJSON(rows []store.ConnRow) []map[string]any {
	out := make([]map[string]any, 0, len(rows))
	for _, c := range rows {
		out = append(out, map[string]any{"at": c.At.Unix(), "subject": c.Subject, "kind": c.Kind, "host": c.Host,
			"bytes": c.Bytes, "outcome": c.Outcome})
	}
	return out
}

func (s *Server) adminConns(w http.ResponseWriter, r *http.Request, _ Viewer) {
	var before time.Time
	if b := intParam(r, "before", 0, 1<<40); b > 0 {
		before = time.Unix(b, 0)
	}
	rows, err := s.DB.Conns(r.URL.Query().Get("subject"), before, int(intParam(r, "limit", 100, 1000)))
	if err != nil {
		http.Error(w, "Could not read the connection log.", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"conns": connsJSON(rows)})
}

func (s *Server) adminCaps(w http.ResponseWriter, r *http.Request, _ Viewer) {
	caps, err := s.DB.Caps()
	if err != nil {
		http.Error(w, "Could not read the caps.", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"caps": caps})
}

func (s *Server) adminSetCap(w http.ResponseWriter, r *http.Request, v Viewer) {
	var in struct {
		Service     string `json:"service"`
		BytesPerDay *int64 `json:"bytes_per_day"`
	}
	if err := decode(r, &in); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if in.BytesPerDay == nil || *in.BytesPerDay < 0 {
		http.Error(w, "Give bytes_per_day, 0 or more (0 means no cap).", http.StatusBadRequest)
		return
	}
	if err := s.DB.SetCap(v.Subject, in.Service, *in.BytesPerDay); err != nil {
		http.Error(w, "Unknown service, or the change failed.", http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
