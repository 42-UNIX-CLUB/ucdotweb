package web

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/42-UNIX-CLUB/ucdotweb/internal/store"
)

// The safety part of the admin API. Administrators only, like the rest of /api/admin/.
//
//	POST /api/admin/reports                   {"severity": "low"|"medium"|"high"|"critical", "subject": "...", "source": "...", "summary": "..."}
//	GET  /api/admin/reports?before=ID&limit=N abuse reports, newest first
//	GET  /api/admin/safety                    the watcher's switch, last pass, checks and last suspension
//
// A critical report runs the watcher at once, so the suspension is in place when the answer
// comes back. Reports are entered by administrators only: there is no public intake.
func (s *Server) safetyRoutes(mux *http.ServeMux) {
	if err := s.DB.EnsureSafety(); err != nil && s.Log != nil { // idempotent; also done by safety.New
		s.Log.Printf("safety: %v", err)
	}
	mux.HandleFunc("POST /api/admin/reports", s.adminChange(s.adminFileReport))
	mux.HandleFunc("GET /api/admin/reports", s.admin(s.adminReports))
	mux.HandleFunc("GET /api/admin/safety", s.admin(s.adminSafety))
}

func (s *Server) adminFileReport(w http.ResponseWriter, r *http.Request, v Viewer) {
	var in struct {
		Severity string `json:"severity"`
		Subject  string `json:"subject"`
		Source   string `json:"source"`
		Summary  string `json:"summary"`
	}
	if err := decode(r, &in); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !store.ReportSeverityValid(in.Severity) {
		http.Error(w, "Unknown severity (low, medium, high or critical).", http.StatusBadRequest)
		return
	}
	in.Summary = strings.TrimSpace(in.Summary)
	if in.Summary == "" {
		http.Error(w, "A report needs a summary.", http.StatusBadRequest)
		return
	}
	if len(in.Subject) > 200 || len(in.Source) > 200 || len(in.Summary) > 2000 {
		http.Error(w, "Too long (subject and source 200 characters, summary 2000).", http.StatusBadRequest)
		return
	}
	id, err := s.DB.AddReport(v.Subject, store.Report{Severity: in.Severity, Subject: in.Subject,
		Source: in.Source, Summary: in.Summary})
	if err != nil {
		http.Error(w, "Could not store the report.", http.StatusInternalServerError)
		return
	}
	out := map[string]any{"id": id, "watcher": s.Safety != nil}
	if s.Safety != nil && in.Severity == "critical" {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), time.Minute)
		st := s.Safety.Check(ctx)
		cancel()
		out["suspended"] = st.Suspended
		out["switch"] = st.Switch
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	writeJSON(w, out)
}

func (s *Server) adminReports(w http.ResponseWriter, r *http.Request, _ Viewer) {
	rows, err := s.DB.Reports(intParam(r, "before", 0, 1<<62), int(intParam(r, "limit", 100, 1000)))
	if err != nil {
		http.Error(w, "Could not read the reports.", http.StatusInternalServerError)
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, x := range rows {
		out = append(out, map[string]any{"id": x.ID, "at": x.At.Unix(), "actor": x.Actor, "severity": x.Severity,
			"subject": x.Subject, "source": x.Source, "summary": x.Summary})
	}
	writeJSON(w, map[string]any{"reports": out})
}

func (s *Server) adminSafety(w http.ResponseWriter, r *http.Request, _ Viewer) {
	if s.Safety == nil {
		http.Error(w, "The safety watcher is not running.", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, s.Safety.Status())
}
