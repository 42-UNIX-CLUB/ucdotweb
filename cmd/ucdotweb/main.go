// Command ucdotweb is the UC.OS web platform service. Configuration comes from the
// environment; secrets are read from files so they never appear in a process listing or a
// shell history.
//
//	UCDOTWEB_LISTEN         address to listen on, for example 127.0.0.1:8090 (behind the TLS terminator)
//	UCDOTWEB_ORIGIN         our public origin, for example https://dux.ensui.dev
//	UCDOTWEB_ISSUER         the identity provider's issuer URL
//	UCDOTWEB_CLIENT_ID      our client id at the provider
//	UCDOTWEB_SECRET_FILE    a file holding the client secret (one line)
//	UCDOTWEB_DB             the SQLite database file
//	UCDOTWEB_DB_KEY_FILE    a file holding 64 hex characters (32 bytes): encrypts sessions at rest; seals the pending sign-in cookie
//	UCDOTWEB_ADMIN_LOGINS   comma-separated 42 logins of the maintainers (administrators); counts only with ft_linked true
//	UCDOTWEB_PROXY_RULES    optional JSON file that seeds the proxy's allow-list on the first start only (default: built in)
//	UCDOTWEB_RELAY_KEY_FILE a file holding 64 hex characters: the Ed25519 seed that signs relay tokens
//	UCDOTWEB_RELAY_PORTS    optional, comma-separated destination ports (default 80,443)
//	UCDOTWEB_ADMIN_FRESH    optional: how recently an administrator must have signed in to change anything (default 15m)
//	UCDOTWEB_BUNDLE_DIR     optional: where device-transfer bundles are kept (default: a "bundles" directory beside the database)
//	UCDOTWEB_INSECURE_COOKIES=1  only for local tests over plain http
//
// Safety automation (all optional; see internal/safety):
//
//	UCDOTWEB_SAFETY_SWITCH          which switch an automatic suspension sets: relay_off (default), proxy_off, all_off
//	UCDOTWEB_SAFETY_INTERVAL        time between checks, for example 1m (default)
//	UCDOTWEB_SAFETY_TRAFFIC_FACTOR  today's traffic above this many times the 7-day daily average trips (default 5)
//	UCDOTWEB_SAFETY_TRAFFIC_FLOOR   and at least this many bytes (default 10 GB)
//	UCDOTWEB_WEBHOOK_URL_FILE       a file holding the chat webhook's https URL; unset: no webhook
//	UCDOTWEB_WEBHOOK_FORMAT         content (Discord) or text (Slack and others); default from the host
//	UCDOTWEB_SMTP_HOST              mail server; unset: no mail. STARTTLS is required
//	UCDOTWEB_SMTP_PORT              default 587
//	UCDOTWEB_SMTP_FROM, UCDOTWEB_SMTP_TO   sender, and a comma-separated list of recipients
//	UCDOTWEB_SMTP_AUTH_FILE         optional: user name on line 1, password on line 2
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/42-UNIX-CLUB/ucdotweb/internal/oidc"
	"github.com/42-UNIX-CLUB/ucdotweb/internal/proxy"
	"github.com/42-UNIX-CLUB/ucdotweb/internal/relay"
	"github.com/42-UNIX-CLUB/ucdotweb/internal/safety"
	"github.com/42-UNIX-CLUB/ucdotweb/internal/session"
	"github.com/42-UNIX-CLUB/ucdotweb/internal/store"
	"github.com/42-UNIX-CLUB/ucdotweb/internal/web"
)

func need(name string) string {
	v := os.Getenv(name)
	if v == "" {
		log.Fatalf("%s is not set", name)
	}
	return v
}

func hexFile(logger *log.Logger, env string, n int) []byte {
	raw, err := os.ReadFile(need(env))
	if err != nil {
		logger.Fatalf("reading %s: %v", env, err)
	}
	b, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(b) != n {
		logger.Fatalf("%s must hold %d hex characters (make one: openssl rand -hex %d)", env, 2*n, n)
	}
	return b
}

func main() {
	logger := log.New(os.Stderr, "ucdotweb: ", log.LstdFlags)
	origin := need("UCDOTWEB_ORIGIN")
	if err := web.CheckOrigin(origin); err != nil {
		logger.Fatalf("UCDOTWEB_ORIGIN: %v", err) // every Origin check compares this exact string
	}
	secret, err := os.ReadFile(need("UCDOTWEB_SECRET_FILE"))
	if err != nil {
		logger.Fatalf("reading the client secret file: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	prov, err := oidc.Discover(ctx, oidc.Config{
		Issuer: need("UCDOTWEB_ISSUER"), ClientID: need("UCDOTWEB_CLIENT_ID"),
		ClientSecret: strings.TrimSpace(string(secret)), RedirectURL: origin + "/auth/callback",
		Scopes: []string{"uc-os:connect"},
	}, nil)
	cancel()
	if err != nil {
		logger.Fatalf("identity provider: %v", err)
	}
	key := hexFile(logger, "UCDOTWEB_DB_KEY_FILE", 32)
	db, err := store.Open(need("UCDOTWEB_DB"), key)
	if err != nil {
		logger.Fatalf("database: %v", err)
	}
	defer db.Close()
	rules, err := proxy.LoadRules(os.Getenv("UCDOTWEB_PROXY_RULES"))
	if err != nil {
		logger.Fatalf("proxy rules: %v", err)
	}
	var admins []string
	for _, a := range strings.Split(os.Getenv("UCDOTWEB_ADMIN_LOGINS"), ",") {
		if a = strings.TrimSpace(a); a != "" {
			admins = append(admins, a)
		}
	}
	const idle, absolute = 30 * time.Minute, 12 * time.Hour
	srv := &web.Server{Provider: prov, Origin: origin, Log: logger, DB: db, AdminLogins: admins,
		Sessions: session.NewWith(db, idle, absolute, os.Getenv("UCDOTWEB_INSECURE_COOKIES") != "1")}
	px := &proxy.Proxy{Rules: rules, DB: db, Who: srv.Who}
	if err := px.Start(); err != nil {
		logger.Fatalf("proxy allow-list: %v", err)
	}
	srv.Proxy = px
	relayKey := ed25519.NewKeyFromSeed(hexFile(logger, "UCDOTWEB_RELAY_KEY_FILE", 32))
	srv.Minter = &relay.Minter{Issuer: origin, Kid: "relay-1", Key: relayKey}
	verifier, err := relay.NewVerifier(origin, "relay-1", relayKey.Public().(ed25519.PublicKey))
	if err != nil {
		logger.Fatalf("relay key: %v", err)
	}
	ports := []int{80, 443}
	if v := os.Getenv("UCDOTWEB_RELAY_PORTS"); v != "" {
		ports = nil
		for _, p := range strings.Split(v, ",") {
			n, err := strconv.Atoi(strings.TrimSpace(p))
			if err != nil || n < 1 || n > 65535 {
				logger.Fatalf("UCDOTWEB_RELAY_PORTS: bad port %q", p)
			}
			ports = append(ports, n)
		}
	}
	srv.Relay = &relay.Relay{Verifier: verifier, DB: db, Origin: origin, Check: srv.CheckRelay, Ports: ports, Log: logger}
	safetyCfg, err := safety.ConfigFromEnv(os.Getenv)
	if err != nil {
		logger.Fatalf("safety: %v", err)
	}
	notifier, err := safety.NotifierFromEnv(os.Getenv)
	if err != nil {
		logger.Fatalf("notifications: %v", err)
	}
	if notifier == nil {
		logger.Printf("safety: no notifications configured (UCDOTWEB_WEBHOOK_URL_FILE, UCDOTWEB_SMTP_HOST)")
	}
	watcher, err := safety.New(db, safetyCfg, notifier, logger)
	if err != nil {
		logger.Fatalf("safety: %v", err)
	}
	srv.Safety = watcher
	if v := os.Getenv("UCDOTWEB_ADMIN_FRESH"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d < time.Minute {
			logger.Fatalf("UCDOTWEB_ADMIN_FRESH: want a duration of a minute or more, like 15m")
		}
		srv.AdminFresh = d
	}
	srv.BundleDir = os.Getenv("UCDOTWEB_BUNDLE_DIR")
	if srv.BundleDir == "" {
		srv.BundleDir = filepath.Join(filepath.Dir(need("UCDOTWEB_DB")), "bundles")
	}
	if err := os.MkdirAll(srv.BundleDir, 0o700); err != nil {
		logger.Fatalf("bundle directory: %v", err)
	}
	go watcher.Run(context.Background())
	go func() { // housekeeping: expired sessions, connection logs past 30 days, old report summaries, expired bundles
		for {
			_, _ = db.SessionPurge(idle, absolute)
			_, _ = db.PurgeLogs(30 * 24 * time.Hour)
			_, _ = db.EraseOldReportSummaries(365 * 24 * time.Hour) // decided: report summaries kept 12 months
			if _, err := srv.PurgeBundles(); err != nil {
				logger.Printf("bundles: purge: %v", err)
			}
			time.Sleep(time.Hour)
		}
	}()
	hs := &http.Server{Addr: need("UCDOTWEB_LISTEN"), Handler: srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute}
	logger.Printf("listening on %s for %s", hs.Addr, origin)
	logger.Fatal(hs.ListenAndServe())
}
