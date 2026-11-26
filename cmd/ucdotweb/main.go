// Command ucdotweb is the UC.OS web platform service. Configuration comes from the
// environment; secrets are read from files so they never appear in a process listing or a
// shell history.
//
//	UCDOTWEB_LISTEN         address to listen on, for example 127.0.0.1:8090 (behind the TLS terminator)
//	UCDOTWEB_ORIGIN         our public origin, for example https://dux.ensui.dev
//	UCDOTWEB_ISSUER         the identity provider's issuer URL
//	UCDOTWEB_CLIENT_ID      our client id at the provider
//	UCDOTWEB_SECRET_FILE    a file holding the client secret (one line)
//	UCDOTWEB_INSECURE_COOKIES=1  only for local tests over plain http
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/42-UNIX-CLUB/ucdotweb/internal/oidc"
	"github.com/42-UNIX-CLUB/ucdotweb/internal/session"
	"github.com/42-UNIX-CLUB/ucdotweb/internal/web"
)

func need(name string) string {
	v := os.Getenv(name)
	if v == "" {
		log.Fatalf("%s is not set", name)
	}
	return v
}

func main() {
	logger := log.New(os.Stderr, "ucdotweb: ", log.LstdFlags)
	origin := need("UCDOTWEB_ORIGIN")
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
	srv := &web.Server{Provider: prov, Origin: origin, Log: logger,
		Sessions: session.New(30*time.Minute, 12*time.Hour, os.Getenv("UCDOTWEB_INSECURE_COOKIES") != "1")}
	hs := &http.Server{Addr: need("UCDOTWEB_LISTEN"), Handler: srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute}
	logger.Printf("listening on %s for %s", hs.Addr, origin)
	logger.Fatal(hs.ListenAndServe())
}
