// Command oidc-standin runs the test identity provider locally, standing in for the Virtual
// Clubroom. TESTS AND LOCAL DEVELOPMENT ONLY: it approves everyone as one fixed user.
// It refuses to listen on anything but a loopback address.
//
//	oidc-standin -listen 127.0.0.1:8091 -redirect http://127.0.0.1:8090/auth/callback -login rucosta -member
package main

import (
	"flag"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/42-UNIX-CLUB/ucdotweb/internal/standin"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:8091", "loopback address to listen on")
	redirect := flag.String("redirect", "http://127.0.0.1:8090/auth/callback", "the platform's callback URL")
	clientID := flag.String("client-id", "uc-os", "client id")
	secret := flag.String("secret", "local-test-secret", "client secret (a test value)")
	login := flag.String("login", "testuser", "login of the test user")
	member := flag.Bool("member", false, "the test user is a member (linked 42 account)")
	admin := flag.Bool("admin", false, "the test user is a UC.OS administrator")
	flag.Parse()

	host, _, err := net.SplitHostPort(*listen)
	if ip := net.ParseIP(host); err != nil || ip == nil || !ip.IsLoopback() {
		log.Fatalf("refusing to listen on %q: loopback addresses only", *listen)
	}
	p := standin.New("http://"+*listen, *clientID, *secret, *redirect, standin.User{
		Subject: "standin-" + *login,
		Claims: map[string]any{"login": *login, "status": "active", "ft_linked": *member,
			"campus": "Lisboa", "uc_os_member": false, "uc_os_admin": *admin},
	})
	log.Printf("test identity provider at http://%s (issuer), user %q", *listen, *login)
	hs := &http.Server{Addr: *listen, Handler: p.Handler(), ReadHeaderTimeout: 10 * time.Second}
	log.Fatal(hs.ListenAndServe())
}
