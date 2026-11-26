// Package standin is a minimal OpenID Connect provider for TESTS ONLY. It stands in for the
// Virtual Clubroom until the Clubroom's provider exists, speaking the protocol we will ask of
// it: discovery, authorization code with PKCE (S256 only), a token endpoint with client
// authentication, an Ed25519-signed ID token, and a JWK set. It approves every request as the
// test user it was given and never asks anything. Never expose it on a network.
package standin

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/42-UNIX-CLUB/ucdotweb/internal/jose"
)

// User is the identity the stand-in hands out, with the claims the Clubroom will send.
type User struct {
	Subject string
	Claims  map[string]any // for example login, status, ft_linked, campus, uc_os_member, uc_os_admin
}

// Provider is the stand-in.
type Provider struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	User         User

	priv  ed25519.PrivateKey
	pub   ed25519.PublicKey
	kid   string
	mu    sync.Mutex
	codes map[string]grant
}

type grant struct {
	challenge, nonce, redirect string
	expires                    time.Time
}

// New makes a stand-in with a fresh signing key.
func New(issuer, clientID, secret, redirect string, u User) *Provider {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	return &Provider{Issuer: issuer, ClientID: clientID, ClientSecret: secret, RedirectURL: redirect, User: u,
		priv: priv, pub: pub, kid: "standin-1", codes: map[string]grant{}}
}

// Handler serves the provider's endpoints under the issuer's path.
func (p *Provider) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("GET /authorize", p.authorize)
	mux.HandleFunc("POST /token", p.token)
	mux.HandleFunc("GET /jwks", p.jwks)
	return mux
}

func (p *Provider) discovery(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{
		"issuer":                                p.Issuer,
		"authorization_endpoint":                p.Issuer + "/authorize",
		"token_endpoint":                        p.Issuer + "/token",
		"jwks_uri":                              p.Issuer + "/jwks",
		"response_types_supported":              []string{"code"},
		"code_challenge_methods_supported":      []string{"S256"},
		"id_token_signing_alg_values_supported": []string{"EdDSA"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic"},
	})
}

func (p *Provider) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("client_id") != p.ClientID || q.Get("redirect_uri") != p.RedirectURL {
		http.Error(w, "unknown client or redirect", 400)
		return
	}
	if q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		http.Error(w, "code flow with PKCE S256 only", 400)
		return
	}
	code := rnd(24)
	p.mu.Lock()
	p.codes[code] = grant{challenge: q.Get("code_challenge"), nonce: q.Get("nonce"), redirect: q.Get("redirect_uri"),
		expires: time.Now().Add(time.Minute)}
	p.mu.Unlock()
	to, _ := url.Parse(p.RedirectURL)
	v := to.Query()
	v.Set("code", code)
	v.Set("state", q.Get("state"))
	to.RawQuery = v.Encode()
	http.Redirect(w, r, to.String(), http.StatusFound)
}

func (p *Provider) token(w http.ResponseWriter, r *http.Request) {
	id, secret, ok := r.BasicAuth()
	if ok {
		id, _ = url.QueryUnescape(id)
		secret, _ = url.QueryUnescape(secret)
	}
	if !ok || id != p.ClientID || subtle.ConstantTimeCompare([]byte(secret), []byte(p.ClientSecret)) != 1 {
		writeJSON(w, 401, map[string]string{"error": "invalid_client"})
		return
	}
	if err := r.ParseForm(); err != nil || r.PostForm.Get("grant_type") != "authorization_code" {
		writeJSON(w, 400, map[string]string{"error": "unsupported_grant_type"})
		return
	}
	code := r.PostForm.Get("code")
	p.mu.Lock()
	g, found := p.codes[code]
	delete(p.codes, code) // a code is good once
	p.mu.Unlock()
	ch := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if !found || time.Now().After(g.expires) || g.redirect != r.PostForm.Get("redirect_uri") ||
		base64.RawURLEncoding.EncodeToString(ch[:]) != g.challenge {
		writeJSON(w, 400, map[string]string{"error": "invalid_grant"})
		return
	}
	now := time.Now()
	claims := map[string]any{}
	for k, v := range p.User.Claims {
		claims[k] = v
	}
	claims["iss"], claims["sub"], claims["aud"] = p.Issuer, p.User.Subject, p.ClientID
	claims["iat"], claims["exp"], claims["nonce"] = now.Unix(), now.Add(5*time.Minute).Unix(), g.nonce
	idt, _ := jose.SignEdDSA(p.priv, p.kid, claims)
	writeJSON(w, 200, map[string]any{"token_type": "Bearer", "id_token": idt, "access_token": rnd(24),
		"refresh_token": rnd(24), "expires_in": 300})
}

func (p *Provider) jwks(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"keys": []jose.JWK{jose.Ed25519JWK(p.kid, p.pub)}})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func rnd(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
