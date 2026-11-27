// Package oidc is the client side of OpenID Connect's authorization code flow with PKCE
// (RFC 7636), as a confidential client (backend for frontend): discovery, the authorize
// URL, the code exchange, and verification of the ID token against the provider's keys.
package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/42-UNIX-CLUB/ucdotweb/internal/jose"
)

// Config describes this client at the provider.
type Config struct {
	Issuer       string // the provider's issuer URL, exactly as in its tokens
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string // "openid" is always added
}

// Provider is a discovered provider.
type Provider struct {
	cfg      Config
	http     *http.Client
	authURL  string
	tokenURL string
	infoURL  string
	jwksURL  string

	mu      sync.Mutex
	keys    *jose.KeySet
	keysAt  time.Time
	nowFunc func() time.Time
}

// Discover reads the provider's /.well-known/openid-configuration.
func Discover(ctx context.Context, cfg Config, hc *http.Client) (*Provider, error) {
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	var doc struct {
		Issuer   string   `json:"issuer"`
		Auth     string   `json:"authorization_endpoint"`
		Token    string   `json:"token_endpoint"`
		UserInfo string   `json:"userinfo_endpoint"`
		JWKS     string   `json:"jwks_uri"`
		PKCE     []string `json:"code_challenge_methods_supported"`
	}
	if err := getJSON(ctx, hc, strings.TrimRight(cfg.Issuer, "/")+"/.well-known/openid-configuration", &doc); err != nil {
		return nil, fmt.Errorf("discovery: %w", err)
	}
	if doc.Issuer != cfg.Issuer {
		return nil, fmt.Errorf("discovery: issuer %q does not match configured %q", doc.Issuer, cfg.Issuer)
	}
	if doc.Auth == "" || doc.Token == "" || doc.JWKS == "" {
		return nil, errors.New("discovery: missing endpoints")
	}
	s256 := false
	for _, m := range doc.PKCE {
		s256 = s256 || m == "S256"
	}
	if !s256 {
		return nil, errors.New("discovery: provider does not offer PKCE S256")
	}
	return &Provider{cfg: cfg, http: hc, authURL: doc.Auth, tokenURL: doc.Token, infoURL: doc.UserInfo,
		jwksURL: doc.JWKS, nowFunc: time.Now}, nil
}

// Pending holds what must survive between the redirect to the provider and the callback.
// The server keeps it in a sealed, short-lived cookie (internal/web/pending.go), never in
// the URL.
type Pending struct {
	State    string
	Nonce    string
	Verifier string
	Created  time.Time
}

// Start returns the authorize URL and the values to keep until the callback.
func (p *Provider) Start() (string, Pending) { return p.StartWith(nil) }

// StartWith is Start with extra authorization request parameters, for example prompt=login.
// They cannot replace the ones Start sets.
func (p *Provider) StartWith(extra url.Values) (string, Pending) {
	pd := Pending{State: Random(32), Nonce: Random(32), Verifier: Random(48), Created: p.nowFunc()}
	ch := sha256.Sum256([]byte(pd.Verifier))
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {p.cfg.ClientID},
		"redirect_uri":          {p.cfg.RedirectURL},
		"scope":                 {strings.Join(append([]string{"openid"}, p.cfg.Scopes...), " ")},
		"state":                 {pd.State},
		"nonce":                 {pd.Nonce},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(ch[:])},
		"code_challenge_method": {"S256"},
	}
	for k, v := range extra {
		if _, set := q[k]; !set {
			q[k] = v
		}
	}
	sep := "?"
	if strings.Contains(p.authURL, "?") {
		sep = "&"
	}
	return p.authURL + sep + q.Encode(), pd
}

// Identity is what the platform learns about the user from the provider.
type Identity struct {
	Subject      string
	Claims       map[string]any // every claim of the ID token
	RefreshToken string
	AccessToken  string
	Expiry       time.Time
}

// Finish checks state, exchanges the code and verifies the ID token.
func (p *Provider) Finish(ctx context.Context, pd Pending, gotState, code string) (*Identity, error) {
	if pd.State == "" || gotState != pd.State {
		return nil, errors.New("state does not match")
	}
	if p.nowFunc().Sub(pd.Created) > 10*time.Minute {
		return nil, errors.New("sign-in took too long, start again")
	}
	if code == "" {
		return nil, errors.New("no code")
	}
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {p.cfg.RedirectURL},
		"code_verifier": {pd.Verifier},
		"client_id":     {p.cfg.ClientID},
	}
	var tok struct {
		IDToken      string `json:"id_token"`
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
		TokenType    string `json:"token_type"`
	}
	req, _ := http.NewRequestWithContext(ctx, "POST", p.tokenURL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(p.cfg.ClientID), url.QueryEscape(p.cfg.ClientSecret))
	if err := doJSON(p.http, req, &tok); err != nil {
		return nil, fmt.Errorf("token exchange: %w", err)
	}
	if tok.IDToken == "" {
		return nil, errors.New("token exchange: no id_token")
	}
	claims, err := p.VerifyIDToken(ctx, tok.IDToken, pd.Nonce)
	if err != nil {
		return nil, err
	}
	id := &Identity{Claims: claims, RefreshToken: tok.RefreshToken, AccessToken: tok.AccessToken}
	id.Subject, _ = claims["sub"].(string)
	if tok.ExpiresIn > 0 {
		id.Expiry = p.nowFunc().Add(time.Duration(tok.ExpiresIn) * time.Second)
	}
	return id, nil
}

// VerifyIDToken checks signature, issuer, audience, time and nonce, and returns all claims.
func (p *Provider) VerifyIDToken(ctx context.Context, raw, nonce string) (map[string]any, error) {
	payload, err := p.verify(ctx, raw)
	if err != nil {
		return nil, err
	}
	var c jose.Claims
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, errors.New("id token: bad claims")
	}
	if err := c.Check(p.cfg.Issuer, p.cfg.ClientID, p.nowFunc(), time.Minute); err != nil {
		return nil, fmt.Errorf("id token: %w", err)
	}
	if nonce == "" || c.Nonce != nonce {
		return nil, errors.New("id token: nonce does not match")
	}
	all := map[string]any{}
	if err := json.Unmarshal(payload, &all); err != nil {
		return nil, errors.New("id token: bad claims")
	}
	return all, nil
}

// verify checks a JWS against the provider's keys, refreshing them once if the kid is new.
func (p *Provider) verify(ctx context.Context, raw string) ([]byte, error) {
	ks, err := p.keySet(ctx, false)
	if err != nil {
		return nil, err
	}
	if _, payload, err := ks.Verify(raw); err == nil {
		return payload, nil
	}
	ks, err = p.keySet(ctx, true)
	if err != nil {
		return nil, err
	}
	_, payload, err := ks.Verify(raw)
	return payload, err
}

func (p *Provider) keySet(ctx context.Context, force bool) (*jose.KeySet, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.keys != nil && !force && p.nowFunc().Sub(p.keysAt) < time.Hour {
		return p.keys, nil
	}
	if p.keys != nil && force && p.nowFunc().Sub(p.keysAt) < 30*time.Second {
		return p.keys, nil // do not let unknown kids make us fetch on every request
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", p.jwksURL, nil)
	resp, err := p.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("jwks: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("jwks: status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	ks, err := jose.ParseKeySet(data)
	if err != nil {
		return nil, err
	}
	p.keys, p.keysAt = ks, p.nowFunc()
	return ks, nil
}

// Random returns n random bytes, base64url encoded.
func Random(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func getJSON(ctx context.Context, hc *http.Client, u string, out any) error {
	req, _ := http.NewRequestWithContext(ctx, "GET", u, nil)
	return doJSON(hc, req, out)
}

func doJSON(hc *http.Client, req *http.Request, out any) error {
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return json.Unmarshal(body, out)
}
