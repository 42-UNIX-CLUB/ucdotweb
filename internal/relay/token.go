package relay

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"time"

	"github.com/42-UNIX-CLUB/ucdotweb/internal/jose"
)

// Audience of relay tokens: a token for anything else is refused, and the reverse.
const Audience = "ucdotweb-relay"

// Lifetime of a relay token (decided: 5 minutes). It only has to last until the WebSocket
// opens; a live connection is re-checked by the relay on its own timer.
const Lifetime = 5 * time.Minute

// Claims of a relay token.
type Claims struct {
	jose.Claims
	Sid string `json:"sid"` // the session it was minted for, so signing out revokes it
}

// Minter signs relay tokens. Only the web side holds it.
type Minter struct {
	Issuer string
	Kid    string
	Key    ed25519.PrivateKey
}

// Mint returns a token for subject and session.
func (m *Minter) Mint(subject, sid string, now time.Time) (string, error) {
	c := Claims{Claims: jose.Claims{Iss: m.Issuer, Sub: subject, Aud: jose.Audience{Audience},
		Iat: now.Unix(), Exp: now.Add(Lifetime).Unix()}, Sid: sid}
	return jose.SignEdDSA(m.Key, m.Kid, c)
}

// Verifier checks relay tokens with the public key only.
type Verifier struct {
	Issuer string
	Keys   *jose.KeySet
}

// NewVerifier makes a verifier from a public key.
func NewVerifier(issuer, kid string, pub ed25519.PublicKey) (*Verifier, error) {
	doc, _ := json.Marshal(map[string]any{"keys": []jose.JWK{jose.Ed25519JWK(kid, pub)}})
	ks, err := jose.ParseKeySet(doc)
	if err != nil {
		return nil, err
	}
	return &Verifier{Issuer: issuer, Keys: ks}, nil
}

// Verify checks signature, issuer, audience and time.
func (v *Verifier) Verify(tok string, now time.Time) (Claims, error) {
	var c Claims
	h, payload, err := v.Keys.Verify(tok)
	if err != nil {
		return c, err
	}
	if h.Alg != "EdDSA" {
		return c, errors.New("relay token: wrong algorithm")
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		return c, errors.New("relay token: bad claims")
	}
	if err := c.Check(v.Issuer, Audience, now, 30*time.Second); err != nil {
		return c, err
	}
	if c.Sid == "" {
		return c, errors.New("relay token: no session")
	}
	return c, nil
}
