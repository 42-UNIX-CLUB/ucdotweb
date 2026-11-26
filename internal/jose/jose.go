// Package jose verifies and signs compact JSON Web Signatures (JWS, RFC 7515) and reads
// JSON Web Key sets (RFC 7517), only as far as this platform needs: EdDSA (Ed25519),
// RS256 and ES256 for verifying tokens from the identity provider, and EdDSA for signing
// our own relay tokens. Algorithm "none" and anything else is refused.
package jose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

var b64 = base64.RawURLEncoding

// Header is the protected header of a JWS.
type Header struct {
	Alg string `json:"alg"`
	Kid string `json:"kid,omitempty"`
	Typ string `json:"typ,omitempty"`
}

// Key is one public key from a JWK set.
type Key struct {
	Kid string
	Alg string
	Pub crypto.PublicKey
}

// JWK is the JSON form of a public key.
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid,omitempty"`
	Alg string `json:"alg,omitempty"`
	Use string `json:"use,omitempty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
}

// KeySet is a parsed JWK set.
type KeySet struct{ Keys []Key }

// ParseKeySet reads a JWK set document. Keys of kinds we do not use are skipped.
func ParseKeySet(data []byte) (*KeySet, error) {
	var doc struct {
		Keys []JWK `json:"keys"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("jwks: %w", err)
	}
	ks := &KeySet{}
	for _, j := range doc.Keys {
		if j.Use != "" && j.Use != "sig" {
			continue
		}
		k, err := j.Public()
		if err != nil {
			continue
		}
		ks.Keys = append(ks.Keys, k)
	}
	if len(ks.Keys) == 0 {
		return nil, errors.New("jwks: no usable keys")
	}
	return ks, nil
}

// Public converts a JWK to a Key.
func (j JWK) Public() (Key, error) {
	k := Key{Kid: j.Kid, Alg: j.Alg}
	switch j.Kty {
	case "OKP":
		if j.Crv != "Ed25519" {
			return k, errors.New("unsupported curve")
		}
		x, err := b64.DecodeString(j.X)
		if err != nil || len(x) != ed25519.PublicKeySize {
			return k, errors.New("bad Ed25519 key")
		}
		k.Pub = ed25519.PublicKey(x)
		if k.Alg == "" {
			k.Alg = "EdDSA"
		}
	case "RSA":
		n, err1 := b64.DecodeString(j.N)
		e, err2 := b64.DecodeString(j.E)
		if err1 != nil || err2 != nil || len(e) == 0 || len(e) > 4 {
			return k, errors.New("bad RSA key")
		}
		pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
		if pub.N.BitLen() < 2048 {
			return k, errors.New("RSA key shorter than 2048 bits")
		}
		k.Pub = pub
		if k.Alg == "" {
			k.Alg = "RS256"
		}
	case "EC":
		if j.Crv != "P-256" {
			return k, errors.New("unsupported curve")
		}
		x, err1 := b64.DecodeString(j.X)
		y, err2 := b64.DecodeString(j.Y)
		if err1 != nil || err2 != nil || len(x) != 32 || len(y) != 32 {
			return k, errors.New("bad EC key")
		}
		pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
			return k, errors.New("EC point not on curve")
		}
		k.Pub = pub
		if k.Alg == "" {
			k.Alg = "ES256"
		}
	default:
		return k, errors.New("unsupported key type")
	}
	return k, nil
}

// Ed25519JWK returns the public JWK of an Ed25519 key.
func Ed25519JWK(kid string, pub ed25519.PublicKey) JWK {
	return JWK{Kty: "OKP", Crv: "Ed25519", X: b64.EncodeToString(pub), Kid: kid, Alg: "EdDSA", Use: "sig"}
}

// Verify checks the signature of a compact JWS against the set and returns its payload.
// The key is chosen by kid; the header's alg must match the key's.
func (ks *KeySet) Verify(token string) (Header, []byte, error) {
	var h Header
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return h, nil, errors.New("jws: not three parts")
	}
	hb, err := b64.DecodeString(parts[0])
	if err != nil {
		return h, nil, errors.New("jws: bad header encoding")
	}
	if err := json.Unmarshal(hb, &h); err != nil {
		return h, nil, errors.New("jws: bad header")
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil {
		return h, nil, errors.New("jws: bad signature encoding")
	}
	payload, err := b64.DecodeString(parts[1])
	if err != nil {
		return h, nil, errors.New("jws: bad payload encoding")
	}
	signed := []byte(parts[0] + "." + parts[1])
	for _, k := range ks.Keys {
		if h.Kid != "" && k.Kid != h.Kid {
			continue
		}
		if k.Alg != h.Alg {
			continue
		}
		if verifyWith(k, signed, sig) {
			return h, payload, nil
		}
	}
	return h, nil, errors.New("jws: signature does not verify")
}

func verifyWith(k Key, signed, sig []byte) bool {
	switch k.Alg {
	case "EdDSA":
		pub, ok := k.Pub.(ed25519.PublicKey)
		return ok && ed25519.Verify(pub, signed, sig)
	case "RS256":
		pub, ok := k.Pub.(*rsa.PublicKey)
		if !ok {
			return false
		}
		d := sha256.Sum256(signed)
		return rsa.VerifyPKCS1v15(pub, crypto.SHA256, d[:], sig) == nil
	case "ES256":
		pub, ok := k.Pub.(*ecdsa.PublicKey)
		if !ok || len(sig) != 64 {
			return false
		}
		d := sha256.Sum256(signed)
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])
		return ecdsa.Verify(pub, d[:], r, s)
	}
	return false
}

// SignEdDSA produces a compact JWS of payload with an Ed25519 key.
func SignEdDSA(priv ed25519.PrivateKey, kid string, payload any) (string, error) {
	hb, _ := json.Marshal(Header{Alg: "EdDSA", Kid: kid, Typ: "JWT"})
	pb, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	signed := b64.EncodeToString(hb) + "." + b64.EncodeToString(pb)
	return signed + "." + b64.EncodeToString(ed25519.Sign(priv, []byte(signed))), nil
}

// Claims are the registered claims this platform checks.
type Claims struct {
	Iss   string   `json:"iss"`
	Sub   string   `json:"sub"`
	Aud   Audience `json:"aud"`
	Exp   int64    `json:"exp"`
	Nbf   int64    `json:"nbf,omitempty"`
	Iat   int64    `json:"iat,omitempty"`
	Nonce string   `json:"nonce,omitempty"`
}

// Audience accepts a string or an array of strings.
type Audience []string

func (a *Audience) UnmarshalJSON(b []byte) error {
	var one string
	if json.Unmarshal(b, &one) == nil {
		*a = Audience{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*a = many
	return nil
}

func (a Audience) Has(s string) bool {
	for _, x := range a {
		if x == s {
			return true
		}
	}
	return false
}

// Check validates issuer, audience and time, with skew allowed on both sides.
func (c Claims) Check(iss, aud string, now time.Time, skew time.Duration) error {
	if c.Iss != iss {
		return fmt.Errorf("token issuer %q, want %q", c.Iss, iss)
	}
	if !c.Aud.Has(aud) {
		return errors.New("token audience does not include us")
	}
	if c.Sub == "" {
		return errors.New("token has no subject")
	}
	if c.Exp == 0 || now.Add(-skew).Unix() >= c.Exp {
		return errors.New("token expired")
	}
	if c.Nbf != 0 && now.Add(skew).Unix() < c.Nbf {
		return errors.New("token not valid yet")
	}
	return nil
}
