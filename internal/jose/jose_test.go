package jose

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func keyset(t *testing.T) (*KeySet, ed25519.PrivateKey) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	doc, _ := json.Marshal(map[string]any{"keys": []JWK{Ed25519JWK("k1", pub)}})
	ks, err := ParseKeySet(doc)
	if err != nil {
		t.Fatal(err)
	}
	return ks, priv
}

func TestSignVerify(t *testing.T) {
	ks, priv := keyset(t)
	tok, _ := SignEdDSA(priv, "k1", map[string]any{"sub": "a"})
	if _, p, err := ks.Verify(tok); err != nil || !strings.Contains(string(p), `"sub":"a"`) {
		t.Fatalf("verify: %v", err)
	}
}

func TestRejects(t *testing.T) {
	ks, priv := keyset(t)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	good, _ := SignEdDSA(priv, "k1", map[string]any{"sub": "a"})
	parts := strings.Split(good, ".")
	enc := base64.RawURLEncoding
	none := enc.EncodeToString([]byte(`{"alg":"none","kid":"k1"}`)) + "." + parts[1] + "."
	hs := enc.EncodeToString([]byte(`{"alg":"HS256","kid":"k1"}`)) + "." + parts[1] + "." + parts[2]
	wrongKey, _ := SignEdDSA(other, "k1", map[string]any{"sub": "a"})
	tampered := parts[0] + "." + enc.EncodeToString([]byte(`{"sub":"b"}`)) + "." + parts[2]
	unknownKid, _ := SignEdDSA(priv, "k2", map[string]any{"sub": "a"})
	for name, tok := range map[string]string{"alg none": none, "alg HS256": hs, "wrong key": wrongKey,
		"tampered payload": tampered, "unknown kid": unknownKid, "two parts": parts[0] + "." + parts[1]} {
		if _, _, err := ks.Verify(tok); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestClaimsCheck(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	ok := Claims{Iss: "https://i", Sub: "s", Aud: Audience{"c"}, Exp: now.Unix() + 60}
	if err := ok.Check("https://i", "c", now, time.Minute); err != nil {
		t.Fatalf("good claims: %v", err)
	}
	bad := map[string]Claims{
		"issuer":   {Iss: "https://evil", Sub: "s", Aud: Audience{"c"}, Exp: now.Unix() + 60},
		"audience": {Iss: "https://i", Sub: "s", Aud: Audience{"other"}, Exp: now.Unix() + 60},
		"expired":  {Iss: "https://i", Sub: "s", Aud: Audience{"c"}, Exp: now.Unix() - 120},
		"no exp":   {Iss: "https://i", Sub: "s", Aud: Audience{"c"}},
		"future":   {Iss: "https://i", Sub: "s", Aud: Audience{"c"}, Exp: now.Unix() + 600, Nbf: now.Unix() + 300},
		"no sub":   {Iss: "https://i", Aud: Audience{"c"}, Exp: now.Unix() + 60},
	}
	for name, c := range bad {
		if c.Check("https://i", "c", now, time.Minute) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestShortRSAKeyRefused(t *testing.T) {
	n := base64.RawURLEncoding.EncodeToString(make([]byte, 128)) // 1024 bits of zeros: too short
	if _, err := (JWK{Kty: "RSA", N: n, E: "AQAB"}).Public(); err == nil {
		t.Fatal("1024-bit RSA key accepted")
	}
}
