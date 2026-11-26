# ucdotweb

The web platform of UC.OS, the operating system of the 42 UNIX Club that runs in a browser
(https://github.com/42-UNIX-CLUB/ucdotos). It lets UC.OS reach the internet safely:

- an allow-listed proxy for signed-in users (package mirrors, source hosts for `git clone`);
- a relay for members (a linked 42 account, or granted by an administrator), under quotas;
- quotas, safety automation, global panic switches and an admin interface.

Accounts, sign-in and the 42 link live in the club's Virtual Clubroom, which is the identity
provider. This platform holds no passwords and no 42 application.

Status: early. Built so far: sign-in through an OpenID Connect provider as a backend for
frontend (authorization code with PKCE, state, nonce, ID token verification), server-side
sessions, and a test stand-in for the identity provider. No proxy, relay or admin yet.

Go standard library only, so far. Tests: `go test ./...` (add `-race` for the race detector).

Try it locally (two terminals; test values only, never real credentials):

```sh
go run ./cmd/oidc-standin -login rucosta -member
echo local-test-secret > build-secret.txt
UCDOTWEB_LISTEN=127.0.0.1:8090 UCDOTWEB_ORIGIN=http://127.0.0.1:8090 \
UCDOTWEB_ISSUER=http://127.0.0.1:8091 UCDOTWEB_CLIENT_ID=uc-os \
UCDOTWEB_SECRET_FILE=build-secret.txt UCDOTWEB_INSECURE_COOKIES=1 go run ./cmd/ucdotweb
# then open http://127.0.0.1:8090/auth/login and http://127.0.0.1:8090/api/me
```

| File | What |
|---|---|
| `docs/DESIGN.md` | the options, the owners' decisions so far, the design around the Clubroom |
| `docs/THREAT-MODEL.md` | what we protect, from whom, and how |
| `internal/jose` | JWS verification (EdDSA, RS256, ES256) and EdDSA signing; JWK sets |
| `internal/oidc` | the OpenID Connect client: discovery, PKCE, code exchange, ID token checks |
| `internal/session` | server-side sessions behind an HttpOnly cookie |
| `internal/web` | the HTTP routes: `/auth/login`, `/auth/callback`, `/auth/logout`, `/api/me` |
| `internal/standin`, `cmd/oidc-standin` | the test identity provider (loopback only) |
| `cmd/ucdotweb` | the service |
