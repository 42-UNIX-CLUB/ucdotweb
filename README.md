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
sessions in SQLite (id hashed, data encrypted), users with platform grants and bans, admin
bootstrap by 42 login, panic switches, the allow-listed proxy with quotas and a host-only log,
an append-only audit log, the members' relay (Wisp v1 over a WebSocket, 5-minute Ed25519
tokens, quotas, live re-checks), the admin API (users, grants and bans, quotas, panic
switches, audit and connection logs, the proxy's allow-list; JSON under `/api/admin/`, listed
in `internal/web/admin.go`), and a test stand-in for the identity provider. The allow-list
lives in the database: it is seeded once from `UCDOTWEB_PROXY_RULES` or the built-in list on
the first start, then edited by administrators, live. Safety automation: a watcher that sets a
panic switch by itself (three or more users hitting limits within 10 minutes, traffic far
above the 7-day norm, or a critical abuse report filed by an administrator), never lifts it,
and notifies by chat webhook and e-mail when those are configured (`cmd/ucdotweb/main.go`
lists the variables). Also: switches for sign-in and new sign-ups, a recent sign-in for admin
changes, 42-based membership that follows the 42 account's own state (the Clubroom's
`ft_active` claim), and daily caps per service for the whole platform (docs/DESIGN.md 15.8
and 15.9). Not built yet: the admin program (a UC.OS program,
decided).

Go standard library plus one module: github.com/mattn/go-sqlite3 (cgo, needs a C compiler). Tests: `go test ./...` (add `-race` for the race detector).

Try it locally (two terminals; test values only, never real credentials):

```sh
go run ./cmd/oidc-standin -login rucosta -member
echo local-test-secret > build-secret.txt
openssl rand -hex 32 > build-dbkey.txt
openssl rand -hex 32 > build-relaykey.txt
UCDOTWEB_LISTEN=127.0.0.1:8090 UCDOTWEB_ORIGIN=http://127.0.0.1:8090 \
UCDOTWEB_ISSUER=http://127.0.0.1:8091 UCDOTWEB_CLIENT_ID=uc-os \
UCDOTWEB_SECRET_FILE=build-secret.txt UCDOTWEB_DB=build-test.db UCDOTWEB_DB_KEY_FILE=build-dbkey.txt UCDOTWEB_RELAY_KEY_FILE=build-relaykey.txt \
UCDOTWEB_ADMIN_LOGINS=rucosta UCDOTWEB_INSECURE_COOKIES=1 go run ./cmd/ucdotweb
# then open http://127.0.0.1:8090/auth/login and http://127.0.0.1:8090/api/me
```

| File | What |
|---|---|
| `docs/DESIGN.md` | the options, the owners' decisions so far, the design around the Clubroom |
| `docs/THREAT-MODEL.md` | what we protect, from whom, and how |
| `docs/DEPLOY.md` | deploying on a server over SSH: a private test now, production later |
| `internal/jose` | JWS verification (EdDSA, RS256, ES256) and EdDSA signing; JWK sets |
| `internal/oidc` | the OpenID Connect client: discovery, PKCE, code exchange, ID token checks |
| `internal/session` | server-side sessions behind an HttpOnly cookie |
| `internal/web` | the HTTP routes: `/auth/login`, `/auth/callback`, `/auth/logout`, `/api/me`, `/api/relay-token`; `admin.go`: the admin API |
| `internal/standin`, `cmd/oidc-standin` | the test identity provider (loopback only) |
| `internal/store` | the SQLite database: sessions, users, quotas, usage, switches, logs, audit |
| `internal/netguard` | which addresses may be reached; a dialer that checks every resolved address |
| `internal/proxy` | the allow-listed proxy at `/proxy/{host}/{path}` |
| `internal/ws` | a small WebSocket server (RFC 6455), our own |
| `internal/relay` | the members' relay at `/relay` (Wisp v1) and its tokens (`POST /api/relay-token`) |
| `cmd/ucdotweb` | the service |
