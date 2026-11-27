# Threat model

First version, 2026-11-26. Written before any code, as the design asks. It covers the
platform as decided in `docs/DESIGN.md` (sections 0b and 15): one VPS, one origin, a Go
service behind a TLS terminator, the Virtual Clubroom as identity provider, the UC.OS page
as a backend-for-frontend client, an allow-listed proxy for signed-in users, a Wisp-compatible
relay for members.

Marked **[design]** where the control comes from the design decisions, **[decided]** where it
was this document's proposal and the owner accepted it (2026-11-26 13:27: "go with all your
recommends").

## 1. What we protect

| Asset | Why it matters |
|---|---|
| The relay and proxy as network exits | anything sent through them comes from our IP address: abuse complaints, blocklisting, the host closing the account, legal exposure (the network study, section 7.1) |
| The signing key for relay tokens | whoever holds it can mint access for anyone |
| The Clubroom client secret (backend-for-frontend) | lets someone pose as UC.OS to the Clubroom |
| Session cookies | a stolen session is a stolen account on this platform |
| Users' data on the platform | usage counters, connection logs (destination, bytes, time), encrypted device-transfer bundles; personal data under the GDPR |
| Administrator powers | quotas, grants, bans, panic switches, the allow-list |
| Availability | the OS still works without the platform, but members lose the relay and apt loses the proxy |

## 2. Who might attack, and how capable

| Actor | Can | Wants |
|---|---|---|
| Anonymous internet user | send any HTTP or WebSocket request, any header, any Origin; script it; use many IP addresses | free proxy or relay, scanning, spam, attacks routed through us |
| Signed-in user | everything above plus a valid session and proxy access | more than their quota; reaching hosts not on the allow-list |
| Member | plus relay access | using the relay for attacks; more quota |
| A member's stolen token or session | as the member, until it expires or is revoked | as above |
| Code running inside UC.OS in the user's browser | whatever the OS lets programs do; it is untrusted (it may be a Debian package) | reading the user's token or session to use elsewhere |
| A malicious web page in the same browser | cross-site requests to our origin | acting as the user (CSRF), reading responses (blocked by CORS unless we allow it) |
| A compromised or curious mirror, CDN or relay operator in a bring-your-own setup | read or alter traffic it carries | altered packages |
| Someone who gains a shell on the VPS | read secrets and logs, change code | everything |
| An administrator acting badly, or with a phished account | admin powers | anything admins can do |

## 3. Trust boundaries

1. Browser to our origin (TLS): the page, the API, the proxy endpoint, the relay WebSocket.
2. Our service to the Clubroom (TLS): the code exchange, token refresh, change notifications.
3. Our proxy and relay to the internet: every destination is untrusted.
4. Inside the browser: the page's host layer (`boot/` JavaScript, ours) against programs in the
   OS (untrusted). Tokens and the session cookie must stay on the host side of that line.
5. Inside the VPS: the TLS terminator, the Go service, the database file, the secret files.

## 4. Threats and the controls for each


### Abuse of the exits
- Open proxy through the relay or proxy: only members reach the relay, only signed-in users
  reach the proxy, every request carries a token [design]. Relay ports 80 and 443 only; proxy
  restricted to the allow-list by host and path prefix, methods GET and HEAD plus the
  git-upload-pack POST [design].
- Server-side request forgery into our own network or the cloud metadata service: resolve the
  name, refuse loopback, private, link-local, CGNAT, multicast and metadata ranges (IPv4 and
  IPv6, including IPv4-mapped IPv6), then connect to that exact address so a second DNS answer
  cannot change it (DNS rebinding) [design]. The proxy checks every redirect hop against the
  allow-list and the address rules [design].
- Scanning and fan-out: the 15-new-destinations-a-minute quota per member; refused-destination
  counters feed the safety automation [design].
- Volume: per-user daily bytes and connection limits; global caps below the VPS allowance
  [design].
- Our IP blocklisted or the host account closed: the automatic global suspension and the panic
  switches [design]; an abuse contact address published: `abuse@ucos.ensui.dev` in
  `/.well-known/security.txt` [built].
- Stream churn and proxy pile-up: at most 60 new relay streams a minute per member (an admin
  setting) and 8 running proxy requests per user [built].

### Identity and sessions
- Forged identity: the service accepts only the Clubroom's signed tokens or introspection
  results, checks issuer, audience (the UC.OS client), expiry and the UC.OS scope [design].
- OAuth attacks on the code flow: PKCE, an exact redirect URI, a `state` value bound to the
  browser's pre-login cookie (sealed with AES-GCM, 10 minutes; DESIGN.md 15.12), and a
  `nonce` with OpenID Connect [decided, standard].
- Session theft: the session cookie is `HttpOnly`, `Secure`, `SameSite=Lax` (or `Strict` for
  admin paths), `__Host-` prefixed, rotated at sign-in, with an idle and an absolute expiry
  [decided].
- CSRF: state-changing API calls need a non-simple request (a custom header or JSON body),
  checked Origin, and `SameSite` cookies [decided]. No CORS for our API from other origins.
- Token theft by code inside the OS: relay and proxy tokens live only in the page's host layer;
  programs ask the host to open connections and never receive a token [design]. Tokens last
  5 minutes and are bound to a session id that the service can revoke [design].
- Programs inside the OS reaching the platform's own pages: every same-origin endpoint that
  trusts the cookie and the Origin header answers whatever script the page runs. The OS host
  layer is the only guard between a program and those endpoints: programs' requests carry no
  login (UC.OS decision 30), and the host builds proxy addresses only from plain host names
  and checks the result still starts with `/proxy/{host}/`. A first version let `Host: ..`
  turn `/proxy/../api/me` into `/api/me` in the browser, before the server could see it; found
  and fixed on 2026-11-27 before any release [built, OS side].
- Token theft by a script injected into the page: a strict Content-Security-Policy on the page
  (no inline script, `connect-src` limited to our origin), no third-party scripts [decided];
  the session cookie is not readable by script (`HttpOnly`).
- A user disabled or a role removed in the Clubroom: change notification from the Clubroom plus
  short token lifetimes; on notice the service drops the user's live relay streams [design;
  depends on the Clubroom update].
- Relay signing key stolen from the relay process: Ed25519, the relay holds only the public key;
  the private key lives in the token-minting part of the service [design, assumption].

### Administration
- Phished administrator: second factor required at the Clubroom for admin accounts [design];
  admin actions need a fresh sign-in within the last N minutes [decided]; every admin action
  in the audit log [design].
- Insider misuse: the audit log is append-only from the application's point of view and lists
  who did what; administrators are the maintainers and bootstrapped by 42 login, for an account with a linked 42 account only [design].
- Panic switch itself abused (denial of service by an admin): logged; only administrators
  [design].

### Data
- Logs reveal where users go: keep destination host, bytes and time only, never full URLs or
  bodies, for 30 days, counters aggregated after [design]. The proxy necessarily sees URLs while
  serving a request: they are not written to disk [decided].
- Device-transfer bundles (QR option b): encrypted in the browser with a random key that never
  reaches the server; deleted at the expiry the user chose; size limited by quota [design]. The
  server cannot read them; it can lose them.
- Database stolen: holds no passwords and no 42 tokens; Clubroom refresh tokens are encrypted at
  rest with a key kept outside the database [decided].

### Integrity of what users download
- A proxy, mirror or relay altering packages: apt verifies the archive's OpenPGP signature in
  the OS (stream `pgp` in the OS repository) [design]. Our proxy terminates TLS, so without that
  check we could alter packages ourselves: the check is what makes us untrusted transport.
- `git clone` through the proxy: git checks object hashes but not the remote's identity; the
  proxy could serve a different repository. Users who need assurance check signed tags or
  commits [decided: say so in the documentation].

### Availability and the server
- Denial of service on sign-in or the API: rate limits per IP and per session; connection caps
  on the relay [design].
- Secrets in the repository or logs: secrets only in files outside the repository, read at
  start, never logged; a check in CI for committed secrets [decided].
- Supply chain: Go standard library plus a short, pinned list of modules, each named in the
  design with its reason [design]; `go mod verify` and checksums in CI [decided].
- The VPS compromised: separate system user for the service, no shell for it, the TLS
  terminator separate, automatic security updates, SSH keys only [decided]; backups of the
  database encrypted.

## 5. Out of scope, stated

- Root inside a user's own copy of UC.OS: protects nothing on the server; the service never
  trusts it (DESIGN.md point 12).
- File import from the user's disk into the OS: stays in the browser, never reaches us.
- Bring-your-own relays: the user is the operator and carries the responsibility.
- The browser extension idea: not designed yet.

## 6. Points settled on 2026-11-26 13:27

The owner accepted all recommendations ("go with all your recommends"). For the three points
that had no recommendation yet, these were made and are recorded as accepted:
1. **Abuse contact**: an address on the club's domain is published before the relay goes live.
   Which address is the owner's to create.
2. **VPS provider**: chosen only after reading its acceptable-use policy for a members-only
   relay; the candidates' policies are read when hosting is set up.
3. **Connection logs** carry only the pseudonymous Clubroom user id, not the 42 login; an
   administrator maps the id to a person when handling a complaint.
