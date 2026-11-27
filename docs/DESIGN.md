# The UC.OS web platform: options for the owners

The platform's design. First draft, 2026-11-26. Nothing here is decided except
what section 0 quotes. Every other point lists options with facts and costs and no
recommendation. Marks, as in the network study:

- **[read]** taken from a source cited by URL. Not tested here.
- **[tested]** run on this machine. (Nothing in this draft is tested yet.)
- **[estimate]** reasoning of this document. Not measured.

The first draft was written before the repository existed, because where the platform's
code lives was itself point 1 below. It now lives in this repository.

## 0. What the owner decided (2026-11-26)

The owner's words, in short:

| Kind of user | What they reach |
|---|---|
| Not signed in | what a browser page reaches by itself (hosts that send CORS headers: npm, PyPI, crates.io, jsDelivr, raw GitHub, DNS over HTTPS), plus a relay they run themselves |
| Signed in (a platform account) | the above, plus a rate-limited proxy restricted to an allow-list of high-trust hosts (package mirrors, source hosts for `git clone`) |
| Member (a linked 42 account, or authorised by an administrator) | the above, plus the project's relay, under quotas |

And: the 42 account is **linked** to a platform account, it does not create it, so a student
whose 42 access is frozen can still sign in. Administrators manage users, roles, quotas,
platform limits and global panic switches. Unusual or unsafe states notify the configured
administrators and can suspend the relay globally by themselves. apt checks package
signatures (being built in the OS, stream `pgp`). The colleague's network stack (pull
request #17) is wired in later, together with the owner.

Decided later the same day (2026-11-26 11:29), the owner's words: "There will be an update
for vclubroom that adds the missing account linkage requirement so it should be fine, let's
design around that". So **the Virtual Clubroom is the identity provider for UC.OS**: accounts,
sign-in and the 42 link live there, with the link-only rule the Clubroom update adds. Section
0b is the design that follows from it; points 4 and 5 below are now the Clubroom's.

## 0a. What already exists: the club's Virtual Clubroom (`~/vclubroom`)

The owner pointed to it [read: the code in `~/vclubroom`, 2026-11-26; secrets not read]. It
is the club's own web application (a hackathon project, then its own private repository
`42-UNIX-CLUB/vclubroom` from 2026-10-30, decision D-39 there). What it already has that
this platform needs:
- **42 OAuth, working**: Spring Boot with Spring Security's `oauth2Login`. Authorize
  `https://api.intra.42.fr/oauth/authorize`, token `https://api.intra.42.fr/oauth/token`,
  user info `https://api.intra.42.fr/v2/me`, scope `public`, client authentication
  `client_secret_post`, redirect `{public-url}/login/oauth2/code/fortytwo`. The secret comes
  from environment variables `FT_CLIENT_ID` and `FT_CLIENT_SECRET`; the application at 42 is
  registered at https://profile.intra.42.fr/oauth/applications.
- **What `/v2/me` gives with scope `public`** (from its mapper `FortyTwoProfileMapper.java`):
  `id`, `login`, `email`, `displayname`, `image` (avatar), `pool_year`, `pool_month`,
  `alumni?`, `staff?`, `campus[].name`, `cursus_users[].cursus.slug`. So campus and cursus are
  available for role rules without extra scopes.
- **Accounts and roles**: users with a platform role (USER, ADMIN) and a status (ACTIVE,
  DISABLED); local password accounts beside 42 accounts (passwords through Spring's
  delegating encoder, bcrypt by default); admin bootstrap by a list of 42 logins or a local
  admin from environment variables; campus groups synced from 42 data at each login.
- **Single origin behind Cloudflare Tunnel**: `https://42clubroom.ensui.dev`, the web app at
  `/`, the API at `/api`, WebSocket at `/ws` (its D-33, D-34). PostgreSQL, Redis, S3-style
  storage, e-mail through an SMTP provider.
- **Decided there but not built yet** (no code found for them): personal access tokens
  (D-51) and OAuth apps that other applications can register, with authorization code and
  PKCE, consent page and scopes (D-52). Built, that would make the Clubroom an identity
  provider that UC.OS's platform could use.
- **One difference from this platform's rule**: the Clubroom CREATES an account at the first
  42 login (`UserProvisioningService.provisionFromFortyTwo`), and a 42 account has no local
  password (`User.java`: "Only local accounts have passwords"). So a student whose 42 access
  is frozen cannot sign in to the Clubroom. The owner's rule for UC.OS is the opposite
  (link only, so sign-in survives a freeze).
- Production is planned on 42's infrastructure (its open items O-01, O-02).

What this changes in the options below:
- **A new option for identity (points 1, 2, 4, 5): use the Clubroom as the identity
  provider.** UC.OS's platform would then hold no passwords; users "sign in with Clubroom";
  roles could come from the Clubroom. It needs the Clubroom's D-52 built (or a narrower
  trust link between the two servers), and it needs the Clubroom to support the owner's
  freeze rule (a 42-registered user able to add a local password or passkey, or account
  linking there).
- **Or reuse its parts**: the 42 OAuth configuration and the profile mapping are a proven
  reference for a platform of our own, in whatever stack is chosen.
- **Or keep the two separate**, each with its own 42 application and its own accounts.
- The stack question (point 2) gains a fact: the club already runs Java and Spring Boot with
  third-party libraries for its web application, so rule 3 was not applied there.

## 0b. Design around the Clubroom as identity provider

### What the UC.OS platform becomes

With accounts in the Clubroom, the UC.OS platform holds **no passwords, no 42 application and
no personal profile data**. It is a resource server: the allow-listed proxy, the members'
relay, quotas, safety automation, panic switches, and the admin views for those. It trusts the
Clubroom for who a user is and which role they have.

```
user's browser
  UC.OS page (static: OS, host layer)            Clubroom (accounts, 42 link, roles)
     |  1. sign in (redirect, code + PKCE)  ----->  consent, session
     |  2. tokens (access, refresh)         <-----
     |  3. wss/https with a short-lived token
     v
  UC.OS platform service (proxy, relay, quotas, safety, admin API)
     |  4. checks the token (signature or introspection), reads role claims
     |  5. receives revocations and role changes from the Clubroom
```

### What the Clubroom must provide (requirements, for whoever builds its update)

The owner mentioned the account-linkage update. Designing around the Clubroom ALSO needs its
identity-provider part, which is decided there (D-52, OAuth apps with authorization code and
PKCE, consent, scopes, revocation) but not built [read: no code found]. Listed so nothing is
assumed silently:

1. **Account linkage (the update the owner announced)**: a Clubroom account exists on its own
   (local sign-in method), a 42 account is linked to it, sign-in keeps working when 42 access
   is frozen.
2. **An authorization server for other applications**: authorization code with PKCE, a consent
   page, refresh tokens, revocation (D-52). UC.OS registered as one client. Ideally OpenID
   Connect on top (an ID token and a discovery document), so the token format is standard.
3. **Claims or a user-info endpoint** carrying what UC.OS needs (point "Claims" below).
4. **Signed access tokens checkable without a call per request** (JWT signed with a key the
   Clubroom publishes, for example a JWKS URL), or a token-introspection endpoint. Signed
   tokens let the relay check every connection without calling the Clubroom.
5. **Change notification**: when a user is disabled, loses a role, or unlinks 42, UC.OS must
   learn it quickly: a webhook to the UC.OS platform, or short token lifetimes plus refresh
   that fails, or both.
6. **A scope for UC.OS**: for example `uc-os:connect` (use proxy and relay) and
   `uc-os:admin` (UC.OS administration), so a token for another Clubroom app cannot be used
   here and the reverse.

### Claims UC.OS needs

| Claim | For |
|---|---|
| a stable user id (`sub`) | quotas, logs, revocation |
| login (display only) | the admin views |
| account status (active, disabled) | refusing disabled users |
| `ft_linked` and campus | the member tier, if the rule is "linked 42 account" (and which campuses count: open, point 5) |
| `uc_os_member` granted by an administrator | the member tier for people without 42 |
| `uc_os_admin` | UC.OS administration (see roles below) |

### Roles: where they are managed (open)

| Option | Facts |
|---|---|
| a. In the Clubroom | one admin interface for people; UC.OS reads roles from claims; the Clubroom needs UC.OS-specific roles (member, UC.OS admin) or generic groups UC.OS maps |
| b. In UC.OS | the Clubroom only says who the user is; UC.OS keeps its own table of roles per Clubroom user id, with its own admin views; two places to manage people |
| c. Split | identity, status and 42 link from the Clubroom; UC.OS-only grants (member by an administrator, UC.OS admin, quotas) in UC.OS |

Quotas, limits, allow-list, panic switches and safety rules are UC.OS's own in every option.

### How the UC.OS page signs in (open)

| Option | Facts |
|---|---|
| a. Public client in the page | the page does authorization code with PKCE directly with the Clubroom and holds the tokens in the host layer (JavaScript in `boot/`), never visible to programs in the OS; no UC.OS server involved in sign-in; tokens live in browser storage (theft by script injection is the risk) |
| b. Confidential client on the UC.OS platform (backend for frontend) | the UC.OS platform does the code exchange and keeps tokens server-side; the page holds only a session cookie with the UC.OS platform; it mints short-lived connection tokens for the relay and proxy; needs the page and the platform on one origin or credentialed CORS |

Either way the token reaches the relay or proxy only through the host layer, and programs
inside the OS ask the host to open connections; they never see a token (point 8).

### Origins (point 3 sharpened)

The Clubroom runs at `42clubroom.ensui.dev` today (single origin, its D-33) and may move to
42's infrastructure (its O-02). UC.OS's page is a different origin in every case (for example
`dux.ensui.dev`). Redirect-based sign-in works across origins by design; what needs care is
only the UC.OS side: the page and the UC.OS platform on one origin (simplest for option b), or
the page alone with the platform elsewhere (option a, tokens instead of cookies).

### What becomes simpler or disappears

- Point 4 (sign-in methods) and point 5 (the 42 link, freezes, campus data, registering a 42
  application) are the Clubroom's.
- Data protection for UC.OS shrinks to: a pseudonymous user id, usage counters, connection
  logs (destination host, bytes, time) and their retention.
- Point 2 (stack) applies only to the proxy, relay and admin API: no password hashing, no
  OAuth client secrets for 42, no account recovery.

### Until the Clubroom's provider part exists

Options for building UC.OS's side before then: (a) wait; (b) build against a stand-in
authorization server of our own used only in tests, speaking the same protocol the Clubroom
will (OpenID Connect with PKCE is the obvious target), so the switch is configuration; (c) a
temporary invitation-token scheme run by UC.OS administrators, removed later.

## 1. Where the code lives

| Option | Facts |
|---|---|
| a. A directory in this repository (for example `web/`) | one place, one set of rules and reviews; the OS's `make dist` and the server can share the wire protocol definition; but the repository is public and GPL-2.0-or-later, so the server is public too (that is fine for code, never for secrets); the OS's CI and suites would run on server changes unless separated |
| b. A repository of its own under the club's organisation | its own licence (the owners may choose a different one: a server is not linked into the OS, so GPL does not follow it), its own access rights (who may push and deploy can be narrower than for the OS), its own CI and deployment secrets kept away from the OS repository |
| c. A private repository | hides the server code; security that depends on hidden code is weak, and a student club loses the review that a public repository invites; deployment secrets are equally safe in a public repository if they are never committed |

Either way, the OS keeps only the client side: the host-layer code that talks to the relay
and proxy (that is the OS side's area, with the colleague).

## 2. The stack, and whether "everything custom" applies here

The project's rule 3 ("no third-party code, unless an owner explicitly asks") was written for
the operating system. A sign-in server is different ground: the classic ways real systems are
broken are hand-rolled password storage, session handling, token signing, OAuth state checks
and TLS. Options:

| Option | What is ours | What is not | Risk |
|---|---|---|---|
| a. Fully custom, as the OS | everything, including HTTP parsing, WebSocket framing, JSON, password hashing, token signing; TLS left to a reverse proxy in front | only the operating system and the TLS terminator | highest: every security primitive is new code; time to a safe first version is longest |
| b. Language standard library only | the application: accounts, roles, quotas, relay, admin UI | the runtime's own HTTP, crypto (HMAC, random, password hashing if the standard library has one) and TLS | moderate: standard libraries of Go, Node and Python are widely reviewed; nothing to audit beyond the language |
| c. Standard library plus a short, named list of audited dependencies | as b | for example a database driver, an Argon2id implementation, a WebAuthn verifier | lowest for security primitives; each dependency is a supply-chain risk and needs a version pin and updates |

Facts that bear on it:
- Password storage: OWASP's Password Storage Cheat Sheet recommends Argon2id with at least
  19 MiB of memory, 2 iterations and parallelism 1 (or 46 MiB, 1 iteration) [read:
  https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html, figures
  as quoted by secondary sources; the page itself must be checked]. Go's standard library has
  no Argon2 (it is in the separate `golang.org/x/crypto` module); Node's has scrypt and
  PBKDF2 built in (`crypto.scrypt`, which OWASP lists as acceptable); Python's has scrypt
  through hashlib when OpenSSL provides it [read, from memory of the libraries: to verify].
- Runtimes on this machine [tested: `command -v`]: Node, Go, Python 3, Rust, Bun. The OS's own
  tooling (tools/*.mjs, the relay prototype `relay.mjs`) is Node already.
- If sign-in uses passkeys only (point 4), there is no password to store at all, but WebAuthn
  verification (CBOR, COSE keys, attestation formats) is a sizeable piece to write or to take
  from a library.

| Runtime | For | Against |
|---|---|---|
| Node | same language as the OS's host layer and the relay prototype; WebSocket and HTTP servers are easy with the standard library plus little code; scrypt built in | no WebSocket server in the standard library (only a client), so framing is written by us or taken from a dependency |
| Go | one static binary to deploy; HTTP, TLS and crypto in the standard library; strong concurrency for a relay with many connections | Argon2id and WebSocket need `x/` modules or own code; a second language in the project |
| Python | quick to write admin pages | slowest for a relay pushing many MB/s; async WebSocket needs a dependency |
| Rust | performance and memory safety | slowest to write; nearly everything is a dependency |

The database: SQLite in a file (no server, enough for a club's users; one writer at a time),
or PostgreSQL (a server to run and back up). Quotas that change per packet must not hit the
database per packet in either case (point 7).

## 3. Hosting

The network study found that Cloudflare's, Deno Deploy's and Vercel's terms forbid general
proxies ([read], quoted in the OS repository's network study, `docs/NETWORK-ACCESS.md` section 6), so the relay
needs a machine the club controls. The proxy restricted to an allow-list is closer to a
"reverse proxy", which Deno's terms allow; Cloudflare's wording ("other similar proxy
services") is broader. Options:

| Option | Runs | Facts |
|---|---|---|
| a. One small VPS for everything (static site, accounts, proxy, relay) | all of it | one machine to patch and back up; bandwidth of every member goes through it; cost: a few euros a month at common providers [estimate: prices not read]; the provider's own acceptable-use policy must allow a members-only relay (not read yet) |
| b. Static site on a static host, server on a VPS | the OS from the static host; accounts, proxy and relay on the VPS | cookies and CORS cross two origins (see below); the static host is free and fast; the VPS carries only server traffic |
| c. A machine at 42 or of a club member | everything | no hosting cost; 42's network rules and uptime; legal exposure of whoever owns the line (the study quotes Tor's warning about running exits from home) |
| d. Serverless for the proxy, VPS for the relay | proxy on a platform whose terms allow a reverse proxy | two deployments; the relay still needs a VPS |

Same origin or not matters:
- If the page that runs UC.OS and the account server share an origin (for example
  `dux.ensui.dev` serves both, the server behind a path such as `/api/`), a session cookie
  works with no CORS and the page's storage and the session belong to the same site.
- If they differ, the page must call the server cross-origin with credentials (CORS with
  `Access-Control-Allow-Credentials`, cookies `SameSite=None; Secure`, and third-party cookie
  restrictions in browsers apply), or carry a token instead of a cookie.
- A relay must be `wss://` from an https page, with a valid certificate [tested in the
  network study]. Certificates: Let's Encrypt on the VPS, or the static host's own.
- Domains named at the start of the project: `dux.ensui.dev` and the colleagues' subdomains
  (DECISIONS.md, hosting is open). Several domains serving the OS would each be a separate
  origin with separate browser storage for the user's files (persistence is per origin).

## 4. How platform accounts sign in

The 42 link is not a sign-in (owner's decision), so the platform needs its own:

| Option | Facts |
|---|---|
| a. E-mail and password | familiar; needs password hashing (point 2), password reset by e-mail (so an e-mail sender), protection against credential stuffing (rate limits, breached-password check optional) |
| b. Passkeys (WebAuthn) | no password to steal or reset; phishing-resistant; supported by current browsers; recovery when the device is lost needs a second passkey or another method; server-side verification is a sizeable piece of code (point 2) |
| c. Magic link by e-mail | no password; depends on e-mail delivery and on the mailbox being safe; an e-mail sender is required |
| d. Invitation by an administrator | the administrator creates the account and sends a one-time link to set a passkey or password; no open sign-up |
| e. Combinations | for example open sign-up with passkey plus e-mail recovery; or invitation only |

Open sign-up against invitation is a real choice: open sign-up lets anyone get the "signed
in" tier (the allow-listed proxy), so abuse limits on that tier matter more.

Personal data: keep it minimal (an e-mail address only if a method needs it; the 42 login
and id if linked). A student club in Portugal storing accounts is subject to the GDPR. What
the owners should check (this is not legal advice): who the controller is (the club, an
association, or individuals); a privacy notice; the legal basis; retention of logs (an IP
address is personal data, CJEU C-582/14, as quoted in the network study); what happens to
data when a member leaves; whether 42's own rules for applications using its API add
conditions.

## 5. The 42 link

- 42's API is an OAuth 2 provider. The web application flow: redirect to
  `https://api.intra.42.fr/oauth/authorize` with `client_id`, `redirect_uri`,
  `response_type=code`, `scope` and `state`; exchange the code for a token on the server;
  read `/v2/me` [read, network study section 7.3 and
  https://api.intra.42.fr/apidoc/guides/web_application_flow].
- Scopes: `public` is the default in client libraries; `projects` and `profile` appear as
  optional; no complete list was found without a 42 login [read: client libraries such as
  https://github.com/42Berlin/api42lib and https://packagist.org/packages/mehdibo/oauth2-fortytwo].
  A link needs only `public`.
- Rate limit: one project reports 2 requests per second per application; applications can be
  approved as Official or Certified to raise limits [read:
  https://api.intra.42.fr/apidoc/guides/getting_started, via search summaries]. A link costs
  one or two requests per user, once.
- What to store: the 42 user id and login, and the campus if the role depends on campus
  (for example 42 Lisboa only, or any 42 campus: an owner decision). No 42 access token needs
  to be kept after the link is made.
- Registering the application needs a 42 account (an owner or a member) and the redirect
  URL of the platform; the client secret lives only on the server.
- A frozen 42 account: sign-in to the platform is unaffected (decided). Open: does a freeze
  remove the member role, and how would the platform even know? The link is made once; the
  platform does not see a later freeze unless it re-checks. Options: the member role lasts
  until an administrator removes it; re-check at each new link or periodically (needs the
  user to re-authorise, which a frozen account cannot do); an expiry on the role (for example
  a school year) after which the user re-links.
- Unlinking: the user can remove the link; an administrator can too; the 42 id is then
  deleted or kept to stop the same 42 account being linked to several platform accounts (one
  42 account to one platform account is a likely rule: owner decision).

## 6. Roles and permissions

A starting model to discuss [estimate]:

| Role | How one gets it | Can |
|---|---|---|
| guest | not signed in | nothing on the server |
| user | has a platform account | use the allow-listed proxy within quotas; manage own account and own relay address |
| member | linked 42 account (rule as in point 5) or granted by an administrator | use the relay within quotas |
| administrator | granted by another administrator; the first one created at installation | users and roles (create, read, update, delete), quotas and limits, the allow-list, panic switches, the audit log |

Open: separate moderator and administrator roles; whether administrators need a second factor
(likely yes); whether any action needs two administrators (for example deleting another
administrator); an audit log of every administrative action, kept how long.

## 7. Quotas and limits

- Per user: bytes per day, simultaneous connections, connections per minute, destinations
  per minute (fan-out, a sign of scanning), and for the proxy requests per minute.
- Global: total bandwidth, total connections, per-destination caps (so a mirror is not
  hammered).
- What the user sees when a limit is reached: an error that reaches the program inside the OS
  (an HTTP 429 from the proxy; a refused stream with a reason code from the relay) and a line
  in the OS's terminal or notification area (the OS side).
- Speed: the relay keeps counters in memory and checks them per stream open and per chunk,
  and writes totals to the database periodically; quotas are loaded at connect time and
  refreshed on a short timer or when an administrator changes them [estimate].

## 8. Tokens between the page, the OS and the relay or proxy

- Sign-in happens on the platform's own pages, outside the OS (a normal web page), or in a
  dialog the OS's page shows. The OS itself never sees a password.
- The page then holds a session (a cookie on the platform origin). For each relay or proxy
  connection the page obtains a short-lived token (minutes) from the platform and presents it
  on the WebSocket upgrade or the proxy request.
- Programs inside the OS must not be able to read or exfiltrate the token: the token stays in
  the host layer (JavaScript in `boot/`), and programs only ask the host to open a connection
  or fetch a URL. This fits the prototype, where the relay client lives in the host layer
  [read: `boot/net-proto/wisp.mjs`].
- Token format: an HMAC-signed string (user id, role, expiry, a session id for revocation)
  checked by the relay with a shared secret; or an asymmetric signature so the relay holds
  only a public key. Revocation within the token's lifetime: a short list of revoked session
  ids pushed to the relay.

## 9. The relay and the proxy as services

- Wire protocol: the prototype uses Wisp v1 framing over one WebSocket. The colleague's
  stack (pull request #17) may want a different interface (a packet tunnel, or sockets). To
  be settled with the owner and the colleague; it is not decided here.
- Destination policy (relay): ports (80 and 443 only for members, or wider), block private,
  loopback, link-local, CGNAT and cloud metadata addresses after resolution, connect to the
  address that was checked (against DNS rebinding) [read: network study 7.2; the prototype
  does this].
- The allow-list (proxy): which hosts and path prefixes (Debian and Ubuntu mirrors,
  github.com smart HTTP paths for clone, release asset hosts, PyPI, crates, GNU, kernel.org);
  who maintains it (administrators, from the admin interface); redirects checked hop by hop.
- `git clone` through a proxy that terminates TLS works over smart HTTP (GET `info/refs`,
  POST `git-upload-pack`), tested through the prototype for refs [read: network study]. A
  push would need POST `git-receive-pack` with credentials passing through the proxy: likely
  excluded.
- Logging: what is logged (account, destination host, bytes, time), for how long, who can
  see it. The proxy sees full URLs and content; the relay sees only host, port and volume when
  the OS does TLS itself (today it does not: an open point for the OS side and the owner).

## 10. Safety automation and panic switches

- Signals of trouble: a user's fan-out (many destinations or ports in a short time), many
  refused destinations, traffic to mail ports if allowed, sudden volume, many failed sign-ins,
  abuse reports. Thresholds per signal, starting conservative [estimate].
- Actions, in order: throttle the user, suspend the user, suspend a tier, suspend the relay
  globally. The owner asked for automatic global suspension on emergencies: define what an
  emergency is (for example several users tripping limits at once, or total traffic far above
  normal, or the host provider's abuse contact) and how it is lifted (only by an
  administrator).
- Notification: e-mail to configured administrators, or a webhook to a chat (Discord, Slack,
  Matrix), or both. Each needs an account or a sender on an outside service: the owners
  choose which.
- Panic switches in the admin interface: relay off, proxy off, sign-in off, new sign-ups off;
  each takes effect within seconds on live connections (the relay checks a flag on each
  chunk or receives a push).

## 11. Bring your own relay

- The smallest form is the prototype's one file, `relay.mjs` (148 lines, Node only), behind a
  TLS terminator on a machine with a public `wss://` name [read: network study 7.4].
- Platforms: the quoted terms of Cloudflare, Deno and Vercel forbid general proxies even for
  one user; a user's own VPS or home machine does not conflict with a platform's terms.
- In UC.OS: a setting where the user types the relay's address (stored in the page's
  storage, not on the platform, so it works without an account). Whether the platform should
  also store it for signed-in users (so it follows them across browsers) is open.

## 12. Root in the OS and the platform

The owner said a root user exists "perhaps for authenticated admin users or even authenticated
42 or specifically authorized users by admins". The OS side is building a switch: the page tells
the kernel at boot whether this user is entitled to root.
- What the platform would assert: "this session belongs to a user with role X", in a signed
  token the page fetches (point 8).
- Can a static page trust it? Partly. The page runs on the user's own machine: anyone can edit
  the page in their browser and set the switch to true. Root inside the user's own copy of
  UC.OS, on their own machine, protects nothing the user could not already change. What root
  must NOT unlock is anything on the server side: the relay and proxy check their own tokens
  and never trust the OS's root. So the switch is a convenience inside the OS, and the real
  access control lives in the platform and the relay [estimate].
- The open question then is product, not security: which roles see root by default.

## 13. Order of building, once the owners have chosen (proposal for discussion)

1. Threat model written down.
2. A local test environment with a stand-in OAuth server of our own (no real 42 credentials).
3. Accounts and roles, with an authorisation test for every endpoint and role.
4. The proxy with the allow-list, quotas and the panic switch.
5. The relay for members, with quotas and destination policy.
6. Safety automation and notifications.
7. The admin interface.
8. Wiring into the OS's host layer, with the OS side and the colleague.

No deployment, no outside account, no 42 application registration, no purchase, until the
owner asks for that specific step.

## 14. Decisions for the owners, in one list

0. ~~Identity~~ DECIDED: the Clubroom is the identity provider (section 0b).
0b. From 0b: where roles are managed (Clubroom, UC.OS, or split); how the page signs in (public client or backend for frontend); the protocol to ask of the Clubroom (OpenID Connect with PKCE, signed tokens, a UC.OS scope, change notification); what to do until it exists.
1. Where the code lives (point 1).
2. Whether rule 3 applies to the platform, and which runtime and database (point 2).
3. Hosting and domain layout, same origin or not (point 3).
4. ~~Sign-in method~~ now the Clubroom's.
5. Which 42 accounts count (Lisboa only or any campus); one 42 account per platform account;
   what a freeze does to the member role (point 5).
6. The role model and whether administrators need a second factor (point 6).
7. Default quotas (point 7).
8. Token format (point 8).
9. Relay wire protocol, together with the colleague (point 9).
10. What counts as an emergency; notification channel (point 10).
11. Whether the platform stores a user's own relay address (point 11).
12. Which roles get root in the OS by default (point 12).
13. Data protection: controller, privacy notice, log retention (point 4).

## 15. Second round of owner decisions (2026-11-26 12:53)

The owner answered section 14 point by point. In their words where they gave words:

| Point | Decision |
|---|---|
| Roles | split: identity, account status and the 42 link in the Clubroom; member grants, UC.OS administrators, quotas and relay bans in UC.OS |
| Page sign-in | backend for frontend: the UC.OS platform does the code exchange and holds tokens; the page has a session cookie; relay tokens are minted short-lived |
| Until the Clubroom provider exists | a test stand-in that speaks OpenID Connect with PKCE |
| Code | its own repository in the club's organisation |
| Stack | "for now c with Go, but later we'd like to build a fully custom server in C for this" (deferred) |
| Hosting | one VPS, one origin: site, platform, proxy and relay |
| 42 accounts | any campus; one 42 account to one platform account; member role expires each school year, renewable by re-linking, revocable early by an administrator ("All of your review is good") |
| Admins | "The admins are the maintainers"; administrators are bootstrapped directly by 42 login (as the Clubroom does with its bootstrap list); no two-administrator rule; audit log kept; moderator role deferred; second factor for administrators stays a requirement on the Clubroom |
| Relay quotas | "make it half on all 3 params for now and tune over time": 2.5 GB a day, 8 simultaneous connections, 15 new destinations a minute, ports 80 and 443 only. Assumption: the proxy's quotas for signed-in users stay as proposed (2 GB a day, 120 requests a minute) because the owner wrote "if this is only the relay quotas" |
| Wire protocol | Wisp-compatible now, our own later (deferred) |
| Emergencies | as proposed: automatic global suspension on three or more users tripping limits within 10 minutes, traffic far above the 7-day norm, or a critical abuse report; lifted only by an administrator; e-mail plus a club chat webhook |
| Own relay address | in the browser by default, optional sync for signed-in users |
| Root in the OS | root for everyone in their own copy; network access is what roles gate |
| Data | Clubroom user id, counters, connection logs of destination host, bytes and time, 30 days |

Point 10 (token format) turned into a different question; see 15.1. Point 13 brought a new
idea; see 15.2.

### 15.1 Token format, and moving a user's data between devices

**The token question first.** The relay token does not tie anything to a device. On any
device, the user signs in at the Clubroom; the UC.OS platform then gives that browser a session
cookie, and whenever the OS opens a relay or proxy connection, the page asks the platform for a
5-minute token and hands it to the relay. Two laptops, one account: both work, each with its
own short tokens. The open part of point 10 is only how the token is signed (an HMAC secret
shared with the relay, or an Ed25519 key pair so the relay holds only the public key). That
stays as proposed (Ed25519) unless the owner says otherwise.

**The new question: carrying a user's UC.OS data to another device.** Today everything a user
writes lives in that browser's storage on that device (persistence, being built). Options:

| Option | How | Holds | Expires | Facts |
|---|---|---|---|---|
| a. QR code holding the data itself | the OS encodes settings into a QR shown on screen; the other device scans it | at most 2,953 bytes in the largest QR code (version 40, lowest error correction); about 2,331 bytes with medium correction | cannot expire: the data is in the picture, anyone with a photo of it has it forever | enough for a settings file (theme, keyboard, relay address); far too small for files: a single wallpaper or one `.shrc` with history does not fit |
| b. QR code as a pairing key, data through the platform (the WhatsApp model) | the old device encrypts a bundle with a fresh random key, uploads the ciphertext to the platform with an expiry the user picks; the QR holds only the bundle id and the key; the new device scans it, downloads, decrypts | as much as the quota allows (whole home directory) | yes: the platform deletes the ciphertext at expiry, and the key in the QR is useless after that | the platform never sees the plaintext (it holds a random-key ciphertext); needs a signed-in user and a storage quota on the server; the scanning device needs a camera, or the QR also carries a short code to type |
| c. Encrypted file export | download a file (an archive of chosen paths, encrypted with a passphrase); import it on the other device by dropping it on the page | everything | no (it is a file the user keeps) | no server, no account, works offline; the file import path is being built in the doom stream |
| d. Continuous sync for signed-in users | the platform stores an encrypted copy of chosen directories and keeps devices in step | chosen paths | n/a | the most convenient; the largest piece of work (conflicts when two devices change the same file); server storage per user |

**My view:** b for moving between devices, c as the offline and no-account path, a only for
the small settings bundle where a single scan is convenient. d later if people ask for it. b
and c share most of their code (the same encrypted bundle format; b adds an upload with
expiry), so building c first and b on top is natural.

### 15.2 Browser extension relay (idea)

What an extension can and cannot do [read from memory of the platforms' documentation; to
verify before any work]:
- **It can fetch any site without CORS**, if it declares host permissions; the page talks to it
  through `externally_connectable` (Chrome) or messages. That alone gives apt from official
  mirrors and `git clone` over https with no server at all, and the operator (us) sees
  nothing: a per-user version of shape B, running in the user's own browser.
- **It cannot open raw TCP.** Chrome's socket API was for Chrome Apps, which are gone.
  Arbitrary TCP needs a native helper program (native messaging), which is an installation.
- **Install flow**: Chrome removed inline installation from other sites in 2018; a button can
  only send the user to the extension's Chrome Web Store page, where they click Add. Firefox
  allows installing a signed extension from a link with a browser prompt. Safari needs an app.
- **Costs**: store review and policies (a general fetch-anything extension draws scrutiny),
  one build per browser family, keeping it updated, and it is the user installing software,
  which the owner wanted to avoid for the default path; as an optional extra it fits beside
  bring-your-own relay.

Listed as an idea for later, not a decision.

### 15.3 Decisions of 2026-11-26 13:12

- **Moving user data between devices**: the owner took the proposal as written: "build c first (the offline path, no account needed), then b on top, since they share the encrypted bundle format; use a for small settings only; d later if people ask". So: encrypted file export and import first; then the QR pairing key with the encrypted bundle held by the platform until the expiry the user sets; a small settings QR; continuous sync deferred.
- **Repository**: https://github.com/42-UNIX-CLUB/ucdotweb, created 2026-11-26 13:12 UTC, PRIVATE, empty, no licence. Facts that follow: GitHub rulesets and branch protection are not available on a private repository of a free organisation ("Upgrade to GitHub Pro or make this repository public to enable this feature", from the API), so `main` cannot be protected there as the OS repository's is. No licence means all rights reserved by the authors.

### 15.4 Recommendations accepted (2026-11-26 13:27)

The owner: "go with all your recommends". Recorded as decided:
- Every control marked as a proposal in `docs/THREAT-MODEL.md` (cookies, CSRF, OAuth state and
  nonce, content security policy, log minimisation, encrypted refresh tokens, VPS hardening,
  secret checks and module verification in CI, an abuse contact, the git-clone notice).
- Connection logs carry the pseudonymous Clubroom id, not the 42 login.
- Repository: it stays private as the owner created it; `main` cannot be protected on a free
  organisation's private repository, so work still goes through branches and pull requests by
  convention, as in the OS repository. No licence file while private; choose one before the
  code is ever published.
- Token signing: Ed25519, 5-minute relay tokens, revocation list pushed to the relay.

### 15.5 Outside modules (2026-11-26)

The design allows the Go standard library plus a short, named list of modules. The list:

| Module | Version | Why | Notes |
|---|---|---|---|
| github.com/mattn/go-sqlite3 | v1.14.53 | the database (SQLite in one file, decided as "SQLite or PostgreSQL" was left to the recommendations, which the owner accepted) | uses cgo: building needs a C compiler; it bundles SQLite's C source. A pure-Go alternative (modernc.org/sqlite) avoids cgo but is a much larger dependency |

### 15.6 Admin pages (2026-11-26 19:56)

Decided by the owner: the admin pages are a **UC.OS program** (C, a libui window inside the
OS) that calls the admin API (`/api/admin/`, see `internal/web/admin.go`).

Open, for the owners: how that program reaches the API without opening it to every program.
The threat model treats code inside UC.OS as untrusted (it may be a Debian package). Today the
router's host half (`boot/hostnet.mjs` in the OS repository) carries a program's HTTP
request through the page's `fetch()`. A request to the page's own origin carries the
session cookie, because `fetch()` sends credentials to the same origin by default. On a POST
the browser adds the page's own Origin header. Read from the code and the Fetch standard;
not yet tested in a browser. So once the platform shares the OS's origin, any program run by a
signed-in administrator could call the admin API with that administrator's rights, and any
program run by a member could mint a relay token. The program never sees the cookie, but it
does not need to. Options:

| Option | What changes | Cost and limits |
|---|---|---|
| a. Programs' requests carry no credentials | `hostnet.mjs` passes `credentials: 'omit'`; the platform is reached only through a separate host channel that only allowed programs can use (for example a device that only the admin program, as installed in the image, may open) | closes the hole for every program; needs a new kernel and host channel and a rule for which programs count as allowed; the proxy and relay go through the host layer anyway (section 8) |
| b. A confirmation outside the OS | the page shows its own dialog, drawn by `boot/` and not by any program, with the action spelled out; the platform accepts a change only with a short-lived confirmation it minted after that dialog | stops silent changes even from a hostile program; reads (user list, logs) stay open to programs unless they are also confirmed; one click more for each change |
| c. A header programs cannot set | `hostnet.mjs` refuses one header name from programs (it already refuses Cookie and Origin); the page's own admin channel sets it and the platform requires it on `/api/admin/` and `/api/relay-token` | small change; who may use that channel remains the question of option a |
| d. Accept the risk | nothing | an administrator must use the admin program only in a session where they run nothing else |

Until one is chosen, the platform should not be served on the OS's origin with real
administrators signed in. (It is not deployed: the identity provider does not exist yet.)

Decided by the owner (2026-11-26, after 19:58): **option a, with the admin program as the only
allowed one.** Programs' requests through the router carry no credentials. Only the admin
program reaches the platform with the session, through its own channel. What this asks of
the OS side (kernel and `boot/`): the router's fetch omits credentials; a channel
that carries the session, which the kernel lets only the admin program use; and a way to know
it is the admin program as installed in the image, which a program cannot fake by writing a
file of the same name. The proxy and relay for other programs still go through the host
layer (section 8), which also holds the session; that path is for members' traffic, not for
the admin API.

### 15.7 Allow-list and safety automation as built (2026-11-26)

Mechanical choices made inside decided designs; each can be reversed.

Allow-list (`internal/store/allowlist.go`, `internal/proxy/rules.go`):
- It lives in the database. It is seeded once per database from `UCDOTWEB_PROXY_RULES` or the
  built-in list, with an audit entry by "seed". After that only administrators change it. An
  emptied list stays empty after a restart.
- Changes take effect on the next request, with no restart. The proxy reloads when a change
  counter moves. A change written by another process (the sqlite3 shell) is not seen until
  the next change made through the service.
- If the list cannot be read, the proxy refuses (503) rather than keep an old copy.
- Input is checked: plain lowercase DNS names only (no IP literal, port, scheme or wildcard,
  and no private suffix such as localhost, local, internal, lan, home.arpa, test, onion).
  Prefixes start with "/" and carry no dot segments or encoded slashes. A rules file is now
  checked the same way, so a file accepted before can now be refused.

Safety automation (`internal/safety`, `internal/store/safety.go`):
- A pass runs every minute. A tripped check sets the switch with actor "safety", writes the
  reason to the audit log and notifies once. A switch that is already on is left alone. The
  watcher never lifts a switch. After an administrator lifts it, only newer evidence counts,
  and the traffic check rests for the rest of that UTC day.
- Limit trips are read from the connection log. These outcomes count: too many connections,
  too many destinations, daily quota, cut at daily quota, rate limited, and "... cut at quota".
  Refused ports, addresses outside the allow-list and blocked addresses do not count.
- Traffic: today's bytes above 5 times the daily average of the previous 7 days and above
  10 GB (about four members at full quota). It is not checked until 7 days of history exist.
- Abuse reports are filed by administrators only (`POST /api/admin/reports`); a critical one
  suspends at once.
- Notifications: chat webhook (URL in a file, https only; Discord's or Slack's body) and
  e-mail over SMTP with STARTTLS required. Each is off until configured. A message holds the
  switch, the time and the reasons, with pseudonymous ids only.

Open, for the owners:
1. Which service an automatic suspension stops. The decision says "global suspension"; the
   design text says the relay. Built default: relay only (`relay_off`), with proxy only or
   everything (`all_off`) as settings.
2. Whether refused ports or destinations count as tripping a limit.
3. Whether a user who used up their quota and keeps retrying counts (each retry logs "daily
   quota" again, but they count as one user).
4. The traffic factor (5), floor (10 GB) and the 7-day history rule.
5. What the traffic check does on the day an administrator lifts a traffic suspension
   (built: it rests until midnight UTC).
6. Which chat service and which mail sender. Both need outside accounts; none was created.
7. Whether abuse reports ever get a public intake (needed for the published abuse contact).

### 15.8 Decisions of 2026-11-26, late evening ("yes" to the recommendations)

The owner was asked for recommendations on the open points of 15.7 and on what to take from
an independent second build (branch `web/platform-cloud`, for comparison only), and answered
"yes". Decided, and built unless marked otherwise:

- **Switches** "sign-in off" (`signin_off`) and "new sign-ups off" (`signup_off`), as listed
  in section 10. Administrators and maintainers stay exempt from both.
- **Recent sign-in for admin changes:** within 15 minutes (`UCDOTWEB_ADMIN_FRESH`). It is
  measured from the provider's `auth_time` when sent, else from the session's start. A stale
  one gets 401 with `{"error": "reauth", "login": "/auth/login?reauth=1"}`. That URL asks the
  provider for a real sign-in (`prompt=login`, `max_age=0`). Not checked: whether the
  Clubroom honours those parameters.
- **School year:** replaced by 15.9 (42 has no fixed start of the year).
- **Platform caps:** a daily byte cap per service, for all users together, set by
  administrators (`/api/admin/caps`). Off (0) until the VPS allowance is known. A cap stops
  new requests and connections within about 10 seconds of being reached.
- **Retention:** the audit log is kept indefinitely. Abuse report summaries are erased after
  12 months; the rest of each report stays.
- **Safety:** a suspension stops the relay only. Refused ports and destinations do not
  count. A retrying user counts once. Traffic: 5 times the 7-day average and at least 10 GB,
  tuned after about a month of data, and counted only for the service the switch stops (a
  proxy surge cannot suspend the relay). The traffic check rests until midnight UTC on the
  day an administrator lifts a suspension.
- **Notifications:** a chat webhook only at first, to a private admin channel on the club's
  chat. E-mail can come later. On 2026-11-27 the owner left the choice to the platform's
  developers ("what you believe fit best is fine"): a Discord webhook, its URL in
  `/etc/ucdotweb/webhook.url` on the server, written there by an administrator
  (DEPLOY.md 2.6.1). Not configured yet: the webhook has to be made in Discord.
- **Abuse reports:** a published e-mail address that forwards to the administrators, before
  the relay opens to members; no public web form. Administrators file reports through the
  API. Not set up: the address needs an owner.
- **Kept as built on the laptop:** SQLite, sessions on disk encrypted, the relay key from a
  file, and the relay token in the WebSocket protocol header.
- Not taken from the second build: the example allow-list file.

### 15.9 Member role from a 42 link follows the 42 account (2026-11-27)

The owner: "there is no year fixed start". The options were: a fixed term from the link date;
follow the 42 account's own state; a date chosen by the club; no automatic expiry. The owner
chose "b": **the member role from a 42 link lasts while the linked 42 account is active.**
This replaces "expires each school year, renewable by re-linking" (section 14 and 15).

- The Clubroom decides "active" from 42's data (for example a cursus not ended and not
  blackholed) and sends it as the claim `ft_active` (true or false). This is new work in the
  Clubroom, alongside its linkage update.
- The platform reads the claim at sign-in, so a change at 42 shows at the next sign-in (a
  session lasts 12 hours at most).
- Mechanical choice, reversible: until the Clubroom sends the claim, a missing `ft_active`
  counts as active, so nobody loses the role before the Clubroom ships it (`ftActive` in
  `internal/web/web.go`).
- An administrator's member grant still counts on its own, whatever the claim says.

### 15.10 Device-transfer bundles: the server side (2026-11-27)

Option b of 15.1 (decided 15.3): the OS encrypts a bundle in the browser with a random key,
uploads only the ciphertext, and shows a QR code holding the bundle id and the key. The owner
answered the three open numbers on 2026-11-27:

- **Who may download:** the same account only. Another account, or a missing or expired
  bundle, all get the same 404.
- **Space:** a per-tier limit on the bytes a user keeps in pending bundles, `bundle_bytes` in
  the quotas table, set by administrators through `POST /api/admin/quotas` (now five limits,
  all required). Default 50 MB for both tiers. 0 means no limit, as for every quota.
- **Longest expiry:** 30 days. The user picks it per bundle (`expires_in`, 60 seconds to 30
  days).

Built (`internal/web/bundles.go`, `internal/store/bundles.go`):

| Route | What |
|---|---|
| `POST /api/bundles?expires_in=SECONDS` | body: the ciphertext as `application/octet-stream`, from our own origin. Answers 201 with `id`, `size`, `expires_at` |
| `GET /api/bundles` | the user's pending bundles, `used` and `limit` |
| `GET /api/bundles/{id}` | the ciphertext, as a download (`attachment`, `sandbox`, `no-store`) |
| `DELETE /api/bundles/{id}` | removes it at once, from our own origin |

Mechanical choices, reversible:
- A bundle is a file named by its id in `UCDOTWEB_BUNDLE_DIR` (default: `bundles` beside the
  database), not a database row, so large bundles do not pass through SQLite. The id is 128
  random bits.
- One upload at a time per user (a second gets 409), so the space check cannot be raced.
- Housekeeping, hourly, removes expired bundles and stray files more than an hour old.
- Any signed-in user may upload: the design names no role for it.
- Not built: an administrator view of bundles or a way to delete another user's. The server
  cannot read them, so there is nothing to moderate; ask if one is wanted.

Left for the OS side: the bundle format, the encryption, and the QR code. 15.1 also
plans an offline encrypted file export (option c) first, built entirely in the OS.

### 15.11 Fixes from the first code review (2026-11-27)

A code review read the whole code base and confirmed each of these with a test (the tests
are in the `opt_test.go` files). Fixed, inside the decided design:

- Relay: the new-destinations-a-minute limit no longer resets when the socket is closed and
  reopened. A user's state is kept until their last destination is a minute old.
- Relay: a stream may have at most 8 MiB of client data waiting for the far end (credit
  counts packets, and one packet may be 1 MiB). That is a full credit of 64 KiB packets, the
  size the OS's client sends, so an honest client never reaches it. A first cap of 1 MiB reset
  such clients and was raised.
- Relay: a CLOSE that arrives while the connection is being made no longer leaves that
  connection open. Refused CONNECTs are logged at most 10 a minute per user and kind of
  refusal (all refused ports are one kind), so a flood of one kind cannot hide a limit trip.
- Address guard: an IPv6 literal with a zone (`%lo`) is refused; it escaped the prefix list.
- Panic switches: a switch that cannot be read counts as on (fails closed).
- Proxy: the rate limit is checked before anything is logged, so refused requests are limited
  too; only the first refusal of a burst writes a "rate limited" row; hosts over 253
  characters are refused.
- Bundles: the space limit bounds the disk. Expired bundles count until their file is gone,
  and a user's own expired bundles are removed at their next upload. Housekeeping keeps a file
  when it cannot read the database, and goes on past a file it cannot remove. A failure on our
  disk answers 500 and is logged.

Open, put to the owners on 2026-11-27 with options: anonymous
`/auth/login` stores a row each time; the admin bootstrap reads the `login` claim without the
42 link; limit trips of either service suspend the relay; bundle traffic is outside the
quotas and caps, and `bundle_bytes = 0` has no ceiling.

### 15.12 Sign-in hardening (2026-11-27)

The owner decided three of the points left open in 15.11. Built:

- **Sealed cookie (finding 7).** `GET /auth/login` writes no database row. The pending
  sign-in (state, nonce, PKCE verifier, start time) lives in a cookie sealed with AES-GCM.
  The sealed content carries its own expiry, 10 minutes after the start. The callback opens
  it, checks it and clears it. A missing, tampered or expired cookie gets the existing 400
  ("No sign-in in progress"). A session row is written only when the callback succeeds.
- **Current session kept (finding 15).** `GET /auth/login` no longer drops the visitor's
  session. It stays until a callback succeeds; then the new session replaces it, with a new
  id as before. A refused or failed callback leaves it as it was.
- **Maintainer bootstrap needs a 42 link (finding 8).** A login in `UCDOTWEB_ADMIN_LOGINS`
  counts only when the claim `ft_linked` is true. The same rule applies to the maintainers'
  exemption from `signin_off` and `signup_off`, the only other place maintainers are
  treated specially (`isMaintainer` in `internal/web/web.go`). An administrator with an
  admin grant stays exempt from `signin_off` whatever the claim says, as before.

Mechanical choices, each reversible:
- The cookie's key is HMAC-SHA256 of the label "ucdotweb pending sign-in v1" under the
  database key (`store.DeriveKey`). No new secret file. The label is also the AES-GCM
  additional data. To use a separate key instead, add a key file and pass it to the server.
- The cookie is `HttpOnly`, `SameSite=Lax`, `Max-Age=600`, and `Secure` unless
  `UCDOTWEB_INSECURE_COOKIES=1`. Its name is `__Host-ucdotweb-signin` (or
  `ucdotweb-signin` without Secure) with path `/`, like the session cookie, so no other site
  under the same domain can plant one. A first version used `__Secure-` with path
  `/auth/callback`, which a sibling name could set; the review caught it. The cost: during a
  sign-in the cookie (a few hundred bytes) goes with every request to the origin. Change `pendingPath` and `pendingCookie` in
  `internal/web/pending.go`.
- Reuse: the callback clears the cookie, and the state of each sign-in that completes is
  remembered in memory until its expiry. A second callback with the same cookie, even with
  a new valid code, gets 403. Only completed sign-ins are remembered, so the list grows with
  real sign-ins only. A restart forgets it. Remove `usedStates` to drop this.
- A refused sign-in leaves the current session alone, with one exception: when the provider
  says this very account is not active, or the account is banned here, that account's
  session is ended too (`dropSessionOf`). `ft_active` plays no part in the maintainer rule.
- The 15.11 test `TestOptLoginStoresARowPerAnonymousRequest` passes unchanged (0 rows for
  300 requests). The two tests that sign in as a maintainer now send `ft_linked: true`.

### 15.13 Safety and bundle limits (2026-11-27)

The owner answered two of the points left open in 15.11.

**Finding 9, "relay trips only".** The limit check (three or more users hitting limits within
10 minutes) counted limit outcomes from every kind of connection log line, so three users at
the proxy's rate limit suspended the relay. Decided: it counts only trips of the service the
switch stops, as the traffic check already did. Built (`switchKinds` in
`internal/safety/safety.go`; `LimitSubjects` and `TrafficByDay` in `internal/store/safety.go`
take a list of kinds):

| Switch | Limit trips counted | Traffic counted |
|---|---|---|
| `relay_off` (default) | relay | relay |
| `proxy_off` | proxy | proxy |
| `all_off` | relay and proxy | relay and proxy |

Mechanical choice: `all_off` counts the relay and the proxy, not "every kind". Before, it
counted every usage kind; now that bundle traffic is in the usage table too (below), "every
kind" would let a bundle surge stop the relay and the proxy, and no switch stops bundles.
Bundles write no connection log lines, so for the limit check the two readings are the same.
To reverse: make `switchKinds` return nil for `all_off` (nil means every kind).

**Findings B4 and B5, bundle limits.** The owner picked all three options:

1. **Count in the daily quota.** Bundle bytes uploaded and downloaded count against the
   user's daily byte quota and a platform daily cap, like proxy traffic.
2. **Per-upload ceiling.** One upload is 200 MB at most, even when `bundle_bytes` is 0.
3. **Platform storage cap.** A total for all users' stored bundles together, set by
   administrators, 0 (no cap) by default.

Built (`internal/web/bundles.go`, `internal/store/caps.go`, `internal/store/bundles.go`,
`internal/web/admin.go`):

| Limit | Where it is set | Refusal |
|---|---|---|
| user's daily bundle bytes | the tier's `bytes_per_day` (quotas API), counted over bundle traffic only | 429 |
| platform daily bundle bytes | caps row `bundle` (`POST /api/admin/caps`) | 503 |
| one upload | fixed, `BundleMaxUpload` = 200 MB | 413 |
| user's stored bundles | the tier's `bundle_bytes` (as before) | 413 |
| platform stored bundles | `POST /api/admin/storage` `{"name": "bundles", "bytes": N}`; `GET` shows the cap and the bytes kept now | 507 |

Each answer has its own message, so the OS can say which limit it was. `GET /api/bundles`
now also gives `max_upload`.

Mechanical choices, each reversible:
- Bundle traffic is in the usage table with the kind `bundle`, one request per upload or
  download. The tier is "member" for a member, else "user" (`tierOf`), as for the space
  limit. So a user has separate daily allowances for the proxy and for bundles, each of the
  tier's `bytes_per_day`, not one shared allowance. To share one, count the proxy and bundle
  kinds together in `UsageLeft` and `TakeUsage`.
- An upload is checked before any byte is read: refused when a limit is already reached or a
  `Content-Length` would pass it. The body is then read through `MaxBytesReader` with the
  tightest limit left, so an upload without a length stops at that limit with that limit's
  answer. The bytes an upload moved count even when it is refused part way (they crossed the
  network); a failure on our own disk does not count.
- A download takes its whole size from the quota and the cap when it starts, even if the
  client stops early or asks for a range. A HEAD request takes nothing. The check and the
  addition are one transaction (`TakeUsage`), so two downloads at once cannot both pass.
- The platform caps for bundles are read fresh on each request, not through the 10-second
  cache the proxy and relay use (`CapReached`), so a bundle's whole size can be checked
  against what is left. A database error answers 500, as the bundle routes did for the
  quota before; `CapReached` fails open instead.
- The storage cap answers 507 Insufficient Storage, not 503: 503 already means a daily cap,
  which clears at midnight UTC, while this one clears only when bundles are deleted or
  expire. It counts expired bundles until their files are gone, as the per-user space does.
- The storage cap lives in its own table (`storage_caps`, one row `bundles`) and route,
  because it bounds bytes kept, not bytes a day; putting it in `caps` would give the column
  `bytes_per_day` a second meaning.
- Not exact across users: one upload at a time per user still holds, so the user's own limits
  cannot be raced, but two users uploading at once both see the same room. The platform daily
  cap and the storage cap can each be passed by at most one upload per user uploading at that
  moment (each at most 200 MB). Making it exact would need a reservation held across the
  upload; ask if it matters.
- Not done: bundle refusals write no connection log line (bundles never did), so they do not
  feed the safety watcher and are not in `GET /api/admin/conns`. The per-user view
  (`GET /api/admin/users/{subject}`) shows bundle usage with the kind `bundle`.

The remaining open points of 15.11 (anonymous `/auth/login` rows, the admin bootstrap reading
`login` without the 42 link) are not touched here.


### 15.14 Small fixes (2026-11-27)

- `users.member_until` is no longer read. Nothing has written it since the member role began
  to follow `ft_active` (15.9). The column stays in the table, unused, so no migration is
  needed; the admin API no longer shows it.
- `UCDOTWEB_ORIGIN` is checked at start: scheme and host only, lower case, no trailing slash.
  Before, a trailing slash made every Origin check fail with no message.
- A guard test sends 2,000,000 awkward request paths through the proxy's checks and confirms
  none leaves its allowed prefix after one decoding (`internal/proxy/optpath_test.go`). A
  server that decodes twice could be led out with `%25`; the listed mirrors are not known to
  do that. Refusing `%25` would close it and also refuse file names with a literal percent
  sign: open, for the owners.
- Proxy: a POST body over 8 MiB is refused with 413 instead of being cut and sent on. The
  log says why a download ended early: "cut at quota", "cut at time limit" (the 10 minutes a
  request may last), "upstream error" or "client gone".
- Shutdown: on SIGTERM or Ctrl-C the server stops taking requests, gives running proxy
  requests up to 20 seconds to finish and write their usage, then writes the relay's pending
  usage. systemd's default stop timeout (90 s) leaves room for it. A proxy download still
  running after 20 seconds is cut, and its bytes since the start are not counted.
