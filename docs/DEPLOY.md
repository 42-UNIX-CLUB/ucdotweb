# Deploying ucdotweb on a server over SSH

Written 2026-11-26. **Not yet tested on a real server**: every step below was written for a
Debian or Ubuntu VPS, and the service itself was only run on the development laptop.

## 0. What can be deployed today, and what cannot

The service runs on any Linux server. But two things decide what a deployment is good for:

| Piece | State | Consequence |
|---|---|---|
| The identity provider (the Virtual Clubroom's OpenID Connect part) | not built yet | the service cannot sign real users in. It refuses to start without a provider to discover |
| The test stand-in (`oidc-standin`) | built | approves everyone as one fixed user, and listens on loopback only. It must never be reachable from the internet |
| The UC.OS page side (the host layer that calls `/proxy/` and `/relay`) | not built | nothing in UC.OS uses the platform yet |
| Admin API, safety automation, notifications | built (the admin program in UC.OS is not; notifications need a webhook, 2.6.1) | admins can work through the API; the safety watcher runs on its own |
| A published abuse contact | not set up | the threat model asks for it before the relay is open to members; the address needs an owner |

So there are two kinds of deployment:

- **A. Private test (possible now).** The service and the stand-in run on the server, bound
  to `127.0.0.1` only. You reach them through an SSH tunnel from your laptop. Nothing is open
  to the internet except SSH. This tests the server, the build, the database, real outbound
  traffic from the server's network, and the relay from a real data centre.
- **B. Production (after the Clubroom's provider exists).** TLS on the public domain, one
  origin with the UC.OS page, the real provider. Section 3.

## 1. The server

- A VPS with Debian 13 or Ubuntu 24.04, 1 vCPU and 1 GB of RAM is plenty to start.
- Before choosing a provider, read its acceptable-use policy for a members-only relay
  (decided in the threat model, section 6).
- A DNS name pointing at the server, for production (for example `dux.ensui.dev`).

In the commands below, replace `SERVER` with your server's address and `ADMIN` with your login
on it. Commands marked **laptop** run on your machine; **server** ones run over SSH.

## 2. Private test deployment (A)

### 2.1 First login and basics (server)

```sh
ssh ADMIN@SERVER
sudo apt update && sudo apt upgrade -y
sudo apt install -y golang-go gcc sqlite3 rsync ufw unattended-upgrades
go version            # needs 1.24 or newer; if older, install Go from https://go.dev/dl/
sudo dpkg-reconfigure -plow unattended-upgrades   # automatic security updates
```

SSH keys only (do this only after your key login works, or you lock yourself out):

```sh
sudo sed -i 's/^#\?PasswordAuthentication .*/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo systemctl reload ssh
```

Firewall: SSH only for the private test.

```sh
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow OpenSSH
sudo ufw enable
```

### 2.2 A user for the service, and its directories (server)

```sh
sudo useradd --system --home /var/lib/ucdotweb --shell /usr/sbin/nologin ucdotweb
sudo mkdir -p /opt/ucdotweb/src /etc/ucdotweb /var/lib/ucdotweb
sudo chown ucdotweb:ucdotweb /var/lib/ucdotweb
sudo chmod 700 /var/lib/ucdotweb /etc/ucdotweb
sudo chown ADMIN /opt/ucdotweb/src
```

### 2.3 Copy the source (laptop)

The repository is private and the server has no key for it, so copy the working tree with
rsync. Local build output and test secrets stay behind.

```sh
rsync -av --delete --exclude .git --exclude 'build*' --exclude '*.db*' \
  /home/ensui/ucdotweb/ ADMIN@SERVER:/opt/ucdotweb/src/
```

(Later, a read-only deploy key on the server with `git clone` is the cleaner way.)

### 2.4 Build on the server (server)

The SQLite driver uses cgo, so build on the server itself: a binary built on the laptop (Arch,
newer C library) may not run on Debian.

```sh
cd /opt/ucdotweb/src
go test ./...                       # optional, takes about a minute
go build -o /tmp/ucdotweb-bin/ ./cmd/...
sudo install -m 755 /tmp/ucdotweb-bin/ucdotweb /tmp/ucdotweb-bin/oidc-standin /usr/local/bin/
```

### 2.5 Secrets (server)

Three files, readable only by the service user. Generated on the server, never copied around.

```sh
sudo sh -c 'openssl rand -hex 32 > /etc/ucdotweb/db.key'
sudo sh -c 'openssl rand -hex 32 > /etc/ucdotweb/relay.key'
sudo sh -c 'echo standin-test-secret > /etc/ucdotweb/client.secret'   # test value for the stand-in
sudo chown ucdotweb:ucdotweb /etc/ucdotweb/*
sudo chmod 600 /etc/ucdotweb/*
```

Back up `db.key`: without it the stored sessions cannot be read (they are only sessions; users
would sign in again). `relay.key` can be regenerated at any time; open relay tokens then stop
working, which lasts at most 5 minutes.

### 2.6 Configuration (server)

```sh
sudo tee /etc/ucdotweb/env >/dev/null <<'EOF'
UCDOTWEB_LISTEN=127.0.0.1:8090
UCDOTWEB_ORIGIN=http://127.0.0.1:8090
UCDOTWEB_ISSUER=http://127.0.0.1:8091
UCDOTWEB_CLIENT_ID=uc-os
UCDOTWEB_SECRET_FILE=/etc/ucdotweb/client.secret
UCDOTWEB_DB=/var/lib/ucdotweb/ucdotweb.db
UCDOTWEB_DB_KEY_FILE=/etc/ucdotweb/db.key
UCDOTWEB_RELAY_KEY_FILE=/etc/ucdotweb/relay.key
UCDOTWEB_ADMIN_LOGINS=rucosta,mju-ferr
UCDOTWEB_INSECURE_COOKIES=1
EOF
sudo chmod 600 /etc/ucdotweb/env
```

`UCDOTWEB_PROXY_RULES` (optional) is read only on the first start with a new database: after
that the allow-list lives in the database and administrators edit it. Safety automation runs
without configuration. Its notifications (chat webhook, e-mail) are off until their variables
are set; `cmd/ucdotweb/main.go` lists them.

### 2.6.1 Safety notifications (server)

The chosen setup: a Discord webhook posting to a private admin channel on the club's server.
Only administrators should see that channel.

1. In Discord: the admin channel's settings, Integrations, Webhooks, New Webhook. Copy its URL.
2. On the server, write it into a file yourself. Do not paste it into a chat or a commit: anyone
   with the URL can post to the channel.

```sh
sudo sh -c 'cat > /etc/ucdotweb/webhook.url'     # paste the URL, Enter, then Ctrl-D
sudo chown ucdotweb:ucdotweb /etc/ucdotweb/webhook.url
sudo chmod 600 /etc/ucdotweb/webhook.url
echo 'UCDOTWEB_WEBHOOK_URL_FILE=/etc/ucdotweb/webhook.url' | sudo tee -a /etc/ucdotweb/env
sudo systemctl restart ucdotweb
```

The message format follows the host (Discord's for discord.com). If the URL is ever leaked,
delete the webhook in Discord and make a new one. Until the file exists the log says
"safety: no notifications configured".

`UCDOTWEB_INSECURE_COOKIES=1` is only for this private test over plain http through the
tunnel. It must not be set in production.

Abuse contact (decided: `abuse@ucos.ensui.dev`). The owner sets up the address as a
Cloudflare e-mail forward (Email Routing on the `ensui.dev` zone, a custom address `abuse@ucos`
forwarding to an admin's inbox). Then:

```sh
echo 'UCDOTWEB_ABUSE_CONTACT=mailto:abuse@ucos.ensui.dev' | sudo tee -a /etc/ucdotweb/env
sudo systemctl restart ucdotweb
curl -s http://127.0.0.1:8090/.well-known/security.txt    # Contact, Expires, Preferred-Languages
```

`UCDOTWEB_STATIC_DIR` (local tests only) makes the service also serve a folder at `/`, for
example an OS build's `dist`, so a browser on one local port gets the page and the platform
together. Leave it unset on a server: there the page is served in front of the service.
It serves files only: no folder listings and nothing whose name starts with a dot.

### 2.7 systemd units (server)

The stand-in (test only):

```sh
sudo tee /etc/systemd/system/oidc-standin.service >/dev/null <<'EOF'
[Unit]
Description=ucdotweb test identity provider (TEST ONLY, loopback)
After=network.target

[Service]
User=ucdotweb
ExecStart=/usr/local/bin/oidc-standin -listen 127.0.0.1:8091 -redirect http://127.0.0.1:8090/auth/callback -secret standin-test-secret -login rucosta -member
Restart=on-failure
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
EOF
```

The service:

```sh
sudo tee /etc/systemd/system/ucdotweb.service >/dev/null <<'EOF'
[Unit]
Description=ucdotweb, the UC.OS web platform
After=network-online.target oidc-standin.service
Wants=network-online.target

[Service]
User=ucdotweb
Group=ucdotweb
EnvironmentFile=/etc/ucdotweb/env
ExecStart=/usr/local/bin/ucdotweb
Restart=on-failure
RestartSec=3
# hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ReadWritePaths=/var/lib/ucdotweb
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
CapabilityBoundingSet=
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable --now oidc-standin ucdotweb
systemctl status ucdotweb --no-pager
journalctl -u ucdotweb -n 20 --no-pager      # expect: "listening on 127.0.0.1:8090"
```

### 2.8 Use it through an SSH tunnel (laptop)

```sh
ssh -N -L 8090:127.0.0.1:8090 -L 8091:127.0.0.1:8091 ADMIN@SERVER
```

Leave it running. Then in a browser on your laptop: `http://127.0.0.1:8090/auth/login`, then
`http://127.0.0.1:8090/api/me`. Or with curl:

```sh
J=/tmp/ucdotweb-jar.txt
curl -s -L -c $J -b $J -o /dev/null http://127.0.0.1:8090/auth/login
curl -s -b $J http://127.0.0.1:8090/api/me
curl -s -b $J -H 'X-UCOS-Proxy: 1' -o /dev/null -w '%{http_code} %{size_download}\n' \
  http://127.0.0.1:8090/proxy/deb.debian.org/debian/dists/stable/InRelease
```

The proxy fetch then comes from the server's network, not your laptop's.

### 2.9 Updating (laptop, then server)

```sh
rsync -av --delete --exclude .git --exclude 'build*' --exclude '*.db*' \
  /home/ensui/ucdotweb/ ADMIN@SERVER:/opt/ucdotweb/src/
ssh ADMIN@SERVER 'cd /opt/ucdotweb/src && go build -o /tmp/ucdotweb-bin/ ./cmd/... && \
  sudo install -m 755 /tmp/ucdotweb-bin/* /usr/local/bin/ && sudo systemctl restart ucdotweb'
```

### 2.10 Backup of the database (server)

```sh
sudo -u ucdotweb sqlite3 /var/lib/ucdotweb/ucdotweb.db ".backup /var/lib/ucdotweb/backup.db"
```

Copy `backup.db` off the server (it holds pseudonymous ids, counters, 30 days of host-only
logs and the audit log; sessions inside are encrypted with `db.key`).

Device-transfer bundles live as files in `/var/lib/ucdotweb/bundles` (the default,
`UCDOTWEB_BUNDLE_DIR` to move it), created on the first start. They are ciphertext the server
cannot read, and they expire within 30 days, so they need no backup. Their disk use is at most
the bundle limit (50 MB by default) times the number of users; `du -sh` on that directory
shows it. A tier whose bundle limit is 0 has no per-user limit, but one upload is still
200 MB at most.

To bound the total on a small disk, an administrator sets the platform storage cap for
bundles (0 means none, the default). It counts every user's bundles together, expired ones
too until their files are gone, and refuses uploads past it with 507:

```sh
curl -s -b $J http://127.0.0.1:8090/api/admin/storage          # the cap and the bytes kept now
curl -s -b $J -H 'Content-Type: application/json' -H 'Origin: http://127.0.0.1:8090' \
  -d '{"name":"bundles","bytes":5000000000}' http://127.0.0.1:8090/api/admin/storage
```

Bundle traffic (uploads and downloads) also counts against each user's daily bytes and
against a platform daily cap, the caps row `bundle` (0 means none, the default), set like the
proxy's and the relay's: `POST /api/admin/caps` with `{"service":"bundle","bytes_per_day":N}`.

## 3. Production (B), once the Clubroom's provider exists

Changes from the private test:

1. **Stop and remove the stand-in**: `sudo systemctl disable --now oidc-standin` and delete
   its unit. It must never run on a public server.
2. **Register UC.OS as a client at the Clubroom** with the redirect URL
   `https://DOMAIN/auth/callback` and the scope `uc-os:connect`. Put the client id in
   `UCDOTWEB_CLIENT_ID` and the secret in `/etc/ucdotweb/client.secret`.
3. **Configuration**: `UCDOTWEB_ORIGIN=https://DOMAIN`, `UCDOTWEB_ISSUER=` the Clubroom's
   issuer URL, and remove `UCDOTWEB_INSECURE_COOKIES`.
4. **TLS and one origin** (decided: one VPS, one origin). A TLS terminator serves the UC.OS
   page (`make dist` from the OS repository) at `/` and passes the platform's paths to the
   service. Example with Caddy (it gets and renews the certificate by itself):

   ```sh
   sudo apt install -y caddy
   sudo tee /etc/caddy/Caddyfile >/dev/null <<'EOF'
   DOMAIN {
       @platform path /auth/* /api/* /proxy/* /relay /.well-known/security.txt
       handle @platform {
           reverse_proxy 127.0.0.1:8090
       }
       handle {
           root * /srv/ucos
           file_server
       }
       header {
           Strict-Transport-Security "max-age=31536000"
           X-Content-Type-Options nosniff
       }
   }
   EOF
   sudo systemctl reload caddy
   ```

   and copy the OS build: `rsync -av build-NAME/dist/ ADMIN@SERVER:/srv/ucos/` (the folder
   must exist and be readable by Caddy). nginx works too; the WebSocket at `/relay` then needs
   `proxy_http_version 1.1` and the `Upgrade` and `Connection` headers passed.
5. **Firewall**: `sudo ufw allow 80/tcp && sudo ufw allow 443/tcp`.
6. **Before members get the relay** (threat model): an abuse contact published, the admin
   interface and the safety automation built, notifications configured.

## 4. Checking it is healthy

```sh
systemctl is-active ucdotweb
journalctl -u ucdotweb -f
sudo -u ucdotweb sqlite3 /var/lib/ucdotweb/ucdotweb.db \
  "select kind, host, bytes, outcome from conn_log order by at desc limit 10;"
```

Turning everything off in an emergency, without the admin interface:

```sh
sudo -u ucdotweb sqlite3 /var/lib/ucdotweb/ucdotweb.db \
  "insert or replace into flags values ('all_off', 1, strftime('%s','now'), 'ssh');"
```

(It takes effect on new requests at once and on open relay sockets within 5 seconds. This
write skips the audit log; prefer the admin endpoint when it is reachable.)
