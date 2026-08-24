# WireScope installation

This document is the appliance installer for a **generic Linux** server or VM
(Debian/Ubuntu and RPM families such as Fedora, RHEL/Rocky, and openSUSE).
Raspberry Pi hardware is optional; Raspberry Pi OS is not required.

Operators collect a report in either of two equally valid modes:

- **Автономный (киоск):** local display on this computer, no management network
- **Удалённый браузер:** LAN/TLS from another PC (reverse proxy)

The operator GUI is Russian. This file stays English; see the short Russian
note below.

## Get the source (Git)

The GitHub repository is **private**:
[https://github.com/kmvkos/wirescope](https://github.com/kmvkos/wirescope).
Clone with SSH keys or HTTPS credentials (a token, not the account password).

The installer **runs from the checkout** (venv, frontend, kiosk scripts). It
does not copy the tree into `/opt/wirescope`. Mutable data stays in
`/var/lib/wirescope`; config in `/etc/wirescope`. `--project-root` defaults
to the directory that contains `packaging/` (the clone root).
`packaging/install.sh` always passes that directory.

Two layouts are supported:

1. Clone into `/opt/wirescope` (recommended production layout).
2. Clone elsewhere and pass `--project-root` (or just run that clone's
   `packaging/install.sh`).

### Clone into `/opt/wirescope` (recommended)

```bash
sudo git clone git@github.com:kmvkos/wirescope.git /opt/wirescope
cd /opt/wirescope
sudo git checkout milestone-8-appliance   # or main if that is current enough
sudo ./packaging/install.sh --with-kiosk --enable-kiosk
```

`sudo git clone` uses **root's** SSH keys. If the key is on your account,
clone without `sudo` and `sudo mv wirescope /opt/wirescope`, or install from
another path with `--project-root`.

### Clone elsewhere

```bash
git clone git@github.com:kmvkos/wirescope.git
cd wirescope
git checkout milestone-8-appliance   # or main if that is current enough
sudo ./packaging/install.sh \
  --project-root "$PWD" \
  --generate-admin-password \
  --bind-host 127.0.0.1
```

Do not rename or delete that checkout after install: systemd units point at it.

Kiosk (any clone):

```bash
sudo ./packaging/install.sh \
  --project-root "$PWD" \
  --generate-admin-password \
  --bind-host 127.0.0.1 \
  --with-kiosk --enable-kiosk
```

User systemd (no passwordless root; dumpcap still needs root once):

```bash
./packaging/install.sh \
  --user-install \
  --generate-admin-password \
  --bind-host 127.0.0.1
```

### HTTPS clone

```bash
git clone https://github.com/kmvkos/wirescope.git
cd wirescope
git checkout milestone-8-appliance   # or main if that is current enough
sudo ./packaging/install.sh \
  --project-root "$PWD" \
  --generate-admin-password \
  --bind-host 127.0.0.1
```

Private repo: GitHub will prompt for credentials or a personal access token.

## What the installer does

`packaging/install.sh` (or `python3 -m appliance install`) is idempotent:

1. Detect OS family (`apt`, `dnf`, `yum`, or `zypper`) and `amd64` or `arm64`.
   Raspberry Pi hardware is not required.
2. Install required base packages and selected optional providers using each
   distro's package names (`dumpcap`/`tshark`/`nmap` differ). Nuclei and
   Nikto are never installed by default.
3. Reuse or create the unprivileged `wirescope` service account.
4. Create controlled data directories under `/var/lib/wirescope`.
5. Configure `dumpcap` file capabilities only (`setcap`). The API and worker
   stay unprivileged and do not receive `CAP_NET_RAW` / `CAP_NET_ADMIN`.
6. Create or reuse a virtualenv and install pinned Python dependencies.
7. Write `/etc/wirescope/wirescope.env` without passwords.
8. Install `wirescope-api` and `wirescope-worker` systemd units.
9. Apply SQLite migrations.
10. Create the first auditor from a mode `0600` password file, or generate one.
11. Enable and start API + worker. Open the local GUI at
    `http://127.0.0.1:8000/` on this computer (kiosk or any local browser),
    or use a remote browser over LAN/TLS. Chromium kiosk packages are
    optional (`--with-kiosk`). `--enable-kiosk` enables a **system** unit on
    tty1 after boot (no desktop). `--user-kiosk` is only for an existing
    graphical login.

Upgrade is the same command (`packaging/upgrade.sh`). It reuses the service
account, keeps an existing env file, re-verifies dumpcap, upgrades the venv,
and migrates SQLite.

## Operator access modes

Two equally valid ways to collect a report. Capture-NIC addressing is
independent: that interface may have **no IP and no DHCP**. The operator
still uses the local GUI.

### Автономный (киоск): local display, no management network

**Без рабочего стола: киоск на tty1 после boot.** No XFCE, GNOME, KDE, GDM,
or LightDM. Bind stays `127.0.0.1:8000`. After boot, systemd starts
`wirescope-api`, then `wirescope-kiosk` takes tty1 and opens Chromium
fullscreen to `http://127.0.0.1:8000/` once `/api/health` answers. Sign in
as `auditor` in that browser. Capture-NIC addressing is independent.

Сеть до вашего ПК не нужна: откройте GUI на этом компьютере / киоск.

Boot sequence (Debian/Ubuntu server, no desktop):

1. `multi-user.target` ( `graphical.target` is unused )
2. Optional `getty@tty1` autologin drop-in (idle while the kiosk runs)
3. `wirescope-api.service` and `wirescope-worker.service`
4. `wirescope-kiosk.service` `After=wirescope-api.service`, `WantedBy=multi-user.target`
5. The kiosk unit `Conflicts=getty@tty1.service` and uses `TTYPath=/dev/tty1`.
   `OnFailure=getty@tty1.service` returns a text login if the kiosk cannot start.
6. `kiosk.sh` starts **xinit + Xorg + Chromium `--kiosk`** on VMware (not Cage),
   or **Cage + Chromium** on other hardware, else xinit
7. Operator logs into WireScope as `auditor`

```bash
# System unit: boot → tty1 kiosk, no desktop, no display-manager login
sudo /opt/wirescope/packaging/install.sh \
  --project-root /opt/wirescope \
  --generate-admin-password \
  --bind-host 127.0.0.1 \
  --with-kiosk --enable-kiosk

# User unit only after an existing graphical login (not required)
/opt/wirescope/packaging/install.sh \
  --user-install \
  --generate-admin-password \
  --bind-host 127.0.0.1 \
  --user-kiosk
```

`--with-kiosk` installs a **minimal** stack: `cage` or `xserver-xorg`/`xinit`/`openbox`,
plus `chromium` (or `chromium-browser`). On VMware it also pulls
`xserver-xorg-video-vmware`, `xserver-xorg-input-all`, and `open-vm-tools`,
and the kiosk uses **Xorg rather than Cage**. Not a GNOME/XFCE/KDE desktop.
Headless servers that will never attach a console can omit `--with-kiosk`.
`--enable-kiosk` still enables the system unit when Chromium is present,
even if this VM has no monitor yet. Missing Chromium is a skip (same idea
as Playwright), not an installer failure.

`--user-install` does not install OS packages; install Chromium and Cage or
xinit as root (`--with-kiosk`) or via the distro, then enable the user unit
after a graphical login.

The kiosk unit waits for the API, binds the browser to loopback, and does
not stop the worker if Chromium restarts. System kiosk uses
`WantedBy=multi-user.target`. User kiosk uses `WantedBy=graphical-session.target`.

Raspberry Pi kiosk hardware remains optional. Do not require Raspberry Pi OS.

### Удалённый браузер: LAN / TLS

Use a browser on another PC. Preferred path: API stays on loopback, Caddy or
nginx terminates TLS (`--trust-proxy`). Details follow.

## Bind address and LAN TLS

Default bind is `0.0.0.0:8000` so the operator GUI is reachable on LAN IPv4
addresses as well as on the kiosk (`http://127.0.0.1:8000/`). Loopback-only
bind remains available with `--bind-host 127.0.0.1` (user-session kiosk /
reverse proxy).

### From another PC (preferred)

Keep the unprivileged API on loopback. Terminate TLS on Caddy or nginx.
Session cookies become `Secure`. Do not expose TCP 8000.

On this host:

```bash
sudo /opt/wirescope/packaging/install.sh \
  --project-root /opt/wirescope \
  --generate-admin-password \
  --trust-proxy \
  --bind-host 127.0.0.1
```

On the other machine open **`https://<hostname>/`** (not `http://<host>:8000`).
Sample configs land in `/etc/wirescope/proxy/` (`Caddyfile`, `nginx.conf`,
`nftables.nft`, `ufw.example`, `firewalld.example`). The installer does not
start Caddy/nginx and does not rewrite the host firewall. Details:
[packaging/proxy/README.md](../packaging/proxy/README.md).

| This host | Proxy | Firewall | URL from another PC |
| --- | --- | --- | --- |
| This Debian VM | `apt install caddy` or `nginx` | nftables or ufw | `https://<debian-host>/` |
| Ubuntu | `apt install caddy` or `nginx` | ufw | `https://<ubuntu-host>/` |
| Fedora / RHEL | `dnf install caddy` or `nginx` | firewalld | `https://<fedora-host>/` |

Lab self-signed certificate (browser warning; not for an untrusted network):

```bash
sudo python3 -m appliance tls-selfsigned \
  --output-dir /etc/wirescope/tls \
  --common-name wirescope.example
```

**Let's Encrypt** (public DNS name pointing at this host, TCP 80 + 443):

- Caddy: delete the `tls` line in the Caddyfile; Caddy obtains and renews
  certificates automatically.
- nginx: `certbot certonly --webroot -w /var/www/html -d <hostname>` then
  use `/etc/letsencrypt/live/<hostname>/fullchain.pem` and `privkey.pem`.
  Debian/Ubuntu: `apt install certbot`. Fedora: `dnf install certbot`.

### Direct TLS or bare HTTP (less preferred)

Cert/key paths go in `wirescope.env`, never in systemd units. The API stays
unprivileged. URL: `https://<host>:8443/`.

```bash
sudo /opt/wirescope/packaging/install.sh \
  --project-root /opt/wirescope \
  --generate-admin-password \
  --bind-host 0.0.0.0 \
  --bind-port 8443 \
  --tls-cert /etc/wirescope/tls/cert.pem \
  --tls-key /etc/wirescope/tls/key.pem
```

Bare HTTP on `0.0.0.0:8000` (`http://<host>:8000/`) is still possible but is
not a safe LAN default. Restrict 443, 8443, or 8000 with nftables, ufw, or
firewalld. See [SECURITY_MODEL.md](SECURITY_MODEL.md).

## This Debian VM

Stay logged in as the Linux user `wirescope` (the OS account). Do not log in
as the WireScope GUI user `auditor` for this step.

`sudo` prompts for the **wirescope** Linux password (not the GUI password).

First-time kiosk install. Chromium is large (5–15 minutes). Watch apt output.
Do not press Ctrl+C:

```bash
sudo /opt/wirescope/packaging/install.sh \
  --project-root /opt/wirescope \
  --generate-admin-password \
  --bind-host 127.0.0.1 \
  --with-kiosk --enable-kiosk
```

Already-installed packages are skipped. `--with-kiosk` does not pull GNOME or
XFCE; boot kiosk is Chromium on tty1.

If packages already exist and you only want to enable the kiosk:

```bash
sudo /opt/wirescope/packaging/install.sh --skip-packages --enable-kiosk
# or, after units exist:
sudo systemctl enable --now wirescope-kiosk
```

After success, reboot with the **VM console attached** (not SSH-only). tty1
shows Chromium; sign into the WireScope GUI as `auditor`. SSH from the host
still works for admin; the kiosk takes the local screen only.

From another PC on this VM: install with `--trust-proxy --bind-host 127.0.0.1`,
enable Caddy or nginx from `/etc/wirescope/proxy/`, open
`https://<this-host>/`. Local GUI remains `http://127.0.0.1:8000/` (kiosk or
any browser on this computer). This VM may be headless: `--enable-kiosk`
still enables the system tty1 unit when Chromium is installed. Without
`--enable-kiosk` the unit stays installed but disabled.

If this host has no passwordless root, install into the operator's user systemd
session (dumpcap capabilities still need root once):

```bash
/opt/wirescope/packaging/install.sh \
  --user-install \
  --generate-admin-password \
  --bind-host 127.0.0.1
```

User-session paths default to `~/.local/share/wirescope`, `~/.config/wirescope`,
and `~/.config/systemd/user`. Start/stop with `systemctl --user`.

User systemd inherits groups from the session manager (`user@.service`).
`SupplementaryGroups=` is not available in a user unit. If this account was
added to `wireshark` after that manager started, `/usr/bin/dumpcap` (`0750
root:wireshark`) is not executable and `/api/ready` shows `dumpcap: false`
even though `python3 -m appliance verify` succeeds. `--user-install` therefore
starts API and worker via `sg wireshark`, which rebuilds group 103 from
`/etc/group` without a logout. User units omit `ReadWritePaths=` because that
mount namespace makes `sg` fail with `setgid EINVAL`. After install or upgrade:

```bash
systemctl --user daemon-reload
systemctl --user restart wirescope-api wirescope-worker
```

A root system install instead sets `SupplementaryGroups=wireshark` on the
units. The backend process still has no capabilities. Optional:
`sudo loginctl enable-linger $USER` so the user manager starts at boot.

## Ubuntu

Same installer as Debian (`apt`). From the checkout:

```bash
sudo apt-get update
sudo ./packaging/install.sh \
  --project-root "$PWD" \
  --generate-admin-password \
  --bind-host 127.0.0.1
```

Capture packages are `tshark` and `wireshark-common` (provides `dumpcap`).
From another PC: `--trust-proxy`, `apt install caddy` or `nginx`, apply
`packaging/proxy/ufw.example`, open `https://<ubuntu-host>/`.

## Fedora / RHEL / Rocky

The installer uses `dnf` when present, otherwise `yum`. Capture is the
`wireshark-cli` package (provides both `dumpcap` and `tshark`). DNS/SMB/SNMP
optional tools use RPM names (`bind-utils`, `samba-client`, `net-snmp-utils`).

```bash
sudo dnf -y install python3
sudo ./packaging/install.sh \
  --project-root "$PWD" \
  --generate-admin-password \
  --bind-host 127.0.0.1
```

On RHEL-like systems without `dnf`, the same script selects `yum`. From
another PC: `--trust-proxy`, `dnf install caddy` or `nginx`, apply
`packaging/proxy/firewalld.example`, open `https://<fedora-host>/`. Restrict
TCP 8000 with `firewalld` only if you insist on a direct HTTP bind.

## openSUSE / SLES

The installer uses `zypper`. Capture is `wireshark-cli` (fallback `wireshark`);
`setcap` comes from `libcap-progs`.

```bash
sudo zypper --non-interactive install python3
sudo ./packaging/install.sh \
  --project-root "$PWD" \
  --generate-admin-password \
  --bind-host 127.0.0.1
```

From another PC: `--trust-proxy`, `zypper install caddy` or `nginx`, apply
`packaging/proxy/firewalld.example`, open `https://<suse-host>/`.

| Concern | Debian / Ubuntu | Fedora / RHEL | openSUSE |
| --- | --- | --- | --- |
| Package manager | `apt-get` | `dnf` or `yum` | `zypper` |
| dumpcap / tshark | `wireshark-common`, `tshark` | `wireshark-cli` | `wireshark-cli` or `wireshark` |
| `setcap` | `libcap2-bin` | `libcap` | `libcap-progs` |
| python headers | `python3-dev` | `python3-devel` | `python3-devel` |
| iproute | `iproute2` | `iproute` | `iproute2` |
| sqlite CLI | `sqlite3` | `sqlite` | `sqlite3` |
| optional DNS | `bind9-dnsutils` | `bind-utils` | `bind-utils` |
| firewall if LAN bind | `nftables` / `ufw` | `firewalld` | `firewalld` |
| reverse proxy | `caddy` or `nginx` (`apt`) | `caddy` or `nginx` (`dnf`) | `caddy` or `nginx` (`zypper`) |
| Let's Encrypt | `certbot` or Caddy automatic | `certbot` or Caddy automatic | `certbot` or Caddy automatic |

systemd unit shape, service user, dumpcap capabilities, and `--user-install`
are the same on all supported families.

Useful flags:

- `--dry-run` — print the plan without changing the system
- `--skip-packages` / `--skip-apt` — skip apt/dnf/zypper (enable kiosk without reinstalling)
- `--skip-pip` — reuse the existing venv
- `--no-start` — write units but do not `systemctl enable --now`
- `--no-optional-providers` — base capture/decode tools only
- `--with-kiosk` — optional local-display packages (cage or xinit + Chromium,
  not a full desktop)
- `--enable-kiosk` — enable the system kiosk on tty1 after boot (Chromium
  required; no desktop / GDM / LightDM)
- `--user-kiosk` — enable the user kiosk after graphical login (loopback GUI)
- `--auditor-password-file /root/auditor.pass` — mode `0600` file instead of generating
- `--overwrite-env` — replace `/etc/wirescope/wirescope.env`
- `--bind-host` / `--bind-port` — API listen address (default loopback)
- `--trust-proxy` — LAN reverse proxy: Secure cookies, trust forwarded headers from 127.0.0.1
- `--tls-cert` / `--tls-key` — optional direct TLS (paths only; no PEM in units)

The generated password is written to `/etc/wirescope/initial-admin.txt`
(mode `0600`, root only). Copy it out, then delete that file.

### Login

```bash
# health (public, on the appliance)
curl -sS http://127.0.0.1:8000/api/health
curl -sS http://127.0.0.1:8000/api/ready
# from another PC after Caddy/nginx:
# curl -sS https://<host>/api/health

# GUI on this computer (autonomous kiosk / local browser)
xdg-open http://127.0.0.1:8000/
# from another PC: https://<host>/
```

Sign in as `auditor` with the generated password. Production OpenAPI/Swagger
routes are disabled (`WIRESCOPE_DOCS_ENABLED=false`).

### Start / stop without reinstalling

```bash
sudo systemctl status wirescope-api wirescope-worker
sudo systemctl restart wirescope-api wirescope-worker
sudo journalctl -u wirescope-api -u wirescope-worker -e
```

## Заметка для оператора

Графический интерфейс WireScope на русском языке. Эта инструкция — на
английском. **Сеть до вашего ПК не нужна: откройте GUI на этом компьютере /
киоск** (`http://127.0.0.1:8000/`). С другого ПК откройте `https://<хост>/`
через Caddy/nginx (`--trust-proxy`). Если cookie не сохраняется, страница
должна быть HTTPS, а не HTTP. Войдите как `auditor`. Если захват пакетов
недоступен, проверьте группу `wireshark` и перезапустите службы:
`systemctl restart wirescope-api wirescope-worker` или
`systemctl --user restart wirescope-api wirescope-worker`.

Установка из Git (репозиторий приватный, нужна авторизация). Рекомендуемый
layout — клон в `/opt/wirescope`. Можно клонировать куда угодно и указать
`--project-root` (каталог с `packaging/`). Установщик работает **из клона**,
не копирует дерево в `/opt/wirescope`.

```bash
# SSH, клон в /opt/wirescope
sudo git clone git@github.com:kmvkos/wirescope.git /opt/wirescope
cd /opt/wirescope
sudo git checkout milestone-8-appliance   # или main, если он достаточно свежий
sudo ./packaging/install.sh --with-kiosk --enable-kiosk

# SSH, клон куда угодно
git clone git@github.com:kmvkos/wirescope.git
cd wirescope
git checkout milestone-8-appliance
sudo ./packaging/install.sh \
  --project-root "$PWD" \
  --generate-admin-password \
  --bind-host 127.0.0.1

# HTTPS (нужен токен GitHub)
git clone https://github.com/kmvkos/wirescope.git
cd wirescope
git checkout milestone-8-appliance
sudo ./packaging/install.sh \
  --project-root "$PWD" \
  --generate-admin-password \
  --bind-host 127.0.0.1

# user systemd
./packaging/install.sh --user-install --generate-admin-password --bind-host 127.0.0.1
```

### Эта Debian VM (последовательность)

1. Оставайтесь в Linux под пользователем `wirescope`, не `auditor`.
2. `sudo` спрашивает пароль Linux-пользователя **wirescope**.
3. Полная установка киоска (Chromium 5–15 минут). Смотрите вывод apt, не
   нажимайте Ctrl+C:

   `sudo /opt/wirescope/packaging/install.sh --with-kiosk --enable-kiosk`

4. Если пакеты уже стоят и нужен только киоск:

   `sudo /opt/wirescope/packaging/install.sh --skip-packages --enable-kiosk`

   или `sudo systemctl enable --now wirescope-kiosk`.

5. После успеха перезагрузите ВМ с подключённой **консолью** (не только SSH).
   На tty1 откроется Chromium; в GUI войдите как `auditor`.
6. SSH с хоста для админки работает; киоск занимает только локальный экран.
7. Если консоль VMware **чёрная** (нет login и нет Chromium): киоск занял
   tty1 и не смог открыть экран. По SSH:

   `sudo systemctl start getty@tty1`

   На консоли должен появиться login. Затем
   `sudo systemctl status wirescope-kiosk` и журнал.

## Production paths

Keep mutable data outside the application checkout:

```bash
WIRESCOPE_DATA_DIR=/var/lib/wirescope
WIRESCOPE_DATABASE_PATH=/var/lib/wirescope/wirescope.db
WIRESCOPE_EVIDENCE_DIR=/var/lib/wirescope/evidence
WIRESCOPE_RUNTIME_DIR=/var/lib/wirescope/runtime
WIRESCOPE_CAPTURE_DIR=/var/lib/wirescope/runtime/captures
WIRESCOPE_BIND_HOST=127.0.0.1
WIRESCOPE_BIND_PORT=8000
WIRESCOPE_DOCS_ENABLED=false
```

Directories are owned by `wirescope` and are not world-readable. Use a local
Linux filesystem suitable for SQLite locking. Do not place the database on NFS.

Environment variables live in `/etc/wirescope/wirescope.env`. systemd unit
files must not contain passwords.

## Database initialization

The installer runs migrations as `wirescope`. To apply them manually:

```bash
sudo -u wirescope \
  env WIRESCOPE_DATA_DIR=/var/lib/wirescope \
  /opt/wirescope/.venv/bin/alembic \
  -c /opt/wirescope/alembic.ini upgrade head
```

Readiness remains false when the database revision does not match Alembic
head, or when the worker is not heartbeating.

## Capture privilege

The API and worker must not run as root. `dumpcap` alone receives
`CAP_NET_RAW` and `CAP_NET_ADMIN`, and the service account receives execute
access through the `wireshark` group.

Verified shape:

- `/usr/bin/dumpcap` owned `root:wireshark`, mode `0750`, not setuid
- file capabilities `cap_net_admin,cap_net_raw=eip`
- `wirescope` is a member of `wireshark`
- Python/uvicorn have no those capabilities

```bash
sudo python3 -m appliance verify --project-root /opt/wirescope
sudo -u wirescope /usr/bin/dumpcap -D
```

The worker unit does **not** set `NoNewPrivileges=true`, because that would
block dumpcap file capabilities. The API unit also omits `NoNewPrivileges`
so the unprivileged process can `sudo -n /usr/lib/wirescope/netctl` via a
tight sudoers drop-in (never `shell=True`).

## Process order

1. migration / first-admin bootstrap (installer)
2. `wirescope-worker`
3. `wirescope-api`
4. local kiosk or browser client (independent of API and worker; loopback)

The worker performs restart recovery before accepting queued work. Reloading
the GUI must not terminate audits.

## Initial admin

There is no built-in default password. The installer creates the first
auditor only when the `users` table is empty, using a mode `0600` password
file. An optional viewer password file may be supplied the same way.

Development-only environment bootstrap (`WIRESCOPE_BOOTSTRAP_*`) still works
when the table is empty, but must not be copied into systemd units.

## Upgrade and rollback

Upgrade:

```bash
sudo /opt/wirescope/packaging/upgrade.sh --project-root /opt/wirescope --skip-packages
```

Before a schema change, take a backup:

```bash
sudo -u wirescope env WIRESCOPE_DATA_DIR=/var/lib/wirescope \
  /opt/wirescope/.venv/bin/python -m appliance backup
```

Rollback guidance:

1. `systemctl stop wirescope-api wirescope-worker`
2. Restore the SQLite backup (and evidence tree if required)
3. Check out the previous known-good Git revision of `/opt/wirescope`
4. `pip install -e /opt/wirescope` in the venv
5. Start the units
6. Do not run `alembic downgrade` unless that revision was tested

Alembic migrations in this project are forward-only in normal operation.
Keep the pre-upgrade SQLite copy until the new revision is confirmed.

## Local operator kiosk

First-class autonomous mode: Chromium on the appliance display against
`http://127.0.0.1:8000/`. **Без рабочего стола: киоск на tty1 после boot.**
See [Operator access modes](#operator-access-modes).
Raspberry Pi hardware is optional; Raspberry Pi OS is not required. Live
Pi OS Lite, touch, and on-device ARM64 smoke tests remain unused
(`pytest -m live_pi` with `WIRESCOPE_LIVE_PI=1` on Pi hardware only).

Headless CI and servers omit Chromium; Playwright/kiosk browser tests skip
when Chromium is missing.

## Release checksums

```bash
python3 -m appliance checksums --project-root /opt/wirescope \
  --output /opt/wirescope/packaging/SHA256SUMS
sha256sum -c packaging/SHA256SUMS
```

Sign `packaging/SHA256SUMS` with an operator key when distributing artifacts
(`gpg --detach-sign`). The installer never embeds that key.

## Power loss

SQLite runs in WAL mode with foreign keys, short transactions, busy timeout,
and `synchronous=FULL` by default. Evidence uses temporary files and atomic
rename. Startup removes abandoned temporary files, stale managed capture
directories, orphan final files, and abandoned locks.

Running jobs become `interrupted` with `application_restart`. Queued jobs
remain queued. There is no automatic retry.

Use `python -m appliance backup` / `restore` for operator backups.
