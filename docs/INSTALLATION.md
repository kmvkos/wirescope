# WireScope installation

This document is the appliance installer for a **generic Linux** server or VM
(Debian/Ubuntu and RPM families such as Fedora, RHEL/Rocky, and openSUSE).
The same installer can later be used on Raspberry Pi OS; that path is an
optional extra, not a required stage.

The operator GUI is Russian. This file stays English; see the short Russian
note below.

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
11. Enable and start API + worker. Open the GUI in any browser at the
    configured bind address. Chromium kiosk is a later extra and is not
    enabled unless you pass `--with-kiosk --enable-kiosk`.

Upgrade is the same command (`packaging/upgrade.sh`). It reuses the service
account, keeps an existing env file, re-verifies dumpcap, upgrades the venv,
and migrates SQLite.

## Bind address

Default bind is `127.0.0.1:8000` (local browser only). For a VM or LAN
deploy, pass `--bind-host 0.0.0.0` and restrict TCP 8000 on the host
firewall. See [SECURITY_MODEL.md](SECURITY_MODEL.md).

## This Debian VM

Run as root from the checkout. This does not rewrite Git history and keeps
mutable state out of the source tree.

```bash
sudo /opt/wirescope/packaging/install.sh \
  --project-root /opt/wirescope \
  --generate-admin-password \
  --bind-host 127.0.0.1
```

LAN example:

```bash
sudo /opt/wirescope/packaging/install.sh \
  --project-root /opt/wirescope \
  --generate-admin-password \
  --bind-host 0.0.0.0
```

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
Use `--bind-host 0.0.0.0` when the GUI should be reachable from other hosts
on a trusted network.

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

On RHEL-like systems without `dnf`, the same script selects `yum`. Restrict
TCP 8000 with `firewalld` if you bind `0.0.0.0`.

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

## What stays distro-specific

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

systemd unit shape, service user, dumpcap capabilities, and `--user-install`
are the same on all supported families.

Useful flags:

- `--dry-run` — print the plan without changing the system
- `--skip-packages` / `--skip-apt` — reuse already installed packages
- `--skip-pip` — reuse the existing venv
- `--no-start` — write units but do not `systemctl enable --now`
- `--no-optional-providers` — base capture/decode tools only
- `--with-kiosk` / `--enable-kiosk` — optional local Chromium extra
- `--auditor-password-file /root/auditor.pass` — mode `0600` file instead of generating
- `--overwrite-env` — replace `/etc/wirescope/wirescope.env`
- `--bind-host` / `--bind-port` — API listen address

The generated password is written to `/etc/wirescope/initial-admin.txt`
(mode `0600`, root only). Copy it out, then delete that file.

### Login

```bash
# health (public)
curl -sS http://127.0.0.1:8000/api/health
curl -sS http://127.0.0.1:8000/api/ready

# GUI
xdg-open http://127.0.0.1:8000/   # or any local browser
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
английском. После установки откройте `http://127.0.0.1:8000/` (или адрес
хоста, если задан `--bind-host 0.0.0.0`) и войдите как `auditor`. Если захват
пакетов недоступен, проверьте группу `wireshark` и перезапустите службы:
`systemctl restart wirescope-api wirescope-worker` или
`systemctl --user restart wirescope-api wirescope-worker`.

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
block dumpcap file capabilities. The API unit may use `NoNewPrivileges`.

## Process order

1. migration / first-admin bootstrap (installer)
2. `wirescope-worker`
3. `wirescope-api`
4. optional browser client (independent of API and worker)

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

## Optional kiosk (Raspberry Pi later extra)

Not required for generic Linux. Use a normal browser against the API.

```bash
sudo /opt/wirescope/packaging/install.sh --with-kiosk --enable-kiosk
```

`packaging/kiosk/` is a Chromium/X11 extra for a local display. Live
Raspberry Pi OS Lite, touch, and on-device ARM64 smoke tests remain unused
(`pytest -m live_pi` with `WIRESCOPE_LIVE_PI=1` on Pi hardware only).

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
