# WireScope installation

This document is the appliance installer and Debian VM bring-up guide.
The same installer is intended for Raspberry Pi OS Lite (ARM64) later; this
pass is verified on Debian AMD64.

## What the installer does

`packaging/install.sh` (or `python3 -m appliance install`) is idempotent:

1. Detect a Debian-family OS and `amd64` or `arm64`.
2. Install required base packages and selected optional providers.
   Nuclei and Nikto are never installed by default.
3. Reuse or create the unprivileged `wirescope` service account.
4. Create controlled data directories under `/var/lib/wirescope`.
5. Configure `dumpcap` file capabilities only. The API and worker stay
   unprivileged and do not receive `CAP_NET_RAW` / `CAP_NET_ADMIN`.
6. Create or reuse a virtualenv and install pinned Python dependencies.
7. Write `/etc/wirescope/wirescope.env` without passwords.
8. Install `wirescope-api` and `wirescope-worker` systemd units.
9. Apply SQLite migrations.
10. Create the first auditor from a mode `0600` password file, or generate one.
11. Enable and start API + worker. The Chromium kiosk unit is optional and
    is not required for a Debian VM: open `http://127.0.0.1:8000/` in a browser.

Upgrade is the same command (`packaging/upgrade.sh`). It reuses the service
account, keeps an existing env file, re-verifies dumpcap, upgrades the venv,
and migrates SQLite.

## Debian VM (current host)

Run as root from the checkout. This does not rewrite Git history and keeps
mutable state out of the source tree.

```bash
sudo /opt/wirescope/packaging/install.sh \
  --project-root /opt/wirescope \
  --generate-admin-password \
  --bind-host 127.0.0.1
```

If this host has no passwordless root, install into the operator's user systemd
session (API still binds to loopback; dumpcap capabilities still need root):

```bash
/opt/wirescope/packaging/install.sh \
  --user-install \
  --generate-admin-password \
  --bind-host 127.0.0.1
```

User-session paths default to `~/.local/share/wirescope`, `~/.config/wirescope`,
and `~/.config/systemd/user`. Start/stop with `systemctl --user`.

User systemd may not inherit the `wireshark` group until a new login. Until
then `/api/ready` can show `dumpcap: false` even though `python3 -m appliance
verify` succeeds. A root system install sets `SupplementaryGroups=wireshark`
on the units. The backend process still has no capabilities.

Useful flags:

- `--dry-run` — print the plan without changing the system
- `--skip-apt` / `--skip-pip` — reuse already installed packages or venv
- `--no-start` — write units but do not `systemctl enable --now`
- `--no-optional-providers` — base capture/decode tools only
- `--with-kiosk` / `--enable-kiosk` — Pi-oriented Chromium stack (optional)
- `--auditor-password-file /root/auditor.pass` — mode `0600` file instead of generating
- `--overwrite-env` — replace `/etc/wirescope/wirescope.env`

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
4. optional kiosk/browser client (independent of API and worker)

The worker performs restart recovery before accepting queued work. Reloading
the GUI or kiosk must not terminate audits.

## Initial admin

There is no built-in default password. The installer creates the first
auditor only when the `users` table is empty, using a mode `0600` password
file. An optional viewer password file may be supplied the same way.

Development-only environment bootstrap (`WIRESCOPE_BOOTSTRAP_*`) still works
when the table is empty, but must not be copied into systemd units.

## Upgrade and rollback

Upgrade:

```bash
sudo /opt/wirescope/packaging/upgrade.sh --project-root /opt/wirescope --skip-apt
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

## Raspberry Pi OS Lite (later)

Use the same installer on ARM64 Raspberry Pi OS. Add `--with-kiosk` and
`--enable-kiosk` only when a local HDMI/DSI display should open Chromium at
480×320. Live Pi hardware validation, touch calibration, and ARM64 smoke on
device remain a separate attempt. See [RUNBOOK.md](RUNBOOK.md).

## Bind address and firewall

Default bind is `127.0.0.1:8000`. That is enough for a local browser on the
VM. Listening on `0.0.0.0` is an explicit `--bind-host` choice and requires
firewall rules; see [SECURITY_MODEL.md](SECURITY_MODEL.md). Direct TLS versus
a reverse proxy is still deferred.

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
