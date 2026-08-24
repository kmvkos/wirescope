# Installing WireScope

[Русский](../INSTALLATION.md)

WireScope can be installed as a dedicated Linux appliance or on an existing VM/server. Supported targets include Debian/Ubuntu, Fedora/RHEL/Rocky, and openSUSE on `amd64` and `arm64`. Raspberry Pi is a supported hardware option but is not required.

The installer runs **from the Git checkout**. A typical system installation keeps code in `/opt/wirescope`, mutable data in `/var/lib/wirescope`, and configuration in `/etc/wirescope`.

## Recommended installation

The repository is private, so use an SSH key or GitHub token.

```bash
git clone git@github.com:kmvkos/wirescope.git
cd wirescope
git checkout milestone-8-appliance
cd ..
sudo mv wirescope /opt/wirescope
cd /opt/wirescope
```

Clone without `sudo` so Git uses the current user's SSH keys. Checkout before moving the repository into `/opt` to avoid unnecessary ownership and `safe.directory` problems.

Basic system installation:

```bash
sudo ./packaging/install.sh --generate-admin-password
```

The API defaults to **`127.0.0.1:8000`**, which is the safe setup for a local browser, kiosk, or reverse proxy.

### Local kiosk

```bash
sudo ./packaging/install.sh \
  --generate-admin-password \
  --with-kiosk \
  --enable-kiosk
```

`--with-kiosk` installs a minimal display stack: Chromium plus Cage or Xorg/xinit. A full GNOME/KDE/XFCE desktop is not required. VMware uses the Xorg path.

The system kiosk starts on `tty1` after boot and opens `http://127.0.0.1:8000/`. Restarting Chromium does not stop the API, worker, or an active audit.

### Access from another machine

Preferred layout:

```text
browser → HTTPS 443 → Caddy/nginx → 127.0.0.1:8000
```

Install WireScope on loopback with proxy trust enabled:

```bash
sudo ./packaging/install.sh \
  --generate-admin-password \
  --trust-proxy
```

Caddy/nginx and firewall examples live under `packaging/proxy/` and are copied to `/etc/wirescope/proxy/` by a system install. The installer does not start the reverse proxy or rewrite the host firewall.

### Direct LAN bind

If a reverse proxy is intentionally not used, expose the API explicitly:

```bash
sudo ./packaging/install.sh \
  --generate-admin-password \
  --bind-host 0.0.0.0
```

Plain HTTP on `0.0.0.0:8000` is not the recommended production layout. Restrict it with a firewall or use direct TLS.

Direct TLS example:

```bash
sudo ./packaging/install.sh \
  --generate-admin-password \
  --bind-host 0.0.0.0 \
  --bind-port 8443 \
  --tls-cert /etc/wirescope/tls/cert.pem \
  --tls-key /etc/wirescope/tls/key.pem
```

PEM contents do not go into systemd units; only certificate/key paths are stored in the environment file.

## What the installer does

`packaging/install.sh` invokes `python -m appliance install` and performs idempotent setup:

1. detect distro family, package manager, and architecture;
2. install required packages and available optional providers;
3. create or reuse the unprivileged `wirescope` account;
4. create data/runtime/evidence directories;
5. configure capabilities only on `dumpcap`;
6. create `.venv` and install pinned Python dependencies;
7. write `/etc/wirescope/wirescope.env`;
8. install API/worker systemd units and optional kiosk units;
9. apply Alembic migrations;
10. create the first auditor without a built-in default password;
11. start services unless `--no-start` is used.

Nuclei and Nikto are not installed by default.

## Main paths

System install:

```text
/opt/wirescope
    Git checkout + .venv

/etc/wirescope/
    wirescope.env
    proxy/
    initial-admin.txt   # only when a password is generated; remove after storing it

/var/lib/wirescope/
    wirescope.db
    evidence/
    runtime/
    backups/
```

User installs use `~/.local/share/wirescope`, `~/.config/wirescope`, and `~/.config/systemd/user`.

## Service model

A normal system install runs:

```text
wirescope-worker.service
wirescope-api.service
[wirescope-kiosk.service]
```

API and worker run as an unprivileged account. System units receive `wireshark` membership through `SupplementaryGroups=wireshark`.

User units cannot use the same mechanism, so the installer launches through `sg wireshark` to make updated group membership effective without requiring a logout.

## Packet-capture privileges

Expected state:

```text
/usr/bin/dumpcap
owner: root
 group: wireshark
 mode: 0750
 capabilities: cap_net_admin,cap_net_raw=eip
```

Python and uvicorn must not receive those capabilities.

Verify with:

```bash
sudo /opt/wirescope/.venv/bin/python -m appliance verify \
  --project-root /opt/wirescope
sudo -u wirescope /usr/bin/dumpcap -D
```

## First login

With `--generate-admin-password`, the initial password is written to a protected file, normally `/etc/wirescope/initial-admin.txt`. Store the password in a password manager and remove the file.

The default GUI username is `auditor`. There is no permanent built-in password.

Recovery if access is lost:

```bash
/opt/wirescope/.venv/bin/python -m appliance set-password auditor
```

## Post-install verification

```bash
systemctl status wirescope-api wirescope-worker
curl -sS http://127.0.0.1:8000/api/health
curl -sS http://127.0.0.1:8000/api/v1/health
curl -sS http://127.0.0.1:8000/api/ready
```

`/api/v1` is the canonical API. `/api` remains a compatibility alias for the current GUI and existing clients.

`/api/health` checks that the API is alive. `/api/ready` also requires an accessible database, current migrations, a live worker heartbeat, and required binaries.

## Debian / Ubuntu

The installer uses `apt`. Core packages include Python, `iproute2`, `tshark`, `wireshark-common`/`dumpcap`, SQLite, and `libcap2-bin`.

```bash
sudo ./packaging/install.sh --generate-admin-password
```

Add `--with-kiosk --enable-kiosk` for a local kiosk.

## Fedora / RHEL / Rocky

The installer uses `dnf`, or `yum` when `dnf` is unavailable. `dumpcap` and `tshark` come from `wireshark-cli`.

```bash
sudo dnf -y install python3
sudo ./packaging/install.sh --generate-admin-password
```

## openSUSE / SLES

The installer uses `zypper`; the capture package is `wireshark-cli` or the distro fallback.

```bash
sudo zypper --non-interactive install python3
sudo ./packaging/install.sh --generate-admin-password
```

## User install

```bash
./packaging/install.sh \
  --user-install \
  --generate-admin-password
```

OS packages and the initial `dumpcap` capability setup still need administrative configuration at least once.

## Useful flags

```text
--dry-run                 show the plan without modifying the system
--skip-packages           skip the package manager
--skip-pip                reuse the current venv
--no-start                do not start units
--no-optional-providers   base dependencies only
--with-kiosk              install minimal kiosk packages
--enable-kiosk            enable the system tty1 kiosk
--user-kiosk              user-session kiosk
--user-install            user systemd install
--bind-host               API address; default 127.0.0.1
--bind-port               API port; default 8000
--trust-proxy             reverse-proxy mode
--tls-cert / --tls-key    direct TLS
--overwrite-env           replace an existing wirescope.env
```

## Updating an existing VM

If the checkout already lives at `/opt/wirescope`, update it through normal Git operations.

Before updating:

```bash
cd /opt/wirescope
git status
git branch --show-current
git fetch origin
```

If the worktree is clean and the current branch is the one you want:

```bash
git pull --ff-only
```

After a code-only update with no new migration or dependency changes, this is normally enough:

```bash
sudo systemctl restart wirescope-worker wirescope-api
curl -sS http://127.0.0.1:8000/api/ready
```

For the general upgrade path use:

```bash
sudo ./packaging/upgrade.sh --project-root /opt/wirescope
```

The upgrade path rechecks environment, venv, dumpcap, and migrations.

## Backup before a substantial upgrade

```bash
sudo -u wirescope env WIRESCOPE_DATA_DIR=/var/lib/wirescope \
  /opt/wirescope/.venv/bin/python -m appliance backup
```

Backups are stored below `/var/lib/wirescope/backups/`.

## Rollback

1. stop API and worker;
2. restore the pre-upgrade backup if schema/data formats changed;
3. return to the previous known-good Git revision;
4. reinstall the editable package in `.venv` if needed;
5. start worker and API;
6. verify `/api/ready`.

Alembic is treated as a forward migration mechanism during normal operation; an arbitrary `alembic downgrade` is not a replacement for restoring a tested backup.

## Power loss and restart

SQLite uses WAL and short transactions. Evidence files are written atomically.

After a worker restart:

- `running` jobs become `interrupted` with `application_restart`;
- `queued` jobs remain queued;
- there is no automatic retry;
- stale temporary files and locks are cleaned conservatively.

Restarting the browser or kiosk does not change job state.
