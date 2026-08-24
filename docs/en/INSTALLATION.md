# Installing WireScope

[Русский](../INSTALLATION.md) · **English**

WireScope installs on a normal Linux host or VM. Supported families are:

- Debian / Ubuntu;
- Fedora / RHEL / Rocky;
- openSUSE / SLES;
- `amd64` and `arm64`.

Raspberry Pi is a valid hardware target, but Raspberry Pi OS is not required.

## Deployment modes

There are two normal ways to operate the appliance:

1. **local kiosk** — a monitor is connected to the WireScope host and Chromium opens the local UI;
2. **remote browser** — an operator connects from another machine through HTTPS and a reverse proxy.

Both modes use the same API and worker.

Recommended system-install layout:

```text
/opt/wirescope                  Git checkout + .venv
/etc/wirescope                  configuration
/var/lib/wirescope              SQLite, runtime, evidence, backups
/etc/systemd/system             systemd units
```

The installer **runs from the checkout**. It does not copy the project tree into `/opt/wirescope` after the fact. Systemd units reference that checkout, so do not delete or rename it after installation.

## Clone the repository

### SSH

If the SSH key belongs to your regular account, clone without `sudo`:

```bash
git clone git@github.com:kmvkos/wirescope.git
sudo mv wirescope /opt/wirescope
cd /opt/wirescope
sudo git checkout milestone-8-appliance
```

Using `sudo git clone` would use root's SSH configuration and keys.

If root already has GitHub access, cloning directly to `/opt` is fine:

```bash
sudo git clone git@github.com:kmvkos/wirescope.git /opt/wirescope
cd /opt/wirescope
sudo git checkout milestone-8-appliance
```

### HTTPS

```bash
git clone https://github.com/kmvkos/wirescope.git
sudo mv wirescope /opt/wirescope
cd /opt/wirescope
sudo git checkout milestone-8-appliance
```

For the private repository, use a GitHub token or credential helper rather than an account password.

## Basic system install

For an autonomous appliance with a local display:

```bash
cd /opt/wirescope
sudo ./packaging/install.sh \
  --generate-admin-password \
  --bind-host 127.0.0.1 \
  --with-kiosk \
  --enable-kiosk
```

Then reboot:

```bash
sudo reboot
```

After boot, `wirescope-kiosk` owns `tty1` and opens Chromium at:

```text
http://127.0.0.1:8000/
```

A full desktop environment is not required.

### Why `--bind-host 127.0.0.1` is explicit

The application default in `config/settings.py` is `127.0.0.1`. The appliance installer CLI currently has a separate default of `--bind-host 0.0.0.0`.

For that reason the documented kiosk and reverse-proxy setups pass the desired bind explicitly:

```bash
--bind-host 127.0.0.1
```

Plain HTTP on `0.0.0.0:8000` should be a deliberate lab or management choice with an appropriate firewall. For ordinary LAN operation, HTTPS through Caddy or nginx is preferred.

## What the installer does

`packaging/install.sh` eventually calls `python -m appliance install`.

A system install:

1. detects the distribution, package manager, and architecture;
2. installs system dependencies through `apt`, `dnf`, `yum`, or `zypper`;
3. creates or reuses the unprivileged `wirescope` service account;
4. creates managed data directories;
5. configures `dumpcap` using the `wireshark` group and file capabilities;
6. creates `.venv` and installs pinned Python dependencies;
7. writes `/etc/wirescope/wirescope.env`;
8. installs `wirescope-api` and `wirescope-worker` systemd units;
9. applies Alembic migrations;
10. creates the first GUI operator;
11. starts the services;
12. optionally installs the minimal browser/display stack;
13. optionally enables the kiosk unit on `tty1`.

The installer is designed to be re-run for upgrades and idempotent setup.

## Initial operator account

There is no built-in default password.

The easiest setup is:

```bash
sudo ./packaging/install.sh \
  --generate-admin-password \
  --bind-host 127.0.0.1
```

The generated password is written to:

```text
/etc/wirescope/initial-admin.txt
```

The file is mode `0600`. Copy the password to a password manager and remove the file afterwards.

Default username:

```text
auditor
```

To supply your own password file:

```bash
sudo ./packaging/install.sh \
  --auditor-password-file /root/auditor.pass \
  --bind-host 127.0.0.1
```

The password file must be mode `0600` or stricter.

For lock-out recovery:

```bash
/opt/wirescope/.venv/bin/python -m appliance set-password auditor
```

For normal password changes, use **Change password** in the GUI instead.

## Local kiosk

WireScope does not install GNOME, KDE, XFCE, GDM, or LightDM.

The normal system kiosk is:

```text
multi-user.target
    ├── wirescope-api
    ├── wirescope-worker
    └── wirescope-kiosk
             ↓
           tty1
             ↓
      Cage or Xorg/xinit
             ↓
          Chromium
             ↓
  http://127.0.0.1:8000/
```

Install it with:

```bash
sudo ./packaging/install.sh \
  --generate-admin-password \
  --bind-host 127.0.0.1 \
  --with-kiosk \
  --enable-kiosk
```

If the packages are already installed and only the unit needs enabling:

```bash
sudo ./packaging/install.sh --skip-packages --enable-kiosk
```

or:

```bash
sudo systemctl enable --now wirescope-kiosk
```

### VMware

On VMware the kiosk uses Xorg/xinit instead of Cage. The installer can add the VMware Xorg driver/input packages and `open-vm-tools` when needed.

Reboot with the VM console attached. SSH remains available; the kiosk owns local `tty1`, not the network stack or sshd.

If the console is black and shows neither Chromium nor a login prompt:

```bash
sudo systemctl start getty@tty1
sudo systemctl status wirescope-kiosk
sudo journalctl -u wirescope-kiosk -e
```

The kiosk unit is also configured to fall back to a text login on failure.

## Remote browser over HTTPS

Preferred LAN layout:

```text
browser
   │ HTTPS :443
   ▼
Caddy / nginx
   │ HTTP loopback
   ▼
127.0.0.1:8000
   │
WireScope API
```

Install WireScope like this:

```bash
sudo ./packaging/install.sh \
  --generate-admin-password \
  --trust-proxy \
  --bind-host 127.0.0.1
```

`--trust-proxy` enables the reverse-proxy session mode: cookies become `Secure`, and forwarded headers are trusted only from the loopback proxy.

Proxy examples live under:

```text
packaging/proxy/
```

Installed copies may also be placed under:

```text
/etc/wirescope/proxy/
```

See [packaging/proxy/README.md](../../packaging/proxy/README.md).

The installer does **not** start Caddy/nginx and does not rewrite the firewall. Publish 443 to the management network; do not publish 8000 unless that is an explicit design choice.

### Lab self-signed certificate

```bash
sudo python3 -m appliance tls-selfsigned \
  --output-dir /etc/wirescope/tls \
  --common-name wirescope.example
```

For production, use a normal certificate: Caddy automatic HTTPS or certbot/nginx are the expected paths.

### Direct TLS with Uvicorn

Direct TLS is also supported:

```bash
sudo ./packaging/install.sh \
  --generate-admin-password \
  --bind-host 0.0.0.0 \
  --bind-port 8443 \
  --tls-cert /etc/wirescope/tls/cert.pem \
  --tls-key /etc/wirescope/tls/key.pem
```

Then open:

```text
https://<host>:8443/
```

Certificate and key paths belong in the environment file. PEM contents should never be embedded in systemd units.

## User-systemd install

If system services are not appropriate:

```bash
./packaging/install.sh \
  --user-install \
  --generate-admin-password \
  --bind-host 127.0.0.1
```

User-install paths become:

```text
~/.local/share/wirescope
~/.config/wirescope
~/.config/systemd/user
```

Manage the services with:

```bash
systemctl --user status wirescope-api wirescope-worker
systemctl --user restart wirescope-api wirescope-worker
journalctl --user -u wirescope-api -u wirescope-worker -e
```

`--user-install` does not install OS packages. `dumpcap` still needs one-time root configuration.

User units cannot use `SupplementaryGroups=` in the same way system units can, so WireScope launches the relevant processes through `sg wireshark` to pick up current `wireshark` membership without forcing a logout/login.

Optional boot persistence for the user manager:

```bash
sudo loginctl enable-linger "$USER"
```

## Distribution notes

### Debian / Ubuntu

Main capture packages:

- `tshark`;
- `wireshark-common` (`dumpcap`);
- `libcap2-bin`.

```bash
sudo apt-get update
sudo ./packaging/install.sh \
  --generate-admin-password \
  --bind-host 127.0.0.1
```

### Fedora / RHEL / Rocky

The installer uses `dnf` when available and falls back to `yum`.

The main Wireshark CLI package is:

```text
wireshark-cli
```

Example:

```bash
sudo dnf -y install python3
sudo ./packaging/install.sh \
  --generate-admin-password \
  --bind-host 127.0.0.1
```

### openSUSE / SLES

The installer uses `zypper`.

The capture package is normally `wireshark-cli` with `wireshark` as a fallback. `setcap` is provided by `libcap-progs`.

```bash
sudo zypper --non-interactive install python3
sudo ./packaging/install.sh \
  --generate-admin-password \
  --bind-host 127.0.0.1
```

### Package-name differences

| Purpose | Debian / Ubuntu | Fedora / RHEL | openSUSE |
| --- | --- | --- | --- |
| Package manager | `apt-get` | `dnf` / `yum` | `zypper` |
| dumpcap/tshark | `wireshark-common`, `tshark` | `wireshark-cli` | `wireshark-cli` / `wireshark` |
| `setcap` | `libcap2-bin` | `libcap` | `libcap-progs` |
| Python headers | `python3-dev` | `python3-devel` | `python3-devel` |
| iproute | `iproute2` | `iproute` | `iproute2` |
| sqlite CLI | `sqlite3` | `sqlite` | `sqlite3` |
| DNS tools | `bind9-dnsutils` | `bind-utils` | `bind-utils` |

## Useful installer flags

```text
--dry-run
--skip-packages
--skip-apt                 alias for --skip-packages
--skip-pip
--no-start
--no-optional-providers
--with-kiosk
--enable-kiosk
--user-kiosk
--user-install
--generate-admin-password
--auditor-password-file PATH
--overwrite-env
--bind-host HOST
--bind-port PORT
--trust-proxy
--tls-cert PATH
--tls-key PATH
```

`--user-kiosk` is for an existing graphical user session. A normal desktop-less appliance should use the system `--enable-kiosk` path.

## Verify the installation

```bash
sudo systemctl status wirescope-api wirescope-worker
curl -sS http://127.0.0.1:8000/api/health
curl -sS http://127.0.0.1:8000/api/ready
sudo python3 -m appliance verify --project-root /opt/wirescope
```

`/api/health` confirms that the API process is alive.

`/api/ready` additionally requires:

- accessible SQLite;
- database revision at Alembic head;
- a current worker heartbeat;
- required binaries (`dumpcap`, `tshark`, `nmap`).

## Verify `dumpcap` privileges

Expected system-install state:

```text
/usr/bin/dumpcap
owner: root
 group: wireshark
 mode: 0750
 caps: cap_net_admin,cap_net_raw=eip
```

Check it with:

```bash
getent group wireshark
getcap /usr/bin/dumpcap
stat -c '%U:%G %a' /usr/bin/dumpcap
sudo -u wirescope /usr/bin/dumpcap -D
getcap /opt/wirescope/.venv/bin/python || true
```

The Python interpreter must not have packet-capture capabilities. API and worker should not run as root.

## Runtime paths

A system install normally writes settings equivalent to:

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

Environment file:

```text
/etc/wirescope/wirescope.env
```

Keep the live SQLite database on a local filesystem with proper locking semantics. Do not place it on NFS.

## Migrations

The installer applies Alembic migrations automatically.

Manual equivalent:

```bash
sudo -u wirescope \
  env WIRESCOPE_DATA_DIR=/var/lib/wirescope \
  /opt/wirescope/.venv/bin/alembic \
  -c /opt/wirescope/alembic.ini upgrade head
```

WireScope does not create production tables through `Base.metadata.create_all()`.

## Upgrade

Take a backup before a significant upgrade:

```bash
sudo -u wirescope env WIRESCOPE_DATA_DIR=/var/lib/wirescope \
  /opt/wirescope/.venv/bin/python -m appliance backup
```

Then update the checkout and run the upgrade wrapper:

```bash
cd /opt/wirescope
git pull
sudo ./packaging/upgrade.sh --project-root /opt/wirescope
```

If OS packages are already known-good:

```bash
sudo ./packaging/upgrade.sh \
  --project-root /opt/wirescope \
  --skip-packages
```

Verify afterwards:

```bash
curl -sS http://127.0.0.1:8000/api/ready
```

## Rollback

Rollback is backup-based. Do not assume `alembic downgrade` is safe.

1. Stop API and worker.
2. Restore the pre-upgrade database/evidence backup.
3. Check out the previous known-good Git revision.
4. Reinstall the checkout into `.venv`.
5. Start worker and API.
6. Verify readiness and login.

Example:

```bash
sudo systemctl stop wirescope-api wirescope-worker

sudo -u wirescope env WIRESCOPE_DATA_DIR=/var/lib/wirescope \
  /opt/wirescope/.venv/bin/python -m appliance restore \
  /var/lib/wirescope/backups/TIMESTAMP

cd /opt/wirescope
git checkout <known-good-commit>
/opt/wirescope/.venv/bin/pip install -e /opt/wirescope

sudo systemctl start wirescope-worker wirescope-api
```

Treat migrations as forward-only in normal operation unless a specific downgrade path has been tested.

## Backup and restore

Backup:

```bash
sudo -u wirescope env WIRESCOPE_DATA_DIR=/var/lib/wirescope \
  /opt/wirescope/.venv/bin/python -m appliance backup
```

Default destination:

```text
/var/lib/wirescope/backups/<UTC timestamp>/
```

Restore with services stopped:

```bash
sudo systemctl stop wirescope-api wirescope-worker

sudo -u wirescope env WIRESCOPE_DATA_DIR=/var/lib/wirescope \
  /opt/wirescope/.venv/bin/python -m appliance restore \
  /var/lib/wirescope/backups/TIMESTAMP

sudo systemctl start wirescope-worker wirescope-api
```

## Power loss and reboot recovery

SQLite uses WAL, foreign keys, short transactions, and `synchronous=FULL` by default. Evidence files use a temporary-file and atomic-rename path.

When the worker starts again:

- queued jobs remain queued;
- jobs that were running become `interrupted` with `application_restart`;
- there is no automatic retry;
- startup maintenance clears stale locks and controlled temporary files.

Restarting the browser or kiosk does not affect job lifetime.

## Release checksums

```bash
python3 -m appliance checksums \
  --project-root /opt/wirescope \
  --output /opt/wirescope/packaging/SHA256SUMS

sha256sum -c /opt/wirescope/packaging/SHA256SUMS
```

When distributing release artifacts, `SHA256SUMS` can be signed with an operator-managed GPG key. The installer never stores that private key.

## Related documentation

- [Architecture](ARCHITECTURE.md)
- [Security model](SECURITY_MODEL.md)
- [Runbook](RUNBOOK.md)
- [Development](DEVELOPMENT.md)
