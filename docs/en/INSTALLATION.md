# Installing WireScope

[Русский](../INSTALLATION.md)

WireScope can be installed as a dedicated Linux appliance, VM, or application on an existing server. Supported targets include Debian/Ubuntu/Raspberry Pi OS, Fedora/RHEL/Rocky, and openSUSE on `amd64` and `arm64`.

## Recommended system layout

A system install runs from the Git checkout and uses:

```text
/opt/wirescope                  Git checkout + .venv
/etc/wirescope                  configuration
/var/lib/wirescope              SQLite, runtime, evidence, backups
/etc/systemd/system             systemd units
```

System installation from `/home/...` or `/root/...` is intentionally rejected. Generated systemd units use `ProtectHome=true`, so the production checkout must live outside a home directory.

## Clean installation from public GitHub

```bash
git clone https://github.com/kmvkos/wirescope.git
sudo mv wirescope /opt/wirescope
cd /opt/wirescope
```

Do not check out an old `milestone-*` branch from historical instructions. A normal `git clone` should provide the current public project line.

### Basic installation

```bash
sudo ./packaging/install.sh --generate-admin-password
```

### Appliance with local kiosk

```bash
sudo ./packaging/install.sh \
  --generate-admin-password \
  --with-kiosk \
  --enable-kiosk
```

`--with-kiosk` installs a minimal display stack: Chromium and Cage or Xorg/xinit. GNOME/KDE/XFCE are not required. Raspberry Pi OS does not need an additional desktop environment.

A normal appliance install listens on `0.0.0.0:8000`. The local kiosk opens `http://127.0.0.1:8000/`.

For loopback-only access:

```bash
sudo ./packaging/install.sh \
  --generate-admin-password \
  --bind-host 127.0.0.1
```

## What the installer does

`packaging/install.sh` idempotently performs:

1. distro family, package manager, and architecture detection;
2. required package and available optional-provider installation;
3. creation or reuse of the unprivileged `wirescope` account;
4. data/runtime/evidence directory setup;
5. creation of the `wireshark` group on clean Debian/Raspberry Pi OS systems when required;
6. packet-capture privileges on `/usr/bin/dumpcap` only;
7. `.venv` creation and Python dependency installation;
8. `/etc/wirescope/wirescope.env` generation;
9. API/worker systemd units and optional kiosk units;
10. Alembic migrations;
11. first `auditor` creation without a built-in default password;
12. service startup unless `--no-start` is supplied.

The generic kiosk dependency set must not contain VMware-only packages. VMware-specific Xorg integration is not a Raspberry Pi/ARM64 dependency.

## Services

A system installation uses:

```text
wirescope-api.service
wirescope-worker.service
[wirescope-kiosk.service]
```

API and worker run unprivileged.

Packet-capture privileges remain on `dumpcap` only:

```text
/usr/bin/dumpcap
owner: root
 group: wireshark
 mode: 0750
 capabilities: cap_net_admin,cap_net_raw=eip
```

Verify with:

```bash
sudo /opt/wirescope/.venv/bin/python -m appliance verify \
  --project-root /opt/wirescope
sudo -u wirescope /usr/bin/dumpcap -D
```

## First login

With `--generate-admin-password`, the initial password is stored in:

```text
/etc/wirescope/initial-admin.txt
```

Default username:

```text
auditor
```

Read the generated password with:

```bash
sudo cat /etc/wirescope/initial-admin.txt
```

After storing it in a password manager, the file can be removed.

## Post-install verification

```bash
systemctl is-active wirescope-api
systemctl is-active wirescope-worker
systemctl is-active wirescope-kiosk 2>/dev/null || true

curl -sS http://127.0.0.1:8000/api/v1/health
curl -sS http://127.0.0.1:8000/api/v1/ready
curl -sS http://127.0.0.1:8000/api/v1/capabilities
```

Expected behavior:

- `/health` confirms that the API is alive;
- `/ready` checks database, migrations, worker, `dumpcap`, and `tshark`;
- `/capabilities` reports optional provider availability.

## Raspberry Pi OS

64-bit Raspberry Pi OS Lite is recommended. A full desktop is not required.

A typical appliance layout is:

- `wlan0` for management/Web UI;
- `eth0` for the audited network;
- local Chromium kiosk on the attached display.

WireScope does not require Raspberry Pi OS as its only supported OS, but Pi OS is a convenient base for Raspberry Pi hardware/display integration.

## TLS / reverse proxy

For loopback + reverse proxy:

```bash
sudo ./packaging/install.sh \
  --generate-admin-password \
  --bind-host 127.0.0.1 \
  --trust-proxy
```

Caddy/nginx templates live in `packaging/proxy/` and are copied to `/etc/wirescope/proxy/` by a system install. The installer does not start a reverse proxy and does not rewrite the host firewall automatically.

Direct TLS:

```bash
sudo ./packaging/install.sh \
  --generate-admin-password \
  --bind-host 0.0.0.0 \
  --bind-port 8443 \
  --tls-cert /etc/wirescope/tls/cert.pem \
  --tls-key /etc/wirescope/tls/key.pem
```

## User install

User-systemd installs may run from a home checkout:

```bash
./packaging/install.sh \
  --user-install \
  --generate-admin-password
```

Paths:

```text
~/.local/share/wirescope
~/.config/wirescope
~/.config/systemd/user
```

## Useful flags

```text
--dry-run                 show the plan without changes
--skip-packages           skip the package manager
--skip-pip                reuse the current venv
--no-start                do not start units
--no-optional-providers   install base dependencies only
--with-kiosk              install the minimal kiosk stack
--enable-kiosk            enable the system tty1 kiosk
--user-kiosk              user-session kiosk
--user-install            user systemd install
--bind-host               API bind; appliance default 0.0.0.0
--bind-port               API port; default 8000
--trust-proxy             reverse-proxy mode
--tls-cert / --tls-key    direct TLS
--overwrite-env           replace wirescope.env
```

## Updating

Inspect the checkout first:

```bash
cd /opt/wirescope
git status --short
git branch --show-current
git rev-parse HEAD
git fetch --tags origin
```

Create a backup before a substantial upgrade:

```bash
sudo -u wirescope env WIRESCOPE_DATA_DIR=/var/lib/wirescope \
  /opt/wirescope/.venv/bin/python -m appliance backup
```

Then:

```bash
sudo ./packaging/upgrade.sh --project-root /opt/wirescope
```

After upgrade:

```bash
systemctl is-active wirescope-api wirescope-worker
curl -sS http://127.0.0.1:8000/api/v1/ready
```

For production/reproducible deployments, pin a release/tag/commit SHA rather than an arbitrary intermediate development revision.

## Installation diagnostics

If the installer reports that a systemd service failed to start, inspect the actual service journal first:

```bash
sudo journalctl -u wirescope-api.service -b -n 120 --no-pager
sudo journalctl -u wirescope-worker.service -b -n 120 --no-pager
sudo journalctl -u wirescope-kiosk.service -b -n 120 --no-pager
```

Do not move an already-created `.venv` between different filesystem paths. If the checkout was moved after venv creation, remove only `.venv` and let the installer recreate it in the final path.
