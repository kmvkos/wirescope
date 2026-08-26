# Installing WireScope

[Русский](../INSTALLATION.md)

WireScope can be installed as a dedicated Linux appliance, a VM, or an application on an existing server. Supported targets include Debian/Ubuntu, Fedora/RHEL/Rocky, and openSUSE on `amd64` and `arm64`. Raspberry Pi is a supported hardware option but is not required.

The installer runs **from the Git checkout**. The recommended system layout is:

```text
/opt/wirescope                  Git checkout + .venv
/etc/wirescope                  configuration
/var/lib/wirescope              SQLite, runtime, evidence, backups
/etc/systemd/system             systemd units
```

## Clone the repository

The repository is private, so use an SSH key or GitHub token.

```bash
git clone git@github.com:kmvkos/wirescope.git
cd wirescope
git fetch --tags origin

# For reproducible installation, select the intended release/tag/checkpoint:
# git checkout <release-or-checkpoint>

cd ..
sudo mv wirescope /opt/wirescope
cd /opt/wirescope
```

Do not copy an old milestone branch name from historical instructions. Production-like deployments should pin a known release/tag/checkpoint and record its exact SHA.

Clone without `sudo` so Git uses the current user's SSH configuration. Checkout before moving the repository into `/opt` to avoid unnecessary ownership and `safe.directory` issues.

## Basic system installation

```bash
sudo ./packaging/install.sh --generate-admin-password
```

A normal appliance install listens on **`0.0.0.0:8000`**. This is intentional: the UI is expected to be reachable through any configured WireScope interface, including Ethernet and Wi-Fi.

A local browser can use:

```text
http://127.0.0.1:8000/
```

while another machine can use the address of a WireScope interface:

```text
http://<wirescope-ip>:8000/
```

A deployment that needs loopback-only access can request it explicitly:

```bash
sudo ./packaging/install.sh \
  --generate-admin-password \
  --bind-host 127.0.0.1
```

Firewall rules, TLS, and a reverse proxy remain available as deployment hardening options.

## Local kiosk

```bash
sudo ./packaging/install.sh \
  --generate-admin-password \
  --with-kiosk \
  --enable-kiosk
```

`--with-kiosk` installs a minimal display stack: Chromium and Cage or Xorg/xinit. A full GNOME/KDE/XFCE desktop is not required. VMware uses the Xorg path.

After boot, the system kiosk owns `tty1` and opens `http://127.0.0.1:8000/`. Restarting Chromium does not stop the API, worker, or an active audit.

## TLS / reverse proxy when needed

For environments where plain HTTP is undesirable, bind WireScope to loopback and place Caddy/nginx in front of it:

```text
browser → HTTPS 443 → Caddy/nginx → 127.0.0.1:8000
```

Example:

```bash
sudo ./packaging/install.sh \
  --generate-admin-password \
  --bind-host 127.0.0.1 \
  --trust-proxy
```

Templates live under `packaging/proxy/` and are copied to `/etc/wirescope/proxy/` by a system installation. The installer does not start Caddy/nginx automatically and does not rewrite the host firewall.

Direct TLS is also supported:

```bash
sudo ./packaging/install.sh \
  --generate-admin-password \
  --bind-host 0.0.0.0 \
  --bind-port 8443 \
  --tls-cert /etc/wirescope/tls/cert.pem \
  --tls-key /etc/wirescope/tls/key.pem
```

Only certificate/key paths are stored in the environment/systemd configuration; PEM contents are not embedded in unit files.

## What the installer does

`packaging/install.sh` invokes the appliance installer and idempotently performs:

1. distro family, package manager, and architecture detection;
2. required packages and available optional-provider installation;
3. creation or reuse of the unprivileged `wirescope` account;
4. data/runtime/evidence directory setup;
5. packet-capture privileges on `dumpcap` only;
6. `.venv` creation and pinned Python dependency installation;
7. `/etc/wirescope/wirescope.env` generation;
8. API/worker systemd units and optional kiosk units;
9. Alembic migrations;
10. first `auditor` creation without a built-in default password;
11. service startup unless `--no-start` is supplied.

Nuclei and Nikto are not installed by default. Optional topology-management providers include Net-SNMP tools and the OpenSSH client; their absence does not make the base appliance `not_ready`.

## Services

A normal system installation runs:

```text
wirescope-api.service
wirescope-worker.service
[wirescope-kiosk.service]
```

API and worker run as an unprivileged account.

Packet-capture privileges should remain on `dumpcap` only:

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

With `--generate-admin-password`, the installer writes the initial password to a protected file, normally:

```text
/etc/wirescope/initial-admin.txt
```

The default username is `auditor`. There is no permanent built-in password. Store the generated password securely and remove the file afterwards.

Password recovery:

```bash
/opt/wirescope/.venv/bin/python -m appliance set-password auditor
```

## Post-install verification

```bash
systemctl status wirescope-api wirescope-worker
curl -sS http://127.0.0.1:8000/api/v1/health
curl -sS http://127.0.0.1:8000/api/v1/ready
curl -sS http://127.0.0.1:8000/api/v1/capabilities
```

From another machine, replace `127.0.0.1` with the WireScope interface address.

`/health` checks that the API is alive. `/ready` checks SQLite, migrations, the worker, `dumpcap`, and `tshark`. Optional providers are reported through `/capabilities` and do not make the entire appliance `not_ready`.

## Distribution notes

### Debian / Ubuntu

The installer uses `apt`. Core packages include Python, `iproute2`, Wireshark CLI tools, SQLite, and `libcap2-bin`.

```bash
sudo ./packaging/install.sh --generate-admin-password
```

### Fedora / RHEL / Rocky

The installer uses `dnf`, with `yum` as a fallback. `dumpcap`/`tshark` normally come from `wireshark-cli`.

```bash
sudo dnf -y install python3
sudo ./packaging/install.sh --generate-admin-password
```

### openSUSE / SLES

The installer uses `zypper` and the distro Wireshark CLI package.

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

User installs use:

```text
~/.local/share/wirescope
~/.config/wirescope
~/.config/systemd/user
```

OS packages and the initial `dumpcap` setup may still require root once.

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

## Updating an installed VM

If the checkout already lives at `/opt/wirescope`, first confirm the working tree is clean:

```bash
cd /opt/wirescope
git status --short
git branch --show-current
git rev-parse HEAD
git fetch --tags origin
```

For a reproducible upgrade, switch to a specific known-good ref:

```bash
git checkout <release-tag-or-checkpoint>
git rev-parse HEAD
```

Before a substantial upgrade, create a backup, then use the full upgrade path:

```bash
sudo -u wirescope env WIRESCOPE_DATA_DIR=/var/lib/wirescope \
  /opt/wirescope/.venv/bin/python -m appliance backup

sudo ./packaging/upgrade.sh --project-root /opt/wirescope
```

After upgrade:

```bash
systemctl is-active wirescope-api wirescope-worker
curl -sS http://127.0.0.1:8000/api/v1/ready
curl -sS http://127.0.0.1:8000/api/v1/capabilities
```

Do not use `git pull` as a substitute for selecting a release/checkpoint when the appliance is expected to remain on a reproducible revision.

The upgrade entrypoint uses the same `0.0.0.0` appliance default unless an explicit `--bind-host` override is provided.

## Backup and rollback

A backup should already exist before a substantial upgrade.

For rollback:

1. stop API and worker;
2. restore the backup if schema/data formats changed;
3. return to the previous known-good Git revision;
4. reinstall the package in `.venv` if needed;
5. start worker and API;
6. verify `/api/v1/ready`.

## Restart / power loss

SQLite uses WAL mode and short transactions. Evidence files are written atomically.

After a worker restart:

- `running` jobs become `interrupted` with `application_restart`;
- `queued` jobs remain queued;
- there is no automatic retry;
- stale locks/temp files are cleaned conservatively.

Restarting the browser or kiosk does not change job state.