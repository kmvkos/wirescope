# WireScope operational runbook

Day-2 operations for the generic Linux appliance (Debian/Ubuntu, Fedora/RHEL,
openSUSE). Commands are the same on each family; package names differ only
during install. Raspberry Pi hardware is optional; Raspberry Pi OS is not
required.

## Service health

```bash
systemctl is-active wirescope-api wirescope-worker
curl -sS http://127.0.0.1:8000/api/health
# LAN via reverse proxy:
# curl -sS https://wirescope.example/api/health
curl -sS http://127.0.0.1:8000/api/ready
python3 -m appliance verify --project-root /opt/wirescope
python3 -m appliance detect
```

`/api/health` is public and does not require the worker. `/api/ready` is
false until migrations match and a worker heartbeat is current. The login
page still loads from the API process alone.

Logs:

```bash
journalctl -u wirescope-api -u wirescope-worker --since -1h
```

Journal retention is capped by `packaging/systemd/40-wirescope.journald.conf`
(`SystemMaxUse=256M`, 14 days) when the installer installed that drop-in.

Restart limits are five failures per 60 seconds (`StartLimitBurst`).

On `--user-install`, use `systemctl --user` and `journalctl --user`.

## Sign in

1. On this computer: `http://127.0.0.1:8000/` (kiosk or local browser).
   Сеть до вашего ПК не нужна: откройте GUI на этом компьютере / киоск.
   From another PC: `https://<host>/` through Caddy or nginx (see
   `packaging/proxy/README.md`).
2. Use the auditor username (`auditor` unless overridden).
3. Use the password from `/etc/wirescope/initial-admin.txt` or the operator
   password file supplied to the installer.
4. Delete `/etc/wirescope/initial-admin.txt` after copying it to a password
   manager.

The GUI is Russian. Viewers can inspect results but cannot start or cancel
work. If login does not stick, the page is probably HTTP while cookies are
`Secure` — open the GUI over HTTPS.

## From another PC

Preferred: API stays on `127.0.0.1:8000`, Caddy or nginx on 443,
`--trust-proxy`. Open `https://<host>/`.

| Family | Enable proxy | Open 443 | URL |
| --- | --- | --- | --- |
| This Debian VM | `apt install caddy` or `nginx`; copy `/etc/wirescope/proxy/` | `nftables.nft` or `ufw.example` | `https://<debian-host>/` |
| Ubuntu | same packages (`apt`); `ufw.example` | ufw | `https://<ubuntu-host>/` |
| Fedora / RHEL | `dnf install caddy` or `nginx`; `firewalld.example` | firewalld | `https://<fedora-host>/` |

Lab: `python3 -m appliance tls-selfsigned`. Real hostname: Let's Encrypt
(Caddy automatic HTTPS, or `certbot` with nginx). Optional direct TLS:
`https://<host>:8443/`. The installer does not start a proxy or change
nft/ufw/firewalld.

## Reboot during an audit

| Job state at reboot | After worker start |
| --- | --- |
| `running` | `interrupted`, error `application_restart`, not retried |
| `queued` | still `queued`, eligible to be claimed |
| `cancelled` | remains cancelled |

The GUI polls durable jobs. Reloading the browser, restarting the local
kiosk, or bouncing `wirescope-api` does not cancel worker jobs. Only an
auditor Stop action or process-level worker restart of a *running* job
changes execution.

After reboot: wait until `/api/ready` shows `worker: true`, then open the
audit from the home list. Interrupted jobs stay interrupted.

## Capture permission check

```bash
getent group wireshark
/usr/sbin/getcap /usr/bin/dumpcap
stat -c '%U:%G %a' /usr/bin/dumpcap
sudo -u wirescope /usr/bin/dumpcap -D
/usr/sbin/getcap /opt/wirescope/.venv/bin/python || true
```

Expected: dumpcap `root:wireshark` `750` with `cap_net_admin,cap_net_raw=eip`;
Python has no those capabilities; `dumpcap -D` works as `wirescope`.
`getcap` may be `/usr/sbin/getcap` or `/sbin/getcap` depending on the distro.

On a `--user-install`, also check the worker process groups include
`wireshark`. If not, the units should exec via `sg wireshark`; then
`systemctl --user restart wirescope-api wirescope-worker` is enough without
a logout. System units use `SupplementaryGroups=wireshark`.

## Backup

```bash
systemctl stop wirescope-api wirescope-worker   # optional, quieter SQLite
sudo -u wirescope env WIRESCOPE_DATA_DIR=/var/lib/wirescope \
  /opt/wirescope/.venv/bin/python -m appliance backup
systemctl start wirescope-worker wirescope-api
```

Copies land under `/var/lib/wirescope/backups/<UTC-stamp>/` (`wirescope.db`
plus `evidence/` when present). Files are mode `0600`.

## Restore

```bash
systemctl stop wirescope-api wirescope-worker
sudo -u wirescope env WIRESCOPE_DATA_DIR=/var/lib/wirescope \
  /opt/wirescope/.venv/bin/python -m appliance restore \
  /var/lib/wirescope/backups/TIMESTAMP
systemctl start wirescope-worker wirescope-api
```

Stop the services first. Restore replaces the live database (and evidence
tree when the archive contains one).

## Upgrade

```bash
sudo -u wirescope env WIRESCOPE_DATA_DIR=/var/lib/wirescope \
  /opt/wirescope/.venv/bin/python -m appliance backup
sudo /opt/wirescope/packaging/upgrade.sh --project-root /opt/wirescope
curl -sS http://127.0.0.1:8000/api/ready
```

The upgrade path does not install Nuclei or Nikto. Optional protocol tools
that are missing from the distro are skipped with a warning. Re-running
install/upgrade is idempotent.

## Rollback

1. Stop API and worker.
2. Restore the pre-upgrade backup.
3. Check out the last known-good revision of `/opt/wirescope`.
4. `/opt/wirescope/.venv/bin/pip install -e /opt/wirescope`
5. Start worker, then API.
6. Confirm `/api/ready` and a login.

Do not assume `alembic downgrade` is safe.

## Local operator kiosk

Autonomous mode: Chromium on the appliance display, loopback only. Capture
NIC addressing is independent. Restarting the kiosk does not stop API or
worker.

```bash
sudo /opt/wirescope/packaging/install.sh --with-kiosk --enable-kiosk
# or, after graphical login on a VM:
systemctl --user enable --now wirescope-kiosk
sudo systemctl status wirescope-kiosk          # system unit
systemctl --user status wirescope-kiosk        # user unit
```

`--with-kiosk` installs openbox or labwc plus Chromium, not a full desktop.
Headless hosts leave the unit installed but disabled. Live Raspberry Pi OS
Lite tests stay unused (`pytest -m live_pi` with `WIRESCOPE_LIVE_PI=1`).

## Dependency inventory

See [packaging/inventory/DEPENDENCIES.md](../packaging/inventory/DEPENDENCIES.md)
or `python3 -m appliance inventory`.
