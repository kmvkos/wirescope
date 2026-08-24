# WireScope operational runbook

Day-2 operations for the generic Linux appliance (Debian/Ubuntu, Fedora/RHEL,
openSUSE). Commands are the same on each family; package names differ only
during install. Raspberry Pi kiosk hardware is an optional later extra.

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

1. Open `http://127.0.0.1:8000/` on the appliance, or `https://<host>/` through
   the reverse proxy (see `packaging/proxy/README.md`).
2. Use the auditor username (`auditor` unless overridden).
3. Use the password from `/etc/wirescope/initial-admin.txt` or the operator
   password file supplied to the installer.
4. Delete `/etc/wirescope/initial-admin.txt` after copying it to a password
   manager.

The GUI is Russian. Viewers can inspect results but cannot start or cancel
work. If login does not stick, the page is probably HTTP while cookies are
`Secure` — open the GUI over HTTPS.

## LAN TLS

Preferred: API on loopback, Caddy or nginx on 443, `--trust-proxy`.
Optional: uvicorn `--tls-cert` / `--tls-key` on 8443. Firewall examples are
in `packaging/proxy/`. The installer does not start a proxy or change nft/ufw.

## Reboot during an audit

| Job state at reboot | After worker start |
| --- | --- |
| `running` | `interrupted`, error `application_restart`, not retried |
| `queued` | still `queued`, eligible to be claimed |
| `cancelled` | remains cancelled |

The GUI polls durable jobs. Reloading the browser, restarting an optional
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

## Optional kiosk (Raspberry Pi later extra)

Not required. Keep using a normal browser on generic Linux.

```bash
sudo /opt/wirescope/packaging/install.sh --with-kiosk --enable-kiosk
sudo systemctl status wirescope-kiosk
```

The optional extra loops Chromium against `http://127.0.0.1:8000/`. If
Chromium exits, the unit restarts the browser only. It does not restart or
stop the API or worker.

Live Raspberry Pi OS Lite, touch, and ARM64-on-device smoke tests are
opt-in and unused (`pytest -m live_pi` with `WIRESCOPE_LIVE_PI=1` on the Pi).

## Dependency inventory

See [packaging/inventory/DEPENDENCIES.md](../packaging/inventory/DEPENDENCIES.md)
or `python3 -m appliance inventory`.
