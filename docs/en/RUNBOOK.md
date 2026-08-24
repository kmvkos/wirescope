# WireScope operational runbook

[Русский](../RUNBOOK.md) · **English**

This is the day-to-day operations guide for an already installed appliance. First-time installation is covered in [INSTALLATION.md](INSTALLATION.md).

Commands below assume a system install in `/opt/wirescope`. For `--user-install`, use `systemctl --user`, `journalctl --user`, and the corresponding user paths.

## Quick health check

```bash
systemctl is-active wirescope-api wirescope-worker
curl -sS http://127.0.0.1:8000/api/health
curl -sS http://127.0.0.1:8000/api/ready
/opt/wirescope/.venv/bin/python -m appliance verify --project-root /opt/wirescope
/opt/wirescope/.venv/bin/python -m appliance detect
```

Endpoint meaning:

- `/api/health` — API process is alive;
- `/api/ready` — database revision, worker heartbeat, and required binaries are also ready.

`/api/health` may be OK while the worker is down. That is the intended distinction between liveness and readiness.

## Logs

Last hour:

```bash
journalctl \
  -u wirescope-api \
  -u wirescope-worker \
  --since -1h
```

Follow live:

```bash
journalctl -f -u wirescope-api -u wirescope-worker
```

Kiosk:

```bash
journalctl -u wirescope-kiosk -e
```

When installed, the WireScope journald drop-in caps journal usage so an appliance cannot consume the whole disk with logs.

## Login check

Local:

```text
http://127.0.0.1:8000/
```

Through a reverse proxy:

```text
https://<host>/
```

The default GUI username is normally:

```text
auditor
```

The initial generated password is stored after install in:

```text
/etc/wirescope/initial-admin.txt
```

Move it to a password manager and remove the file.

If authentication succeeds but the browser immediately returns to the login screen, check HTTP versus HTTPS. A `Secure` session cookie will not persist over plain HTTP.

## Change or reset a password

Normal path: GUI → **Change password**.

Lock-out recovery:

```bash
/opt/wirescope/.venv/bin/python \
  -m appliance set-password auditor
```

The command updates the live SQLite database, revokes that user's sessions, and writes the new password to a mode-`0600` file.

## API does not respond

Check:

```bash
systemctl status wirescope-api
journalctl -u wirescope-api -e
ss -lntp | grep ':8000\|:8443' || true
```

Inspect environment settings if necessary:

```bash
sudo cat /etc/wirescope/wirescope.env
```

Do not paste full environment files into tickets or chats when they may contain sensitive deployment information.

If a reverse proxy is in use, first confirm the loopback API works:

```bash
curl -sS http://127.0.0.1:8000/api/health
```

Only then troubleshoot Caddy/nginx, TLS, or firewall policy.

## `/api/ready` returns 503

Inspect the response body:

```bash
curl -sS http://127.0.0.1:8000/api/ready
```

Readiness requires:

- accessible database;
- migrations current;
- current worker heartbeat;
- `dumpcap`;
- `tshark`;
- `nmap`.

### Migrations are not current

```bash
sudo -u wirescope \
  env WIRESCOPE_DATA_DIR=/var/lib/wirescope \
  /opt/wirescope/.venv/bin/alembic \
  -c /opt/wirescope/alembic.ini upgrade head
```

Then:

```bash
sudo systemctl restart wirescope-worker wirescope-api
```

### Worker is not ready

```bash
systemctl status wirescope-worker
journalctl -u wirescope-worker -e
```

If the worker was stopped while jobs were running, startup recovery will mark those jobs `interrupted`. That is expected behavior.

## Packet capture does not work

Check `dumpcap`:

```bash
getent group wireshark
getcap /usr/bin/dumpcap
stat -c '%U:%G %a' /usr/bin/dumpcap
sudo -u wirescope /usr/bin/dumpcap -D
getcap /opt/wirescope/.venv/bin/python || true
```

Expected:

```text
/usr/bin/dumpcap
root:wireshark
0750
cap_net_admin,cap_net_raw=eip
```

Python should have no packet-capture capabilities.

If `dumpcap -D` fails as `wirescope`, run verification and inspect the distro-specific Wireshark setup:

```bash
sudo /opt/wirescope/.venv/bin/python \
  -m appliance verify --project-root /opt/wirescope
```

### User install

A `--user-install` worker should obtain the `wireshark` group through `sg wireshark`.

After group changes:

```bash
systemctl --user daemon-reload
systemctl --user restart wirescope-api wirescope-worker
```

A logout is normally unnecessary because the units use `sg wireshark` explicitly.

## Capture sees very little traffic

This is not necessarily a fault.

Without a switch SPAN/mirror configuration, promiscuous mode still only receives frames the switch sends to the port.

Typical visible traffic includes:

- broadcasts;
- flooded frames;
- multicast delivered to the port;
- unicast to the WireScope MAC;
- control traffic such as LLDP/CDP/STP when delivered to the port.

Use SPAN/mirror or a TAP when you need visibility into other hosts' unicast traffic.

## VLAN ID is unknown

An access port commonly sends untagged frames. In that case WireScope intentionally leaves VLAN ID unknown.

Check separately:

- whether 802.1Q-tagged frames were present;
- LLDP/CDP-advertised VLAN metadata;
- configured VLAN subinterfaces;
- switch-port configuration.

LLDP PVID/native VLAN metadata and an 802.1Q frame tag are not the same thing.

## Active discovery will not start

Check:

1. scope has been confirmed;
2. an L3 address exists for the required family;
3. `ip route get <target>` uses the selected interface;
4. target is allowed by scope policy;
5. target count is below the profile cap;
6. Nmap is installed;
7. no other job owns `interface:<name>`.

Useful commands:

```bash
ip -j addr
ip -j route
ip route get <target>
nmap --version
curl -sS http://127.0.0.1:8000/api/ready
```

Passive capture can work without an IP address. Active discovery cannot: Nmap needs a real L3 path.

## A protocol module did not run

That can be normal.

Check:

- a matching service exists in inventory;
- the address is inside confirmed scope;
- the module safety class is allowed;
- the required binary is installed;
- the module is not `never-default`.

Tool availability:

```bash
command -v ssh-audit
command -v openssl
command -v curl
command -v dig
command -v smbclient
command -v snmpget
command -v ldapsearch
```

A missing optional tool does not fail the whole audit; the observation records `tool_unavailable`.

## Reboot during an audit

Recovery behavior:

| State before reboot | State after worker recovery |
| --- | --- |
| `queued` | remains `queued` |
| `running` | `interrupted`, `application_restart` |
| `cancelled` | remains `cancelled` |
| terminal | unchanged |

There is no automatic retry or mid-job resume.

After reboot:

```bash
curl -sS http://127.0.0.1:8000/api/ready
```

Once the worker is ready, open the audit from GUI history.

Reloading the browser or restarting the kiosk does not itself stop a running job.

## Cancellation appears stuck

Check worker logs:

```bash
journalctl -u wirescope-worker -e
```

A normal cancellation propagates to the cooperative token and terminates the provider subprocess group.

If the worker was killed abruptly, startup recovery will later mark the job `interrupted`.

## Kiosk does not start

Check:

```bash
systemctl status wirescope-kiosk
journalctl -u wirescope-kiosk -e
```

Restore a text login on tty1:

```bash
sudo systemctl start getty@tty1
```

Check Chromium:

```bash
command -v chromium || command -v chromium-browser
```

On VMware, also inspect the Xorg/video stack.

Restarting the kiosk does not require restarting API/worker:

```bash
sudo systemctl restart wirescope-kiosk
```

## Reverse proxy does not work

First test the local API:

```bash
curl -sS http://127.0.0.1:8000/api/health
```

Then check the proxy:

```bash
systemctl status caddy || systemctl status nginx
```

Check the listener:

```bash
ss -lntp | grep ':443'
```

Then inspect the firewall.

Example configurations are under `packaging/proxy/`.

When WireScope is installed with `--trust-proxy`, remote users should open the HTTPS URL. A `Secure` session cookie will not work over plain HTTP.

## Backup

An online backup path exists, but stopping services before major maintenance can make the operational procedure simpler:

```bash
sudo systemctl stop wirescope-api wirescope-worker

sudo -u wirescope env WIRESCOPE_DATA_DIR=/var/lib/wirescope \
  /opt/wirescope/.venv/bin/python -m appliance backup

sudo systemctl start wirescope-worker wirescope-api
```

Default backup location:

```text
/var/lib/wirescope/backups/<UTC timestamp>/
```

Backups contain SQLite and, unless excluded, the evidence tree. Protect backups as sensitive audit data.

## Restore

Stop services first:

```bash
sudo systemctl stop wirescope-api wirescope-worker

sudo -u wirescope env WIRESCOPE_DATA_DIR=/var/lib/wirescope \
  /opt/wirescope/.venv/bin/python -m appliance restore \
  /var/lib/wirescope/backups/TIMESTAMP

sudo systemctl start wirescope-worker wirescope-api
```

Then verify:

```bash
curl -sS http://127.0.0.1:8000/api/ready
```

## Upgrade

Back up first:

```bash
sudo -u wirescope env WIRESCOPE_DATA_DIR=/var/lib/wirescope \
  /opt/wirescope/.venv/bin/python -m appliance backup
```

Upgrade:

```bash
cd /opt/wirescope
git pull
sudo ./packaging/upgrade.sh --project-root /opt/wirescope
```

Verify:

```bash
curl -sS http://127.0.0.1:8000/api/ready
systemctl status wirescope-api wirescope-worker
```

Optional protocol tools missing from distro repositories may be skipped with warnings. Nikto and Nuclei are not installed by default.

## Rollback

1. Stop API/worker.
2. Restore the pre-upgrade backup.
3. Check out the previous known-good revision.
4. Reinstall the checkout into `.venv`.
5. Start worker, then API.
6. Verify readiness and login.

Do not use `alembic downgrade` as a universal rollback mechanism unless that specific migration path has been tested.

## Disk usage

Check:

```bash
du -sh /var/lib/wirescope
find /var/lib/wirescope/evidence -type f | wc -l
df -h /var/lib/wirescope
```

Listen/record PCAPs can consume storage quickly if operators retain many captures.

Full policy-driven cleanup of registered audits/evidence is not implemented yet, so do not manually delete files from the evidence tree without understanding the matching database references.

## Dependency inventory

```bash
/opt/wirescope/.venv/bin/python -m appliance inventory
```

or read:

```text
packaging/inventory/DEPENDENCIES.md
```

## Before asking for diagnostics

Useful output:

```bash
/opt/wirescope/.venv/bin/python -m appliance detect
/opt/wirescope/.venv/bin/python -m appliance verify --project-root /opt/wirescope
curl -sS http://127.0.0.1:8000/api/health
curl -sS http://127.0.0.1:8000/api/ready
systemctl status wirescope-api wirescope-worker --no-pager
journalctl -u wirescope-api -u wirescope-worker --since -10m --no-pager
```

Do not attach raw PCAPs, the live database, password files, or the complete evidence tree unless they are specifically required. They may contain sensitive network data.
