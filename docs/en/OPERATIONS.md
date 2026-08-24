# Operating WireScope

[Русский](../OPERATIONS.md) · **English**

This document covers the life of an installed WireScope appliance: health checks, restart behavior, stage retry, retention, backup, restore, and upgrade.

## Diagnostics

An auditor normally does not need shell access for the first health check. Open **Overview → Operations** or call:

```text
GET /api/v1/diagnostics
```

The snapshot includes:

- SQLite accessibility;
- Alembic revision;
- `PRAGMA quick_check`;
- worker heartbeat;
- core `dumpcap`/`tshark` capabilities;
- free disk space;
- evidence-store usage;
- listener/TLS/proxy state;
- retention candidates;
- recent operational events.

A safe JSON snapshot is available from:

```text
GET /api/v1/diagnostics/export
```

It intentionally excludes passwords, session cookies/tokens, and provider raw stdout.

## Restart behavior

Jobs are durable and live in SQLite rather than browser memory.

If API/worker restarts during execution:

```text
running → interrupted
```

Queued jobs remain queued and stale worker resource locks are released.

WireScope does not try to reconstruct the internal state of a dead Nmap or dumpcap process. An operator may explicitly retry an interrupted, failed, or cancelled stage:

```text
POST /api/v1/jobs/{job_id}/retry
```

A **new** queued job is created with the same parameters. The historical job remains immutable.

## Retention

WireScope separates normalized audit results from large raw artifacts.

Defaults:

| Type | Retention |
| --- | ---: |
| temporary | 24 hours |
| debug | 7 days |
| packet capture | 30 days |
| Nmap XML | 90 days |
| protocol raw output | 90 days |
| inventory/findings/reports | no automatic deletion |

Configuration:

```text
WIRESCOPE_TEMP_ARTIFACT_RETENTION_HOURS
WIRESCOPE_DEBUG_RETENTION_DAYS
WIRESCOPE_PCAP_RETENTION_DAYS
WIRESCOPE_RAW_EVIDENCE_RETENTION_DAYS
```

### Why raw data is not deleted automatically

The first stable release uses a conservative policy: aged PCAP/Nmap/protocol evidence is shown as a cleanup candidate but is deleted only after explicit auditor confirmation. This avoids unexpected evidence loss.

Preview:

```json
POST /api/v1/maintenance/cleanup
{"confirm": false, "include_raw": true}
```

Apply:

```json
POST /api/v1/maintenance/cleanup
{"confirm": true, "include_raw": true}
```

Safe housekeeping for stale temporary/orphan files remains separate and does not erase normalized audit history.

## Operational audit log

The operational log is distinct from job events. Job events describe one durable job; the operational log answers “who changed or triggered what on the appliance”.

```text
GET /api/v1/audit-log
```

Records include:

- UTC timestamp;
- actor;
- role;
- action;
- HTTP method/path;
- status code;
- client IP;
- audit id when derivable from the URL.

It does not store:

- passwords;
- request bodies;
- session cookies/tokens;
- provider stdout/stderr.

## Backup

Full local SQLite + evidence backup:

```bash
cd /opt/wirescope
sudo ./.venv/bin/python -m appliance backup
```

By default the archive is written under the data directory in `backups/`.

Without evidence:

```bash
sudo ./.venv/bin/python -m appliance backup --no-evidence
```

SQLite is copied through the SQLite backup API rather than by copying a live WAL database file.

## Restore

Restore replaces the working database/evidence. Stop API/worker first:

```bash
sudo systemctl stop wirescope-api wirescope-worker
sudo /opt/wirescope/.venv/bin/python -m appliance restore /path/to/backup
sudo systemctl start wirescope-worker wirescope-api
```

The backup database must pass `PRAGMA integrity_check` before replacement.

After restore:

```bash
curl -sS http://127.0.0.1:8000/api/v1/health
curl -sS http://127.0.0.1:8000/api/v1/ready
```

and check Diagnostics in the GUI.

## Upgrade

Normal checkout-based upgrade:

```bash
cd /opt/wirescope
git pull --ff-only
sudo ./packaging/upgrade.sh --project-root /opt/wirescope
```

Upgrade should:

- update the venv/dependencies when needed;
- apply migrations;
- preserve `/var/lib/wirescope`;
- preserve existing configuration unless explicitly overridden;
- restart services;
- keep `0.0.0.0:8000` as the normal listener unless the installation was explicitly configured otherwise.

Take a backup before significant upgrades.

## First troubleshooting steps

1. open **Operations**;
2. check Database / Worker / Core tools / Free space;
3. download the diagnostics JSON;
4. inspect failed/interrupted jobs;
5. retry only the affected stage when the error is understood and transient;
6. use SSH/journald only when needed.

System logs:

```bash
journalctl -u wirescope-api -u wirescope-worker --since today
```

## Release readiness

The formal boundary between a development build and the first stable release candidate is defined in [RELEASE_READINESS.md](RELEASE_READINESS.md).
