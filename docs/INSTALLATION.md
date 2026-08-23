# WireScope installation foundation

Milestone 2 prepares the runtime boundaries but does not yet ship final
systemd or Raspberry Pi installer files.

## Production paths

Keep mutable data outside the application checkout. A production deployment
should set, for example:

```bash
WIRESCOPE_DATA_DIR=/var/lib/wirescope
WIRESCOPE_DATABASE_PATH=/var/lib/wirescope/wirescope.db
WIRESCOPE_EVIDENCE_DIR=/var/lib/wirescope/evidence
WIRESCOPE_RUNTIME_DIR=/var/lib/wirescope/runtime
WIRESCOPE_CAPTURE_DIR=/var/lib/wirescope/runtime/captures
```

These are deployment examples, not hardcoded application paths. Directories
must be owned by the unprivileged `wirescope` service account and not be
world-readable.

Use a local Linux filesystem suitable for SQLite locking. Do not place the
database on NFS or removable storage with unsafe write caching.

## Database initialization

Apply migrations before starting services:

```bash
sudo -u wirescope \
  env WIRESCOPE_DATA_DIR=/var/lib/wirescope \
  /opt/wirescope/.venv/bin/alembic \
  -c /opt/wirescope/alembic.ini upgrade head
```

Readiness remains false when the database revision does not match Alembic
head.

## Capture privilege

The API and worker must not run as root. `dumpcap` alone receives
`CAP_NET_RAW` and `CAP_NET_ADMIN`, and the service account receives execute
access through the `wireshark` group. Verify ownership, mode, capabilities,
and a bounded unprivileged capture before enabling the worker.

## Process order

The intended appliance units are:

1. migration/bootstrap operation;
2. `wirescope-worker`;
3. `wirescope-api`;
4. kiosk/UI later.

The worker and API share SQLite and evidence roots but have independent
lifetimes. The worker performs restart recovery before accepting queued work.

## Power loss

SQLite runs in WAL mode with foreign keys, short transactions, busy timeout,
and `synchronous=FULL` by default. Evidence uses temporary files and atomic
rename.
Startup removes abandoned temporary files, stale managed capture directories,
orphan final files, and abandoned locks.

This reduces damage from sudden power loss but is not a backup strategy.
Automated SQLite backup/export and corruption-recovery tooling remain open
appliance work.
