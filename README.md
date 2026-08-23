# WireScope

WireScope is a portable network discovery, diagnostics, and security audit
appliance intended for Raspberry Pi OS on ARM64 and Debian-based development
systems on AMD64.

The current `0.1.0` codebase is an early prototype being stabilized in
milestones. It can inspect the host network environment, capture through
`dumpcap`, and decode one normalized stream for fourteen passive sensors.
Audit sessions, jobs, progress, events, cancellation, and result artifacts are
durable across backend restarts. Active discovery, findings, reporting,
authentication, and appliance deployment are planned work and are not
complete.

## Current components

- `backend/` — FastAPI application and HTTP endpoints.
- `engine/` — environment discovery, passive orchestration, and assessment.
- `jobs/` — durable state service, handler registry, worker, and maintenance.
- `persistence/` — SQLAlchemy schema and Alembic migrations.
- `storage/` — atomic evidence files and metadata integration.
- `providers/` — controlled external-tool and packet-capture boundaries.
- `parsers/` — single-pass tshark EK decoding.
- `sensors/` — passive protocol sensors.
- `frontend/` — minimal environment dashboard.
- `config/` — centralized application paths and runtime settings.
- `tests/` — tests that do not require live packet capture.

See [Architecture](docs/ARCHITECTURE.md) for current boundaries and
[Implementation plan](docs/IMPLEMENTATION_PLAN.md) for the milestone roadmap.
Operational details are in [Development](docs/DEVELOPMENT.md),
[Installation](docs/INSTALLATION.md), and
[Security model](docs/SECURITY_MODEL.md).

## Development setup

WireScope requires Python 3.11 or newer. The existing development environment
uses Python 3.13.

```bash
python3 -m venv .venv
.venv/bin/pip install --upgrade pip
.venv/bin/pip install -e '.[dev]'
```

Required host tools for the current prototype:

- `ip` from `iproute2` for environment discovery;
- `dumpcap` for bounded capture;
- `tshark` for pcap decoding;
- packet capture permissions configured separately from the backend process.

Create or upgrade the local database:

```bash
WIRESCOPE_DATA_DIR="$PWD/data" .venv/bin/alembic upgrade head
```

Run the API and worker as separate development processes:

```bash
.venv/bin/uvicorn backend.app:app --host 127.0.0.1 --port 8000
.venv/bin/python -m jobs.worker
```

Start passive work through the job-oriented API:

```bash
curl http://127.0.0.1:8000/api/interfaces
curl -X POST http://127.0.0.1:8000/api/audits \
  -H 'content-type: application/json' \
  -d '{"profile":"passive","interface":"eth0","scope":{}}'
curl -X POST http://127.0.0.1:8000/api/audits/AUDIT_ID/passive \
  -H 'content-type: application/json' \
  -d '{"duration_seconds":30}'
```

Run tests:

```bash
.venv/bin/pytest
.venv/bin/python -m compileall -q backend config engine jobs parsers \
  persistence providers sensors storage tests
.venv/bin/pip check
```

Do not run the WireScope backend as root. Give only `/usr/bin/dumpcap`
`CAP_NET_RAW` and `CAP_NET_ADMIN`, and grant the service user execute access
through the `wireshark` group. See
[Architecture](docs/ARCHITECTURE.md#privilege-model).

## Runtime configuration

- `WIRESCOPE_ROOT` — application root; defaults to the source checkout.
- `WIRESCOPE_FRONTEND_DIR` — static frontend directory.
- `WIRESCOPE_DATA_DIR` — runtime data directory.
- `WIRESCOPE_DATABASE_PATH` — SQLite database path; defaults below the data
  directory.
- `WIRESCOPE_EVIDENCE_DIR` — controlled artifact root.
- `WIRESCOPE_RUNTIME_DIR` — temporary runtime state root.
- `WIRESCOPE_CAPTURE_DIR` — parent directory for temporary bounded captures.
- `WIRESCOPE_ALLOWED_INTERFACES` — comma-separated interface allowlist; empty
  means any interface that passes policy.
- `WIRESCOPE_ALLOW_LOOPBACK` — allow loopback capture; defaults to false.
- `WIRESCOPE_REQUIRE_INTERFACE_UP` — require an up link; defaults to true.
- `WIRESCOPE_PASSIVE_DURATION_MIN`, `_MAX`, `_DEFAULT` — passive duration
  policy.
- `WIRESCOPE_CAPTURE_MAX_PACKETS` and `_MAX_FILESIZE_KB` — independent capture
  limits.
- `WIRESCOPE_CAPTURE_SNAPLEN` — packet snapshot length; defaults to 65,535.
- `WIRESCOPE_CAPTURE_PROMISCUOUS` — opt in to promiscuous mode; defaults to
  false.
- `WIRESCOPE_PASSIVE_RETAIN_CAPTURE` — retain successful PCAP as audit
  evidence; defaults to false.
- `WIRESCOPE_WORKER_CONCURRENCY` — bounded worker threads; defaults to one.
- `WIRESCOPE_MAX_PACKET_CAPTURES` — global concurrent capture limit; defaults
  to one.
- `WIRESCOPE_SQLITE_BUSY_TIMEOUT_MS` — SQLite lock wait limit.
- `WIRESCOPE_SQLITE_SYNCHRONOUS` — `FULL` by default; `NORMAL` is an explicit
  performance/durability trade-off.
- `WIRESCOPE_WORKER_STALE_AFTER_SECONDS` — worker readiness/lease timeout.
- `WIRESCOPE_JOB_EVENT_RETENTION_DAYS` — explicit terminal-event retention
  policy used by maintenance.
- `WIRESCOPE_TEMP_FILE_MAX_AGE_SECONDS` — stale runtime cleanup threshold.
- `WIRESCOPE_DUMPCAP_BINARY` and `WIRESCOPE_TSHARK_BINARY` — tool paths or
  names.
- `WIRESCOPE_DOCS_ENABLED` — enables FastAPI OpenAPI, Swagger, and ReDoc
  routes; defaults to true for development.
