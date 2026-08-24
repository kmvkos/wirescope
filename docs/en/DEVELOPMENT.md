# Developing WireScope

[Русский](../DEVELOPMENT.md) · **English**

This is the short working guide for local development. Production deployment is documented separately in [INSTALLATION.md](INSTALLATION.md).

## Requirements

- Python 3.11+;
- Linux;
- `dumpcap` and `tshark` for real passive capture;
- Nmap for active discovery;
- protocol-specific tools only when exercising their modules.

Most tests use fixtures and do not require scanners to be installed.

## Create the environment

```bash
python3 -m venv .venv
.venv/bin/pip install --upgrade pip
.venv/bin/pip install -e '.[dev]'
.venv/bin/alembic upgrade head
```

Production tables are created by Alembic migrations. `Base.metadata.create_all()` is not the production database bootstrap path.

## Run locally

API and worker are separate processes.

Terminal 1:

```bash
.venv/bin/uvicorn backend.app:app \
  --host 127.0.0.1 \
  --port 8000
```

Terminal 2:

```bash
.venv/bin/python -m jobs.worker
```

Open:

```text
http://127.0.0.1:8000/
```

The API creates durable jobs but does not execute them. The worker handles startup recovery, claiming, handlers, progress, and cancellation.

Stopping the API does not remove jobs from SQLite and does not stop a separately running worker.

## Worker model

Only one supervisor process should run at a time. Internal concurrency comes from the bounded worker thread pool configured in settings.

Do not launch several `python -m jobs.worker` processes as a shortcut for more throughput; that breaks the intended appliance process model and supervisor lease.

## Job handler contract

Long-running workflows are implemented as handlers registered in `HandlerRegistry`.

A handler receives controlled runtime context including:

- immutable audit/job data;
- settings;
- cancellation token;
- evidence store;
- progress callback;
- required domain services/providers.

Handlers should not return large raw documents into a job row. Large results belong in `EvidenceStore`; the job keeps a compact result reference and summary.

Emit progress at meaningful stages, not once per packet, host, or stdout line.

## External tools

Common rules:

- argv arrays;
- no `shell=True`;
- timeout support;
- process-group cancellation;
- bounded output;
- structured error categories;
- raw output stored as evidence when needed.

User input must not become unrestricted scanner flags.

## Database schema changes

1. Change SQLAlchemy models in `persistence/models.py`.
2. Generate a revision:

```bash
.venv/bin/alembic revision \
  --autogenerate \
  -m 'describe change'
```

3. Review the generated migration manually.
4. Check:
   - constraints;
   - indexes;
   - SQLite compatibility;
   - upgrade order;
   - downgrade behavior if a downgrade is actually claimed to work.
5. Test upgrade on both a fresh database and the previous released revision.

Do not keep a SQLAlchemy transaction open while a scanner, capture, or parser performs long-running work.

## Tests

Normal run:

```bash
.venv/bin/pytest
```

The default marker expression in `pyproject.toml` excludes:

```text
network
live_pi
```

So the default suite must not scan the live network.

### Main markers

- `network` — opt-in live-network tests;
- `integration` — broader pipeline tests, not necessarily live network;
- `browser` — optional Playwright/Chromium tests;
- `live_pi` — Raspberry Pi hardware-specific checks.

Live-network tests require an explicitly configured scope such as `WIRESCOPE_LIVE_SCOPE` and must be selected with `-m network`.

Findings and reporting tests do not need network access at all.

## Import and syntax checks

```bash
.venv/bin/python -m compileall -q \
  backend config engine inventory jobs parsers persistence \
  protocol_audits findings reports providers sensors storage \
  auth appliance tests
```

Dependency consistency:

```bash
.venv/bin/pip check
```

## Benchmarks

The repository includes lightweight persistence/inventory benchmarks:

```bash
.venv/bin/python -m scripts.benchmark_persistence
.venv/bin/python -m scripts.benchmark_inventory
```

Treat these as regression indicators rather than universal performance guarantees.

## Development user bootstrap

For development only, the first users may be created from environment variables when the `users` table is empty:

```bash
export WIRESCOPE_BOOTSTRAP_AUDITOR_USERNAME=auditor
export WIRESCOPE_BOOTSTRAP_AUDITOR_PASSWORD='choose-a-long-password'
export WIRESCOPE_BOOTSTRAP_VIEWER_USERNAME=viewer
export WIRESCOPE_BOOTSTRAP_VIEWER_PASSWORD='choose-a-long-password'
```

Accounts are bootstrapped once.

Do not place these secrets in production systemd units. The appliance installer uses the password-file/bootstrap flow documented in [INSTALLATION.md](INSTALLATION.md).

## Frontend

There is no separate frontend build system.

Files:

```text
frontend/index.html
frontend/app.js
frontend/i18n.js
frontend/style.css
```

UI changes should be checked at least for:

- 480×320 kiosk layout;
- desktop width ≥ 900px;
- auditor/viewer role behavior;
- reload during a running job;
- error/partial/cancelled states.

Optional browser tests skip when Chromium/Playwright is unavailable.

## Passive fixtures

Parser and sensor tests should use stored PCAP/normalized fixtures rather than requiring live capture.

A new sensor/provider should have fixtures for at least:

- normal success;
- absence of matching protocol evidence;
- malformed input;
- provider/parser failure where applicable.

A parser failure should not be asserted as `detected=false`; the expected contract is `partial` or `error`.

## Protocol modules

A new module defines:

- predicates;
- tool;
- safety class;
- argv builder;
- parser;
- observation kinds;
- timeout;
- fixtures.

Module parsers do not write directly to SQLite. Persistence belongs to orchestration/store layers.

## Finding rules

Finding rules operate only on normalized data and evidence references.

Do not add raw scanner stdout parsing to a finding rule. If a rule needs a field that does not exist, first add that field to the normalized observation contract.

## Documentation changes

When behavior changes, update the document for the layer that actually changed:

- scope/Nmap/protocol modules → `SCANNING_MODEL.md`;
- privilege/auth/evidence → `SECURITY_MODEL.md`;
- persistence/process boundaries → `ARCHITECTURE.md`;
- finding semantics → `FINDINGS_MODEL.md`;
- report schema → `REPORTING_MODEL.md`;
- UI workflow → `GUI_MODEL.md`;
- installer/systemd → `INSTALLATION.md` and `RUNBOOK.md`.

Do not use `IMPLEMENTATION_PLAN.md` as the only place that documents already-existing runtime behavior.
