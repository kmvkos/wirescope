# WireScope development

## Setup

```bash
python3 -m venv .venv
.venv/bin/pip install --upgrade pip
.venv/bin/pip install -e '.[dev]'
.venv/bin/alembic upgrade head
```

The application never creates production tables with
`Base.metadata.create_all()`. Apply Alembic migrations before starting either
process.

## Development process model

Use two terminals:

```bash
.venv/bin/uvicorn backend.app:app --host 127.0.0.1 --port 8000
.venv/bin/python -m jobs.worker
```

The API only enqueues durable jobs. The worker performs startup recovery,
maintenance, claiming, execution, progress, and cancellation. Stopping the API
does not remove job metadata or stop a separately running worker.

Only one worker supervisor process is allowed. Concurrency is supplied by its
bounded worker thread pool.

## Schema changes

1. Update `persistence/models.py`.
2. Generate a revision against an empty or migrated development database:

   ```bash
   .venv/bin/alembic revision --autogenerate -m 'describe change'
   ```

3. Review generated constraints, indexes, downgrade order, and SQLite
   compatibility.
4. Test both `alembic upgrade head` on an empty database and application use.

Do not hold a SQLAlchemy session or transaction while a scanner, capture, or
parser runs.

## Verification

```bash
.venv/bin/pytest
.venv/bin/python -m compileall -q backend config engine inventory jobs \
  parsers persistence protocol_audits findings reports providers sensors \
  storage auth appliance tests
.venv/bin/pip check
.venv/bin/python -m scripts.benchmark_persistence
.venv/bin/python -m scripts.benchmark_inventory
```

Tests use a temporary migrated SQLite database and temporary evidence root.
The default `pytest` invocation excludes `@pytest.mark.network`. Passive,
active, protocol-audit, findings, reporting, and GUI tests use fixtures and
do not scan the live network. Live Nmap or protocol probes require an
explicit `WIRESCOPE_LIVE_SCOPE` and `pytest -m network`. Findings evaluation
and report generation never contact a network. Optional Playwright kiosk
tests (`@pytest.mark.browser`) skip when Playwright or Chromium is not
installed. The appliance kiosk extra does the same: missing Chromium is a
skip, not a CI failure. The system kiosk is a boot unit on tty1 (Cage or
xinit), not a desktop session.

Create the first local operators only when the user table is empty:

```bash
export WIRESCOPE_BOOTSTRAP_AUDITOR_USERNAME=auditor
export WIRESCOPE_BOOTSTRAP_AUDITOR_PASSWORD='choose-a-long-password'
export WIRESCOPE_BOOTSTRAP_VIEWER_USERNAME=viewer
export WIRESCOPE_BOOTSTRAP_VIEWER_PASSWORD='choose-a-long-password'
```

Restarting the API process bootstraps those accounts once. There is no
default password. The kiosk/UI is a browser client; stopping it does not
cancel worker jobs.

## Durable handler contract

Register handlers in `HandlerRegistry`. A handler receives:

- immutable audit/job records;
- settings;
- a cooperative cancellation token;
- an atomic evidence store;
- a progress callback.

Handlers return only a compact result reference and audit summary. Large
documents belong in the evidence store. Emit progress only at meaningful
stages; never insert one event per packet.
