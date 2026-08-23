# WireScope

WireScope is a portable network discovery, diagnostics, and security audit
appliance intended for Raspberry Pi OS on ARM64 and Debian-based development
systems on AMD64.

The current `0.1.0` codebase is an early prototype being stabilized in
milestones. It can inspect the host network environment and perform passive
packet capture and protocol observations through `tshark`. Active discovery,
durable jobs, findings, reporting, authentication, and appliance deployment
are planned work and are not complete.

## Current components

- `backend/` — FastAPI application and HTTP endpoints.
- `engine/` — environment discovery, passive orchestration, assessment, and
  prototype jobs.
- `sensors/` — passive protocol sensors.
- `frontend/` — minimal environment dashboard.
- `config/` — centralized application paths and runtime settings.
- `tests/` — tests that do not require live packet capture.

See [Architecture](docs/ARCHITECTURE.md) for current boundaries and
[Implementation plan](docs/IMPLEMENTATION_PLAN.md) for the milestone roadmap.

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
- `tshark` for pcap parsing;
- packet capture permissions configured separately from the backend process.

Run the API from the project root:

```bash
.venv/bin/uvicorn backend.app:app --host 127.0.0.1 --port 8000
```

Run tests:

```bash
.venv/bin/pytest
```

Do not run the WireScope backend as root. The production capture privilege
model will use an unprivileged backend and a narrowly privileged `dumpcap`
provider.

## Runtime configuration

- `WIRESCOPE_ROOT` — application root; defaults to the source checkout.
- `WIRESCOPE_FRONTEND_DIR` — static frontend directory.
- `WIRESCOPE_DATA_DIR` — runtime data directory.
- `WIRESCOPE_DOCS_ENABLED` — enables FastAPI OpenAPI, Swagger, and ReDoc
  routes; defaults to true for development.
