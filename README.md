# WireScope

WireScope is a portable network discovery, diagnostics, and security audit
appliance intended for Raspberry Pi OS on ARM64 and Debian-based development
systems on AMD64.

The current `0.1.0` codebase is an early prototype being stabilized in
milestones. It can inspect the host network environment, capture through
`dumpcap`, and decode one normalized stream for fourteen passive sensors.
Active discovery,
durable jobs, findings, reporting, authentication, and appliance deployment
are planned work and are not complete.

## Current components

- `backend/` — FastAPI application and HTTP endpoints.
- `engine/` — environment discovery, passive orchestration, assessment, and
  prototype jobs.
- `providers/` — controlled external-tool and packet-capture boundaries.
- `parsers/` — single-pass tshark EK decoding.
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
- `dumpcap` for bounded capture;
- `tshark` for pcap decoding;
- packet capture permissions configured separately from the backend process.

Run the API from the project root:

```bash
.venv/bin/uvicorn backend.app:app --host 127.0.0.1 --port 8000
```

Start passive work through the job-oriented API:

```bash
curl http://127.0.0.1:8000/api/interfaces
curl -X POST http://127.0.0.1:8000/api/passive/start \
  -H 'content-type: application/json' \
  -d '{"interface":"eth0","duration_seconds":30}'
```

Run tests:

```bash
.venv/bin/pytest
```

Do not run the WireScope backend as root. Give only `/usr/bin/dumpcap`
`CAP_NET_RAW` and `CAP_NET_ADMIN`, and grant the service user execute access
through the `wireshark` group. See
[Architecture](docs/ARCHITECTURE.md#privilege-model).

## Runtime configuration

- `WIRESCOPE_ROOT` — application root; defaults to the source checkout.
- `WIRESCOPE_FRONTEND_DIR` — static frontend directory.
- `WIRESCOPE_DATA_DIR` — runtime data directory.
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
- `WIRESCOPE_DUMPCAP_BINARY` and `WIRESCOPE_TSHARK_BINARY` — tool paths or
  names.
- `WIRESCOPE_DOCS_ENABLED` — enables FastAPI OpenAPI, Swagger, and ReDoc
  routes; defaults to true for development.
