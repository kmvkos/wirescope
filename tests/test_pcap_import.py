from __future__ import annotations

import struct

from sqlalchemy import func, select

from jobs.worker import JobWorker, build_registry
from persistence.models import ArtifactModel
from tests.helpers import http_request


def _classic_pcap() -> bytes:
    # little-endian PCAP global header, no packets required for import validity
    return (
        b"\xd4\xc3\xb2\xa1"
        + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1)
    )


def _pcapng() -> bytes:
    return (
        b"\x0a\x0d\x0d\x0a"
        + struct.pack("<I", 28)
        + b"\x4d\x3c\x2b\x1a"
        + struct.pack("<HH", 1, 0)
        + b"\xff" * 8
        + struct.pack("<I", 28)
    )


def _run_worker(api_context):
    app, jobs, evidence, _environment = api_context
    worker = JobWorker(
        worker_id="pcap-import-test",
        service=jobs,
        registry=build_registry(),
        evidence_store=evidence,
        settings=app.state.settings,
    )
    assert worker.run_once() is True


def _upload(app, payload: bytes, filename: str = "capture.pcap", *, role="auditor"):
    return http_request(
        app,
        "POST",
        "/api/v1/captures/import",
        as_role=role,
        content=payload,
        headers={
            "Content-Type": "application/octet-stream",
            "X-WireScope-Filename": filename,
        },
    )


def test_import_classic_pcap_becomes_normal_capture_source(api_context):
    app, jobs, evidence, _environment = api_context
    payload = _classic_pcap()

    accepted = _upload(app, payload, "external test.pcap")
    assert accepted.status_code == 202, accepted.text
    ids = accepted.json()
    queued = jobs.get_job(ids["job_id"])
    audit = jobs.get_audit(ids["audit_id"])
    assert queued.type == "packet_capture"
    assert queued.parameters["source_origin"] == "imported"
    assert queued.parameters["network_io"] is False
    assert queued.parameters["active_scope_authorized"] is False
    assert audit.profile == "packet_capture"
    assert audit.interface is None
    assert audit.scope["active_scope_authorized"] is False

    staging = evidence.root / "_imports" / f"pcap.tmp-{queued.parameters['staging_token']}"
    assert staging.is_file()

    _run_worker(api_context)
    completed = jobs.get_job(ids["job_id"])
    assert completed.status.value == "completed"
    assert not staging.exists()

    session = http_request(app, "GET", f"/api/v1/captures/{completed.id}")
    assert session.status_code == 200
    item = session.json()
    assert item["source_origin"] == "imported"
    assert item["original_filename"] == "external test.pcap"
    assert item["capture_format"] == "pcap"
    assert item["interface"] == ""
    assert item["pcap_bytes"] == len(payload)
    assert item["pcap_url"]

    result = evidence.read_json(jobs.artifact(completed.result_reference))
    assert result["source_origin"] == "imported"
    assert result["network_io_performed"] is False
    assert result["active_scope_authorized"] is False
    raw = jobs.artifact(result["pcap_artifact_id"])
    assert raw.artifact_type == "packet_capture"
    assert evidence.read_bytes(raw) == payload

    analysis = http_request(app, "POST", f"/api/v1/captures/{completed.id}/analyze")
    assert analysis.status_code == 202
    traffic_job = jobs.get_job(analysis.json()["job_id"])
    assert traffic_job.type == "traffic_analysis"
    assert traffic_job.parameters["source_capture_job_id"] == completed.id
    assert traffic_job.parameters["pcap_artifact_id"] == raw.id


def test_import_pcapng_preserves_format_filename_and_download(api_context):
    app, jobs, evidence, _environment = api_context
    payload = _pcapng()
    accepted = _upload(app, payload, "%2E%2E%2F%2E%2E%2Foffice%20capture.pcapng")
    assert accepted.status_code == 202, accepted.text
    _run_worker(api_context)

    job = jobs.get_job(accepted.json()["job_id"])
    session = http_request(app, "GET", f"/api/v1/captures/{job.id}").json()
    assert session["source_origin"] == "imported"
    assert session["capture_format"] == "pcapng"
    assert session["original_filename"] == "office capture.pcapng"

    result = evidence.read_json(jobs.artifact(job.result_reference))
    raw = jobs.artifact(result["pcap_artifact_id"])
    assert raw.content_type == "application/x-pcapng"
    assert raw.relative_path.endswith(".pcapng")

    download = http_request(app, "GET", f"/api/v1/jobs/{job.id}/pcap")
    assert download.status_code == 200
    assert download.content == payload
    assert download.headers["content-type"].startswith("application/x-pcapng")
    assert ".pcapng" in download.headers["content-disposition"].lower()


def test_import_rejects_invalid_empty_and_viewer_uploads(api_context):
    app, jobs, evidence, _environment = api_context

    viewer = _upload(app, _classic_pcap(), role="viewer")
    assert viewer.status_code == 403

    invalid = _upload(app, b"this is not a capture", "fake.pcap")
    assert invalid.status_code == 422
    assert invalid.json()["detail"]["code"] == "pcap_import_unsupported"

    empty = _upload(app, b"", "empty.pcap")
    assert empty.status_code == 422
    assert empty.json()["detail"]["code"] == "pcap_import_empty"

    assert jobs.list_jobs(limit=100, offset=0, job_type="packet_capture").total == 0
    imports = evidence.root / "_imports"
    assert not imports.exists() or not list(imports.iterdir())


def test_import_size_limit_is_enforced_before_durable_job(api_context, monkeypatch):
    app, jobs, evidence, _environment = api_context
    monkeypatch.setenv("WIRESCOPE_PCAP_IMPORT_MAX_FILESIZE_MB", "1")
    payload = _classic_pcap() + (b"x" * (1024 * 1024))

    response = _upload(app, payload, "too-large.pcap")
    assert response.status_code == 413
    assert response.json()["detail"]["code"] == "pcap_import_too_large"
    assert jobs.list_jobs(limit=100, offset=0, job_type="packet_capture").total == 0
    imports = evidence.root / "_imports"
    assert not imports.exists() or not list(imports.iterdir())


def test_worker_rechecks_staged_checksum_before_registering_raw_artifact(api_context):
    app, jobs, evidence, _environment = api_context
    accepted = _upload(app, _classic_pcap(), "capture.pcap")
    assert accepted.status_code == 202
    job = jobs.get_job(accepted.json()["job_id"])
    staging = evidence.root / "_imports" / f"pcap.tmp-{job.parameters['staging_token']}"
    staging.write_bytes(_pcapng())

    _run_worker(api_context)
    failed = jobs.get_job(job.id)
    assert failed.status.value == "failed"
    assert failed.error.code in {"pcap_import_size_mismatch", "pcap_import_checksum_mismatch"}
    assert not staging.exists()
    with jobs.database.session() as session:
        raw_count = session.scalar(
            select(func.count())
            .select_from(ArtifactModel)
            .where(
                ArtifactModel.audit_id == job.audit_id,
                ArtifactModel.artifact_type == "packet_capture",
            )
        ) or 0
    assert raw_count == 0


def test_import_has_stable_operational_audit_action(api_context):
    app, _jobs, _evidence, _environment = api_context
    accepted = _upload(app, _classic_pcap(), "audit-trail.pcap")
    assert accepted.status_code == 202

    events = http_request(
        app,
        "GET",
        "/api/audit-log",
        params={"action": "capture.pcap_import"},
    )
    assert events.status_code == 200
    assert events.json()["total"] >= 1
    assert events.json()["items"][0]["action"] == "capture.pcap_import"
    assert events.json()["items"][0]["path"] == "/api/captures/import"
