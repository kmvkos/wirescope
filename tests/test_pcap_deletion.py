import pytest

from jobs.models import RetentionClass
from tests.helpers import http_request
from traffic_analysis.service import (
    TrafficAnalysisJobService,
    TrafficAnalysisPcapUnavailable,
)


def _completed_capture(api_context):
    _app, jobs, evidence, _environment = api_context
    audit = jobs.create_audit(profile="packet_capture", interface="eth0")
    job = jobs.create_job(
        audit_id=audit.id,
        job_type="packet_capture",
        target="eth0",
        parameters={
            "interface": "eth0",
            "duration_seconds": 5,
            "max_filesize_kb": 1024,
            "filter": None,
            "promiscuous": True,
        },
        resource_key="interface:eth0",
        resource_group="packet_capture",
        resource_limit=1,
    )
    claimed = jobs.claim_next("pcap-delete-test")
    assert claimed is not None and claimed.id == job.id

    # Real PacketCaptureHandler stores the raw capture under AUDIT retention.
    pcap = evidence.put_bytes(
        audit_id=audit.id,
        job_id=job.id,
        artifact_type="packet_capture",
        payload=b"pcap-test-payload",
        content_type="application/vnd.tcpdump.pcap",
        extension=".pcap",
        retention_class=RetentionClass.AUDIT,
    )
    capture_result = evidence.put_json(
        audit_id=audit.id,
        job_id=job.id,
        artifact_type="capture_result",
        document={
            "schema": "packet-capture-result",
            "schema_version": 1,
            "pcap_artifact_id": pcap.id,
        },
        retention_class=RetentionClass.AUDIT,
        schema_name="packet-capture-result",
        schema_version=1,
    )
    downstream = evidence.put_json(
        audit_id=audit.id,
        job_id=job.id,
        artifact_type="traffic_analysis_result",
        document={"schema": "traffic-analysis", "schema_version": 1},
        retention_class=RetentionClass.AUDIT,
        schema_name="traffic-analysis",
        schema_version=1,
    )
    jobs.complete_job(
        job.id,
        result_reference=capture_result.id,
        summary={
            "frame_count": 4,
            "byte_count": len(b"pcap-test-payload"),
            "pcap_bytes": len(b"pcap-test-payload"),
            "pcap_artifact_id": pcap.id,
        },
    )
    return audit, job, pcap, capture_result, downstream


def _traffic_jobs(jobs, audit_id):
    return [
        row
        for row in jobs.list_jobs(limit=100, offset=0, audit_id=audit_id).items
        if row.type == "traffic_analysis"
    ]


def test_delete_pcap_preserves_capture_history_and_normalized_results(api_context):
    app, jobs, evidence, _environment = api_context
    _audit, job, pcap, capture_result, downstream = _completed_capture(api_context)
    raw_path = evidence.path_for(pcap)
    assert raw_path.is_file()

    before = http_request(app, "GET", f"/api/captures/{job.id}")
    assert before.status_code == 200
    assert before.json()["pcap_url"]

    deleted = http_request(app, "DELETE", f"/api/captures/{job.id}/pcap")
    assert deleted.status_code == 200
    payload = deleted.json()
    assert payload["deleted"] is True
    assert payload["artifact_count"] == 1
    assert payload["file_cleanup_pending"] == 0
    assert not raw_path.exists()

    # The raw packet artifact is gone, but immutable capture metadata and an
    # already-produced normalized analysis artifact remain available.
    assert jobs.artifact(capture_result.id).artifact_type == "capture_result"
    assert jobs.artifact(downstream.id).artifact_type == "traffic_analysis_result"

    after = http_request(app, "GET", f"/api/captures/{job.id}")
    assert after.status_code == 200
    assert after.json()["pcap_url"] is None
    assert after.json()["result_available"] is True

    download = http_request(app, "GET", f"/api/jobs/{job.id}/pcap")
    assert download.status_code == 410
    assert download.json()["detail"]["code"] == "pcap_unavailable"

    analyze = http_request(app, "POST", f"/api/captures/{job.id}/analyze")
    assert analyze.status_code == 409
    assert analyze.json()["detail"]["code"] == "pcap_unavailable"
    assert _traffic_jobs(jobs, job.audit_id) == []

    # Even if an API caller had already read the old artifact id before DELETE
    # committed, the durable enqueue service must re-check it while holding its
    # IMMEDIATE transaction and refuse to create a stale analysis job.
    with pytest.raises(TrafficAnalysisPcapUnavailable):
        TrafficAnalysisJobService(jobs.database).enqueue(
            audit_id=job.audit_id,
            source_capture_job_id=job.id,
            pcap_artifact_id=pcap.id,
        )
    assert _traffic_jobs(jobs, job.audit_id) == []


def test_delete_pcap_is_idempotent_and_viewer_cannot_delete(api_context):
    app, _jobs, _evidence, _environment = api_context
    _audit, job, _pcap, _capture_result, _downstream = _completed_capture(api_context)

    forbidden = http_request(
        app,
        "DELETE",
        f"/api/captures/{job.id}/pcap",
        as_role="viewer",
    )
    assert forbidden.status_code == 403

    first = http_request(app, "DELETE", f"/api/captures/{job.id}/pcap")
    second = http_request(app, "DELETE", f"/api/captures/{job.id}/pcap")
    assert first.status_code == 200
    assert second.status_code == 200
    assert second.json()["deleted"] is False
    assert second.json()["already_absent"] is True


def test_delete_pcap_rejects_active_capture_audit_job(api_context):
    app, jobs, _evidence, _environment = api_context
    audit = jobs.create_audit(profile="packet_capture", interface="eth0")
    job = jobs.create_job(
        audit_id=audit.id,
        job_type="packet_capture",
        target="eth0",
        parameters={"interface": "eth0"},
        resource_key="interface:eth0",
        resource_group="packet_capture",
        resource_limit=1,
    )

    response = http_request(app, "DELETE", f"/api/captures/{job.id}/pcap")
    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "pcap_delete_busy"


def test_delete_pcap_rejects_queued_traffic_analysis(api_context):
    app, jobs, evidence, _environment = api_context
    _audit, job, pcap, _capture_result, _downstream = _completed_capture(api_context)
    raw_path = evidence.path_for(pcap)

    accepted = http_request(app, "POST", f"/api/captures/{job.id}/analyze")
    assert accepted.status_code == 202
    traffic_jobs = _traffic_jobs(jobs, job.audit_id)
    assert len(traffic_jobs) == 1
    assert traffic_jobs[0].status.value == "queued"

    blocked = http_request(app, "DELETE", f"/api/captures/{job.id}/pcap")
    assert blocked.status_code == 409
    assert blocked.json()["detail"]["code"] == "pcap_delete_busy"
    assert raw_path.is_file()
    session = http_request(app, "GET", f"/api/captures/{job.id}")
    assert session.status_code == 200
    assert session.json()["pcap_url"]


def test_capture_listing_does_not_advertise_missing_raw_file(api_context):
    app, jobs, evidence, _environment = api_context
    _audit, job, pcap, _capture_result, _downstream = _completed_capture(api_context)
    evidence.path_for(pcap).unlink()

    session = http_request(app, "GET", f"/api/captures/{job.id}")
    assert session.status_code == 200
    assert session.json()["pcap_url"] is None

    listing = http_request(app, "GET", "/api/captures?limit=20")
    item = next(row for row in listing.json()["items"] if row["job_id"] == job.id)
    assert item["pcap_url"] is None

    # A stale metadata row without the actual raw file must not create a
    # traffic-analysis job that is guaranteed to fail in the worker.
    analyze = http_request(app, "POST", f"/api/captures/{job.id}/analyze")
    assert analyze.status_code == 409
    assert analyze.json()["detail"]["code"] == "pcap_unavailable"
    assert _traffic_jobs(jobs, job.audit_id) == []


def test_pcap_delete_has_stable_operational_audit_action(api_context):
    app, _jobs, _evidence, _environment = api_context
    _audit, job, _pcap, _capture_result, _downstream = _completed_capture(api_context)

    assert http_request(app, "DELETE", f"/api/captures/{job.id}/pcap").status_code == 200
    events = http_request(
        app,
        "GET",
        "/api/audit-log",
        params={"action": "capture.pcap_delete"},
    )
    assert events.status_code == 200
    assert events.json()["total"] >= 1
    assert events.json()["items"][0]["action"] == "capture.pcap_delete"
