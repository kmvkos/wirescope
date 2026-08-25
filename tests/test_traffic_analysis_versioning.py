from jobs.models import RetentionClass
from persistence.models import JobModel
from tests.helpers import http_request as request
from traffic_analysis import ANALYZER_VERSION


def _capture(api_context):
    app, service, evidence, _environment = api_context
    audit = service.create_audit(
        profile="packet_capture",
        interface="eth0",
        scope={"filter": None},
        actor="auditor",
    )
    capture = service.create_job(
        audit_id=audit.id,
        job_type="packet_capture",
        target="eth0",
        parameters={"interface": "eth0"},
        resource_key="interface:eth0",
        resource_group="packet_capture",
        resource_limit=1,
    )
    claimed = service.claim_next("capture-worker")
    assert claimed is not None and claimed.id == capture.id
    pcap = evidence.put_bytes(
        audit_id=audit.id,
        job_id=capture.id,
        artifact_type="packet_capture",
        payload=b"\xd4\xc3\xb2\xa1" + (b"\x00" * 20),
        content_type="application/vnd.tcpdump.pcap",
        extension=".pcap",
        retention_class=RetentionClass.AUDIT,
    )
    result = evidence.put_json(
        audit_id=audit.id,
        job_id=capture.id,
        artifact_type="packet_capture_result",
        document={
            "schema": "packet-capture-result",
            "schema_version": 1,
            "pcap_artifact_id": pcap.id,
        },
        retention_class=RetentionClass.AUDIT,
        schema_name="packet-capture-result",
        schema_version=1,
    )
    service.cancel_running_job(
        capture.id,
        message="Operator stopped capture",
        result_reference=result.id,
        summary={"pcap_artifact_id": pcap.id, "pcap_bytes": pcap.size},
    )
    return app, service, capture.id


def test_same_analyzer_version_is_idempotent_but_old_result_can_be_reanalyzed(api_context):
    app, service, capture_job_id = _capture(api_context)

    first = request(app, "POST", f"/api/v1/captures/{capture_job_id}/analyze")
    assert first.status_code == 202, first.text
    first_id = first.json()["job_id"]
    first_job = service.get_job(first_id)
    assert first_job.parameters["analyzer_version"] == ANALYZER_VERSION

    same = request(app, "POST", f"/api/v1/captures/{capture_job_id}/analyze")
    assert same.status_code == 202
    assert same.json()["job_id"] == first_id

    claimed = service.claim_next("analysis-worker")
    assert claimed is not None and claimed.id == first_id
    service.complete_job(first_id, result_reference=None, summary={})

    # Simulate a completed result produced by the previous analyzer generation.
    with service.database.immediate_session() as session:
        model = session.get(JobModel, first_id)
        parameters = dict(model.parameters or {})
        parameters["analyzer_version"] = ANALYZER_VERSION - 1
        model.parameters = parameters

    upgraded = request(app, "POST", f"/api/v1/captures/{capture_job_id}/analyze")
    assert upgraded.status_code == 202, upgraded.text
    upgraded_id = upgraded.json()["job_id"]
    assert upgraded_id != first_id
    upgraded_job = service.get_job(upgraded_id)
    assert upgraded_job.parameters["analyzer_version"] == ANALYZER_VERSION
