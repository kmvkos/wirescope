from backend.audit_log import operational_action
from jobs.models import ErrorCategory, JobError
from tests.helpers import http_request as request
from tests.test_global_analysis_history import _setup_completed_traffic


def test_global_analysis_rebuild_requires_completed_durable_result(api_context):
    app, service, _evidence, audit, traffic = _setup_completed_traffic(
        api_context,
        marker="failed-rebuild-source",
    )

    worker_id = "failed-global-analysis-source"
    service.register_worker(worker_id)
    failed = service.create_job(
        audit_id=audit.id,
        job_type="global_analysis",
        target="eth0",
        parameters={"traffic_analysis_job_id": traffic.id},
        resource_key=f"audit:{audit.id}:global_analysis",
        resource_group="global_analysis",
        resource_limit=1,
    )
    claimed = service.claim_next(worker_id)
    assert claimed is not None and claimed.id == failed.id
    service.fail_job(
        failed.id,
        JobError(
            code="fixture_failure",
            category=ErrorCategory.INTERNAL,
            message="fixture failure",
            component="global_analysis",
            retryable=False,
        ),
    )

    response = request(
        app,
        "POST",
        f"/api/v1/audits/{audit.id}/global-analysis",
        json={
            "traffic_analysis_job_id": traffic.id,
            "rebuild_of_job_id": failed.id,
        },
    )
    assert response.status_code == 409, response.text
    assert response.json()["detail"]["code"] == "global_analysis_unavailable"


def test_global_analysis_generation_has_stable_operational_action():
    assert (
        operational_action(
            "POST",
            "/api/v1/audits/audit-123/global-analysis",
        )
        == "global_analysis.generate"
    )
    assert (
        operational_action(
            "GET",
            "/api/v1/audits/audit-123/global-analysis/history",
        )
        is None
    )
