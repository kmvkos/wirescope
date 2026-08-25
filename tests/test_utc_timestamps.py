from datetime import datetime, timezone

from jobs.models import AuditRecord, AuditStatus, JobRecord, JobStatus


def test_naive_sqlite_job_timestamps_are_serialized_as_utc():
    naive = datetime(2026, 8, 25, 8, 45, 0)
    job = JobRecord(
        id="job-1",
        audit_id="audit-1",
        type="active_discovery",
        status=JobStatus.RUNNING,
        priority=0,
        created_at=naive,
        started_at=naive,
        finished_at=None,
        updated_at=naive,
        progress=35,
        stage="scanning_tcp",
        message="Scanning TCP services",
        target="ens37",
        parameters={},
        result_reference=None,
        cancel_requested=False,
        worker_id="worker-1",
        attempt=1,
        resource_key="interface:ens37",
        resource_group="network",
        error=None,
    )

    assert job.created_at.tzinfo == timezone.utc
    assert job.started_at.tzinfo == timezone.utc
    assert job.updated_at.tzinfo == timezone.utc
    payload = job.model_dump(mode="json")
    assert payload["created_at"].endswith("Z")
    assert payload["started_at"].endswith("Z")
    assert payload["updated_at"].endswith("Z")


def test_naive_sqlite_audit_timestamps_are_serialized_as_utc():
    naive = datetime(2026, 8, 25, 8, 45, 0)
    audit = AuditRecord(
        id="audit-1",
        created_at=naive,
        started_at=naive,
        finished_at=None,
        status=AuditStatus.RUNNING,
        profile="deep",
        interface="ens37",
        scope={},
        actor="auditor",
        environment_snapshot_reference=None,
        summary={},
        error=None,
    )

    assert audit.created_at.tzinfo == timezone.utc
    assert audit.model_dump(mode="json")["created_at"].endswith("Z")
