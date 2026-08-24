import threading

import pytest

from jobs.models import (
    ErrorCategory,
    JobError,
    JobProgress,
    JobStatus,
)
from jobs.service import WorkerAlreadyRunning
from jobs.state import InvalidTransition


def create_job(job_service, *, interface="eth0", resource=True):
    audit = job_service.create_audit(
        profile="passive",
        interface=interface,
    )
    job = job_service.create_job(
        audit_id=audit.id,
        job_type="passive_discovery",
        target=interface,
        parameters={"interface": interface},
        resource_key=f"interface:{interface}" if resource else None,
        resource_group="packet_capture" if resource else None,
        resource_limit=1 if resource else None,
    )
    return audit, job


def test_create_audit_job_progress_events_and_completion(job_service):
    audit, job = create_job(job_service)
    claimed = job_service.claim_next("worker-1")

    assert claimed is not None
    assert claimed.status == JobStatus.RUNNING
    job_service.update_progress(
        job.id,
        JobProgress(
            percentage=60,
            stage="parsing_packets",
            message="Parsing packets",
        ),
    )
    final = job_service.complete_job(
        job.id,
        result_reference="artifact-id",
        summary={"frame_count": 3},
    )

    assert final.status == JobStatus.COMPLETED
    assert final.progress == 100
    assert final.result_reference == "artifact-id"
    persisted_audit = job_service.get_audit(audit.id)
    assert persisted_audit.status.value == "completed"
    assert persisted_audit.summary == {"frame_count": 3}
    events = job_service.list_events(job.id).items
    assert [event.event_type for event in events] == [
        "job_queued",
        "job_running",
        "progress",
        "job_completed",
    ]


def test_completed_audit_accepts_follow_on_jobs_and_merges_summary(job_service):
    audit, job = create_job(job_service, resource=False)
    job_service.claim_next("worker-1")
    job_service.complete_job(
        job.id,
        result_reference=None,
        summary={"schema": "passive-summary", "frame_count": 3},
    )
    assert job_service.get_audit(audit.id).status.value == "completed"

    follow_on = job_service.create_job(
        audit_id=audit.id,
        job_type="report_generation",
        target="eth0",
    )
    reopened = job_service.get_audit(audit.id)
    assert follow_on.status == JobStatus.QUEUED
    assert reopened.status.value == "running"
    assert reopened.finished_at is None

    job_service.claim_next("worker-2")
    job_service.complete_job(
        follow_on.id,
        result_reference=None,
        summary={"schema": "report-summary", "asset_count": 0},
    )
    final = job_service.get_audit(audit.id)
    assert final.status.value == "completed"
    assert final.summary["frame_count"] == 3
    assert final.summary["asset_count"] == 0
    assert final.summary["schema"] == "report-summary"


def test_failed_audit_rejects_follow_on_jobs(job_service):
    audit, job = create_job(job_service, resource=False)
    job_service.claim_next("worker-1")
    job_service.fail_job(
        job.id,
        JobError(
            code="tool_missing",
            category=ErrorCategory.TOOL_MISSING,
            message="Required tool is missing",
            component="test_handler",
            retryable=False,
        ),
    )

    with pytest.raises(InvalidTransition) as caught:
        job_service.create_job(
            audit_id=audit.id,
            job_type="report_generation",
            target="eth0",
        )
    assert caught.value.current.value == "failed"
    assert "failed" in str(caught.value)


def test_invalid_job_transition_is_rejected(job_service):
    _audit, job = create_job(job_service, resource=False)

    with pytest.raises(InvalidTransition):
        job_service.complete_job(job.id, result_reference=None)

    assert job_service.get_job(job.id).status == JobStatus.QUEUED


def test_queued_cancellation_is_immediate_and_persistent(job_service):
    _audit, job = create_job(job_service)

    cancelled = job_service.request_cancel(job.id)

    assert cancelled.status == JobStatus.CANCELLED
    assert cancelled.error is not None
    assert cancelled.error.category == ErrorCategory.CANCELLED
    assert job_service.claim_next("worker-1") is None


def test_running_job_recovery_interrupts_and_keeps_queued_jobs(job_service):
    audit, running = create_job(job_service)
    queued = job_service.create_job(
        audit_id=audit.id,
        job_type="passive_discovery",
        target="eth1",
        resource_key="interface:eth1",
    )
    assert job_service.claim_next("old-worker").id == running.id

    recovered = job_service.recover_after_restart()

    assert recovered == 1
    interrupted = job_service.get_job(running.id)
    assert interrupted.status == JobStatus.INTERRUPTED
    assert interrupted.error.code == "application_restart"
    assert job_service.get_job(queued.id).status == JobStatus.QUEUED
    assert job_service.claim_next("new-worker").id == queued.id


def test_interface_and_capture_group_locks_serialize_jobs(job_service):
    first_audit, first = create_job(job_service, interface="eth0")
    second = job_service.create_job(
        audit_id=first_audit.id,
        job_type="passive_discovery",
        target="eth0",
        resource_key="interface:eth0",
        resource_group="packet_capture",
        resource_limit=1,
    )
    other_audit, third = create_job(job_service, interface="eth1")

    assert job_service.claim_next("worker-1").id == first.id
    assert job_service.claim_next("worker-2") is None
    assert job_service.get_job(second.id).stage == "resource_wait"
    assert job_service.get_job(third.id).stage == "resource_wait"

    job_service.complete_job(first.id, result_reference=None)
    next_job = job_service.claim_next("worker-2")
    assert next_job is not None
    assert next_job.id in {second.id, third.id}


def test_failure_is_structured_and_lists_are_paginated(job_service):
    _audit, first = create_job(job_service, resource=False)
    job_service.claim_next("worker-1")
    failed = job_service.fail_job(
        first.id,
        JobError(
            code="tool_missing",
            category=ErrorCategory.TOOL_MISSING,
            message="Required tool is missing",
            component="test_handler",
            retryable=False,
        ),
    )
    create_job(job_service, interface="eth1", resource=False)

    assert failed.error.code == "tool_missing"
    page = job_service.list_jobs(limit=1, offset=0)
    assert len(page.items) == 1
    assert page.total == 2
    failed_page = job_service.list_jobs(
        limit=10,
        offset=0,
        status=JobStatus.FAILED,
    )
    assert [job.id for job in failed_page.items] == [first.id]


def test_worker_supervisor_lease_prevents_accidental_second_process(
    job_service,
):
    assert (
        job_service.prepare_supervisor(
            "supervisor-1",
            stale_after_seconds=20,
        )
        == 0
    )

    with pytest.raises(WorkerAlreadyRunning):
        job_service.prepare_supervisor(
            "supervisor-2",
            stale_after_seconds=20,
        )


def test_two_workers_cannot_claim_the_same_job(job_service):
    _audit, job = create_job(job_service, resource=False)
    barrier = threading.Barrier(3)
    claimed = []

    def claim(worker_id):
        barrier.wait()
        claimed.append(job_service.claim_next(worker_id))

    threads = [
        threading.Thread(target=claim, args=(f"worker-{index}",))
        for index in range(2)
    ]
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join(timeout=2)

    assert sum(item is not None for item in claimed) == 1
    assert next(item for item in claimed if item is not None).id == job.id
