import threading
import time

import pytest

from jobs.errors import JobCancelled, JobExecutionError
from jobs.models import (
    ErrorCategory,
    JobError,
    JobProgress,
    JobStatus,
)
from jobs.registry import HandlerRegistry, HandlerResult
from jobs.worker import JobWorker


class SuccessHandler:
    def execute(self, context):
        context.report_progress(
            JobProgress(
                percentage=50,
                stage="working",
                message="Working",
            )
        )
        return HandlerResult(summary={"ok": True})


class FailureHandler:
    def execute(self, context):
        raise JobExecutionError(
            JobError(
                code="fixture_failure",
                category=ErrorCategory.PARSE,
                message="Fixture failed",
                component="fixture_handler",
            )
        )


class BlockingHandler:
    def __init__(self):
        self.started = threading.Event()

    def execute(self, context):
        self.started.set()
        while not context.cancellation_token.cancelled:
            time.sleep(0.01)
        raise JobCancelled()


def create_worker_job(job_service, job_type):
    audit = job_service.create_audit(
        profile="test",
        interface="eth0",
    )
    return job_service.create_job(
        audit_id=audit.id,
        job_type=job_type,
        target="eth0",
    )


def worker(
    job_service,
    evidence_store,
    durable_settings,
    job_type,
    handler,
):
    registry = HandlerRegistry()
    registry.register(job_type, handler)
    return JobWorker(
        worker_id=f"worker-{job_type}",
        service=job_service,
        registry=registry,
        evidence_store=evidence_store,
        settings=durable_settings,
    )


def test_worker_persists_success_progress_and_audit_summary(
    job_service,
    evidence_store,
    durable_settings,
):
    job = create_worker_job(job_service, "success")
    active = worker(
        job_service,
        evidence_store,
        durable_settings,
        "success",
        SuccessHandler(),
    )

    assert active.run_once() is True

    completed = job_service.get_job(job.id)
    assert completed.status == JobStatus.COMPLETED
    assert completed.progress == 100
    assert job_service.get_audit(job.audit_id).summary == {"ok": True}
    assert job_service.worker_is_ready(2)


def test_worker_persists_structured_handler_failure(
    job_service,
    evidence_store,
    durable_settings,
):
    job = create_worker_job(job_service, "failure")
    active = worker(
        job_service,
        evidence_store,
        durable_settings,
        "failure",
        FailureHandler(),
    )

    active.run_once()

    failed = job_service.get_job(job.id)
    assert failed.status == JobStatus.FAILED
    assert failed.error.code == "fixture_failure"
    assert failed.error.category == ErrorCategory.PARSE


def test_running_cancellation_reaches_cooperative_handler(
    job_service,
    evidence_store,
    durable_settings,
):
    handler = BlockingHandler()
    job = create_worker_job(job_service, "blocking")
    active = worker(
        job_service,
        evidence_store,
        durable_settings,
        "blocking",
        handler,
    )
    thread = threading.Thread(target=active.run_once)
    thread.start()
    assert handler.started.wait(timeout=2)

    requested = job_service.request_cancel(job.id)
    assert requested.status == JobStatus.RUNNING
    assert requested.cancel_requested is True
    thread.join(timeout=3)

    assert not thread.is_alive()
    assert job_service.get_job(job.id).status == JobStatus.CANCELLED


def test_handler_registry_rejects_duplicates_and_unknown_types():
    registry = HandlerRegistry()
    registry.register("success", SuccessHandler())

    with pytest.raises(ValueError):
        registry.register("success", SuccessHandler())
    with pytest.raises(LookupError):
        registry.resolve("missing")
