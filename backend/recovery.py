"""Stage-level recovery for failed, cancelled, or interrupted durable jobs."""

from __future__ import annotations

import uuid

from sqlalchemy import select

from jobs.models import AuditStatus, JobStatus
from jobs.service import EntityNotFound, JobService
from jobs.state import require_audit_transition
from persistence.database import Database
from persistence.models import AuditModel, JobEventModel, JobModel, utc_now


class RetryNotAllowed(ValueError):
    pass


class RecoveryService:
    RETRYABLE_STATES = frozenset(
        {JobStatus.FAILED, JobStatus.INTERRUPTED, JobStatus.CANCELLED}
    )

    def __init__(self, database: Database, jobs: JobService) -> None:
        self.database = database
        self.jobs = jobs

    def retry(self, job_id: str, *, actor: str | None = None):
        new_job_id = str(uuid.uuid4())
        with self.database.immediate_session() as session:
            source = session.get(JobModel, job_id)
            if source is None:
                raise EntityNotFound(f"Job not found: {job_id}")
            source_status = JobStatus(source.status)
            if source_status not in self.RETRYABLE_STATES:
                raise RetryNotAllowed(
                    f"Only failed, interrupted, or cancelled jobs can be retried; "
                    f"job is {source_status.value}"
                )
            if source.type == "snmp_topology":
                raise RetryNotAllowed(
                    "SNMP topology jobs require fresh credentials; launch SNMP topology enrichment again from the topology screen"
                )

            active = session.scalar(
                select(JobModel.id)
                .where(
                    JobModel.audit_id == source.audit_id,
                    JobModel.type == source.type,
                    JobModel.status.in_((JobStatus.QUEUED.value, JobStatus.RUNNING.value)),
                )
                .limit(1)
            )
            if active is not None:
                raise RetryNotAllowed(
                    "An equivalent job is already queued or running for this audit"
                )

            audit = session.get(AuditModel, source.audit_id)
            if audit is None:
                raise EntityNotFound(f"Audit not found: {source.audit_id}")
            audit_status = AuditStatus(audit.status)
            if audit_status != AuditStatus.RUNNING:
                require_audit_transition(audit_status, AuditStatus.RUNNING)
                audit.status = AuditStatus.RUNNING.value
                audit.finished_at = None
                audit.error = None

            retried = JobModel(
                id=new_job_id,
                audit_id=source.audit_id,
                type=source.type,
                status=JobStatus.QUEUED.value,
                priority=source.priority,
                progress=0,
                stage="queued",
                message=f"Retry queued for {source.id}",
                target=source.target,
                parameters=dict(source.parameters or {}),
                cancel_requested=False,
                attempt=0,
                resource_key=source.resource_key,
                resource_group=source.resource_group,
                resource_limit=source.resource_limit,
            )
            session.add(retried)
            session.flush()
            session.add(
                JobEventModel(
                    audit_id=retried.audit_id,
                    job_id=retried.id,
                    event_type="job_retried",
                    stage="queued",
                    progress=0,
                    message="Retry queued",
                    details={"retry_of": source.id, "actor": actor},
                )
            )
            session.add(
                JobEventModel(
                    audit_id=source.audit_id,
                    job_id=source.id,
                    event_type="retry_scheduled",
                    stage=source.stage,
                    progress=source.progress,
                    message="Replacement job queued",
                    details={"retry_job_id": retried.id, "actor": actor},
                )
            )
            audit.started_at = audit.started_at or utc_now()

        return self.jobs.get_job(new_job_id)
