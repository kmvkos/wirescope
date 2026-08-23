"""Transactional durable audit and job service."""

from datetime import timedelta
import uuid
from typing import Any

from sqlalchemy import delete, func, select, update
from sqlalchemy.orm import Session

from jobs.models import (
    ArtifactRecord,
    AuditRecord,
    AuditStatus,
    ErrorCategory,
    JobError,
    JobEventRecord,
    JobProgress,
    JobRecord,
    JobStatus,
    Page,
)
from jobs.state import (
    InvalidTransition,
    require_audit_transition,
    require_job_transition,
)
from persistence.database import Database
from persistence.models import (
    ArtifactModel,
    AuditModel,
    JobEventModel,
    JobModel,
    ResourceLockModel,
    WorkerModel,
    utc_now,
)


class EntityNotFound(LookupError):
    pass


class WorkerAlreadyRunning(RuntimeError):
    pass


class JobService:
    def __init__(self, database: Database) -> None:
        self.database = database

    def create_audit(
        self,
        *,
        profile: str,
        interface: str | None,
        scope: dict[str, Any] | None = None,
        actor: str | None = None,
    ) -> AuditRecord:
        audit = AuditModel(
            id=str(uuid.uuid4()),
            status=AuditStatus.CREATED.value,
            profile=profile,
            interface=interface,
            scope_json=scope or {},
            actor=actor,
            summary={},
        )
        with self.database.session() as session, session.begin():
            session.add(audit)
        return self._audit_record(audit)

    def set_environment_reference(
        self,
        audit_id: str,
        artifact_id: str,
    ) -> AuditRecord:
        with self.database.session() as session, session.begin():
            audit = self._require_audit(session, audit_id)
            audit.environment_snapshot_reference = artifact_id
        return self._audit_record(audit)

    def fail_audit(
        self,
        audit_id: str,
        error: JobError,
    ) -> AuditRecord:
        with self.database.session() as session, session.begin():
            audit = self._require_audit(session, audit_id)
            current = AuditStatus(audit.status)
            require_audit_transition(current, AuditStatus.FAILED)
            audit.status = AuditStatus.FAILED.value
            audit.finished_at = utc_now()
            audit.error = error.model_dump(mode="json")
        return self._audit_record(audit)

    def get_audit(self, audit_id: str) -> AuditRecord:
        with self.database.session() as session:
            return self._audit_record(self._require_audit(session, audit_id))

    def list_audits(
        self,
        *,
        limit: int,
        offset: int,
        status: AuditStatus | None = None,
    ) -> Page[AuditRecord]:
        with self.database.session() as session:
            base = select(AuditModel)
            count = select(func.count()).select_from(AuditModel)
            if status is not None:
                base = base.where(AuditModel.status == status.value)
                count = count.where(AuditModel.status == status.value)
            rows = session.scalars(
                base.order_by(AuditModel.created_at.desc())
                .limit(limit)
                .offset(offset)
            ).all()
            total = session.scalar(count) or 0
        return Page[AuditRecord](
            items=[self._audit_record(row) for row in rows],
            limit=limit,
            offset=offset,
            total=total,
        )

    def create_job(
        self,
        *,
        audit_id: str,
        job_type: str,
        target: str | None,
        parameters: dict[str, Any] | None = None,
        priority: int = 0,
        resource_key: str | None = None,
        resource_group: str | None = None,
        resource_limit: int | None = None,
    ) -> JobRecord:
        job = JobModel(
            id=str(uuid.uuid4()),
            audit_id=audit_id,
            type=job_type,
            status=JobStatus.QUEUED.value,
            priority=priority,
            progress=0,
            stage="queued",
            message="Job queued",
            target=target,
            parameters=parameters or {},
            cancel_requested=False,
            attempt=0,
            resource_key=resource_key,
            resource_group=resource_group,
            resource_limit=resource_limit,
        )
        with self.database.session() as session, session.begin():
            audit = self._require_audit(session, audit_id)
            if AuditStatus(audit.status) not in {
                AuditStatus.CREATED,
                AuditStatus.RUNNING,
            }:
                raise InvalidTransition(
                    "audit",
                    AuditStatus(audit.status),
                    AuditStatus.RUNNING,
                )
            session.add(job)
            session.flush()
            self._add_event(
                session,
                job,
                "job_queued",
                "Job queued",
            )
        return self._job_record(job)

    def get_job(self, job_id: str) -> JobRecord:
        with self.database.session() as session:
            return self._job_record(self._require_job(session, job_id))

    def list_jobs(
        self,
        *,
        limit: int,
        offset: int,
        status: JobStatus | None = None,
        audit_id: str | None = None,
    ) -> Page[JobRecord]:
        with self.database.session() as session:
            base = select(JobModel)
            count = select(func.count()).select_from(JobModel)
            if status is not None:
                base = base.where(JobModel.status == status.value)
                count = count.where(JobModel.status == status.value)
            if audit_id is not None:
                base = base.where(JobModel.audit_id == audit_id)
                count = count.where(JobModel.audit_id == audit_id)
            rows = session.scalars(
                base.order_by(JobModel.created_at.desc())
                .limit(limit)
                .offset(offset)
            ).all()
            total = session.scalar(count) or 0
        return Page[JobRecord](
            items=[self._job_record(row) for row in rows],
            limit=limit,
            offset=offset,
            total=total,
        )

    def list_events(
        self,
        job_id: str,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> Page[JobEventRecord]:
        with self.database.session() as session:
            self._require_job(session, job_id)
            base = select(JobEventModel).where(
                JobEventModel.job_id == job_id
            )
            rows = session.scalars(
                base.order_by(JobEventModel.id).limit(limit).offset(offset)
            ).all()
            total = (
                session.scalar(
                    select(func.count())
                    .select_from(JobEventModel)
                    .where(JobEventModel.job_id == job_id)
                )
                or 0
            )
        return Page[JobEventRecord](
            items=[self._event_record(row) for row in rows],
            limit=limit,
            offset=offset,
            total=total,
        )

    def request_cancel(self, job_id: str) -> JobRecord:
        with self.database.immediate_session() as session:
            job = self._require_job(session, job_id)
            status = JobStatus(job.status)
            if status == JobStatus.QUEUED:
                self._transition_job(
                    session,
                    job,
                    JobStatus.CANCELLED,
                    stage="cancelled",
                    progress=job.progress,
                    message="Queued job cancelled",
                    error=JobError(
                        code="cancelled_before_start",
                        category=ErrorCategory.CANCELLED,
                        message="Job was cancelled before execution",
                        component="job_service",
                    ),
                )
                self._refresh_audit(session, job.audit_id)
            elif status == JobStatus.RUNNING:
                if not job.cancel_requested:
                    job.cancel_requested = True
                    self._add_event(
                        session,
                        job,
                        "cancellation_requested",
                        "Cancellation requested",
                    )
            elif status.terminal:
                return self._job_record(job)
        return self._job_record(job)

    def claim_next(self, worker_id: str) -> JobRecord | None:
        with self.database.immediate_session() as session:
            candidates = session.scalars(
                select(JobModel)
                .where(JobModel.status == JobStatus.QUEUED.value)
                .order_by(JobModel.priority.desc(), JobModel.created_at)
            ).all()
            for job in candidates:
                if not self._resource_available(session, job):
                    if job.stage != "resource_wait":
                        job.stage = "resource_wait"
                        job.message = "Waiting for exclusive resource"
                        self._add_event(
                            session,
                            job,
                            "resource_wait",
                            job.message,
                        )
                    continue
                self._transition_job(
                    session,
                    job,
                    JobStatus.RUNNING,
                    stage="starting",
                    progress=max(1, job.progress),
                    message="Worker claimed job",
                )
                job.worker_id = worker_id
                job.attempt += 1
                if job.resource_key or job.resource_group:
                    session.add(
                        ResourceLockModel(
                            resource_key=job.resource_key or f"job:{job.id}",
                            resource_group=job.resource_group,
                            job_id=job.id,
                            worker_id=worker_id,
                        )
                    )
                audit = self._require_audit(session, job.audit_id)
                if AuditStatus(audit.status) == AuditStatus.CREATED:
                    require_audit_transition(
                        AuditStatus.CREATED,
                        AuditStatus.RUNNING,
                    )
                    audit.status = AuditStatus.RUNNING.value
                    audit.started_at = audit.started_at or utc_now()
                return self._job_record(job)
        return None

    def update_progress(
        self,
        job_id: str,
        progress: JobProgress,
    ) -> JobRecord:
        with self.database.session() as session, session.begin():
            job = self._require_job(session, job_id)
            if JobStatus(job.status) != JobStatus.RUNNING:
                raise InvalidTransition(
                    "job",
                    JobStatus(job.status),
                    JobStatus.RUNNING,
                )
            if progress.percentage < job.progress:
                raise ValueError("Job progress cannot move backwards")
            job.progress = progress.percentage
            job.stage = progress.stage
            job.message = progress.message
            self._add_event(
                session,
                job,
                "progress",
                progress.message,
            )
        return self._job_record(job)

    def complete_job(
        self,
        job_id: str,
        *,
        result_reference: str | None,
        summary: dict[str, Any] | None = None,
    ) -> JobRecord:
        with self.database.immediate_session() as session:
            job = self._require_job(session, job_id)
            job.result_reference = result_reference
            self._transition_job(
                session,
                job,
                JobStatus.COMPLETED,
                stage="completed",
                progress=100,
                message="Job completed",
            )
            self._release_lock(session, job.id)
            if summary is not None:
                audit = self._require_audit(session, job.audit_id)
                audit.summary = summary
            self._refresh_audit(session, job.audit_id)
        return self._job_record(job)

    def fail_job(self, job_id: str, error: JobError) -> JobRecord:
        with self.database.immediate_session() as session:
            job = self._require_job(session, job_id)
            self._transition_job(
                session,
                job,
                JobStatus.FAILED,
                stage="failed",
                progress=job.progress,
                message=error.message,
                error=error,
            )
            self._release_lock(session, job.id)
            self._refresh_audit(session, job.audit_id)
        return self._job_record(job)

    def cancel_running_job(
        self,
        job_id: str,
        *,
        message: str = "Job cancelled",
    ) -> JobRecord:
        with self.database.immediate_session() as session:
            job = self._require_job(session, job_id)
            self._transition_job(
                session,
                job,
                JobStatus.CANCELLED,
                stage="cancelled",
                progress=job.progress,
                message=message,
                error=JobError(
                    code="cancelled",
                    category=ErrorCategory.CANCELLED,
                    message=message,
                    component="job_worker",
                ),
            )
            self._release_lock(session, job.id)
            self._refresh_audit(session, job.audit_id)
        return self._job_record(job)

    def recover_after_restart(self) -> int:
        with self.database.immediate_session() as session:
            return self._recover_running(session)

    def prepare_supervisor(
        self,
        supervisor_id: str,
        *,
        stale_after_seconds: int,
    ) -> int:
        cutoff = utc_now() - timedelta(seconds=stale_after_seconds)
        with self.database.immediate_session() as session:
            active = (
                session.scalar(
                    select(func.count())
                    .select_from(WorkerModel)
                    .where(
                        WorkerModel.heartbeat_at >= cutoff,
                        WorkerModel.status.in_(
                            ("starting", "idle", "running")
                        ),
                    )
                )
                or 0
            )
            if active:
                raise WorkerAlreadyRunning(
                    "A healthy worker supervisor is already active"
                )
            recovered = self._recover_running(session)
            now = utc_now()
            supervisor = session.get(WorkerModel, supervisor_id)
            if supervisor is None:
                session.add(
                    WorkerModel(
                        id=supervisor_id,
                        started_at=now,
                        heartbeat_at=now,
                        status="starting",
                    )
                )
            else:
                supervisor.started_at = now
                supervisor.heartbeat_at = now
                supervisor.status = "starting"
                supervisor.current_job_id = None
            return recovered

    def register_worker(self, worker_id: str) -> None:
        now = utc_now()
        with self.database.session() as session, session.begin():
            worker = session.get(WorkerModel, worker_id)
            if worker is None:
                session.add(
                    WorkerModel(
                        id=worker_id,
                        started_at=now,
                        heartbeat_at=now,
                        status="starting",
                    )
                )
            else:
                worker.started_at = now
                worker.heartbeat_at = now
                worker.status = "starting"
                worker.current_job_id = None

    def heartbeat_worker(
        self,
        worker_id: str,
        *,
        status: str,
        current_job_id: str | None = None,
    ) -> None:
        with self.database.session() as session, session.begin():
            worker = session.get(WorkerModel, worker_id)
            if worker is None:
                raise EntityNotFound(f"Worker not found: {worker_id}")
            worker.heartbeat_at = utc_now()
            worker.status = status
            worker.current_job_id = current_job_id

    def worker_is_ready(self, stale_after_seconds: int) -> bool:
        cutoff = utc_now() - timedelta(seconds=stale_after_seconds)
        with self.database.session() as session:
            count = (
                session.scalar(
                    select(func.count())
                    .select_from(WorkerModel)
                    .where(
                        WorkerModel.heartbeat_at >= cutoff,
                        WorkerModel.status.in_(("idle", "running")),
                    )
                )
                or 0
            )
        return count > 0

    def _recover_running(self, session: Session) -> int:
        running = session.scalars(
            select(JobModel).where(
                JobModel.status == JobStatus.RUNNING.value
            )
        ).all()
        audit_ids = {job.audit_id for job in running}
        for job in running:
            self._transition_job(
                session,
                job,
                JobStatus.INTERRUPTED,
                stage="interrupted",
                progress=job.progress,
                message="Application restarted during execution",
                error=JobError(
                    code="application_restart",
                    category=ErrorCategory.INTERNAL,
                    message="Job interrupted by application restart",
                    component="job_recovery",
                    retryable=True,
                ),
            )
        session.execute(delete(ResourceLockModel))
        session.execute(
            update(WorkerModel).values(
                status="stopped",
                current_job_id=None,
            )
        )
        for audit_id in audit_ids:
            self._refresh_audit(session, audit_id)
        return len(running)

    def artifact(self, artifact_id: str) -> ArtifactRecord:
        with self.database.session() as session:
            artifact = session.get(ArtifactModel, artifact_id)
            if artifact is None:
                raise EntityNotFound(f"Artifact not found: {artifact_id}")
            return self._artifact_record(artifact)

    def _resource_available(self, session: Session, job: JobModel) -> bool:
        if job.resource_key and session.get(ResourceLockModel, job.resource_key):
            return False
        if job.resource_group and job.resource_limit:
            active = (
                session.scalar(
                    select(func.count())
                    .select_from(ResourceLockModel)
                    .where(
                        ResourceLockModel.resource_group
                        == job.resource_group
                    )
                )
                or 0
            )
            if active >= job.resource_limit:
                return False
        return True

    @staticmethod
    def _release_lock(session: Session, job_id: str) -> None:
        session.execute(
            delete(ResourceLockModel).where(
                ResourceLockModel.job_id == job_id
            )
        )

    def _refresh_audit(self, session: Session, audit_id: str) -> None:
        audit = self._require_audit(session, audit_id)
        statuses = [
            JobStatus(value)
            for value in session.scalars(
                select(JobModel.status).where(JobModel.audit_id == audit_id)
            ).all()
        ]
        if not statuses:
            return
        current = AuditStatus(audit.status)
        if any(
            status in {JobStatus.QUEUED, JobStatus.RUNNING}
            for status in statuses
        ):
            desired = AuditStatus.RUNNING
        elif JobStatus.FAILED in statuses:
            desired = AuditStatus.FAILED
        elif JobStatus.INTERRUPTED in statuses:
            desired = AuditStatus.INTERRUPTED
        elif JobStatus.CANCELLED in statuses:
            desired = AuditStatus.CANCELLED
        else:
            desired = AuditStatus.COMPLETED
        if current == desired:
            return
        require_audit_transition(current, desired)
        audit.status = desired.value
        if desired == AuditStatus.RUNNING:
            audit.started_at = audit.started_at or utc_now()
        elif desired in {
            AuditStatus.COMPLETED,
            AuditStatus.FAILED,
            AuditStatus.CANCELLED,
            AuditStatus.INTERRUPTED,
        }:
            audit.finished_at = utc_now()
        if desired in {
            AuditStatus.FAILED,
            AuditStatus.INTERRUPTED,
        }:
            failed_job = next(
                (
                    status
                    for status in statuses
                    if status in {
                        JobStatus.FAILED,
                        JobStatus.INTERRUPTED,
                    }
                ),
                None,
            )
            audit.error = {"job_status": failed_job.value} if failed_job else None

    def _transition_job(
        self,
        session: Session,
        job: JobModel,
        desired: JobStatus,
        *,
        stage: str,
        progress: int,
        message: str,
        error: JobError | None = None,
    ) -> None:
        current = JobStatus(job.status)
        require_job_transition(current, desired)
        job.status = desired.value
        job.stage = stage
        job.progress = progress
        job.message = message
        if desired == JobStatus.RUNNING:
            job.started_at = job.started_at or utc_now()
        if desired.terminal:
            job.finished_at = utc_now()
        if error is not None:
            self._apply_error(job, error)
        self._add_event(
            session,
            job,
            f"job_{desired.value}",
            message,
        )

    @staticmethod
    def _apply_error(job: JobModel, error: JobError) -> None:
        job.error_code = error.code
        job.error_category = error.category.value
        job.error_message = error.message
        job.error_component = error.component
        job.error_retryable = error.retryable
        job.error_details = error.details

    @staticmethod
    def _add_event(
        session: Session,
        job: JobModel,
        event_type: str,
        message: str,
    ) -> None:
        session.add(
            JobEventModel(
                audit_id=job.audit_id,
                job_id=job.id,
                event_type=event_type,
                stage=job.stage,
                progress=job.progress,
                message=message,
                details={},
            )
        )

    @staticmethod
    def _require_audit(session: Session, audit_id: str) -> AuditModel:
        audit = session.get(AuditModel, audit_id)
        if audit is None:
            raise EntityNotFound(f"Audit not found: {audit_id}")
        return audit

    @staticmethod
    def _require_job(session: Session, job_id: str) -> JobModel:
        job = session.get(JobModel, job_id)
        if job is None:
            raise EntityNotFound(f"Job not found: {job_id}")
        return job

    @staticmethod
    def _audit_record(model: AuditModel) -> AuditRecord:
        return AuditRecord(
            id=model.id,
            created_at=model.created_at,
            started_at=model.started_at,
            finished_at=model.finished_at,
            status=AuditStatus(model.status),
            profile=model.profile,
            interface=model.interface,
            scope=model.scope_json,
            actor=model.actor,
            environment_snapshot_reference=model.environment_snapshot_reference,
            summary=model.summary,
            error=model.error,
        )

    @staticmethod
    def _job_record(model: JobModel) -> JobRecord:
        error = None
        if model.error_code and model.error_category and model.error_message:
            error = JobError(
                code=model.error_code,
                category=ErrorCategory(model.error_category),
                message=model.error_message,
                component=model.error_component or "unknown",
                retryable=bool(model.error_retryable),
                details=model.error_details or {},
            )
        return JobRecord(
            id=model.id,
            audit_id=model.audit_id,
            type=model.type,
            status=JobStatus(model.status),
            priority=model.priority,
            created_at=model.created_at,
            started_at=model.started_at,
            finished_at=model.finished_at,
            progress=model.progress,
            stage=model.stage,
            message=model.message,
            target=model.target,
            parameters=model.parameters,
            result_reference=model.result_reference,
            cancel_requested=model.cancel_requested,
            worker_id=model.worker_id,
            attempt=model.attempt,
            resource_key=model.resource_key,
            error=error,
        )

    @staticmethod
    def _event_record(model: JobEventModel) -> JobEventRecord:
        return JobEventRecord(
            id=model.id,
            audit_id=model.audit_id,
            job_id=model.job_id,
            created_at=model.created_at,
            event_type=model.event_type,
            stage=model.stage,
            progress=model.progress,
            message=model.message,
            details=model.details,
        )

    @staticmethod
    def _artifact_record(model: ArtifactModel) -> ArtifactRecord:
        return ArtifactRecord(
            id=model.id,
            audit_id=model.audit_id,
            job_id=model.job_id,
            artifact_type=model.artifact_type,
            relative_path=model.relative_path,
            content_type=model.content_type,
            size=model.size,
            sha256=model.sha256,
            created_at=model.created_at,
            retention_class=model.retention_class,
            schema_name=model.schema_name,
            schema_version=model.schema_version,
        )
