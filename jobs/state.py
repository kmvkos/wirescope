"""Central state transition rules for audits and jobs."""

from enum import Enum

from jobs.models import AuditStatus, JobStatus


JOB_TRANSITIONS: dict[JobStatus, frozenset[JobStatus]] = {
    JobStatus.QUEUED: frozenset(
        {
            JobStatus.RUNNING,
            JobStatus.CANCELLED,
        }
    ),
    JobStatus.RUNNING: frozenset(
        {
            JobStatus.COMPLETED,
            JobStatus.FAILED,
            JobStatus.CANCELLED,
            JobStatus.INTERRUPTED,
        }
    ),
    JobStatus.COMPLETED: frozenset(),
    JobStatus.FAILED: frozenset(),
    JobStatus.CANCELLED: frozenset(),
    JobStatus.INTERRUPTED: frozenset(),
}

AUDIT_TRANSITIONS: dict[AuditStatus, frozenset[AuditStatus]] = {
    AuditStatus.CREATED: frozenset(
        {
            AuditStatus.RUNNING,
            AuditStatus.CANCELLED,
            AuditStatus.FAILED,
        }
    ),
    AuditStatus.RUNNING: frozenset(
        {
            AuditStatus.COMPLETED,
            AuditStatus.FAILED,
            AuditStatus.CANCELLED,
            AuditStatus.INTERRUPTED,
        }
    ),
    AuditStatus.COMPLETED: frozenset({AuditStatus.RUNNING}),
    # Terminal audit states may return to RUNNING only through an explicit
    # operator retry of a durable job. Individual terminal jobs remain
    # immutable; recovery always creates a new queued job.
    AuditStatus.FAILED: frozenset({AuditStatus.RUNNING}),
    AuditStatus.CANCELLED: frozenset({AuditStatus.RUNNING}),
    AuditStatus.INTERRUPTED: frozenset({AuditStatus.RUNNING}),
}

AUDIT_JOB_ACCEPTING = frozenset(
    {
        AuditStatus.CREATED,
        AuditStatus.RUNNING,
        AuditStatus.COMPLETED,
    }
)


class InvalidTransition(ValueError):
    def __init__(
        self,
        entity: str,
        current: Enum,
        desired: Enum,
        *,
        reason: str | None = None,
    ) -> None:
        self.entity = entity
        self.current = current
        self.desired = desired
        self.reason = reason
        super().__init__(
            reason
            or (
                f"Invalid {entity} transition: "
                f"{current.value} -> {desired.value}"
            )
        )


def require_job_transition(current: JobStatus, desired: JobStatus) -> None:
    if desired not in JOB_TRANSITIONS[current]:
        raise InvalidTransition("job", current, desired)


def require_audit_transition(
    current: AuditStatus,
    desired: AuditStatus,
) -> None:
    if desired not in AUDIT_TRANSITIONS[current]:
        raise InvalidTransition("audit", current, desired)
