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
    AuditStatus.COMPLETED: frozenset(),
    AuditStatus.FAILED: frozenset(),
    AuditStatus.CANCELLED: frozenset(),
    AuditStatus.INTERRUPTED: frozenset(),
}


class InvalidTransition(ValueError):
    def __init__(self, entity: str, current: Enum, desired: Enum) -> None:
        self.entity = entity
        self.current = current
        self.desired = desired
        super().__init__(
            f"Invalid {entity} transition: {current.value} -> {desired.value}"
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
