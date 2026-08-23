"""Extensible durable job handler registry."""

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

from config.settings import Settings
from jobs.models import AuditRecord, JobProgress, JobRecord
from providers.tools import CancellationToken
from storage.evidence import EvidenceStore


@dataclass(frozen=True)
class HandlerResult:
    result_reference: str | None = None
    summary: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class HandlerContext:
    audit: AuditRecord
    job: JobRecord
    settings: Settings
    cancellation_token: CancellationToken
    evidence_store: EvidenceStore
    report_progress: Callable[[JobProgress], None]


class JobHandler(Protocol):
    def execute(self, context: HandlerContext) -> HandlerResult:
        ...


class HandlerRegistry:
    def __init__(self) -> None:
        self._handlers: dict[str, JobHandler] = {}

    def register(self, job_type: str, handler: JobHandler) -> None:
        if job_type in self._handlers:
            raise ValueError(f"Handler already registered: {job_type}")
        self._handlers[job_type] = handler

    def resolve(self, job_type: str) -> JobHandler:
        try:
            return self._handlers[job_type]
        except KeyError as exc:
            raise LookupError(
                f"No handler registered for job type: {job_type}"
            ) from exc

    @property
    def job_types(self) -> tuple[str, ...]:
        return tuple(sorted(self._handlers))
