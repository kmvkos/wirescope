"""Exceptions that preserve safe structured job errors."""

from typing import Any

from jobs.models import ErrorCategory, JobError


class JobExecutionError(RuntimeError):
    def __init__(self, error: JobError) -> None:
        self.error = error
        super().__init__(error.message)


class JobCancelled(JobExecutionError):
    def __init__(
        self,
        message: str = "Job cancellation requested",
        *,
        result_reference: str | None = None,
        summary: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            JobError(
                code="cancelled",
                category=ErrorCategory.CANCELLED,
                message=message,
                component="job_worker",
                retryable=False,
            )
        )
        self.result_reference = result_reference
        self.summary = summary or {}
