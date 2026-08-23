"""Exceptions that preserve safe structured job errors."""

from jobs.models import ErrorCategory, JobError


class JobExecutionError(RuntimeError):
    def __init__(self, error: JobError) -> None:
        self.error = error
        super().__init__(error.message)


class JobCancelled(JobExecutionError):
    def __init__(self, message: str = "Job cancellation requested") -> None:
        super().__init__(
            JobError(
                code="cancelled",
                category=ErrorCategory.CANCELLED,
                message=message,
                component="job_worker",
                retryable=False,
            )
        )
