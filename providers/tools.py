"""Controlled execution of external command-line tools."""

from collections import Counter
from datetime import datetime, timezone
from enum import Enum
import os
from pathlib import Path
import signal
import subprocess
import threading
import time
from typing import TextIO

from pydantic import BaseModel, ConfigDict, Field

from config.logging import get_logger


class ToolErrorCode(str, Enum):
    MISSING_BINARY = "missing_binary"
    PERMISSION_DENIED = "permission_denied"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    NON_ZERO_EXIT = "non_zero_exit"
    EXECUTION_ERROR = "execution_error"
    OUTPUT_ERROR = "output_error"


class ToolError(BaseModel):
    code: ToolErrorCode
    message: str
    retryable: bool = False


class ToolCommand(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    tool: str = Field(min_length=1)
    args: list[str] = Field(default_factory=list)
    timeout_seconds: float = Field(default=30.0, gt=0, le=21_600)
    cwd: Path | None = None
    stdout_path: Path | None = None
    environment: dict[str, str] = Field(default_factory=dict, exclude=True)
    sensitive_arg_indexes: set[int] = Field(default_factory=set)

    @property
    def argv(self) -> list[str]:
        return [self.tool, *self.args]

    @property
    def sanitized_argv(self) -> list[str]:
        return [
            "<redacted>" if index in self.sensitive_arg_indexes else value
            for index, value in enumerate(self.argv)
        ]


class ToolResult(BaseModel):
    command: list[str]
    tool: str
    exit_code: int | None
    stdout: str
    stderr: str
    stdout_reference: str | None = None
    started_at: datetime
    finished_at: datetime
    duration_seconds: float
    timed_out: bool = False
    cancelled: bool = False
    success: bool
    error: ToolError | None = None


class CancellationToken:
    """Thread-safe cancellation signal for current and future workers."""

    def __init__(self) -> None:
        self._event = threading.Event()

    def cancel(self) -> None:
        self._event.set()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()


class ToolRunner:
    """Execute tools without a shell and retain structured failure details."""

    def __init__(self) -> None:
        self._logger = get_logger("tool_runner")
        self._metrics_lock = threading.Lock()
        self._invocations: Counter[str] = Counter()

    def metrics_snapshot(self) -> dict[str, int]:
        with self._metrics_lock:
            return dict(self._invocations)

    def invocation_count(self, tool: str | None = None) -> int:
        with self._metrics_lock:
            if tool is not None:
                return self._invocations[tool]
            return sum(self._invocations.values())

    def run(
        self,
        command: ToolCommand,
        cancellation_token: CancellationToken | None = None,
    ) -> ToolResult:
        started_at = datetime.now(timezone.utc)
        started_monotonic = time.monotonic()
        stdout_handle: TextIO | None = None
        process: subprocess.Popen[str] | None = None
        stdout = ""
        stderr = ""

        with self._metrics_lock:
            self._invocations[command.tool] += 1

        self._logger.info(
            "external tool started",
            extra={
                "tool": command.tool,
                "command": command.sanitized_argv,
            },
        )

        try:
            if command.stdout_path is not None:
                command.stdout_path.parent.mkdir(parents=True, exist_ok=True)
                stdout_handle = command.stdout_path.open(
                    "w",
                    encoding="utf-8",
                )

            process = subprocess.Popen(
                command.argv,
                cwd=command.cwd,
                env={**os.environ, **command.environment},
                stdin=subprocess.DEVNULL,
                stdout=stdout_handle or subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                shell=False,
                start_new_session=True,
            )

            deadline = started_monotonic + command.timeout_seconds
            timed_out = False
            cancelled = False

            while True:
                if cancellation_token and cancellation_token.cancelled:
                    cancelled = True
                    stdout, stderr = self._terminate(process, stdout_handle)
                    break

                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timed_out = True
                    stdout, stderr = self._terminate(process, stdout_handle)
                    break

                try:
                    stdout, stderr = process.communicate(
                        timeout=min(0.2, remaining),
                    )
                    break
                except subprocess.TimeoutExpired:
                    continue

            exit_code = process.returncode
            error = self._result_error(
                exit_code=exit_code,
                stderr=stderr,
                timed_out=timed_out,
                cancelled=cancelled,
            )
            success = error is None

            return self._finish(
                command=command,
                started_at=started_at,
                started_monotonic=started_monotonic,
                exit_code=exit_code,
                stdout=stdout or "",
                stderr=stderr or "",
                timed_out=timed_out,
                cancelled=cancelled,
                success=success,
                error=error,
            )

        except FileNotFoundError:
            return self._failed_to_start(
                command,
                started_at,
                started_monotonic,
                ToolErrorCode.MISSING_BINARY,
                f"Tool not found: {command.tool}",
            )
        except PermissionError:
            return self._failed_to_start(
                command,
                started_at,
                started_monotonic,
                ToolErrorCode.PERMISSION_DENIED,
                f"Permission denied while starting: {command.tool}",
            )
        except OSError as exc:
            return self._failed_to_start(
                command,
                started_at,
                started_monotonic,
                ToolErrorCode.EXECUTION_ERROR,
                f"Could not execute {command.tool}: {exc}",
            )
        finally:
            if stdout_handle is not None:
                stdout_handle.close()

    def _terminate(
        self,
        process: subprocess.Popen[str],
        stdout_handle: TextIO | None,
    ) -> tuple[str, str]:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            process.terminate()

        try:
            stdout, stderr = process.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                process.kill()
            stdout, stderr = process.communicate()

        return (
            "" if stdout_handle is not None else (stdout or ""),
            stderr or "",
        )

    def _failed_to_start(
        self,
        command: ToolCommand,
        started_at: datetime,
        started_monotonic: float,
        code: ToolErrorCode,
        message: str,
    ) -> ToolResult:
        return self._finish(
            command=command,
            started_at=started_at,
            started_monotonic=started_monotonic,
            exit_code=None,
            stdout="",
            stderr="",
            timed_out=False,
            cancelled=False,
            success=False,
            error=ToolError(code=code, message=message),
        )

    def _finish(
        self,
        *,
        command: ToolCommand,
        started_at: datetime,
        started_monotonic: float,
        exit_code: int | None,
        stdout: str,
        stderr: str,
        timed_out: bool,
        cancelled: bool,
        success: bool,
        error: ToolError | None,
    ) -> ToolResult:
        finished_at = datetime.now(timezone.utc)
        result = ToolResult(
            command=command.sanitized_argv,
            tool=command.tool,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            stdout_reference=(
                str(command.stdout_path)
                if command.stdout_path is not None
                else None
            ),
            started_at=started_at,
            finished_at=finished_at,
            duration_seconds=max(0.0, time.monotonic() - started_monotonic),
            timed_out=timed_out,
            cancelled=cancelled,
            success=success,
            error=error,
        )
        self._logger.log(
            20 if success else 40,
            "external tool finished",
            extra={
                "tool": command.tool,
                "exit_code": exit_code,
                "duration_seconds": result.duration_seconds,
                "error_code": error.code.value if error else None,
            },
        )
        return result

    @staticmethod
    def _result_error(
        *,
        exit_code: int | None,
        stderr: str,
        timed_out: bool,
        cancelled: bool,
    ) -> ToolError | None:
        if cancelled:
            return ToolError(
                code=ToolErrorCode.CANCELLED,
                message="Tool execution was cancelled",
            )
        if timed_out:
            return ToolError(
                code=ToolErrorCode.TIMEOUT,
                message="Tool execution exceeded its timeout",
                retryable=True,
            )
        if exit_code == 0:
            return None

        stderr_lower = stderr.lower()
        if "permission denied" in stderr_lower or "permission" in stderr_lower:
            return ToolError(
                code=ToolErrorCode.PERMISSION_DENIED,
                message="Tool reported a permission error",
            )

        return ToolError(
            code=ToolErrorCode.NON_ZERO_EXIT,
            message=f"Tool exited with status {exit_code}",
        )
