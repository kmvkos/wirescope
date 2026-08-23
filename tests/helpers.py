from datetime import datetime, timezone

from providers.tools import ToolError, ToolResult


def tool_result(
    *,
    tool: str = "fixture",
    stdout: str = "",
    stderr: str = "",
    exit_code: int | None = 0,
    success: bool = True,
    error: ToolError | None = None,
) -> ToolResult:
    now = datetime.now(timezone.utc)
    return ToolResult(
        command=[tool],
        tool=tool,
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        started_at=now,
        finished_at=now,
        duration_seconds=0,
        success=success,
        error=error,
    )
