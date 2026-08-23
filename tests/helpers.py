from datetime import datetime, timezone
from pathlib import Path

from providers.tools import ToolError, ToolErrorCode, ToolResult


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


class RecordingRunner:
    def __init__(self, result_factory=None):
        self.commands = []
        self.result_factory = result_factory or (
            lambda command: tool_result(tool="nmap")
        )

    def run(self, command, cancellation_token=None):
        self.commands.append(command)
        if cancellation_token is not None and cancellation_token.cancelled:
            return tool_result(
                tool="nmap",
                success=False,
                exit_code=None,
                error=ToolError(
                    code=ToolErrorCode.CANCELLED,
                    message="cancelled",
                ),
            ).model_copy(update={"cancelled": True})
        return self.result_factory(command)


def xml_writer(xml, tmp_path: Path):
    def factory(command):
        if "--version" in command.args:
            return tool_result(
                tool="nmap",
                stdout="Nmap version 7.95 ( https://nmap.org )\n",
            )
        if "-oX" in command.args:
            path = Path(command.args[command.args.index("-oX") + 1])
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(xml, encoding="utf-8")
        return tool_result(tool="nmap")

    return factory
