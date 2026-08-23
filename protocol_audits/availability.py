"""Tool presence and minimum-version checks for protocol modules."""

from collections.abc import Sequence
import re
import shutil

from config.settings import Settings
from protocol_audits.models import ToolAvailability
from providers.tools import ToolCommand, ToolRunner


_VERSION_RE = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))?")


def parse_version_tuple(text: str) -> tuple[int, ...] | None:
    match = _VERSION_RE.search(text)
    if match is None:
        return None
    return tuple(int(part) for part in match.groups() if part is not None)


def version_meets(actual: str | None, minimum: str | None) -> bool:
    if not minimum:
        return True
    if not actual:
        return True
    actual_tuple = parse_version_tuple(actual)
    minimum_tuple = parse_version_tuple(minimum)
    if actual_tuple is None or minimum_tuple is None:
        return True
    return actual_tuple >= minimum_tuple


def locate_binary(tool: str) -> str | None:
    return shutil.which(tool)


def inspect_tool(
    *,
    tool: str,
    runner: ToolRunner,
    version_args: Sequence[str] = ("--version",),
    minimum_version: str | None = None,
    timeout_seconds: float = 5,
) -> ToolAvailability:
    binary_path = locate_binary(tool)
    if binary_path is None:
        return ToolAvailability(
            tool=tool,
            available=False,
            meets_minimum=False,
            message=f"Required tool is not installed: {tool}",
        )
    result = runner.run(
        ToolCommand(
            tool=tool,
            args=list(version_args),
            timeout_seconds=timeout_seconds,
        )
    )
    version_text = "\n".join(
        part for part in (result.stdout, result.stderr) if part
    )
    version = None
    parsed = parse_version_tuple(version_text)
    if parsed is not None:
        version = ".".join(str(part) for part in parsed)
    meets = version_meets(version, minimum_version)
    message = "available"
    if not meets:
        message = (
            f"{tool} {version or 'unknown'} is below minimum {minimum_version}"
        )
    return ToolAvailability(
        tool=tool,
        available=True,
        version=version,
        binary_path=binary_path,
        meets_minimum=meets,
        message=message,
    )


def settings_timeout(settings: Settings, module_timeout: float) -> float:
    return float(
        min(settings.protocol_audit_timeout_seconds, module_timeout)
        if settings.protocol_audit_timeout_seconds
        else module_timeout
    )
