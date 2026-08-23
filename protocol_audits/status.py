"""Shared observation helpers independent of persistence."""

from engine.passive_models import ConfidenceLevel
from protocol_audits.models import ObservationDraft
from providers.tools import ToolErrorCode, ToolResult


def tool_status_observation(
    result: ToolResult,
    *,
    source: str,
    parse_on_nonzero_exit: bool,
) -> ObservationDraft | None:
    if result.cancelled:
        return ObservationDraft(
            kind="cancelled",
            data={"tool": result.tool},
            confidence=ConfidenceLevel.UNKNOWN,
            source=source,
        )
    if result.timed_out or (
        result.error is not None
        and result.error.code is ToolErrorCode.TIMEOUT
    ):
        return ObservationDraft(
            kind="tool_timeout",
            data={
                "tool": result.tool,
                "exit_code": result.exit_code,
            },
            confidence=ConfidenceLevel.UNKNOWN,
            source=source,
        )
    if result.error is not None and result.error.code is ToolErrorCode.MISSING_BINARY:
        return ObservationDraft(
            kind="tool_unavailable",
            data={"tool": result.tool, "message": result.error.message},
            confidence=ConfidenceLevel.UNKNOWN,
            source=source,
        )
    if result.success:
        if not (result.stdout or result.stderr):
            return ObservationDraft(
                kind="empty_output",
                data={"tool": result.tool, "exit_code": result.exit_code},
                confidence=ConfidenceLevel.UNKNOWN,
                source=source,
            )
        return None
    if parse_on_nonzero_exit and (result.stdout or result.stderr):
        return None
    return ObservationDraft(
        kind="tool_failed",
        data={
            "tool": result.tool,
            "exit_code": result.exit_code,
            "error_code": (
                result.error.code.value if result.error is not None else None
            ),
        },
        confidence=ConfidenceLevel.UNKNOWN,
        source=source,
    )


def unavailable_observation(tool: str, message: str) -> ObservationDraft:
    return ObservationDraft(
        kind="tool_unavailable",
        data={"tool": tool, "message": message},
        confidence=ConfidenceLevel.UNKNOWN,
        source=tool,
    )


def malformed_observation(source: str, message: str) -> ObservationDraft:
    return ObservationDraft(
        kind="malformed_output",
        data={"message": message},
        confidence=ConfidenceLevel.UNKNOWN,
        source=source,
    )
