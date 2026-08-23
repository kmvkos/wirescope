"""Bounded dumpcap packet capture provider."""

from datetime import datetime, timezone
from pathlib import Path
import re
import shutil
import tempfile

from config.logging import get_logger
from config.settings import Settings, get_settings
from engine.interfaces import InterfaceInfo
from engine.passive_models import (
    CaptureResult,
    CaptureStatus,
    PipelineError,
    PipelineErrorCode,
)
from providers.tools import CancellationToken, ToolCommand, ToolRunner


PACKET_COUNT_PATTERN = re.compile(r"Packets captured:\s*(\d+)", re.IGNORECASE)


class CaptureProvider:
    def __init__(
        self,
        runner: ToolRunner | None = None,
        settings: Settings | None = None,
    ) -> None:
        self.runner = runner or ToolRunner()
        self.settings = settings or get_settings()
        self.logger = get_logger("capture")

    def capture(
        self,
        interface: InterfaceInfo,
        duration_seconds: int,
        *,
        retain: bool = False,
        cancellation_token: CancellationToken | None = None,
    ) -> CaptureResult:
        self._validate_duration(duration_seconds)
        capture_directory = self._create_capture_directory()
        pcap_path = capture_directory / "capture.pcap"
        self.logger.info(
            "packet capture started",
            extra={
                "interface": interface.name,
                "duration_seconds": duration_seconds,
            },
        )

        tool_result = self.runner.run(
            ToolCommand(
                tool=self.settings.dumpcap_binary,
                args=[
                    "-i",
                    interface.name,
                    "-a",
                    f"duration:{duration_seconds}",
                    "-c",
                    str(self.settings.capture_max_packets),
                    "-a",
                    f"filesize:{self.settings.capture_max_filesize_kb}",
                    "-w",
                    str(pcap_path),
                    "-q",
                ],
                timeout_seconds=duration_seconds + 15,
                environment={"LC_ALL": "C"},
            ),
            cancellation_token=cancellation_token,
        )

        errors: list[PipelineError] = []
        if tool_result.cancelled:
            status = CaptureStatus.CANCELLED
            errors.append(
                PipelineError(
                    code=PipelineErrorCode.CANCELLED,
                    component="capture",
                    message="Packet capture was cancelled",
                )
            )
        elif not tool_result.success:
            status = CaptureStatus.FAILED
            errors.append(
                PipelineError(
                    code=PipelineErrorCode.CAPTURE_FAILED,
                    component="capture",
                    message=(
                        tool_result.error.message
                        if tool_result.error
                        else "dumpcap capture failed"
                    ),
                    retryable=(
                        tool_result.error.retryable
                        if tool_result.error
                        else False
                    ),
                    details={
                        "tool_error": (
                            tool_result.error.code.value
                            if tool_result.error
                            else None
                        ),
                        "exit_code": tool_result.exit_code,
                        "stderr": tool_result.stderr,
                    },
                )
            )
        elif not pcap_path.is_file():
            status = CaptureStatus.FAILED
            errors.append(
                PipelineError(
                    code=PipelineErrorCode.CAPTURE_FAILED,
                    component="capture",
                    message="dumpcap completed without producing a pcap",
                )
            )
        else:
            status = CaptureStatus.COMPLETED

        frame_count = self._packet_count(tool_result.stderr)
        result = CaptureResult(
            interface=interface.name,
            status=status,
            started_at=tool_result.started_at,
            finished_at=tool_result.finished_at,
            duration_seconds=tool_result.duration_seconds,
            frame_count=frame_count,
            pcap_path=str(pcap_path),
            pcap_reference=f"capture:{capture_directory.name}/capture.pcap",
            retained=retain,
            errors=errors,
            tool_result=tool_result,
        )

        if status != CaptureStatus.COMPLETED:
            self.cleanup(result)
        self.logger.log(
            20 if status == CaptureStatus.COMPLETED else 40,
            "packet capture finished",
            extra={
                "interface": interface.name,
                "capture_status": status.value,
                "frame_count": frame_count,
                "duration_seconds": result.duration_seconds,
            },
        )
        return result

    def cleanup(self, capture_result: CaptureResult) -> list[PipelineError]:
        if capture_result.retained or not capture_result.pcap_path:
            return []

        pcap_path = Path(capture_result.pcap_path)
        try:
            capture_root = self.settings.capture_dir.resolve()
            parent = pcap_path.parent.resolve()
            if parent.parent != capture_root:
                raise ValueError("capture path is outside the managed root")
            shutil.rmtree(parent)
            capture_result.pcap_path = None
            return []
        except (OSError, ValueError) as exc:
            error = PipelineError(
                code=PipelineErrorCode.CLEANUP_FAILED,
                component="capture",
                message=f"Could not remove temporary capture: {exc}",
            )
            self.logger.error(
                "capture cleanup failed",
                extra={
                    "interface": capture_result.interface,
                    "error": str(exc),
                },
            )
            return [error]

    def _create_capture_directory(self) -> Path:
        self.settings.capture_dir.mkdir(
            mode=0o700,
            parents=True,
            exist_ok=True,
        )
        directory = Path(
            tempfile.mkdtemp(
                prefix="wirescope_",
                dir=self.settings.capture_dir,
            )
        )
        directory.chmod(0o700)
        return directory

    def _validate_duration(self, duration_seconds: int) -> None:
        if not (
            self.settings.passive_duration_min
            <= duration_seconds
            <= self.settings.passive_duration_max
        ):
            raise ValueError(
                "Passive duration must be between "
                f"{self.settings.passive_duration_min} and "
                f"{self.settings.passive_duration_max} seconds"
            )

    @staticmethod
    def _packet_count(stderr: str) -> int | None:
        match = PACKET_COUNT_PATTERN.search(stderr)
        return int(match.group(1)) if match else None
