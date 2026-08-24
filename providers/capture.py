"""Bounded dumpcap packet capture provider."""

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
import re
import shutil
import tempfile
import threading
import time

from config.logging import get_logger
from config.settings import Settings, get_settings
from engine.interfaces import InterfaceInfo
from engine.passive_models import (
    CaptureResult,
    CaptureStatus,
    PipelineError,
    PipelineErrorCode,
)
from providers.bpf import normalize_bpf_filter
from providers.tools import (
    CancellationToken,
    ToolCommand,
    ToolErrorCode,
    ToolResult,
    ToolRunner,
)


PACKET_COUNT_PATTERN = re.compile(r"Packets captured:\s*(\d+)", re.IGNORECASE)
DROPPED_COUNT_PATTERN = re.compile(
    r"Packets dropped(?: by kernel)?:\s*(\d+)",
    re.IGNORECASE,
)
DUMPCAP_PERMISSION_MESSAGE = (
    "Packet capture denied: dumpcap needs the wireshark group "
    "in this service session"
)
DUMPCAP_MISSING_MESSAGE = "Packet capture denied: dumpcap is not available"
PCAP_HEADER_BYTES = 24


@dataclass
class CaptureStats:
    frame_count: int | None = None
    byte_count: int = 0
    elapsed_seconds: float = 0.0
    percentage: int = 0


def _dumpcap_error_message(tool_result: ToolResult) -> str:
    error = tool_result.error
    if error is None:
        return "dumpcap capture failed"
    if error.code == ToolErrorCode.PERMISSION_DENIED:
        return DUMPCAP_PERMISSION_MESSAGE
    if error.code == ToolErrorCode.MISSING_BINARY:
        return DUMPCAP_MISSING_MESSAGE
    return error.message


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

        args = ["-i", interface.name]
        if not self.settings.capture_promiscuous:
            args.append("-p")
        args.extend(
            [
                "-s",
                str(self.settings.capture_snaplen),
                "-a",
                f"duration:{duration_seconds}",
                "-c",
                str(self.settings.capture_max_packets),
                "-a",
                f"filesize:{self.settings.capture_max_filesize_kb}",
                "-w",
                str(pcap_path),
                "-q",
            ]
        )

        tool_result = self.runner.run(
            ToolCommand(
                tool=self.settings.dumpcap_binary,
                args=args,
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
                    message=_dumpcap_error_message(tool_result),
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
        dropped_packets = self._dropped_count(tool_result.stderr)
        warnings = []
        if dropped_packets:
            warnings.append(
                f"dumpcap reported {dropped_packets} dropped packets"
            )
        result = CaptureResult(
            interface=interface.name,
            status=status,
            started_at=tool_result.started_at,
            finished_at=tool_result.finished_at,
            duration_seconds=tool_result.duration_seconds,
            frame_count=frame_count,
            dropped_packets=dropped_packets,
            pcap_path=str(pcap_path),
            pcap_reference=f"capture:{capture_directory.name}/capture.pcap",
            retained=retain,
            warnings=warnings,
            errors=errors,
            tool_result=tool_result,
        )

        if status != CaptureStatus.COMPLETED:
            self.cleanup(result, force=True)
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

    def record(
        self,
        interface: InterfaceInfo,
        *,
        duration_seconds: int | None,
        max_filesize_kb: int,
        bpf_filter: str | None = None,
        cancellation_token: CancellationToken | None = None,
        progress_callback: Callable[[CaptureStats], None] | None = None,
    ) -> CaptureResult:
        """Promiscuous listen capture; always retain the pcap when present."""
        filter_text = normalize_bpf_filter(
            bpf_filter,
            max_length=self.settings.listen_filter_max_length,
        )
        if duration_seconds is None:
            duration_seconds = self.settings.listen_duration_default
        self._validate_listen_limits(duration_seconds, max_filesize_kb)
        capture_directory = self._create_capture_directory()
        pcap_path = capture_directory / "capture.pcap"
        self.logger.info(
            "listen capture started",
            extra={
                "interface": interface.name,
                "duration_seconds": duration_seconds,
                "max_filesize_kb": max_filesize_kb,
                "filter": filter_text,
            },
        )

        args = ["-i", interface.name]
        if filter_text is not None:
            args.extend(["-f", filter_text])
        args.extend(["-s", str(self.settings.capture_snaplen)])
        if duration_seconds > 0:
            args.extend(["-a", f"duration:{duration_seconds}"])
        args.extend(
            [
                "-a",
                f"filesize:{max_filesize_kb}",
                "-w",
                str(pcap_path),
            ]
        )
        timeout_seconds = (
            duration_seconds + 15
            if duration_seconds > 0
            else self.settings.listen_duration_max + 15
        )

        stderr_buffer = ""
        stats_lock = threading.Lock()
        latest = CaptureStats()
        stop_monitor = threading.Event()
        started_monotonic = time.monotonic()

        def on_stderr(chunk: str) -> None:
            nonlocal stderr_buffer
            with stats_lock:
                stderr_buffer = (stderr_buffer + chunk.replace("\r", "\n"))[-8192:]
                frames = self._packet_count(stderr_buffer)
                if frames is not None:
                    latest.frame_count = frames

        def emit_stats() -> None:
            elapsed = time.monotonic() - started_monotonic
            size = pcap_path.stat().st_size if pcap_path.is_file() else 0
            ratios: list[float] = []
            if duration_seconds > 0:
                ratios.append(elapsed / duration_seconds)
            if max_filesize_kb > 0:
                ratios.append(size / (max_filesize_kb * 1024))
            percentage = min(99, int(max(ratios) * 99)) if ratios else 0
            with stats_lock:
                latest.byte_count = size
                latest.elapsed_seconds = elapsed
                latest.percentage = percentage
                snapshot = CaptureStats(
                    frame_count=latest.frame_count,
                    byte_count=latest.byte_count,
                    elapsed_seconds=latest.elapsed_seconds,
                    percentage=latest.percentage,
                )
            if progress_callback is not None:
                progress_callback(snapshot)

        def monitor() -> None:
            while not stop_monitor.wait(1.0):
                emit_stats()

        monitor_thread = threading.Thread(
            target=monitor,
            daemon=True,
            name="listen-capture-stats",
        )
        monitor_thread.start()
        try:
            tool_result = self.runner.run(
                ToolCommand(
                    tool=self.settings.dumpcap_binary,
                    args=args,
                    timeout_seconds=timeout_seconds,
                    environment={"LC_ALL": "C"},
                    on_stderr=on_stderr,
                ),
                cancellation_token=cancellation_token,
            )
        finally:
            stop_monitor.set()
            monitor_thread.join(timeout=2)
            emit_stats()

        stderr_text = tool_result.stderr.replace("\r", "\n")
        pcap_exists = pcap_path.is_file() and pcap_path.stat().st_size >= PCAP_HEADER_BYTES
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
                    message=_dumpcap_error_message(tool_result),
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
        elif not pcap_exists:
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

        frame_count = self._packet_count(stderr_text)
        if frame_count is None:
            frame_count = latest.frame_count
        dropped_packets = self._dropped_count(stderr_text)
        warnings = []
        if dropped_packets:
            warnings.append(
                f"dumpcap reported {dropped_packets} dropped packets"
            )
        byte_count = pcap_path.stat().st_size if pcap_path.is_file() else 0
        result = CaptureResult(
            interface=interface.name,
            status=status,
            started_at=tool_result.started_at,
            finished_at=tool_result.finished_at,
            duration_seconds=tool_result.duration_seconds,
            frame_count=frame_count,
            dropped_packets=dropped_packets,
            pcap_path=str(pcap_path) if pcap_path.is_file() else None,
            pcap_reference=f"capture:{capture_directory.name}/capture.pcap",
            retained=True,
            warnings=warnings,
            errors=errors,
            tool_result=tool_result,
        )
        result.tool_result = tool_result.model_copy(
            update={"stderr": stderr_text},
        )
        if status == CaptureStatus.FAILED or (
            status == CaptureStatus.CANCELLED and not pcap_exists
        ):
            self.cleanup(result, force=True)
        self.logger.log(
            20 if status in {CaptureStatus.COMPLETED, CaptureStatus.CANCELLED} else 40,
            "listen capture finished",
            extra={
                "interface": interface.name,
                "capture_status": status.value,
                "frame_count": frame_count,
                "byte_count": byte_count,
                "duration_seconds": result.duration_seconds,
            },
        )
        return result

    def cleanup(
        self,
        capture_result: CaptureResult,
        *,
        force: bool = False,
    ) -> list[PipelineError]:
        if (capture_result.retained and not force) or not capture_result.pcap_path:
            return []

        pcap_path = Path(capture_result.pcap_path)
        try:
            capture_root = self.settings.capture_dir.resolve()
            parent = pcap_path.parent.resolve()
            if parent.parent != capture_root:
                raise ValueError("capture path is outside the managed root")
            shutil.rmtree(parent)
            capture_result.pcap_path = None
            capture_result.retained = False
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

    def _validate_listen_limits(
        self,
        duration_seconds: int,
        max_filesize_kb: int,
    ) -> None:
        if duration_seconds < 0:
            raise ValueError("Listen duration must not be negative")
        if duration_seconds > self.settings.listen_duration_max:
            raise ValueError(
                "Listen duration must be at most "
                f"{self.settings.listen_duration_max} seconds"
            )
        if (
            duration_seconds > 0
            and duration_seconds < self.settings.listen_duration_min
        ):
            raise ValueError(
                "Listen duration must be between "
                f"{self.settings.listen_duration_min} and "
                f"{self.settings.listen_duration_max} seconds, or 0 to stop manually"
            )
        if not (
            1
            <= max_filesize_kb
            <= self.settings.listen_max_filesize_kb_max
        ):
            raise ValueError(
                "Listen file size must be between 1 and "
                f"{self.settings.listen_max_filesize_kb_max} KiB"
            )

    @staticmethod
    def _packet_count(stderr: str) -> int | None:
        matches = PACKET_COUNT_PATTERN.findall(stderr.replace("\r", "\n"))
        return int(matches[-1]) if matches else None

    @staticmethod
    def _dropped_count(stderr: str) -> int | None:
        match = DROPPED_COUNT_PATTERN.search(stderr)
        return int(match.group(1)) if match else None
