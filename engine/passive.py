"""Passive capture, single-pass decode, sensors, and assessment orchestration."""

from datetime import datetime, timezone
import json
from pathlib import Path
from collections.abc import Callable

from config.settings import Settings, get_settings
from engine.assessment import build_assessment
from engine.interfaces import InterfaceService
from engine.passive_models import (
    CaptureResult,
    CaptureStatus,
    PacketDataset,
    PassiveMetrics,
    PassiveResult,
    PipelineError,
    PipelineErrorCode,
    SensorResult,
    SensorStatus,
)
from parsers.passive import PassivePacketParser
from providers.capture import CaptureProvider
from providers.tools import (
    CancellationToken,
    ToolCommand,
    ToolResult,
    ToolRunner,
)
from sensors.passive import PASSIVE_SENSORS, run_passive_sensors


ProgressCallback = Callable[[int, str, str], None]


class PassivePipeline:
    def __init__(
        self,
        *,
        runner: ToolRunner | None = None,
        settings: Settings | None = None,
        interfaces: InterfaceService | None = None,
        capture_provider: CaptureProvider | None = None,
        parser: PassivePacketParser | None = None,
    ) -> None:
        self.runner = runner or ToolRunner()
        self.settings = settings or get_settings()
        self.interfaces = interfaces or InterfaceService(
            runner=self.runner,
            settings=self.settings,
        )
        self.capture_provider = capture_provider or CaptureProvider(
            runner=self.runner,
            settings=self.settings,
        )
        self.parser = parser or PassivePacketParser(
            runner=self.runner,
            settings=self.settings,
        )

    def run(
        self,
        interface_name: str,
        duration_seconds: int | None = None,
        *,
        retain_capture: bool = False,
        cancellation_token: CancellationToken | None = None,
        progress_callback: ProgressCallback | None = None,
    ) -> PassiveResult:
        duration = (
            duration_seconds
            if duration_seconds is not None
            else self.settings.passive_duration_default
        )
        self._progress(
            progress_callback,
            5,
            "preparing_interface",
            "Preparing interface",
        )
        interface = self.interfaces.validate(interface_name)
        before = self.runner.metrics_snapshot()
        self._progress(
            progress_callback,
            10,
            "capturing",
            "Starting packet capture",
        )
        capture = self.capture_provider.capture(
            interface,
            duration,
            retain=retain_capture,
            cancellation_token=cancellation_token,
        )

        errors = list(capture.errors)
        self._progress(
            progress_callback,
            50,
            "capture_complete",
            "Packet capture complete",
        )
        if capture.status != CaptureStatus.COMPLETED or not capture.pcap_path:
            sensors = self._unavailable_sensors(errors)
            self._progress(
                progress_callback,
                95,
                "building_assessment",
                "Building partial assessment",
            )
            assessment = build_assessment(capture, sensors)
            return PassiveResult(
                interface=interface.name,
                requested_duration_seconds=duration,
                capture=capture,
                sensors=sensors,
                assessment=assessment,
                errors=errors,
                metrics=self._metrics_since(before),
            )

        try:
            try:
                self._progress(
                    progress_callback,
                    60,
                    "parsing_packets",
                    "Parsing captured packets",
                )
                dataset = self.parser.decode(
                    Path(capture.pcap_path),
                    cancellation_token=cancellation_token,
                )
                capture.frame_count = len(dataset.packets)
                errors.extend(dataset.errors)
                self._progress(
                    progress_callback,
                    85,
                    "running_sensors",
                    "Running passive sensors",
                )
                sensors = run_passive_sensors(dataset)
            except Exception as exc:
                parser_error = PipelineError(
                    code=PipelineErrorCode.DECODE_FAILED,
                    component="passive_parser",
                    message=f"Unexpected passive decode failure: {exc}",
                )
                errors.append(parser_error)
                sensors = self._unavailable_sensors([parser_error])
            self._progress(
                progress_callback,
                95,
                "building_assessment",
                "Building assessment",
            )
            assessment = build_assessment(capture, sensors)
        finally:
            if not retain_capture:
                cleanup_errors = self.capture_provider.cleanup(capture)
                errors.extend(cleanup_errors)

        return PassiveResult(
            interface=interface.name,
            requested_duration_seconds=duration,
            capture=capture,
            sensors=sensors,
            assessment=assessment,
            errors=errors,
            metrics=self._metrics_since(before),
        )

    def analyze_pcap(
        self,
        pcap_path: Path,
        *,
        interface_name: str = "fixture",
        cancellation_token: CancellationToken | None = None,
    ) -> PassiveResult:
        before = self.runner.metrics_snapshot()
        dataset = self.parser.decode(
            pcap_path,
            cancellation_token=cancellation_token,
        )
        capture = self._fixture_capture(
            pcap_path,
            interface_name,
            dataset,
        )
        sensors = run_passive_sensors(dataset)
        assessment = build_assessment(capture, sensors)
        return PassiveResult(
            interface=interface_name,
            requested_duration_seconds=0,
            capture=capture,
            sensors=sensors,
            assessment=assessment,
            errors=list(dataset.errors),
            metrics=self._metrics_since(before),
        )

    def _metrics_since(self, before: dict[str, int]) -> PassiveMetrics:
        after = self.runner.metrics_snapshot()
        capture_count = (
            after.get(self.settings.dumpcap_binary, 0)
            - before.get(self.settings.dumpcap_binary, 0)
        )
        decode_count = (
            after.get(self.settings.tshark_binary, 0)
            - before.get(self.settings.tshark_binary, 0)
        )
        return PassiveMetrics(
            capture_subprocesses=max(0, capture_count),
            decode_subprocesses=max(0, decode_count),
        )

    @staticmethod
    def _progress(
        callback: ProgressCallback | None,
        percentage: int,
        stage: str,
        message: str,
    ) -> None:
        if callback is not None:
            callback(percentage, stage, message)

    @staticmethod
    def _unavailable_sensors(
        errors: list[PipelineError],
    ) -> dict[str, SensorResult]:
        fallback = errors or [
            PipelineError(
                code=PipelineErrorCode.CAPTURE_FAILED,
                component="capture",
                message="Packet capture is unavailable",
            )
        ]
        return {
            name: SensorResult(
                name=name,
                status=SensorStatus.ERROR,
                errors=[item.model_copy() for item in fallback],
            )
            for name in PASSIVE_SENSORS
        }

    @staticmethod
    def _fixture_capture(
        pcap_path: Path,
        interface_name: str,
        dataset: PacketDataset,
    ) -> CaptureResult:
        decode_result = dataset.decode_result
        status = (
            CaptureStatus.COMPLETED
            if decode_result.success
            else CaptureStatus.FAILED
        )
        return CaptureResult(
            interface=interface_name,
            status=status,
            started_at=decode_result.started_at,
            finished_at=decode_result.finished_at,
            duration_seconds=decode_result.duration_seconds,
            frame_count=len(dataset.packets),
            pcap_path=str(pcap_path),
            pcap_reference=f"fixture:{pcap_path.name}",
            retained=True,
            errors=list(dataset.errors),
            tool_result=decode_result,
        )


def passive_discovery(
    interface: str,
    duration: int = 30,
) -> dict:
    return PassivePipeline().run(
        interface,
        duration,
    ).model_dump(mode="json")


def analyze_pcap(pcap: str | Path) -> dict:
    return PassivePipeline().analyze_pcap(
        Path(pcap),
    ).model_dump(mode="json")


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python -m engine.passive <interface> [seconds]")
        raise SystemExit(1)

    interface_name = sys.argv[1]
    capture_duration = (
        int(sys.argv[2])
        if len(sys.argv) >= 3
        else get_settings().passive_duration_default
    )
    print(
        json.dumps(
            passive_discovery(interface_name, capture_duration),
            indent=2,
        )
    )
