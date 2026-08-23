from dataclasses import replace
from pathlib import Path

from config.settings import get_settings
from engine.interfaces import InterfaceInfo
from engine.passive_models import CaptureStatus, PipelineErrorCode
from providers.capture import CaptureProvider
from providers.tools import ToolError, ToolErrorCode
from tests.helpers import tool_result


class SuccessfulDumpcap:
    def run(self, command, cancellation_token=None):
        self.command = command
        output = Path(command.args[command.args.index("-w") + 1])
        output.write_bytes(b"pcap")
        return tool_result(
            tool="dumpcap",
            stderr="Packets captured: 4\nPackets dropped: 2\n",
        )


class PermissionDeniedDumpcap:
    def run(self, command, cancellation_token=None):
        return tool_result(
            tool="dumpcap",
            stderr="Permission denied",
            exit_code=1,
            success=False,
            error=ToolError(
                code=ToolErrorCode.PERMISSION_DENIED,
                message="Tool reported a permission error",
            ),
        )


def settings_for(tmp_path):
    return replace(
        get_settings(),
        capture_dir=tmp_path / "captures",
        passive_duration_min=1,
        passive_duration_max=60,
    )


def interface():
    return InterfaceInfo(
        name="eth0",
        state="UP",
        allowed=True,
    )


def test_capture_provider_separates_capture_metadata_and_cleanup(tmp_path):
    runner = SuccessfulDumpcap()
    provider = CaptureProvider(
        runner=runner,
        settings=settings_for(tmp_path),
    )

    result = provider.capture(interface(), 1)

    assert result.status == CaptureStatus.COMPLETED
    assert result.frame_count == 4
    assert result.dropped_packets == 2
    assert result.warnings == ["dumpcap reported 2 dropped packets"]
    assert result.pcap_path is not None
    assert Path(result.pcap_path).is_file()
    assert result.errors == []
    assert "-p" in runner.command.args
    assert runner.command.args[
        runner.command.args.index("-s") + 1
    ] == "65535"

    assert provider.cleanup(result) == []
    assert result.pcap_path is None
    assert not any((tmp_path / "captures").iterdir())


def test_capture_permission_error_is_not_silent_absence(tmp_path):
    provider = CaptureProvider(
        runner=PermissionDeniedDumpcap(),
        settings=settings_for(tmp_path),
    )

    result = provider.capture(interface(), 1)

    assert result.status == CaptureStatus.FAILED
    assert result.errors[0].code == PipelineErrorCode.CAPTURE_FAILED
    assert (
        result.errors[0].details["tool_error"]
        == ToolErrorCode.PERMISSION_DENIED.value
    )
    assert result.pcap_path is None
