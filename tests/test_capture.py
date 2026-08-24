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
        output.write_bytes(b"pcap-header-placeholder!!!!")
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
    assert "wireshark group" in result.errors[0].message
    assert result.pcap_path is None


def test_force_cleanup_removes_retained_capture(tmp_path):
    provider = CaptureProvider(
        runner=SuccessfulDumpcap(),
        settings=settings_for(tmp_path),
    )
    result = provider.capture(interface(), 1, retain=True)
    capture_path = Path(result.pcap_path)

    assert provider.cleanup(result) == []
    assert capture_path.exists()
    assert provider.cleanup(result, force=True) == []
    assert not capture_path.exists()
    assert result.retained is False


def test_listen_record_is_promiscuous_passes_filter_as_single_arg(tmp_path):
    runner = SuccessfulDumpcap()
    settings = replace(
        settings_for(tmp_path),
        listen_duration_min=1,
        listen_duration_max=60,
        listen_duration_default=5,
        listen_max_filesize_kb_default=1024,
        listen_max_filesize_kb_max=2048,
    )
    provider = CaptureProvider(runner=runner, settings=settings)

    result = provider.record(
        interface(),
        duration_seconds=5,
        max_filesize_kb=1024,
        bpf_filter="tcp port 80",
    )

    assert result.status == CaptureStatus.COMPLETED
    assert result.retained is True
    assert "-p" not in runner.command.args
    assert "-c" not in runner.command.args
    filter_index = runner.command.args.index("-f")
    assert runner.command.args[filter_index + 1] == "tcp port 80"
    assert runner.command.args[runner.command.args.index("-a") + 1] == "duration:5"
    assert "filesize:1024" in runner.command.args
    assert runner.command.argv[0] == settings.dumpcap_binary
    assert result.pcap_path is not None
    assert Path(result.pcap_path).is_file()
