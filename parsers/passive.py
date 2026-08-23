"""Single-pass tshark EK decoder for passive packet records."""

from collections import defaultdict
from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
from typing import Any, Iterable

from config.settings import Settings, get_settings
from engine.passive_models import (
    PacketDataset,
    PacketRecord,
    PipelineError,
    PipelineErrorCode,
)
from providers.tools import CancellationToken, ToolCommand, ToolRunner


class PassivePacketParser:
    def __init__(
        self,
        runner: ToolRunner | None = None,
        settings: Settings | None = None,
    ) -> None:
        self.runner = runner or ToolRunner()
        self.settings = settings or get_settings()

    def decode(
        self,
        pcap_path: Path,
        *,
        cancellation_token: CancellationToken | None = None,
    ) -> PacketDataset:
        output_fd, output_name = tempfile.mkstemp(
            prefix="decode_",
            suffix=".ek.jsonl",
            dir=pcap_path.parent,
        )
        Path(output_name).chmod(0o600)
        try:
            # ToolRunner owns the descriptor used for command output.
            # Closing this descriptor avoids leaking the mkstemp handle.
            import os

            os.close(output_fd)
            output_path = Path(output_name)
            decode_result = self.runner.run(
                ToolCommand(
                    tool=self.settings.tshark_binary,
                    args=[
                        "-r",
                        str(pcap_path),
                        "-n",
                        "-l",
                        "-T",
                        "ek",
                    ],
                    timeout_seconds=max(
                        30,
                        self.settings.passive_duration_max,
                    ),
                    stdout_path=output_path,
                    environment={"LC_ALL": "C"},
                ),
                cancellation_token=cancellation_token,
            )

            if not decode_result.success:
                return PacketDataset(
                    packets=[],
                    errors=[
                        PipelineError(
                            code=(
                                PipelineErrorCode.CANCELLED
                                if decode_result.cancelled
                                else PipelineErrorCode.DECODE_FAILED
                            ),
                            component="passive_parser",
                            message=(
                                decode_result.error.message
                                if decode_result.error
                                else "tshark decode failed"
                            ),
                            retryable=(
                                decode_result.error.retryable
                                if decode_result.error
                                else False
                            ),
                            details={
                                "tool_error": (
                                    decode_result.error.code.value
                                    if decode_result.error
                                    else None
                                ),
                                "exit_code": decode_result.exit_code,
                                "stderr": decode_result.stderr,
                            },
                        )
                    ],
                    decode_result=decode_result,
                    decode_reference=f"decode:{pcap_path.name}",
                )

            with output_path.open(encoding="utf-8") as stream:
                packets, errors = self.parse_ek_stream(stream)

            return PacketDataset(
                packets=packets,
                errors=errors,
                decode_result=decode_result,
                decode_reference=f"decode:{pcap_path.name}",
            )
        finally:
            try:
                Path(output_name).unlink(missing_ok=True)
            except OSError:
                pass

    def parse_ek_stream(
        self,
        lines: Iterable[str],
    ) -> tuple[list[PacketRecord], list[PipelineError]]:
        packets: list[PacketRecord] = []
        errors: list[PipelineError] = []

        for line_number, raw_line in enumerate(lines, start=1):
            line = raw_line.strip()
            if not line:
                continue

            try:
                document = json.loads(line)
            except json.JSONDecodeError as exc:
                errors.append(
                    PipelineError(
                        code=PipelineErrorCode.MALFORMED_INPUT,
                        component="passive_parser",
                        message=f"Malformed EK JSON at line {line_number}",
                        details={"error": str(exc)},
                    )
                )
                continue

            if "index" in document and "layers" not in document:
                continue

            layers = document.get("layers")
            if not isinstance(layers, dict):
                continue

            fields = self._flatten_fields(layers)
            draft = PacketRecord(
                frame_number=len(packets) + 1,
                fields=fields,
            )

            frame_number = self._integer(
                draft.first("frame.number", "frame_number")
            )
            timestamp = self._timestamp(
                draft.first("frame.time_epoch", "timestamp")
                or document.get("timestamp")
            )
            protocols = self._protocols(
                draft.first("frame.protocols", "protocols")
            )

            packets.append(
                PacketRecord(
                    frame_number=frame_number or len(packets) + 1,
                    timestamp=timestamp,
                    protocols=protocols,
                    source_mac=draft.first("eth.src", "wlan.sa"),
                    destination_mac=draft.first("eth.dst", "wlan.da"),
                    source_ip=draft.first("ip.src", "ipv6.src"),
                    destination_ip=draft.first("ip.dst", "ipv6.dst"),
                    fields=fields,
                )
            )

        return packets, errors

    def _flatten_fields(
        self,
        layers: dict[str, Any],
    ) -> dict[str, list[str]]:
        flattened: defaultdict[str, list[str]] = defaultdict(list)

        def visit(value: Any, path: str) -> None:
            if isinstance(value, dict):
                for key, child in value.items():
                    child_path = f"{path}.{key}" if path else str(key)
                    visit(child, child_path)
            elif isinstance(value, list):
                for child in value:
                    visit(child, path)
            elif value is not None:
                text = str(value)
                if text not in flattened[path]:
                    flattened[path].append(text)

        visit(layers, "")
        return dict(flattened)

    @staticmethod
    def _integer(value: str | None) -> int | None:
        if value is None:
            return None
        try:
            return int(value, 0)
        except ValueError:
            digits = "".join(character for character in value if character.isdigit())
            return int(digits) if digits else None

    @staticmethod
    def _timestamp(value: Any) -> datetime | None:
        if value in (None, ""):
            return None
        if isinstance(value, str) and ("T" in value or value.endswith("Z")):
            try:
                return datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                pass
        try:
            timestamp = float(value)
            if timestamp > 1_000_000_000_000_000:
                timestamp /= 1_000_000_000
            elif timestamp > 1_000_000_000_000:
                timestamp /= 1_000
            return datetime.fromtimestamp(timestamp, tz=timezone.utc)
        except (TypeError, ValueError, OSError):
            return None

    @staticmethod
    def _protocols(value: str | None) -> list[str]:
        if not value:
            return []
        return [
            protocol.strip().lower()
            for protocol in value.replace(",", ":").split(":")
            if protocol.strip()
        ]
