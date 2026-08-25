"""Portable tshark front-end for advanced traffic diagnostics.

Wireshark versions differ in which tcp.analysis convenience fields they expose.
In particular, tcp.analysis.syn_retransmission is not universally available.
This wrapper requests only stable fields and derives repeated SYN deterministically
from tcp.stream + SYN/ACK flags before delegating to the common aggregator.
"""

from __future__ import annotations

from pathlib import Path
import tempfile
from typing import Any, Callable

from config.settings import Settings, get_settings
from jobs.errors import JobExecutionError
from jobs.models import ErrorCategory, JobError
from providers.tools import CancellationToken, ToolCommand, ToolRunner
from traffic_analysis.advanced import AdvancedTrafficAnalyzer, FIELDS


DERIVED_FIELD = "tcp.analysis.syn_retransmission"
TSHARK_FIELDS: tuple[str, ...] = tuple(name for name in FIELDS if name != DERIVED_FIELD)


class PortableAdvancedTrafficAnalyzer(AdvancedTrafficAnalyzer):
    def __init__(
        self,
        *,
        runner: ToolRunner | None = None,
        settings: Settings | None = None,
    ) -> None:
        super().__init__(runner=runner, settings=settings or get_settings())

    def analyze(
        self,
        pcap_path: Path,
        *,
        cancellation_token: CancellationToken | None = None,
        progress: Callable[[int, str], None] | None = None,
    ) -> dict[str, Any]:
        fd, output_name = tempfile.mkstemp(
            prefix="traffic-advanced-portable-",
            suffix=".tsv",
            dir=pcap_path.parent,
        )
        import os

        os.close(fd)
        output_path = Path(output_name)
        output_path.chmod(0o600)
        try:
            if progress:
                progress(66, "Уточняем TCP, DNS, ARP и ICMP диагностику")
            args = [
                "-r",
                str(pcap_path),
                "-n",
                "-T",
                "fields",
                "-E",
                "separator=/t",
                "-E",
                "occurrence=f",
                "-E",
                "header=n",
            ]
            for name in TSHARK_FIELDS:
                args.extend(["-e", name])
            result = self.runner.run(
                ToolCommand(
                    tool=self.settings.tshark_binary,
                    args=args,
                    timeout_seconds=900,
                    stdout_path=output_path,
                    environment={"LC_ALL": "C"},
                ),
                cancellation_token=cancellation_token,
            )
            if not result.success:
                category = ErrorCategory.INTERNAL
                code = "advanced_traffic_decode_failed"
                retryable = False
                if result.cancelled:
                    category = ErrorCategory.CANCELLED
                    code = "cancelled"
                elif result.timed_out:
                    category = ErrorCategory.TIMEOUT
                    code = "advanced_traffic_decode_timeout"
                    retryable = True
                elif result.error and result.error.code.value == "missing_binary":
                    category = ErrorCategory.TOOL_MISSING
                    code = "tshark_unavailable"
                raise JobExecutionError(
                    JobError(
                        code=code,
                        category=category,
                        message=(
                            result.error.message
                            if result.error
                            else "tshark could not perform advanced PCAP diagnostics"
                        ),
                        component="traffic_analysis",
                        retryable=retryable,
                        details={
                            "exit_code": result.exit_code,
                            "tool_error": result.error.code.value if result.error else None,
                            "stderr": result.stderr[-1000:] if result.stderr else None,
                        },
                    )
                )
            with output_path.open("r", encoding="utf-8", errors="replace") as stream:
                return self.analyze_tsv(
                    self._with_derived_syn_retransmission(stream),
                    progress=progress,
                )
        finally:
            output_path.unlink(missing_ok=True)

    @staticmethod
    def _with_derived_syn_retransmission(lines):
        source_index = {name: index for index, name in enumerate(TSHARK_FIELDS)}
        derived_index = FIELDS.index(DERIVED_FIELD)
        seen_initial_syn_streams: set[str] = set()

        for raw in lines:
            line = raw.rstrip("\r\n")
            if not line:
                continue
            columns = line.split("\t")
            if len(columns) < len(TSHARK_FIELDS):
                columns.extend([""] * (len(TSHARK_FIELDS) - len(columns)))

            def value(name: str) -> str:
                position = source_index[name]
                return columns[position].strip() if position < len(columns) else ""

            stream_id = value("tcp.stream")
            syn = value("tcp.flags.syn").lower() not in {"", "0", "false", "no"}
            ack = value("tcp.flags.ack").lower() not in {"", "0", "false", "no"}
            repeated_syn = ""
            if stream_id and syn and not ack:
                if stream_id in seen_initial_syn_streams:
                    repeated_syn = "1"
                else:
                    seen_initial_syn_streams.add(stream_id)

            columns.insert(derived_index, repeated_syn)
            yield "\t".join(columns) + "\n"
