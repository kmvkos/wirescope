"""Portable TCP ACK RTT hints for retained PCAP evidence.

The analyzer uses tshark's tcp.analysis.ack_rtt only when the installed Wireshark
exposes that field.  ACK RTT is an observation from packets visible in the
capture, not an end-to-end application latency measurement.  Results therefore
remain hints and are omitted when the sample set is too small.
"""

from __future__ import annotations

from collections import defaultdict
import ipaddress
import os
from pathlib import Path
import tempfile
from typing import Any, Callable, Iterable

from config.settings import Settings, get_settings
from jobs.errors import JobExecutionError
from jobs.models import ErrorCategory, JobError
from providers.tools import CancellationToken, ToolCommand, ToolRunner


FIELDS = (
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "tcp.stream",
    "tcp.analysis.ack_rtt",
)


def _float(value: str) -> float | None:
    try:
        result = float(value)
    except (TypeError, ValueError):
        return None
    if result < 0 or result > 60:
        return None
    return result


def _ip(value: str) -> str | None:
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def _pair(a: str | None, b: str | None) -> tuple[str, str] | None:
    if not a or not b or a == b:
        return None
    return tuple(sorted((a, b)))


def _percentile(values: list[float], percentile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    rank = (len(ordered) - 1) * percentile
    lower = int(rank)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = rank - lower
    return ordered[lower] + (ordered[upper] - ordered[lower]) * fraction


def _stats(values: list[float]) -> dict[str, Any]:
    if not values:
        return {"samples": 0, "average_ms": None, "p50_ms": None, "p95_ms": None, "max_ms": None}
    milliseconds = [value * 1000.0 for value in values]
    p50 = _percentile(milliseconds, 0.50)
    p95 = _percentile(milliseconds, 0.95)
    return {
        "samples": len(milliseconds),
        "average_ms": round(sum(milliseconds) / len(milliseconds), 2),
        "p50_ms": round(p50, 2) if p50 is not None else None,
        "p95_ms": round(p95, 2) if p95 is not None else None,
        "max_ms": round(max(milliseconds), 2),
    }


class TcpLatencyAnalyzer:
    def __init__(self, *, runner: ToolRunner | None = None, settings: Settings | None = None) -> None:
        self.runner = runner or ToolRunner()
        self.settings = settings or get_settings()

    def _field_supported(self, pcap_path: Path, cancellation_token: CancellationToken | None) -> bool:
        fd, name = tempfile.mkstemp(prefix="tshark-rtt-fields-", suffix=".txt", dir=pcap_path.parent)
        os.close(fd)
        path = Path(name)
        path.chmod(0o600)
        try:
            result = self.runner.run(
                ToolCommand(
                    tool=self.settings.tshark_binary,
                    args=["-G", "fields"],
                    timeout_seconds=90,
                    stdout_path=path,
                    environment={"LC_ALL": "C"},
                ),
                cancellation_token=cancellation_token,
            )
            if not result.success:
                if result.cancelled:
                    raise JobExecutionError(JobError(code="cancelled", category=ErrorCategory.CANCELLED, message="RTT analysis cancelled", component="traffic_analysis"))
                if result.error and result.error.code.value == "missing_binary":
                    raise JobExecutionError(JobError(code="tshark_unavailable", category=ErrorCategory.TOOL_MISSING, message=result.error.message, component="traffic_analysis"))
                return False
            with path.open("r", encoding="utf-8", errors="replace") as stream:
                for raw in stream:
                    columns = raw.rstrip("\r\n").split("\t")
                    if len(columns) >= 3 and columns[0] == "F" and columns[2] == "tcp.analysis.ack_rtt":
                        return True
            return False
        finally:
            path.unlink(missing_ok=True)

    def analyze(
        self,
        pcap_path: Path,
        *,
        cancellation_token: CancellationToken | None = None,
        progress: Callable[[int, str], None] | None = None,
    ) -> dict[str, Any]:
        if progress:
            progress(76, "Проверяем, можно ли оценить TCP RTT")
        if not self._field_supported(pcap_path, cancellation_token):
            return {
                "status": "unavailable",
                "reason": "tcp.analysis.ack_rtt is not exposed by installed tshark",
                "overall": _stats([]),
                "top_pairs": [],
            }

        fd, name = tempfile.mkstemp(prefix="traffic-rtt-", suffix=".tsv", dir=pcap_path.parent)
        os.close(fd)
        output_path = Path(name)
        output_path.chmod(0o600)
        try:
            if progress:
                progress(77, "Оцениваем TCP ACK RTT по видимым двусторонним потокам")
            args = [
                "-r", str(pcap_path), "-n", "-T", "fields",
                "-E", "separator=/t", "-E", "occurrence=f", "-E", "header=n",
            ]
            for field in FIELDS:
                args.extend(["-e", field])
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
                code = "tcp_rtt_decode_failed"
                if result.cancelled:
                    category, code = ErrorCategory.CANCELLED, "cancelled"
                elif result.timed_out:
                    category, code = ErrorCategory.TIMEOUT, "tcp_rtt_decode_timeout"
                raise JobExecutionError(
                    JobError(
                        code=code,
                        category=category,
                        message=result.error.message if result.error else "tshark could not decode TCP RTT metadata",
                        component="traffic_analysis",
                        details={"exit_code": result.exit_code},
                    )
                )
            with output_path.open("r", encoding="utf-8", errors="replace") as stream:
                return self.analyze_tsv(stream)
        finally:
            output_path.unlink(missing_ok=True)

    def analyze_tsv(self, lines: Iterable[str]) -> dict[str, Any]:
        index = {name: position for position, name in enumerate(FIELDS)}
        overall: list[float] = []
        pair_samples: defaultdict[tuple[str, str], list[float]] = defaultdict(list)
        streams: set[str] = set()

        def value(columns: list[str], name: str) -> str:
            position = index[name]
            return columns[position].strip() if position < len(columns) else ""

        for raw in lines:
            line = raw.rstrip("\r\n")
            if not line:
                continue
            columns = line.split("\t")
            if len(columns) < len(FIELDS):
                columns.extend([""] * (len(FIELDS) - len(columns)))
            rtt = _float(value(columns, "tcp.analysis.ack_rtt"))
            if rtt is None:
                continue
            source = _ip(value(columns, "ip.src")) or _ip(value(columns, "ipv6.src"))
            destination = _ip(value(columns, "ip.dst")) or _ip(value(columns, "ipv6.dst"))
            pair = _pair(source, destination)
            overall.append(rtt)
            if pair:
                pair_samples[pair].append(rtt)
            stream_id = value(columns, "tcp.stream")
            if stream_id:
                streams.add(stream_id)

        rows: list[dict[str, Any]] = []
        for pair, values in pair_samples.items():
            if len(values) < 2:
                continue
            row = {"endpoint_a": pair[0], "endpoint_b": pair[1], **_stats(values)}
            rows.append(row)
        rows.sort(key=lambda item: (item.get("p95_ms") or 0, item.get("samples") or 0), reverse=True)

        status = "measured" if len(overall) >= 3 else "insufficient"
        return {
            "status": status,
            "reason": None if status == "measured" else "Fewer than 3 ACK RTT samples were visible",
            "streams_with_samples": len(streams),
            "overall": _stats(overall),
            "top_pairs": rows[:30],
        }


def merge_tcp_latency(document: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    document["tcp_latency"] = result
    if result.get("status") != "measured":
        return document
    overall = result.get("overall") or {}
    samples = int(overall.get("samples") or 0)
    p95 = float(overall.get("p95_ms") or 0)
    if samples >= 5 and p95 >= 300:
        document.setdefault("observations", []).append(
            {
                "severity": "warning" if samples >= 10 and p95 >= 1000 else "info",
                "category": "latency",
                "title": "Повышенный наблюдаемый TCP ACK RTT",
                "fact": f"По {samples} ACK RTT samples: p50 {float(overall.get('p50_ms') or 0):.1f} мс, p95 {p95:.1f} мс, max {float(overall.get('max_ms') or 0):.1f} мс.",
                "meaning": "Это измерение по ACK, видимым в точке захвата. Высокий RTT может быть нормален для удалённого WAN-сервиса и не равен задержке приложения.",
                "check": "Сопоставьте RTT с конкретными TCP-парами, географией/маршрутом и повторите захват в точке, где гарантированно видны оба направления.",
            }
        )
    return document
