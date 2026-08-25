"""Parse live Nmap status output without depending on locale-sensitive prose.

Nmap is executed with LC_ALL=C, ``-v`` and ``--stats-every``.  The parser is
intentionally tolerant because Nmap can emit progress on stdout or stderr and
subprocess pipe reads are not line-aligned.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
import threading


_OPEN_RE = re.compile(
    r"Discovered open port\s+(?P<port>\d+)/(?:tcp|udp)\s+on\s+(?P<host>\S+)",
    re.IGNORECASE,
)
_PERCENT_RE = re.compile(r"About\s+(?P<percent>\d+(?:\.\d+)?)%\s+done", re.IGNORECASE)
_HOSTS_RE = re.compile(
    r"(?P<completed>\d+)\s+hosts?\s+completed\s+\((?P<up>\d+)\s+up\)",
    re.IGNORECASE,
)
_REMAINING_RE = re.compile(r"\((?P<remaining>[^()]+)\s+remaining\)", re.IGNORECASE)
_PHASE_RE = re.compile(r"(?P<phase>[^\r\n:]+?)\s+Timing:\s+About", re.IGNORECASE)


@dataclass(frozen=True)
class NmapProgressSnapshot:
    percent: float | None
    phase: str | None
    hosts_completed: int | None
    hosts_up: int | None
    open_ports: int
    last_open_port: int | None
    last_open_host: str | None
    remaining: str | None


class NmapProgressParser:
    """Thread-safe stateful parser for Nmap stdout/stderr chunks."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._buffers = {"stdout": "", "stderr": ""}
        self._percent: float | None = None
        self._phase: str | None = None
        self._hosts_completed: int | None = None
        self._hosts_up: int | None = None
        self._remaining: str | None = None
        self._open: set[tuple[str, int]] = set()
        self._last_open_port: int | None = None
        self._last_open_host: str | None = None

    def feed(self, stream: str, chunk: str) -> list[NmapProgressSnapshot]:
        if not chunk:
            return []
        stream_key = "stderr" if stream == "stderr" else "stdout"
        with self._lock:
            text = self._buffers[stream_key] + chunk.replace("\r", "\n")
            lines = text.split("\n")
            self._buffers[stream_key] = lines.pop()
            snapshots: list[NmapProgressSnapshot] = []
            for line in lines:
                snapshot = self._parse_line(line.strip())
                if snapshot is not None:
                    snapshots.append(snapshot)
            return snapshots

    def flush(self) -> list[NmapProgressSnapshot]:
        with self._lock:
            snapshots: list[NmapProgressSnapshot] = []
            for key in ("stdout", "stderr"):
                line = self._buffers[key].strip()
                self._buffers[key] = ""
                snapshot = self._parse_line(line)
                if snapshot is not None:
                    snapshots.append(snapshot)
            return snapshots

    def _parse_line(self, line: str) -> NmapProgressSnapshot | None:
        if not line:
            return None
        changed = False

        opened = _OPEN_RE.search(line)
        if opened:
            host = opened.group("host")
            port = int(opened.group("port"))
            before = len(self._open)
            self._open.add((host, port))
            self._last_open_host = host
            self._last_open_port = port
            changed = len(self._open) != before or changed

        percent = _PERCENT_RE.search(line)
        if percent:
            value = min(100.0, max(0.0, float(percent.group("percent"))))
            if value != self._percent:
                self._percent = value
                changed = True

        hosts = _HOSTS_RE.search(line)
        if hosts:
            completed = int(hosts.group("completed"))
            up = int(hosts.group("up"))
            if completed != self._hosts_completed or up != self._hosts_up:
                self._hosts_completed = completed
                self._hosts_up = up
                changed = True

        remaining = _REMAINING_RE.search(line)
        if remaining:
            value = remaining.group("remaining").strip()
            if value != self._remaining:
                self._remaining = value
                changed = True

        phase = _PHASE_RE.search(line)
        if phase:
            value = phase.group("phase").strip()
            if value != self._phase:
                self._phase = value
                changed = True

        return self.snapshot() if changed else None

    def snapshot(self) -> NmapProgressSnapshot:
        return NmapProgressSnapshot(
            percent=self._percent,
            phase=self._phase,
            hosts_completed=self._hosts_completed,
            hosts_up=self._hosts_up,
            open_ports=len(self._open),
            last_open_port=self._last_open_port,
            last_open_host=self._last_open_host,
            remaining=self._remaining,
        )
