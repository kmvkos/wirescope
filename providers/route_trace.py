"""Bounded unprivileged route tracing for confirmed active scope.

The provider intentionally prefers normal user-space traceroute/tracepath
binaries instead of granting NET_RAW to the WireScope worker.  Missing tools or
individual target failures degrade the route-topology evidence; they do not
fail active discovery.
"""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import re
import shutil
from typing import Any

from providers.tools import CancellationToken, ToolCommand, ToolRunner


_MAX_HOPS = 16
_MAX_TARGETS = 4


@dataclass(frozen=True)
class RouteTraceTarget:
    address: str
    scope_target: str


class RouteTraceProvider:
    def __init__(self, *, runner: ToolRunner | None = None) -> None:
        self.runner = runner or ToolRunner()

    def available_tool(self) -> str | None:
        if shutil.which("traceroute"):
            return "traceroute"
        if shutil.which("tracepath"):
            return "tracepath"
        return None

    def trace_many(
        self,
        targets: list[RouteTraceTarget],
        *,
        interface: str,
        cancellation_token: CancellationToken | None = None,
    ) -> dict[str, Any]:
        selected = targets[:_MAX_TARGETS]
        tool = self.available_tool()
        if tool is None:
            return {
                "schema": "route-trace-result",
                "schema_version": 1,
                "status": "tool_unavailable",
                "tool": None,
                "interface": interface,
                "max_hops": _MAX_HOPS,
                "target_limit": _MAX_TARGETS,
                "traces": [],
                "warnings": [
                    "Neither traceroute nor tracepath is installed; routed topology tracing was skipped."
                ],
            }

        traces = []
        warnings: list[str] = []
        for item in selected:
            if cancellation_token is not None and cancellation_token.cancelled:
                break
            command = self._command(tool, item.address, interface)
            result = self.runner.run(command, cancellation_token=cancellation_token)
            if result.cancelled:
                break
            if not result.success:
                traces.append(
                    {
                        "target": item.address,
                        "scope_target": item.scope_target,
                        "status": "failed",
                        "reached_target": False,
                        "hops": [],
                        "error": result.error.message if result.error else "route trace failed",
                    }
                )
                continue
            hops = (
                _parse_traceroute(result.stdout)
                if tool == "traceroute"
                else _parse_tracepath(result.stdout)
            )
            reached = any(hop.get("address") == item.address for hop in hops)
            traces.append(
                {
                    "target": item.address,
                    "scope_target": item.scope_target,
                    "status": "completed",
                    "reached_target": reached,
                    "hops": hops,
                }
            )
        if len(targets) > len(selected):
            warnings.append(
                f"Route tracing was bounded to {_MAX_TARGETS} representative routed targets."
            )
        return {
            "schema": "route-trace-result",
            "schema_version": 1,
            "status": "completed" if traces else "no_targets",
            "tool": tool,
            "interface": interface,
            "max_hops": _MAX_HOPS,
            "target_limit": _MAX_TARGETS,
            "traces": traces,
            "warnings": warnings,
        }

    @staticmethod
    def _command(tool: str, target: str, interface: str) -> ToolCommand:
        family = ipaddress.ip_address(target).version
        if tool == "traceroute":
            args = [
                "-n",
                "-m",
                str(_MAX_HOPS),
                "-q",
                "1",
                "-w",
                "1",
                "-i",
                interface,
                "-4" if family == 4 else "-6",
                target,
            ]
        else:
            # tracepath follows the already validated kernel route.  It has no
            # portable interface-binding flag across supported distros.
            args = [
                "-n",
                "-m",
                str(_MAX_HOPS),
                "-4" if family == 4 else "-6",
                target,
            ]
        return ToolCommand(tool=tool, args=args, timeout_seconds=22)


def representative_routed_targets(
    *,
    live_addresses: list[str],
    resolved_routes: list[Any],
) -> list[RouteTraceTarget]:
    """Select at most one observed live host from each routed authorized target."""
    live = []
    for raw in live_addresses:
        try:
            live.append(ipaddress.ip_address(raw))
        except ValueError:
            continue

    selected: list[RouteTraceTarget] = []
    seen: set[str] = set()
    for route in resolved_routes:
        if bool(getattr(route, "directly_connected", False)):
            continue
        raw_target = str(getattr(route, "target", "") or "")
        if not raw_target:
            continue
        try:
            network = ipaddress.ip_network(
                raw_target if "/" in raw_target else f"{raw_target}/{32 if getattr(route, 'family', 4) == 4 else 128}",
                strict=False,
            )
        except ValueError:
            continue
        match = next(
            (
                address
                for address in live
                if address.version == network.version and address in network
            ),
            None,
        )
        if match is None:
            continue
        address = str(match)
        if address in seen:
            continue
        seen.add(address)
        selected.append(RouteTraceTarget(address=address, scope_target=raw_target))
        if len(selected) >= _MAX_TARGETS:
            break
    return selected


def _parse_traceroute(text: str) -> list[dict[str, Any]]:
    hops: list[dict[str, Any]] = []
    for raw in text.splitlines():
        line = raw.strip()
        match = re.match(r"^(\d+)\s+(.+)$", line)
        if not match:
            continue
        ttl = int(match.group(1))
        rest = match.group(2).strip()
        if not rest or rest.startswith("*"):
            hops.append({"ttl": ttl, "address": None, "rtt_ms": None, "responded": False})
            continue
        address_match = re.search(r"((?:\d{1,3}\.){3}\d{1,3}|[0-9A-Fa-f:]{2,})", rest)
        address = address_match.group(1) if address_match else None
        rtt_match = re.search(r"([0-9]+(?:\.[0-9]+)?)\s*ms", rest)
        hops.append(
            {
                "ttl": ttl,
                "address": address,
                "rtt_ms": float(rtt_match.group(1)) if rtt_match else None,
                "responded": bool(address),
            }
        )
    return _dedupe_hops(hops)


def _parse_tracepath(text: str) -> list[dict[str, Any]]:
    hops: list[dict[str, Any]] = []
    for raw in text.splitlines():
        line = raw.strip()
        match = re.match(r"^(\d+)[:?]\s+(.+)$", line)
        if not match:
            continue
        ttl = int(match.group(1))
        rest = match.group(2).strip()
        if "LOCALHOST" in rest or "pmtu" in rest.lower() and not re.search(r"\bms\b", rest):
            continue
        if rest.startswith("no reply") or rest.startswith("*"):
            hops.append({"ttl": ttl, "address": None, "rtt_ms": None, "responded": False})
            continue
        address_match = re.search(r"((?:\d{1,3}\.){3}\d{1,3}|[0-9A-Fa-f:]{2,})", rest)
        address = address_match.group(1) if address_match else None
        rtt_match = re.search(r"([0-9]+(?:\.[0-9]+)?)\s*ms", rest)
        hops.append(
            {
                "ttl": ttl,
                "address": address,
                "rtt_ms": float(rtt_match.group(1)) if rtt_match else None,
                "responded": bool(address),
            }
        )
    return _dedupe_hops(hops)


def _dedupe_hops(hops: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_ttl: dict[int, dict[str, Any]] = {}
    for hop in hops:
        ttl = int(hop["ttl"])
        current = by_ttl.get(ttl)
        if current is None or (not current.get("responded") and hop.get("responded")):
            by_ttl[ttl] = hop
    return [by_ttl[ttl] for ttl in sorted(by_ttl)]
