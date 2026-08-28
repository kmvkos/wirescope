"""Milestone-12 traffic analyzer composition.

Version 7 composes the mature traffic diagnostics, additive packet evidence,
conservative identity resolution and a separate discovery-protocol pass. Discovery
metadata can strengthen identity, but communications are still not topology.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Iterable

from jobs.errors import JobExecutionError
from jobs.models import ErrorCategory
from providers.tools import CancellationToken
from traffic_analysis.analyzer_v6 import TrafficAnalyzer as _EvidenceTrafficAnalyzer
from traffic_analysis.discovery import DiscoveryEvidenceAnalyzer, merge_discovery_evidence
from traffic_analysis.identity import build_identity_candidates


class TrafficAnalyzer(_EvidenceTrafficAnalyzer):
    def analyze_tsv(
        self,
        lines: Iterable[str],
        *,
        source: dict[str, Any],
        progress: Callable[[int, str], None] | None = None,
    ) -> dict[str, Any]:
        document = super().analyze_tsv(lines, source=source, progress=progress)
        document["identity_resolution"] = build_identity_candidates(document)
        return document

    def analyze(
        self,
        pcap_path: Path,
        *,
        source: dict[str, Any],
        cancellation_token: CancellationToken | None = None,
        progress: Callable[[int, str], None] | None = None,
    ) -> dict[str, Any]:
        document = super().analyze(
            pcap_path,
            source=source,
            cancellation_token=cancellation_token,
            progress=progress,
        )
        try:
            discovery = DiscoveryEvidenceAnalyzer(
                runner=self.runner,
                settings=self.settings,
            ).analyze(
                pcap_path,
                cancellation_token=cancellation_token,
                progress=progress,
            )
            merge_discovery_evidence(document, discovery)
            # Discovery can add stronger CDP/LLDP/MNDP/DHCP/ND identity links.
            document["identity_resolution"] = build_identity_candidates(document)
            document["discovery_evidence_status"] = {"status": "completed"}
        except JobExecutionError as exc:
            if (
                (cancellation_token is not None and cancellation_token.cancelled)
                or exc.error.category == ErrorCategory.CANCELLED
            ):
                raise
            document["discovery_evidence_status"] = {
                "status": "unavailable",
                "error_code": exc.error.code,
            }
            document.setdefault("limitations", []).append(
                "Discovery/topology evidence pass was unavailable; base traffic and identity evidence were preserved."
            )
        return document
