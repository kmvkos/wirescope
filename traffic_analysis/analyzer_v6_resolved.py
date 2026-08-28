"""Final milestone-12 v6 analyzer composition.

Keeps the packet-evidence pass and identity resolver separate so each layer can be
tested independently. The persisted traffic document receives both the raw-ish
evidence and the conservative resolution result.
"""

from __future__ import annotations

from typing import Any, Callable, Iterable

from traffic_analysis.analyzer_v6 import TrafficAnalyzer as _EvidenceTrafficAnalyzer
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
