"""Deterministic analysis of retained packet captures."""

# Increment whenever the persisted diagnostic semantics materially change.
# The enqueue service uses this value so an old completed analysis does not
# mask improved diagnostics for the same retained PCAP after an upgrade.
ANALYZER_VERSION = 3

from traffic_analysis.analyzer import TrafficAnalyzer
from traffic_analysis.render_v3 import render_markdown, render_text

__all__ = [
    "ANALYZER_VERSION",
    "TrafficAnalyzer",
    "render_markdown",
    "render_text",
]
