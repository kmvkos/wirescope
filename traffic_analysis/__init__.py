"""Deterministic analysis of retained packet captures."""

# Increment whenever the persisted diagnostic semantics materially change.
# The enqueue service uses this value so an old completed analysis does not
# mask improved diagnostics for the same retained PCAP after an upgrade.
ANALYZER_VERSION = 6

# Import the legacy module first, then install the additive v6 analyzer as the
# package/default analyzer. Some existing modules still import
# ``traffic_analysis.analyzer.TrafficAnalyzer`` directly; assigning the class on
# that already-loaded submodule keeps those call sites compatible during the
# milestone-12 migration without duplicating the mature v5 diagnostics code.
from traffic_analysis import analyzer as _analyzer_module
from traffic_analysis.analyzer_v6_resolved import TrafficAnalyzer
from traffic_analysis.render_v5 import render_markdown, render_text

_analyzer_module.TrafficAnalyzer = TrafficAnalyzer

__all__ = [
    "ANALYZER_VERSION",
    "TrafficAnalyzer",
    "render_markdown",
    "render_text",
]
