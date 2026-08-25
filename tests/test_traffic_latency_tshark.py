import shutil

import pytest

from traffic_analysis.latency import TcpLatencyAnalyzer


def test_installed_tshark_exposes_ack_rtt_field(tmp_path):
    if shutil.which("tshark") is None:
        pytest.skip("tshark is not installed")
    probe_path = tmp_path / "probe.pcap"
    assert TcpLatencyAnalyzer()._field_supported(probe_path, None) is True
