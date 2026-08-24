import json

import pytest

from engine.active_profiles import ProfileConfigError, profile_catalog, profile_for
from engine.scope import ActiveProfile


def test_shipped_profiles_are_bounded(durable_settings):
    catalog = profile_catalog(durable_settings)
    assert set(catalog) == {"discovery", "standard", "deep"}
    assert catalog["discovery"]["run_tcp_scan"] is False
    assert catalog["standard"]["tcp_top_ports"] == 1000
    assert catalog["deep"]["tcp_ports"] == "1-65535"
    assert len(catalog["deep"]["udp_ports"]) <= 256


def test_profile_timeout_still_comes_from_settings(durable_settings):
    profile = profile_for(ActiveProfile.STANDARD, durable_settings)
    assert profile.timeout_seconds == durable_settings.nmap_standard_timeout_seconds


def test_profile_file_rejects_unknown_nmap_surface(tmp_path, durable_settings, monkeypatch):
    path = tmp_path / "profiles.json"
    document = {
        "discovery": {
            "timing": "T3",
            "tcp_top_ports": 100,
            "run_tcp_scan": False,
            "run_udp_scan": False,
            "raw_flags": "-sC --script vuln",
        },
        "standard": {
            "timing": "T3",
            "tcp_top_ports": 1000,
        },
        "deep": {
            "timing": "T3",
            "tcp_ports": "1-65535",
        },
    }
    path.write_text(json.dumps(document), encoding="utf-8")
    monkeypatch.setenv("WIRESCOPE_ACTIVE_PROFILES_FILE", str(path))
    with pytest.raises(ProfileConfigError):
        profile_catalog(durable_settings)


def test_profile_file_rejects_arbitrary_tcp_expression(tmp_path, durable_settings, monkeypatch):
    path = tmp_path / "profiles.json"
    document = {
        "discovery": {"timing": "T3", "run_tcp_scan": False},
        "standard": {"timing": "T3", "tcp_top_ports": 1000},
        "deep": {"timing": "T3", "tcp_ports": "22,80,443 --script vuln"},
    }
    path.write_text(json.dumps(document), encoding="utf-8")
    monkeypatch.setenv("WIRESCOPE_ACTIVE_PROFILES_FILE", str(path))
    with pytest.raises(ProfileConfigError):
        profile_catalog(durable_settings)
