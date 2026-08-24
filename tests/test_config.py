from pathlib import Path

import pytest

from config.settings import get_settings


def test_settings_default_to_source_checkout(monkeypatch):
    for name in (
        "WIRESCOPE_ROOT",
        "WIRESCOPE_FRONTEND_DIR",
        "WIRESCOPE_DATA_DIR",
        "WIRESCOPE_CAPTURE_DIR",
        "WIRESCOPE_DATABASE_PATH",
        "WIRESCOPE_EVIDENCE_DIR",
        "WIRESCOPE_RUNTIME_DIR",
        "WIRESCOPE_DOCS_ENABLED",
        "WIRESCOPE_ALLOWED_INTERFACES",
        "WIRESCOPE_ALLOW_LOOPBACK",
        "WIRESCOPE_REQUIRE_INTERFACE_UP",
        "WIRESCOPE_CAPTURE_SNAPLEN",
        "WIRESCOPE_CAPTURE_PROMISCUOUS",
        "WIRESCOPE_WORKER_CONCURRENCY",
        "WIRESCOPE_MAX_PACKET_CAPTURES",
        "WIRESCOPE_SQLITE_SYNCHRONOUS",
    ):
        monkeypatch.delenv(name, raising=False)

    get_settings.cache_clear()
    settings = get_settings()

    assert settings.project_root == Path(__file__).resolve().parents[1]
    assert settings.frontend_dir == settings.project_root / "frontend"
    assert settings.data_dir == settings.project_root / "data"
    assert (
        settings.capture_dir
        == settings.project_root / "data" / "runtime" / "captures"
    )
    assert settings.docs_enabled is True
    assert settings.allowed_interfaces == ()
    assert settings.allow_loopback is False
    assert settings.require_interface_up is True
    assert settings.capture_snaplen == 65_535
    assert settings.capture_promiscuous is False
    assert settings.database_path == settings.data_dir / "wirescope.db"
    assert settings.evidence_dir == settings.data_dir / "evidence"
    assert settings.runtime_dir == settings.data_dir / "runtime"
    assert settings.worker_concurrency == 1
    assert settings.max_packet_captures == 1
    assert settings.max_active_discovery_jobs == 1
    assert settings.max_protocol_audit_jobs == 1
    assert settings.protocol_audit_concurrency == 1
    assert settings.max_findings_jobs == 1
    assert settings.active_standard_max_targets == 1_024
    assert settings.nmap_binary == "nmap"
    assert settings.sqlite_synchronous == "FULL"


def test_settings_reject_unsafe_worker_limits(monkeypatch):
    monkeypatch.setenv("WIRESCOPE_WORKER_CONCURRENCY", "0")
    get_settings.cache_clear()

    with pytest.raises(ValueError, match="worker_concurrency"):
        get_settings()

    get_settings.cache_clear()


def test_settings_accept_environment_overrides(monkeypatch, tmp_path):
    root = tmp_path / "appliance"
    frontend = tmp_path / "ui"
    data = tmp_path / "state"
    captures = tmp_path / "captures"
    database = tmp_path / "database" / "wirescope.db"
    evidence = tmp_path / "artifacts"
    runtime = tmp_path / "runtime"

    monkeypatch.setenv("WIRESCOPE_ROOT", str(root))
    monkeypatch.setenv("WIRESCOPE_FRONTEND_DIR", str(frontend))
    monkeypatch.setenv("WIRESCOPE_DATA_DIR", str(data))
    monkeypatch.setenv("WIRESCOPE_CAPTURE_DIR", str(captures))
    monkeypatch.setenv("WIRESCOPE_DATABASE_PATH", str(database))
    monkeypatch.setenv("WIRESCOPE_EVIDENCE_DIR", str(evidence))
    monkeypatch.setenv("WIRESCOPE_RUNTIME_DIR", str(runtime))
    monkeypatch.setenv("WIRESCOPE_DOCS_ENABLED", "false")
    monkeypatch.setenv("WIRESCOPE_ALLOWED_INTERFACES", "eth0, eth1")
    monkeypatch.setenv("WIRESCOPE_ALLOW_LOOPBACK", "true")
    monkeypatch.setenv("WIRESCOPE_REQUIRE_INTERFACE_UP", "false")

    get_settings.cache_clear()
    settings = get_settings()

    assert settings.project_root == root
    assert settings.frontend_dir == frontend
    assert settings.data_dir == data
    assert settings.capture_dir == captures
    assert settings.database_path == database
    assert settings.evidence_dir == evidence
    assert settings.runtime_dir == runtime
    assert settings.docs_enabled is False
    assert settings.allowed_interfaces == ("eth0", "eth1")
    assert settings.allow_loopback is True
    assert settings.require_interface_up is False

    get_settings.cache_clear()
