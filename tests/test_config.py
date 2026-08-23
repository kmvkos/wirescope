from pathlib import Path

from config.settings import get_settings


def test_settings_default_to_source_checkout(monkeypatch):
    for name in (
        "WIRESCOPE_ROOT",
        "WIRESCOPE_FRONTEND_DIR",
        "WIRESCOPE_DATA_DIR",
        "WIRESCOPE_CAPTURE_DIR",
        "WIRESCOPE_DOCS_ENABLED",
        "WIRESCOPE_ALLOWED_INTERFACES",
        "WIRESCOPE_ALLOW_LOOPBACK",
        "WIRESCOPE_REQUIRE_INTERFACE_UP",
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


def test_settings_accept_environment_overrides(monkeypatch, tmp_path):
    root = tmp_path / "appliance"
    frontend = tmp_path / "ui"
    data = tmp_path / "state"
    captures = tmp_path / "captures"

    monkeypatch.setenv("WIRESCOPE_ROOT", str(root))
    monkeypatch.setenv("WIRESCOPE_FRONTEND_DIR", str(frontend))
    monkeypatch.setenv("WIRESCOPE_DATA_DIR", str(data))
    monkeypatch.setenv("WIRESCOPE_CAPTURE_DIR", str(captures))
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
    assert settings.docs_enabled is False
    assert settings.allowed_interfaces == ("eth0", "eth1")
    assert settings.allow_loopback is True
    assert settings.require_interface_up is False

    get_settings.cache_clear()
