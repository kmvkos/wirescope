from pathlib import Path

from config.settings import get_settings


def test_settings_default_to_source_checkout(monkeypatch):
    for name in (
        "WIRESCOPE_ROOT",
        "WIRESCOPE_FRONTEND_DIR",
        "WIRESCOPE_DATA_DIR",
        "WIRESCOPE_DOCS_ENABLED",
    ):
        monkeypatch.delenv(name, raising=False)

    get_settings.cache_clear()
    settings = get_settings()

    assert settings.project_root == Path(__file__).resolve().parents[1]
    assert settings.frontend_dir == settings.project_root / "frontend"
    assert settings.data_dir == settings.project_root / "data"
    assert settings.docs_enabled is True


def test_settings_accept_environment_overrides(monkeypatch, tmp_path):
    root = tmp_path / "appliance"
    frontend = tmp_path / "ui"
    data = tmp_path / "state"

    monkeypatch.setenv("WIRESCOPE_ROOT", str(root))
    monkeypatch.setenv("WIRESCOPE_FRONTEND_DIR", str(frontend))
    monkeypatch.setenv("WIRESCOPE_DATA_DIR", str(data))
    monkeypatch.setenv("WIRESCOPE_DOCS_ENABLED", "false")

    get_settings.cache_clear()
    settings = get_settings()

    assert settings.project_root == root
    assert settings.frontend_dir == frontend
    assert settings.data_dir == data
    assert settings.docs_enabled is False

    get_settings.cache_clear()
