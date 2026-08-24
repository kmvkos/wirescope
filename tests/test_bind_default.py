import sys
from pathlib import Path

from appliance.__main__ import _argv
from appliance.cli import build_parser
from appliance.install import InstallConfig
from config.settings import get_settings


def test_application_defaults_to_all_interfaces(monkeypatch):
    monkeypatch.delenv("WIRESCOPE_BIND_HOST", raising=False)
    get_settings.cache_clear()
    try:
        assert get_settings().bind_host == "0.0.0.0"
    finally:
        get_settings.cache_clear()


def test_appliance_install_defaults_to_all_interfaces():
    assert InstallConfig.__dataclass_fields__["bind_host"].default == "0.0.0.0"


def test_appliance_parser_defaults_to_all_interfaces():
    args = build_parser().parse_args(["install", "--dry-run"])
    assert args.bind_host == "0.0.0.0"


def test_packaging_entrypoints_pass_all_interface_bind():
    root = Path(__file__).resolve().parents[1]
    for relative in ("packaging/install.sh", "packaging/upgrade.sh"):
        text = (root / relative).read_text(encoding="utf-8")
        assert "--bind-host 0.0.0.0" in text
        # User arguments are appended afterwards, so an explicit bind override
        # remains possible for a special deployment.
        assert '"$@"' in text


def test_direct_appliance_entrypoint_injects_all_interface_bind(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["appliance", "install", "--dry-run"])
    assert _argv() == ["install", "--bind-host", "0.0.0.0", "--dry-run"]


def test_direct_appliance_entrypoint_preserves_explicit_bind(monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        ["appliance", "install", "--bind-host", "127.0.0.1", "--dry-run"],
    )
    assert _argv() == ["install", "--bind-host", "127.0.0.1", "--dry-run"]
