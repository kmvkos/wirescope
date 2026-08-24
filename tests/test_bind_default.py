from pathlib import Path

from appliance.install import InstallConfig


def test_appliance_install_defaults_to_all_interfaces():
    assert InstallConfig.__dataclass_fields__["bind_host"].default == "0.0.0.0"


def test_packaging_entrypoints_pass_all_interface_bind():
    root = Path(__file__).resolve().parents[1]
    for relative in ("packaging/install.sh", "packaging/upgrade.sh"):
        text = (root / relative).read_text(encoding="utf-8")
        assert "--bind-host 0.0.0.0" in text
        # User arguments are appended afterwards, so an explicit bind override
        # remains possible for a special deployment.
        assert '"$@"' in text
