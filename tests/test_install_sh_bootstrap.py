from pathlib import Path


def test_system_installer_bootstraps_wireshark_group_on_clean_host():
    root = Path(__file__).resolve().parents[1]
    script = (root / "packaging" / "install.sh").read_text(encoding="utf-8")

    assert "getent group wireshark" in script
    assert "groupadd --system wireshark" in script
    assert 'if [ "$(id -u)" -eq 0 ]' in script


def test_user_install_path_does_not_unconditionally_require_groupadd():
    root = Path(__file__).resolve().parents[1]
    script = (root / "packaging" / "install.sh").read_text(encoding="utf-8")

    bootstrap = script.index("getent group wireshark")
    root_guard = script.index('if [ "$(id -u)" -eq 0 ]')
    assert root_guard < bootstrap
