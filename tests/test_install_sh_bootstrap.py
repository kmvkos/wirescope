from pathlib import Path


def _script() -> str:
    root = Path(__file__).resolve().parents[1]
    return (root / "packaging" / "install.sh").read_text(encoding="utf-8")


def test_system_installer_bootstraps_wireshark_group_on_clean_host():
    script = _script()

    assert "getent group wireshark" in script
    assert "groupadd --system wireshark" in script
    assert 'if [ "$(id -u)" -eq 0 ]' in script


def test_user_install_path_does_not_unconditionally_require_groupadd():
    script = _script()

    bootstrap = script.index("getent group wireshark")
    root_guard = script.index('if [ "$(id -u)" -eq 0 ]')
    assert root_guard < bootstrap


def test_system_install_rejects_home_checkout_before_mutating_host():
    script = _script()

    guard = script.index("system install from a home directory is unsupported")
    bootstrap = script.index("getent group wireshark")
    assert "/home/*|/root/*" in script
    assert "/opt/wirescope" in script
    assert guard < bootstrap


def test_user_install_is_exempt_from_home_checkout_guard():
    script = _script()

    assert 'if [ "$arg" = "--user-install" ]' in script
    assert '&& [ "$user_install" = false ]' in script
