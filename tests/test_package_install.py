from __future__ import annotations

import subprocess

import pytest

from appliance.cli import main
from appliance.host import HostError, RealHost, debian_amd64_platform
from appliance.packages import (
    APT_LOCK_FRONTEND,
    apt_lock_timeout_message,
    package_install_argv,
    package_install_env,
)


def test_package_install_env_is_noninteractive():
    env = package_install_env("apt", environ={"PATH": "/usr/bin"})
    assert env["DEBIAN_FRONTEND"] == "noninteractive"
    assert env["DEBCONF_NONINTERACTIVE_SEEN"] == "true"
    assert env["APT_LISTCHANGES_FRONTEND"] == "none"
    dnf_env = package_install_env("dnf", environ={"PATH": "/usr/bin"})
    assert "DEBIAN_FRONTEND" not in dnf_env
    assert dnf_env["PATH"] == "/usr/bin"


def test_apt_lock_timeout_message_mentions_fuser():
    message = apt_lock_timeout_message(APT_LOCK_FRONTEND, "1234")
    assert "fuser /var/lib/dpkg/lock-frontend" in message
    assert "1234" in message
    assert "установка" in message


def test_real_host_install_packages_is_noninteractive_and_visible(monkeypatch, capsys):
    host = RealHost()
    monkeypatch.setattr(host, "detect_platform", lambda: debian_amd64_platform())
    monkeypatch.setattr(host, "_dpkg_lock_busy", lambda: False)
    seen: dict[str, object] = {}

    def fake_run(args, **kwargs):
        seen["args"] = args
        seen["kwargs"] = kwargs
        return subprocess.CompletedProcess(args, 0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = host.install_packages(("chromium",))
    assert result.ok
    argv = seen["args"]
    assert argv[0] == "apt-get"
    assert "-y" in argv
    assert any("force-confdef" in str(part) for part in argv)
    assert any("force-confold" in str(part) for part in argv)
    kwargs = seen["kwargs"]
    assert kwargs["stdin"] == subprocess.DEVNULL
    assert kwargs.get("stdout") is None
    assert kwargs.get("stderr") is None
    assert kwargs.get("capture_output") in (None, False)
    assert kwargs["env"]["DEBIAN_FRONTEND"] == "noninteractive"
    printed = capsys.readouterr().out
    assert "apt-get" in printed
    assert package_install_argv("apt", ("chromium",)) == list(argv)


def test_dpkg_lock_timeout_mentions_fuser(monkeypatch, capsys):
    host = RealHost()
    monkeypatch.setattr(host, "_dpkg_lock_busy", lambda: True)
    monkeypatch.setattr(host, "_fuser_lock", lambda _path: "1234")
    monkeypatch.setattr("appliance.host.time.sleep", lambda _seconds: None)
    with pytest.raises(HostError, match="fuser /var/lib/dpkg/lock-frontend") as exc:
        host._wait_for_dpkg_lock(timeout=0.0, interval=0.0)
    assert "1234" in str(exc.value)
    assert "установка" in str(exc.value)
    assert "waiting for apt lock" in capsys.readouterr().out


def test_cli_keyboard_interrupt_exits_130(monkeypatch, capsys):
    from appliance import cli

    def boom(_args):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "cmd_install", boom)
    with pytest.raises(SystemExit) as exc:
        main(["install", "--dry-run"])
    assert exc.value.code == 130
    err = capsys.readouterr().err
    assert "установка прервана" in err
    assert "install interrupted" in err
