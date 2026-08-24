from pathlib import Path
import shutil
import subprocess

import pytest

from appliance.cli import build_parser
from appliance.host import MemoryHost, debian_amd64_platform
from appliance.kiosk import (
    KIOSK_SCRIPT,
    XINITRC,
    DisplayProbe,
    chromium_installed,
    kiosk_boot_note,
    kiosk_enable_reason,
    kiosk_prefers_xorg,
    kiosk_recovers_without_stopping_backend,
    probe_display,
)
from appliance.packages import select_packages
from appliance.paths import InstallPaths, discover_project_root
from appliance.systemd import render_getty_autologin, unit_files


ROOT = Path(__file__).resolve().parents[1]


def test_packaged_kiosk_templates_match_renderer():
    packaged = (ROOT / "packaging" / "kiosk" / "kiosk.sh").read_text(encoding="utf-8")
    xinitrc = (ROOT / "packaging" / "kiosk" / "xinitrc").read_text(encoding="utf-8")
    assert packaged == KIOSK_SCRIPT
    assert xinitrc == XINITRC
    dropin = (ROOT / "packaging" / "systemd" / "getty-tty1-autologin.conf").read_text(
        encoding="utf-8"
    )
    assert dropin == render_getty_autologin()


def test_kiosk_scripts_are_valid_posix_sh():
    for name in ("kiosk.sh", "xinitrc"):
        path = ROOT / "packaging" / "kiosk" / name
        subprocess.run(["sh", "-n", str(path)], check=True)


def test_kiosk_script_recovers_without_stopping_audits():
    assert kiosk_recovers_without_stopping_backend(KIOSK_SCRIPT)
    assert "while true" in KIOSK_SCRIPT
    assert "exec cage" in KIOSK_SCRIPT
    assert "exec xinit" in KIOSK_SCRIPT
    assert "kiosk_prefer_xorg" in KIOSK_SCRIPT
    assert "systemd-detect-virt" in KIOSK_SCRIPT
    assert "vmware" in KIOSK_SCRIPT
    assert "--ozone-platform=x11" in XINITRC
    assert "--window-size=480,320" in KIOSK_SCRIPT
    assert "127.0.0.1:8000" in KIOSK_SCRIPT
    assert "exit 75" in KIOSK_SCRIPT
    assert "WIRESCOPE_KIOSK_HEALTH" in KIOSK_SCRIPT
    assert "systemctl stop" not in KIOSK_SCRIPT
    assert "systemctl stop" not in XINITRC
    assert "openbox" in XINITRC
    assert "labwc" not in XINITRC
    assert "gnome" not in KIOSK_SCRIPT.lower()
    assert "xfce" not in KIOSK_SCRIPT.lower()


def test_kiosk_chromium_missing_is_skipped_like_playwright():
    host = MemoryHost(platform=debian_amd64_platform())
    assert chromium_installed(host.which) is False
    reason = kiosk_enable_reason(
        DisplayProbe(
            attached=True,
            display=":0",
            wayland_display="",
            x11_socket=True,
            drm=True,
            reason="DISPLAY=:0",
        ),
        chromium=False,
        system_boot=True,
    )
    assert reason is not None
    assert "chromium is not installed" in reason
    assert "sudo systemctl enable --now wirescope-kiosk" in reason


@pytest.mark.skipif(
    not any(
        shutil.which(name)
        for name in ("chromium", "chromium-browser", "google-chrome")
    ),
    reason="chromium is not installed",
)
def test_kiosk_script_resolves_installed_chromium():
    found = next(
        name
        for name in ("chromium", "chromium-browser", "google-chrome")
        if shutil.which(name)
    )
    assert found in KIOSK_SCRIPT


def test_probe_display_ignores_drm_without_session(tmp_path):
    drm = tmp_path / "card0"
    drm.write_text("", encoding="utf-8")
    x11 = tmp_path / "empty-x11"
    x11.mkdir()
    probe = probe_display(
        environ={},
        x11_dir=x11,
        drm_card=drm,
    )
    assert probe.drm is True
    assert probe.attached is False
    assert "DRM" in probe.reason
    assert kiosk_enable_reason(probe, chromium=True, system_boot=True) is None
    note = kiosk_boot_note(probe)
    assert note is not None
    assert "tty1" in note


def test_kiosk_prefers_xorg_on_vmware_not_on_bare_metal():
    assert kiosk_prefers_xorg(virt="vmware") is True
    assert kiosk_prefers_xorg(sys_vendor="VMware, Inc.") is True
    assert kiosk_prefers_xorg(lspci="VGA compatible controller: VMware SVGA II Adapter") is True
    assert kiosk_prefers_xorg(virt="kvm") is False
    assert kiosk_prefers_xorg(backend="xorg") is True
    assert kiosk_prefers_xorg(virt="vmware", backend="cage") is False


def test_probe_display_detects_x11_socket_and_env(tmp_path):
    x11 = tmp_path / "X11"
    x11.mkdir()
    (x11 / "X0").write_text("", encoding="utf-8")
    socket_probe = probe_display(environ={}, x11_dir=x11, drm_card=tmp_path / "missing")
    env_probe = probe_display(
        environ={"DISPLAY": ":1"},
        x11_dir=tmp_path / "no-x11",
        drm_card=tmp_path / "missing",
    )
    wayland = probe_display(
        environ={"WAYLAND_DISPLAY": "wayland-0"},
        x11_dir=tmp_path / "no-x11",
        drm_card=tmp_path / "missing",
    )
    assert socket_probe.attached is True
    assert socket_probe.x11_socket is True
    assert env_probe.attached is True
    assert env_probe.display == ":1"
    assert wayland.attached is True
    assert wayland.wayland_display == "wayland-0"
    assert kiosk_enable_reason(env_probe, chromium=True) is None


def test_user_kiosk_still_requires_a_session():
    probe = DisplayProbe(
        attached=False,
        display="",
        wayland_display="",
        x11_socket=False,
        drm=False,
        reason="headless",
    )
    reason = kiosk_enable_reason(probe, chromium=True, system_boot=False)
    assert reason is not None
    assert "no local display" in reason


def test_kiosk_packages_are_minimal_not_a_desktop():
    selected = select_packages(kiosk=True)
    assert "chromium" in selected.kiosk
    assert "cage" in selected.kiosk
    assert "xinit" in selected.kiosk
    assert "xserver-xorg" in selected.kiosk
    assert "openbox" in selected.kiosk
    assert "xserver-xorg-video-vmware" in selected.kiosk
    assert "xserver-xorg-input-all" in selected.kiosk
    assert "open-vm-tools" in selected.kiosk
    assert "labwc" not in selected.kiosk
    combined = " ".join(selected.all_selected)
    assert "gnome" not in combined
    assert "kde" not in combined
    assert "xfce" not in combined
    assert "gdm" not in combined
    assert "lightdm" not in combined
    assert "task-desktop" not in combined
    assert select_packages(kiosk=False).kiosk == ()


def test_system_kiosk_unit_starts_on_tty1_after_api():
    files = {unit.name: unit.content for unit in unit_files(InstallPaths())}
    kiosk = files["wirescope-kiosk.service"]
    assert "After=wirescope-api.service getty@tty1.service systemd-user-sessions.service" in kiosk
    assert "WantedBy=multi-user.target" in kiosk
    assert "Conflicts=getty@tty1.service" in kiosk
    assert "OnFailure=getty@tty1.service" in kiosk
    assert "TTYPath=/dev/tty1" in kiosk
    assert "PAMName=login" in kiosk
    assert "graphical.target" not in kiosk
    assert "graphical-session.target" not in kiosk
    assert "ConditionPathExists=" not in kiosk
    assert "Environment=DISPLAY=:0" not in kiosk
    assert "Environment=XDG_SESSION_TYPE=wayland" not in kiosk
    assert "Environment=XDG_RUNTIME_DIR=/run/wirescope-kiosk" in kiosk
    assert "WIRESCOPE_KIOSK_URL=http://127.0.0.1:8000/" in kiosk
    assert "appliance wait-ready" in kiosk
    assert "RestartPreventExitStatus=75" in kiosk
    assert "PartOf=wirescope-worker" not in kiosk
    assert "PartOf=wirescope-api" not in kiosk
    assert "PrivateTmp=" not in kiosk
    assert "User=root" not in kiosk
    assert "User=wirescope" in kiosk
    dropin = render_getty_autologin()
    assert "--autologin wirescope" in dropin
    assert "PASSWORD" not in dropin.upper()


def test_user_kiosk_unit_starts_after_graphical_login():
    files = {
        unit.name: unit.content
        for unit in unit_files(InstallPaths(), user_session=True)
    }
    kiosk = files["wirescope-kiosk.service"]
    assert "WantedBy=graphical-session.target" in kiosk
    assert "After=graphical-session.target wirescope-api.service" in kiosk
    assert "PassEnvironment=DISPLAY WAYLAND_DISPLAY XAUTHORITY" in kiosk
    assert "User=" not in kiosk
    assert "TTYPath=/dev/tty1" not in kiosk
    assert "Conflicts=getty@tty1.service" not in kiosk
    assert "OnFailure=getty@tty1.service" not in kiosk
    assert "ConditionPathExists=/tmp/.X11-unix/X0" not in kiosk
    assert "appliance wait-ready" in kiosk
    assert "PartOf=wirescope-worker" not in kiosk


def test_cli_user_kiosk_flag_implies_kiosk_install():
    parser = build_parser()
    args = parser.parse_args(
        ["install", "--user-install", "--user-kiosk", "--bind-host", "127.0.0.1"]
    )
    assert args.user_kiosk is True
    assert args.user_install is True
    assert args.enable_kiosk is False
    assert args.with_kiosk is False


def test_cli_enable_kiosk_does_not_require_desktop_flags():
    parser = build_parser()
    args = parser.parse_args(
        ["install", "--enable-kiosk", "--bind-host", "127.0.0.1"]
    )
    assert args.enable_kiosk is True
    assert args.user_kiosk is False


def test_cli_skip_packages_enable_kiosk():
    parser = build_parser()
    args = parser.parse_args(
        ["install", "--skip-packages", "--enable-kiosk", "--bind-host", "127.0.0.1"]
    )
    assert args.skip_packages is True
    assert args.enable_kiosk is True
    assert args.with_kiosk is False


def test_cli_set_password_parses_username():
    parser = build_parser()
    args = parser.parse_args(["set-password", "auditor"])
    assert args.username == "auditor"
    assert args.password_file == ""
    assert args.output == ""
    defaulted = parser.parse_args(["set-password"])
    assert defaulted.username == "auditor"


def test_cli_project_root_defaults_to_checkout_not_only_opt():
    parser = build_parser()
    args = parser.parse_args(["install"])
    checkout = discover_project_root()
    assert Path(args.project_root) == checkout
    assert (checkout / "packaging" / "install.sh").is_file()
    override = parser.parse_args(
        ["install", "--project-root", "/tmp/wirescope-clone"]
    )
    assert override.project_root == "/tmp/wirescope-clone"
