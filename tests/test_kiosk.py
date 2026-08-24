from pathlib import Path

from appliance.cli import build_parser
from appliance.host import MemoryHost, debian_amd64_platform
from appliance.kiosk import (
    KIOSK_SCRIPT,
    XINITRC,
    DisplayProbe,
    chromium_installed,
    kiosk_enable_reason,
    kiosk_recovers_without_stopping_backend,
    probe_display,
)
from appliance.packages import select_packages
from appliance.paths import InstallPaths
from appliance.systemd import unit_files


ROOT = Path(__file__).resolve().parents[1]


def test_packaged_kiosk_templates_match_renderer():
    packaged = (ROOT / "packaging" / "kiosk" / "kiosk.sh").read_text(encoding="utf-8")
    xinitrc = (ROOT / "packaging" / "kiosk" / "xinitrc").read_text(encoding="utf-8")
    assert packaged == KIOSK_SCRIPT
    assert xinitrc == XINITRC


def test_kiosk_script_recovers_without_stopping_audits():
    assert kiosk_recovers_without_stopping_backend(KIOSK_SCRIPT)
    assert "while true" in KIOSK_SCRIPT
    assert "--window-size=480,320" in KIOSK_SCRIPT
    assert "127.0.0.1:8000" in KIOSK_SCRIPT
    assert "exit 75" in KIOSK_SCRIPT
    assert "WIRESCOPE_KIOSK_HEALTH" in KIOSK_SCRIPT
    assert "systemctl stop" not in KIOSK_SCRIPT
    assert "systemctl stop" not in XINITRC
    assert "labwc" in XINITRC
    assert "openbox" in XINITRC


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
    )
    assert reason is not None
    assert "chromium is not installed" in reason


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


def test_kiosk_packages_are_minimal_not_a_desktop():
    selected = select_packages(kiosk=True)
    assert "chromium" in selected.kiosk
    assert "openbox" in selected.kiosk
    assert "labwc" in selected.kiosk
    assert "xserver-xorg" in selected.kiosk
    combined = " ".join(selected.all_selected)
    assert "gnome" not in combined
    assert "kde" not in combined
    assert "task-desktop" not in combined
    assert select_packages(kiosk=False).kiosk == ()


def test_system_kiosk_unit_waits_for_api_and_graphical_target():
    files = {unit.name: unit.content for unit in unit_files(InstallPaths())}
    kiosk = files["wirescope-kiosk.service"]
    assert "After=wirescope-api.service graphical.target" in kiosk
    assert "WantedBy=graphical.target" in kiosk
    assert "ConditionPathExists=/tmp/.X11-unix/X0" in kiosk
    assert "Environment=DISPLAY=:0" in kiosk
    assert "WIRESCOPE_KIOSK_URL=http://127.0.0.1:8000/" in kiosk
    assert "appliance wait-ready" in kiosk
    assert "RestartPreventExitStatus=75" in kiosk
    assert "PartOf=wirescope-worker" not in kiosk
    assert "PartOf=wirescope-api" not in kiosk
    assert "PrivateTmp=" not in kiosk
    assert "User=root" not in kiosk


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
