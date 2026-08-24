"""Local operator kiosk templates and display detection.

The kiosk is a Chromium client on the appliance display. On a Debian/Ubuntu
server install there is no desktop: a system unit takes tty1 after boot and
starts xinit + Xorg + Chromium --kiosk on VMware, or Cage (Wayland) elsewhere.
A user-session unit remains available after a graphical login. Bind stays
loopback. Raspberry Pi hardware is optional, not required.
"""

from __future__ import annotations

from dataclasses import dataclass
from collections.abc import Callable, Mapping
import os
from pathlib import Path


CHROMIUM_CANDIDATES = ("chromium", "chromium-browser", "google-chrome")
KIOSK_UNAVAILABLE_EXIT = 75
DEFAULT_KIOSK_URL = "http://127.0.0.1:8000/"
DEFAULT_KIOSK_HEALTH = "http://127.0.0.1:8000/api/health"
X11_SOCKET_DIR = Path("/tmp/.X11-unix")
DRM_CARD = Path("/dev/dri/card0")
KIOSK_SEAT_GROUPS = ("video", "render", "input")

KIOSK_SCRIPT = r"""#!/bin/sh
set -eu
# Local operator kiosk: Chromium against loopback. Never stop the API or worker.
# Capture NIC addressing is independent; this GUI does not need a LAN.
# Boot path (no desktop): Xorg+xinit on VMware; Cage elsewhere; else xinit.
URL="${WIRESCOPE_KIOSK_URL:-http://127.0.0.1:8000/}"
HEALTH="${WIRESCOPE_KIOSK_HEALTH:-http://127.0.0.1:8000/api/health}"
export WIRESCOPE_KIOSK_HEALTH="$HEALTH"
here=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
if [ -z "${DISPLAY:-}" ] && [ -z "${WAYLAND_DISPLAY:-}" ]; then
    if [ -S /tmp/.X11-unix/X0 ] || [ -e /tmp/.X11-unix/X0 ]; then
        DISPLAY=:0
        export DISPLAY
    fi
fi
BIN=""
for candidate in chromium chromium-browser google-chrome; do
    if command -v "$candidate" >/dev/null 2>&1; then
        BIN=$(command -v "$candidate")
        break
    fi
done
if [ -z "$BIN" ]; then
    echo "wirescope-kiosk: chromium is not installed" >&2
    exit 75
fi
waited=0
while [ "$waited" -lt 90 ]; do
    if command -v curl >/dev/null 2>&1; then
        if curl -fsS --max-time 2 "$HEALTH" >/dev/null 2>&1; then
            break
        fi
    elif command -v python3 >/dev/null 2>&1; then
        if python3 -c 'import os,urllib.request,sys; urllib.request.urlopen(os.environ["WIRESCOPE_KIOSK_HEALTH"], timeout=2)' >/dev/null 2>&1; then
            break
        fi
    else
        break
    fi
    waited=$((waited + 1))
    sleep 1
done
if [ "$waited" -ge 90 ]; then
    echo "wirescope-kiosk: API not ready at $HEALTH" >&2
    exit 75
fi
if [ -n "${DISPLAY:-}" ] || [ -n "${WAYLAND_DISPLAY:-}" ]; then
    while true; do
        "$BIN" \
            --kiosk \
            --no-first-run \
            --noerrdialogs \
            --disable-infobars \
            --disable-session-crashed-bubble \
            --disable-restore-session-state \
            --check-for-update-interval=31536000 \
            --ozone-platform-hint=auto \
            --window-size=480,320 \
            --app="$URL" \
            || true
        sleep 2
    done
fi

# VMware SVGA: Cage/wlroots often hangs (black tty1). Prefer Xorg.
kiosk_prefer_xorg() {
    case "${WIRESCOPE_KIOSK_BACKEND:-}" in
        xorg|x11) return 0 ;;
        cage|wayland) return 1 ;;
    esac
    virt=""
    if command -v systemd-detect-virt >/dev/null 2>&1; then
        virt=$(systemd-detect-virt 2>/dev/null || true)
    fi
    if [ "$virt" = vmware ]; then
        return 0
    fi
    vendor=""
    if [ -r /sys/class/dmi/id/sys_vendor ]; then
        vendor=$(cat /sys/class/dmi/id/sys_vendor 2>/dev/null || true)
    fi
    case "$vendor" in
        *VMware*) return 0 ;;
    esac
    if command -v lspci >/dev/null 2>&1; then
        if lspci 2>/dev/null | grep -qi 'VMware SVGA'; then
            return 0
        fi
    fi
    return 1
}

start_xinit() {
    export WIRESCOPE_KIOSK_BIN="$BIN"
    export WIRESCOPE_KIOSK_URL="$URL"
    export XDG_SESSION_TYPE=x11
    unset WAYLAND_DISPLAY || true
    echo "wirescope-kiosk: starting xinit + Xorg + Chromium --kiosk" >&2
    if command -v Xorg >/dev/null 2>&1; then
        exec xinit "$here/xinitrc" -- "$(command -v Xorg)" :0 vt1 -nolisten tcp -keeptty
    fi
    exec xinit "$here/xinitrc" -- :0 vt1 -nolisten tcp
}

if kiosk_prefer_xorg; then
    if command -v xinit >/dev/null 2>&1; then
        start_xinit
    fi
    echo "wirescope-kiosk: VMware needs xinit/Xorg (cage skipped); install xinit" >&2
    exit 75
fi
if command -v cage >/dev/null 2>&1; then
    export XDG_SESSION_TYPE=wayland
    export WLR_LIBSEAT_BACKEND="${WLR_LIBSEAT_BACKEND:-logind}"
    exec cage -- "$BIN" \
        --ozone-platform=wayland \
        --kiosk \
        --no-first-run \
        --noerrdialogs \
        --disable-infobars \
        --disable-session-crashed-bubble \
        --disable-restore-session-state \
        --check-for-update-interval=31536000 \
        --window-size=480,320 \
        --app="$URL"
fi
if command -v xinit >/dev/null 2>&1; then
    start_xinit
fi
echo "wirescope-kiosk: no compositor (install cage or xinit) and no local display" >&2
exit 75
"""

XINITRC = r"""#!/bin/sh
set -eu
# Minimal X session for packaging/kiosk/kiosk.sh. Not a desktop.
# Chromium --kiosk does not need a WM; openbox is optional.
# Never stops the API or worker.
xset s off -dpms || true
if command -v unclutter >/dev/null 2>&1; then
    unclutter -idle 1 -root &
fi
if command -v openbox >/dev/null 2>&1; then
    openbox &
fi
BIN="${WIRESCOPE_KIOSK_BIN:-}"
if [ -z "$BIN" ]; then
    for candidate in chromium chromium-browser google-chrome; do
        if command -v "$candidate" >/dev/null 2>&1; then
            BIN=$(command -v "$candidate")
            break
        fi
    done
fi
if [ -z "$BIN" ]; then
    echo "wirescope-kiosk: chromium is not installed" >&2
    exit 75
fi
URL="${WIRESCOPE_KIOSK_URL:-http://127.0.0.1:8000/}"
exec "$BIN" \
    --kiosk \
    --no-first-run \
    --noerrdialogs \
    --disable-infobars \
    --disable-session-crashed-bubble \
    --disable-restore-session-state \
    --check-for-update-interval=31536000 \
    --ozone-platform=x11 \
    --window-size=480,320 \
    --app="$URL"
"""


@dataclass(frozen=True)
class DisplayProbe:
    attached: bool
    display: str
    wayland_display: str
    x11_socket: bool
    drm: bool
    reason: str


def probe_display(
    *,
    environ: Mapping[str, str] | None = None,
    x11_dir: Path = X11_SOCKET_DIR,
    drm_card: Path = DRM_CARD,
    exists: Callable[[Path], bool] | None = None,
) -> DisplayProbe:
    """Return whether a local graphical session is already available.

    A DRM node without DISPLAY/Wayland/X11 is not a running session. The
    system kiosk unit starts Cage or xinit itself, so missing DISPLAY is not
    a reason to leave that unit disabled.
    """

    env = os.environ if environ is None else environ
    check = Path.exists if exists is None else exists
    display = (env.get("DISPLAY") or "").strip()
    wayland = (env.get("WAYLAND_DISPLAY") or "").strip()
    drm = bool(check(drm_card))
    x11 = False
    if check(x11_dir):
        try:
            x11 = any(
                item.name.startswith("X")
                for item in x11_dir.iterdir()
                if check(item)
            )
        except OSError:
            x11 = False
    attached = bool(display or wayland or x11)
    if display:
        reason = f"DISPLAY={display}"
    elif wayland:
        reason = f"WAYLAND_DISPLAY={wayland}"
    elif x11:
        reason = "X11 socket present"
    elif drm:
        reason = "DRM device present but no graphical session"
    else:
        reason = "headless (no DISPLAY, Wayland, or X11 socket)"
    return DisplayProbe(
        attached=attached,
        display=display,
        wayland_display=wayland,
        x11_socket=x11,
        drm=drm,
        reason=reason,
    )


def kiosk_prefers_xorg(
    *,
    virt: str = "",
    sys_vendor: str = "",
    lspci: str = "",
    backend: str = "",
) -> bool:
    """Return True when the boot kiosk should use Xorg instead of Cage.

    VMware SVGA typically hangs Cage/wlroots, which leaves tty1 black after
    Conflicts=getty@tty1. Force Xorg with WIRESCOPE_KIOSK_BACKEND=xorg.
    """

    forced = (backend or "").strip().lower()
    if forced in {"xorg", "x11"}:
        return True
    if forced in {"cage", "wayland"}:
        return False
    if (virt or "").strip().lower() == "vmware":
        return True
    if "vmware" in (sys_vendor or "").lower():
        return True
    return "vmware svga" in (lspci or "").lower()


def chromium_installed(which: Callable[[str], str | None]) -> bool:
    return any(which(name) for name in CHROMIUM_CANDIDATES)


def kiosk_enable_reason(
    probe: DisplayProbe,
    *,
    chromium: bool,
    system_boot: bool = False,
) -> str | None:
    """Return a warning if the kiosk unit should stay disabled, else None.

    System boot kiosk starts Xorg or Cage on tty1 and does not need an existing
    graphical session. User-session kiosk still needs a login session.
    """

    enable_hint = (
        "sudo systemctl enable --now wirescope-kiosk"
        if system_boot
        else "systemctl --user enable --now wirescope-kiosk"
    )
    if not chromium:
        return (
            "chromium is not installed; kiosk unit installed but not enabled "
            "(optional extra; CI skips this like Playwright). "
            "Install with --with-kiosk or distro packages, then "
            + enable_hint
        )
    if not system_boot and not probe.attached:
        return (
            "no local display ("
            + probe.reason
            + "); user kiosk unit installed but not enabled. "
            "On a VM console (VMware Workstation GUI, virt-manager, or HDMI): "
            + enable_hint
        )
    return None


def kiosk_boot_note(probe: DisplayProbe) -> str | None:
    """Informational note when enabling the system kiosk without a session."""

    if probe.attached:
        return None
    return (
        "no graphical session yet ("
        + probe.reason
        + "); system kiosk enabled for boot on tty1 "
        "(xinit/Xorg on VMware, else cage or xinit + Chromium after wirescope-api)"
    )


def kiosk_recovers_without_stopping_backend(script: str) -> bool:
    lowered = script.lower()
    return (
        "systemctl stop wirescope-api" not in lowered
        and "systemctl stop wirescope-worker" not in lowered
        and "systemctl restart wirescope-api" not in lowered
        and "systemctl restart wirescope-worker" not in lowered
        and ("while true" in lowered or "exec cage" in lowered or "exec xinit" in lowered)
    )
