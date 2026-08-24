"""Local operator kiosk templates and display detection.

The kiosk is a Chromium client on the appliance display. It is valid on a
generic Linux VM with a graphical session as well as on optional Raspberry Pi
hardware. It is not required for headless servers. Bind stays loopback:
operators collect a report without a management network.
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

KIOSK_SCRIPT = """#!/bin/sh
set -eu
# Local operator kiosk: Chromium against loopback. Never stop the API or worker.
# Capture NIC addressing is independent; this GUI does not need a LAN.
URL="${WIRESCOPE_KIOSK_URL:-http://127.0.0.1:8000/}"
HEALTH="${WIRESCOPE_KIOSK_HEALTH:-http://127.0.0.1:8000/api/health}"
export WIRESCOPE_KIOSK_HEALTH="$HEALTH"
if [ -z "${DISPLAY:-}" ] && [ -z "${WAYLAND_DISPLAY:-}" ]; then
    if [ -S /tmp/.X11-unix/X0 ] || [ -e /tmp/.X11-unix/X0 ]; then
        DISPLAY=:0
        export DISPLAY
    fi
fi
if [ -z "${DISPLAY:-}" ] && [ -z "${WAYLAND_DISPLAY:-}" ]; then
    echo "wirescope-kiosk: no local display (DISPLAY/WAYLAND unset)" >&2
    exit 75
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
while true; do
    "$BIN" \\
        --kiosk \\
        --no-first-run \\
        --noerrdialogs \\
        --disable-infobars \\
        --disable-session-crashed-bubble \\
        --disable-restore-session-state \\
        --check-for-update-interval=31536000 \\
        --ozone-platform-hint=auto \\
        --window-size=480,320 \\
        --app="$URL" \\
        || true
    sleep 2
done
"""

XINITRC = """#!/bin/sh
set -eu
# Minimal local session for packaging/kiosk/kiosk.sh (openbox or labwc).
# Not a full desktop. Never stops the API or worker.
xset s off -dpms || true
unclutter -idle 1 -root &
here=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
if [ -n "${WAYLAND_DISPLAY:-}" ] && command -v labwc >/dev/null 2>&1; then
    labwc &
elif command -v openbox >/dev/null 2>&1; then
    openbox &
fi
exec "$here/kiosk.sh"
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
    """Return whether a local graphical session is available.

    A DRM node without DISPLAY/Wayland/X11 is not a usable operator console
    (typical headless VM with a virtual GPU).
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


def chromium_installed(which: Callable[[str], str | None]) -> bool:
    return any(which(name) for name in CHROMIUM_CANDIDATES)


def kiosk_enable_reason(
    probe: DisplayProbe,
    *,
    chromium: bool,
) -> str | None:
    """Return a warning if the kiosk unit should stay disabled, else None."""

    if not probe.attached:
        return (
            "no local display ("
            + probe.reason
            + "); kiosk unit installed but not enabled. "
            "On a VM console (VMware Workstation GUI, virt-manager, or HDMI): "
            "systemctl --user enable --now wirescope-kiosk"
        )
    if not chromium:
        return (
            "chromium is not installed; kiosk unit installed but not enabled "
            "(optional extra; CI skips this like Playwright). "
            "Install with --with-kiosk or distro packages, then "
            "systemctl --user enable --now wirescope-kiosk"
        )
    return None


def kiosk_recovers_without_stopping_backend(script: str) -> bool:
    lowered = script.lower()
    return (
        "systemctl stop wirescope-api" not in lowered
        and "systemctl stop wirescope-worker" not in lowered
        and "systemctl restart wirescope-api" not in lowered
        and "systemctl restart wirescope-worker" not in lowered
        and "while true" in lowered
    )
