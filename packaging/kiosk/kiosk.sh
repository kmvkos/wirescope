#!/bin/sh
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
