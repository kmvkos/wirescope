#!/bin/sh
set -eu
# Local operator kiosk: Chromium against loopback. Never stop the API or worker.
# Capture NIC addressing is independent; this GUI does not need a LAN.
# Boot path (no desktop): Cage, else xinit + Chromium --kiosk on this VT.
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
if command -v cage >/dev/null 2>&1; then
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
    export WIRESCOPE_KIOSK_BIN="$BIN"
    export WIRESCOPE_KIOSK_URL="$URL"
    exec xinit "$here/xinitrc" -- :0 vt1 -nolisten tcp
fi
echo "wirescope-kiosk: no compositor (install cage or xinit) and no local display" >&2
exit 75
