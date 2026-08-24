"""Optional Chromium kiosk templates.

This is a later extra for a local HDMI/DSI display (for example a Raspberry
Pi). It is not required for the generic Linux appliance: operators use any
local or LAN browser against the API.
"""

from __future__ import annotations

KIOSK_SCRIPT = """#!/bin/sh
set -eu
# Optional later extra: local Chromium kiosk. Not required on generic Linux.
# Local display recovery only. Never stop the API or worker.
URL="${WIRESCOPE_KIOSK_URL:-http://127.0.0.1:8000/}"
BIN=""
for candidate in chromium chromium-browser google-chrome; do
    if command -v "$candidate" >/dev/null 2>&1; then
        BIN=$(command -v "$candidate")
        break
    fi
done
if [ -z "$BIN" ]; then
    echo "wirescope-kiosk: chromium is not installed" >&2
    exit 1
fi
while true; do
    "$BIN" \\
        --kiosk \\
        --noerrdialogs \\
        --disable-infobars \\
        --disable-session-crashed-bubble \\
        --disable-restore-session-state \\
        --check-for-update-interval=31536000 \\
        --window-size=480,320 \\
        --app="$URL" \\
        || true
    sleep 2
done
"""

XINITRC = """#!/bin/sh
set -eu
# Optional later extra: X session wrapper for packaging/kiosk/kiosk.sh.
xset s off -dpms || true
unclutter -idle 1 -root &
openbox &
exec /opt/wirescope/packaging/kiosk/kiosk.sh
"""


def kiosk_recovers_without_stopping_backend(script: str) -> bool:
    lowered = script.lower()
    return (
        "systemctl stop wirescope-api" not in lowered
        and "systemctl stop wirescope-worker" not in lowered
        and "systemctl restart wirescope-api" not in lowered
        and "systemctl restart wirescope-worker" not in lowered
        and "while true" in lowered
    )
