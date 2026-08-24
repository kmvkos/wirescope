#!/bin/sh
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
    "$BIN" \
        --kiosk \
        --noerrdialogs \
        --disable-infobars \
        --disable-session-crashed-bubble \
        --disable-restore-session-state \
        --check-for-update-interval=31536000 \
        --window-size=480,320 \
        --app="$URL" \
        || true
    sleep 2
done
