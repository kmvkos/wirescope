#!/bin/sh
set -eu
# Upgrade is the same installer: packages, venv, migrations, units.
# $here is the Git checkout (directory that contains packaging/).
here=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
export PYTHONPATH="$here${PYTHONPATH:+:$PYTHONPATH}"
if [ -x "$here/.venv/bin/python" ]; then
    python="$here/.venv/bin/python"
else
    python=python3
fi
# Keep the appliance reachable through every configured host interface.
# A later explicit --bind-host still wins.
"$python" -m appliance install --project-root "$here" --bind-host 0.0.0.0 "$@"

# An already-running kiosk Chromium process keeps the old DOM in memory even
# after API/static files are upgraded. Refresh it automatically when present.
if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet wirescope-kiosk.service 2>/dev/null; then
        systemctl restart wirescope-kiosk.service
    fi
fi
