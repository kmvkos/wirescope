#!/bin/sh
set -eu
# Idempotent generic Linux appliance installer.
# Run as root (sudo) for system units, or pass --user-install.
# $here is the Git checkout (directory that contains packaging/), not a
# hardcoded /opt/wirescope. Clone there for the usual layout, or clone
# elsewhere and run this script (override with --project-root PATH).
# Services run from the checkout; data is /var/lib/wirescope.
here=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
export PYTHONPATH="$here${PYTHONPATH:+:$PYTHONPATH}"
export DEBIAN_FRONTEND="${DEBIAN_FRONTEND:-noninteractive}"
if [ -x "$here/.venv/bin/python" ]; then
    python="$here/.venv/bin/python"
else
    python=python3
fi
exec "$python" -m appliance install --project-root "$here" "$@"
