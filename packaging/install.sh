#!/bin/sh
set -eu
# Idempotent generic Linux appliance installer.
# Run as root (sudo) for system units, or pass --user-install.
here=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
export PYTHONPATH="$here${PYTHONPATH:+:$PYTHONPATH}"
if [ -x "$here/.venv/bin/python" ]; then
    python="$here/.venv/bin/python"
else
    python=python3
fi
exec "$python" -m appliance install --project-root "$here" "$@"
