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
exec "$python" -m appliance install --project-root "$here" --bind-host 0.0.0.0 "$@"
