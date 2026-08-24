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
exec "$python" -m appliance install --project-root "$here" "$@"
