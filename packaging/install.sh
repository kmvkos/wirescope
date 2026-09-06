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

# Debian/Raspberry Pi OS can install wireshark-common without creating the
# wireshark group (for example when non-root capture was not enabled through
# debconf). WireScope configures dumpcap capabilities itself, so a system
# install must not depend on that distro-side choice. Bootstrap the group on
# clean systems before the appliance installer adds the service account to it.
if [ "$(id -u)" -eq 0 ] && ! getent group wireshark >/dev/null 2>&1; then
    if command -v groupadd >/dev/null 2>&1; then
        groupadd --system wireshark
        echo "ok: created system group wireshark"
    else
        echo "error: groupadd is required to create the wireshark group" >&2
        exit 1
    fi
fi

if [ -x "$here/.venv/bin/python" ]; then
    python="$here/.venv/bin/python"
else
    python=python3
fi
# Appliance installs are reachable through every configured host interface.
# A later user-supplied --bind-host overrides this default.
exec "$python" -m appliance install --project-root "$here" --bind-host 0.0.0.0 "$@"
