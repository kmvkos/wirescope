#!/bin/sh
set -eu
# Idempotent generic Linux appliance installer.
# Run as root (sudo) for system units, or pass --user-install.
# System installs are expected to live outside /home because the generated
# systemd units intentionally use ProtectHome=true. The documented layout is
# /opt/wirescope. User installs remain allowed from a home checkout.
here=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
export PYTHONPATH="$here${PYTHONPATH:+:$PYTHONPATH}"
export DEBIAN_FRONTEND="${DEBIAN_FRONTEND:-noninteractive}"

user_install=false
for arg in "$@"; do
    if [ "$arg" = "--user-install" ]; then
        user_install=true
        break
    fi
done

if [ "$(id -u)" -eq 0 ] && [ "$user_install" = false ]; then
    case "$here" in
        /home/*|/root/*)
            echo "error: system install from a home directory is unsupported" >&2
            echo "move the checkout to /opt/wirescope first:" >&2
            echo "  sudo mv '$here' /opt/wirescope" >&2
            echo "  cd /opt/wirescope" >&2
            echo "  sudo ./packaging/install.sh $*" >&2
            exit 2
            ;;
    esac
fi

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
