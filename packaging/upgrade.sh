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

# The installer uses `systemctl enable --now`, which starts missing services but
# does not replace an already-running process. An upgrade must load the newly
# pulled Python/frontend code, so explicitly restart the durable API and worker
# before refreshing the kiosk. The API unit waits for readiness in ExecStartPost.
if command -v systemctl >/dev/null 2>&1; then
    systemctl reset-failed wirescope-api.service wirescope-worker.service 2>/dev/null || true
    systemctl restart wirescope-api.service wirescope-worker.service

    # Refresh an installed tty1 kiosk after frontend/backend upgrades. Check
    # enablement rather than activity: a failed kiosk still needs recovery.
    # The kiosk unit Conflicts=getty@tty1.service, so systemd transfers tty1 in
    # the same start transaction. There is intentionally no OnFailure=getty race.
    if systemctl is-enabled --quiet wirescope-kiosk.service 2>/dev/null; then
        systemctl reset-failed wirescope-kiosk.service 2>/dev/null || true
        if ! systemctl restart wirescope-kiosk.service; then
            echo "warning: wirescope-kiosk.service failed to restart; API and worker remain available" >&2
        fi
    fi
fi
