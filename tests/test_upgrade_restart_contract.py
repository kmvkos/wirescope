from pathlib import Path


def test_upgrade_restarts_running_api_worker_before_kiosk():
    root = Path(__file__).resolve().parents[1]
    script = (root / "packaging" / "upgrade.sh").read_text(encoding="utf-8")

    api_worker_restart = (
        "systemctl restart wirescope-api.service wirescope-worker.service"
    )
    kiosk_restart = "systemctl restart wirescope-kiosk.service"

    assert api_worker_restart in script
    assert kiosk_restart in script
    assert script.index(api_worker_restart) < script.index(kiosk_restart)
    assert "systemctl reset-failed wirescope-api.service wirescope-worker.service" in script
