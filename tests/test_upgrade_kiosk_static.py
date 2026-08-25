from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_upgrade_recovers_enabled_kiosk_even_when_failed():
    script = (ROOT / "packaging" / "upgrade.sh").read_text(encoding="utf-8")

    assert "systemctl is-enabled --quiet wirescope-kiosk.service" in script
    assert "if systemctl is-active --quiet wirescope-kiosk.service" not in script
    assert "systemctl reset-failed wirescope-kiosk.service" in script
    assert "systemctl restart wirescope-kiosk.service" in script


def test_kiosk_unit_does_not_race_getty_on_failure():
    unit = (ROOT / "packaging" / "systemd" / "wirescope-kiosk.service").read_text(
        encoding="utf-8"
    )

    assert "Conflicts=getty@tty1.service" in unit
    assert "\nOnFailure=getty@tty1.service\n" not in unit
    assert "Restart=on-failure" in unit
