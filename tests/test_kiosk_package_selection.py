from appliance.packages import running_on_raspberry_pi, select_packages


def test_generic_kiosk_does_not_require_vmware_guest_packages():
    for family in ("debian", "rhel", "suse"):
        selected = select_packages(
            family=family,
            optional_providers=True,
            kiosk=True,
            raspberry_pi=False,
        )
        names = set(selected.all_selected)
        assert "open-vm-tools" not in names
        assert "xserver-xorg-video-vmware" not in names
        assert "xorg-x11-drv-vmware" not in names
        assert "xf86-video-vmware" not in names


def test_raspberry_pi_kiosk_uses_wayland_without_xorg_stack():
    selected = select_packages(
        family="debian",
        optional_providers=True,
        kiosk=True,
        raspberry_pi=True,
    )
    assert selected.kiosk == ("cage", "chromium")
    names = set(selected.all_selected)
    assert "xserver-xorg" not in names
    assert "xserver-xorg-input-all" not in names
    assert "xinit" not in names
    assert "openbox" not in names
    assert "open-vm-tools" not in names
    assert "xserver-xorg-video-vmware" not in names


def test_raspberry_pi_model_detection(tmp_path):
    model = tmp_path / "model"
    model.write_bytes(b"Raspberry Pi 4 Model B Rev 1.5\x00")
    assert running_on_raspberry_pi(model) is True
    model.write_text("Generic ARM64 board", encoding="utf-8")
    assert running_on_raspberry_pi(model) is False
