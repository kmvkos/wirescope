from appliance.packages import select_packages


def test_generic_kiosk_does_not_require_vmware_guest_packages():
    for family in ("debian", "rhel", "suse"):
        selected = select_packages(
            family=family,
            optional_providers=True,
            kiosk=True,
        )
        names = set(selected.all_selected)
        assert "open-vm-tools" not in names
        assert "xserver-xorg-video-vmware" not in names
        assert "xorg-x11-drv-vmware" not in names
        assert "xf86-video-vmware" not in names
