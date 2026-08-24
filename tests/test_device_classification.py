from engine.passive_models import ConfidenceLevel
from inventory.classify import classify_device
from inventory.models import DeviceClassHint


def test_printer_classification_combines_vendor_and_port():
    hint, confidence, sources = classify_device(
        os_family=None,
        os_name=None,
        vendor="Hewlett Packard",
        open_ports={("tcp", 80), ("tcp", 9100)},
        name_sources={"mdns"},
    )
    assert hint is DeviceClassHint.PRINTER
    assert confidence is ConfidenceLevel.HIGH
    assert {"mac-vendor", "printer-port"} <= set(sources)


def test_network_device_uses_vendor_and_management_signals():
    hint, confidence, sources = classify_device(
        os_family=None,
        os_name="RouterOS",
        vendor="MikroTik",
        open_ports={("tcp", 22), ("tcp", 8291), ("udp", 161)},
        name_sources=set(),
    )
    assert hint is DeviceClassHint.NETWORK_DEVICE
    assert confidence is ConfidenceLevel.HIGH
    assert "mac-vendor" in sources
    assert "network-management-ports" in sources


def test_single_weak_signal_does_not_claim_high_confidence():
    hint, confidence, _sources = classify_device(
        os_family=None,
        os_name=None,
        vendor=None,
        open_ports={("tcp", 22), ("tcp", 443)},
        name_sources=set(),
    )
    assert hint is DeviceClassHint.SERVER
    assert confidence in {ConfidenceLevel.LOW, ConfidenceLevel.MEDIUM}
