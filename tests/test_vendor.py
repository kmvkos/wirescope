from dataclasses import replace

from inventory.vendor import BUNDLED_OUI, OuiResolver


def test_local_oui_lookup_does_not_require_http(durable_settings):
    resolver = OuiResolver(
        replace(durable_settings, oui_database_path=BUNDLED_OUI)
    )
    found = resolver.lookup("b8:27:eb:00:11:22")
    missing = resolver.lookup("ff:ff:ff:00:00:01")
    invalid = resolver.lookup("not-a-mac")
    assert found.vendor == "Raspberry Pi Foundation"
    assert found.source in {"ieee-data", "bundled-oui"}
    assert found.database_version
    assert missing.vendor is None
    assert invalid.vendor is None
