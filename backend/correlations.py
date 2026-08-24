"""Explain how passive and active identity signals converge on inventory assets."""

from __future__ import annotations

from typing import Any


def correlation_summary(inventory, audit_id: str) -> dict[str, Any]:
    items: list[dict[str, Any]] = []
    offset = 0
    while True:
        page = inventory.list_assets(
            audit_id=audit_id,
            limit=500,
            offset=offset,
            include_services=True,
        )
        for asset in page.items:
            address_sources = sorted({item.source for item in asset.addresses})
            name_sources = sorted({item.source for item in asset.names})
            service_sources = sorted({item.source for item in asset.services})
            passive_sources = sorted(
                {
                    source
                    for source in [*address_sources, *name_sources]
                    if source in {"arp", "dhcp", "ethernet", "mdns", "llmnr", "nbns"}
                }
            )
            active_sources = sorted(
                {source for source in [*address_sources, *name_sources, *service_sources] if source == "nmap"}
            )
            if asset.mac:
                identity_basis = "mac"
            elif asset.addresses:
                identity_basis = "ip"
            elif asset.names:
                identity_basis = "name-only"
            else:
                identity_basis = "opaque"
            items.append(
                {
                    "asset_id": asset.id,
                    "identity_basis": identity_basis,
                    "mac": asset.mac,
                    "addresses": [
                        {
                            "address": item.address,
                            "source": item.source,
                            "confidence": item.confidence.value,
                        }
                        for item in asset.addresses
                    ],
                    "names": [
                        {
                            "name": item.name,
                            "source": item.source,
                            "confidence": item.confidence.value,
                        }
                        for item in asset.names
                    ],
                    "passive_sources": passive_sources,
                    "active_sources": active_sources,
                    "correlated_passive_active": bool(passive_sources and active_sources),
                    "device_class": asset.device_class_hint.value,
                    "device_class_confidence": asset.device_class_confidence.value,
                    "classification_sources": (
                        (asset.metadata or {}).get("device_class", {}).get("sources", [])
                    ),
                }
            )
        offset += len(page.items)
        if not page.items or offset >= page.total:
            break
    return {
        "audit_id": audit_id,
        "assets": items,
        "correlated_assets": sum(1 for item in items if item["correlated_passive_active"]),
        "total_assets": len(items),
    }
