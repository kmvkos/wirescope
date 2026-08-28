"""Explainable asset-to-identity correlation between inventory and retained PCAP.

Correlation is intentionally separate from observation-domain compatibility.
When sources are in different domains, zero matches are not treated as a failure.
Within a compatible domain, exact MAC is strongest, exact IP is useful, and a
name alone never causes an automatic merge.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any


_CONFIDENCE_RANK = {"none": 0, "low": 1, "medium": 2, "high": 3}


def _bare(value: Any) -> str:
    return str(value or "").split("/", 1)[0].strip()


def _mac(value: Any) -> str | None:
    text = str(value or "").strip().lower()
    parts = text.split(":")
    if len(parts) != 6:
        return None
    try:
        octets = [int(part, 16) for part in parts]
    except ValueError:
        return None
    if text in {"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"} or octets[0] & 0x01:
        return None
    return text


def _normalized_names(values: list[Any]) -> set[str]:
    return {
        str(value).strip().lower().rstrip(".")
        for value in values
        if str(value or "").strip()
    }


def _candidate_names(document: dict[str, Any]) -> dict[str, set[str]]:
    """Map candidate id to names advertised by strong discovery/DHCP evidence."""
    resolution = document.get("identity_resolution") or {}
    candidates = [item for item in resolution.get("candidates") or [] if isinstance(item, dict)]
    by_mac: dict[str, str] = {}
    by_address: dict[str, str] = {}
    for candidate in candidates:
        candidate_id = str(candidate.get("candidate_id") or "")
        if not candidate_id:
            continue
        parsed_mac = _mac(candidate.get("mac"))
        if parsed_mac:
            by_mac[parsed_mac] = candidate_id
        for address in candidate.get("addresses") or []:
            if _bare(address):
                by_address[_bare(address)] = candidate_id

    names: defaultdict[str, set[str]] = defaultdict(set)
    discovery = document.get("discovery_evidence") or {}
    for device in discovery.get("devices") or []:
        if not isinstance(device, dict):
            continue
        candidate_id = None
        parsed_mac = _mac(device.get("source_mac"))
        if parsed_mac:
            candidate_id = by_mac.get(parsed_mac)
        if candidate_id is None:
            for address in device.get("addresses") or []:
                candidate_id = by_address.get(_bare(address))
                if candidate_id:
                    break
        if candidate_id:
            names[candidate_id].update(_normalized_names(list(device.get("names") or [])))

    for assignment in (discovery.get("dhcp") or {}).get("assignments") or []:
        if not isinstance(assignment, dict):
            continue
        candidate_id = None
        parsed_mac = _mac(assignment.get("mac"))
        if parsed_mac:
            candidate_id = by_mac.get(parsed_mac)
        if candidate_id is None and assignment.get("address"):
            candidate_id = by_address.get(_bare(assignment.get("address")))
        hostname = str(assignment.get("hostname") or "").strip().lower().rstrip(".")
        if candidate_id and hostname:
            names[candidate_id].add(hostname)
    return dict(names)


def correlate_inventory_with_pcap(
    *,
    assets: list[dict[str, Any]],
    traffic_document: dict[str, Any],
    compatibility: dict[str, Any],
) -> dict[str, Any]:
    domain_status = str(compatibility.get("status") or "insufficient_evidence")
    resolution = traffic_document.get("identity_resolution") or {}
    candidates = [
        item
        for item in resolution.get("candidates") or []
        if isinstance(item, dict) and item.get("status") in {"resolved", "provisional", "conflict"}
    ]
    names_by_candidate = _candidate_names(traffic_document)

    if domain_status == "different_domain":
        return {
            "schema": "pcap-inventory-correlation",
            "schema_version": 2,
            "status": "skipped_different_domain",
            "domain_status": domain_status,
            "headline": (
                "PCAP и inventory относятся к разным observation domains; отсутствие совпадений не является ошибкой корреляции."
            ),
            "matches": [],
            "conflicts": [],
            "unmatched_inventory_assets": [],
            "unmatched_pcap_candidates": [],
            "weak_observations": [],
            "inventory_asset_count": len(assets),
            "pcap_candidate_count": len(candidates),
            "matched_asset_count": 0,
            "correlation_attempted": False,
        }

    candidate_rows: dict[str, dict[str, Any]] = {}
    by_mac: defaultdict[str, set[str]] = defaultdict(set)
    by_ip: defaultdict[str, set[str]] = defaultdict(set)
    by_name: defaultdict[str, set[str]] = defaultdict(set)
    for candidate in candidates:
        candidate_id = str(candidate.get("candidate_id") or "")
        if not candidate_id:
            continue
        row = dict(candidate)
        row["normalized_names"] = sorted(names_by_candidate.get(candidate_id) or [])
        candidate_rows[candidate_id] = row
        parsed_mac = _mac(candidate.get("mac"))
        if parsed_mac:
            by_mac[parsed_mac].add(candidate_id)
        for address in candidate.get("addresses") or []:
            if _bare(address):
                by_ip[_bare(address)].add(candidate_id)
        for name in names_by_candidate.get(candidate_id) or []:
            by_name[name].add(candidate_id)

    matches: list[dict[str, Any]] = []
    conflicts: list[dict[str, Any]] = []
    weak_observations: list[dict[str, Any]] = []
    matched_assets: set[str] = set()
    matched_candidates: set[str] = set()

    for asset in assets:
        asset_id = str(asset.get("id") or "")
        asset_mac = _mac(asset.get("mac"))
        asset_ips = {_bare(value) for value in asset.get("addresses") or [] if _bare(value)}
        asset_names = _normalized_names(list(asset.get("names") or []))

        mac_candidates = set(by_mac.get(asset_mac, set())) if asset_mac else set()
        ip_candidates = set().union(*(by_ip.get(address, set()) for address in asset_ips)) if asset_ips else set()
        name_candidates = set().union(*(by_name.get(name, set()) for name in asset_names)) if asset_names else set()

        # Exact MAC wins, but multiple candidates with the same MAC are retained
        # as ambiguity rather than selecting one silently.
        if len(mac_candidates) == 1:
            candidate_id = next(iter(mac_candidates))
            candidate = candidate_rows[candidate_id]
            shared_ips = sorted(asset_ips.intersection({_bare(value) for value in candidate.get("addresses") or []}))
            matches.append(
                {
                    "asset_id": asset_id,
                    "candidate_id": candidate_id,
                    "confidence": "high",
                    "basis": "exact_mac",
                    "reason": (
                        "MAC совпал; IP также совпал."
                        if shared_ips
                        else "MAC совпал при отличающемся/изменившемся IP."
                    ),
                    "shared_ips": shared_ips,
                    "mac": asset_mac,
                    "candidate_addresses": list(candidate.get("addresses") or []),
                }
            )
            matched_assets.add(asset_id)
            matched_candidates.add(candidate_id)
            continue
        if len(mac_candidates) > 1:
            conflicts.append(
                {
                    "asset_id": asset_id,
                    "type": "ambiguous_mac",
                    "mac": asset_mac,
                    "candidate_ids": sorted(mac_candidates),
                    "reason": "Один inventory MAC соответствует нескольким PCAP identity candidates.",
                }
            )
            continue

        # Exact IP is acceptable only when a known inventory MAC does not
        # contradict a different known PCAP MAC.
        if len(ip_candidates) == 1:
            candidate_id = next(iter(ip_candidates))
            candidate = candidate_rows[candidate_id]
            candidate_mac = _mac(candidate.get("mac"))
            if asset_mac and candidate_mac and asset_mac != candidate_mac:
                conflicts.append(
                    {
                        "asset_id": asset_id,
                        "candidate_id": candidate_id,
                        "type": "ip_match_mac_conflict",
                        "shared_ips": sorted(asset_ips.intersection({_bare(value) for value in candidate.get("addresses") or []})),
                        "inventory_mac": asset_mac,
                        "pcap_mac": candidate_mac,
                        "reason": "IP совпал, но подтверждённые MAC различаются; автоматический merge запрещён.",
                    }
                )
                continue
            matches.append(
                {
                    "asset_id": asset_id,
                    "candidate_id": candidate_id,
                    "confidence": "medium" if not candidate_mac or not asset_mac else "high",
                    "basis": "exact_ip",
                    "reason": "IP совпал без противоречащего MAC evidence.",
                    "shared_ips": sorted(asset_ips.intersection({_bare(value) for value in candidate.get("addresses") or []})),
                    "mac": candidate_mac or asset_mac,
                    "candidate_addresses": list(candidate.get("addresses") or []),
                }
            )
            matched_assets.add(asset_id)
            matched_candidates.add(candidate_id)
            continue
        if len(ip_candidates) > 1:
            conflicts.append(
                {
                    "asset_id": asset_id,
                    "type": "ambiguous_ip",
                    "candidate_ids": sorted(ip_candidates),
                    "reason": "Inventory IP соответствует нескольким PCAP identity candidates.",
                }
            )
            continue

        # A name is useful evidence for an operator but never enough for an
        # automatic asset merge.
        if name_candidates:
            weak_observations.append(
                {
                    "asset_id": asset_id,
                    "type": "name_only",
                    "candidate_ids": sorted(name_candidates),
                    "shared_names": sorted(
                        asset_names.intersection(
                            set().union(*(set(candidate_rows[cid].get("normalized_names") or []) for cid in name_candidates))
                        )
                    ),
                    "reason": "Совпало только имя; для merge требуется IP/MAC evidence.",
                }
            )

    unmatched_assets = [
        {
            "asset_id": str(asset.get("id") or ""),
            "mac": _mac(asset.get("mac")),
            "addresses": [_bare(value) for value in asset.get("addresses") or [] if _bare(value)],
            "names": sorted(_normalized_names(list(asset.get("names") or []))),
        }
        for asset in assets
        if str(asset.get("id") or "") not in matched_assets
        and not any(item.get("asset_id") == str(asset.get("id") or "") for item in conflicts)
    ]
    unmatched_candidates = [
        {
            "candidate_id": candidate_id,
            "status": candidate.get("status"),
            "confidence": candidate.get("confidence"),
            "mac": _mac(candidate.get("mac")),
            "addresses": list(candidate.get("addresses") or []),
            "names": sorted(names_by_candidate.get(candidate_id) or []),
        }
        for candidate_id, candidate in candidate_rows.items()
        if candidate_id not in matched_candidates
    ]

    if matches:
        status = "matched"
        headline = f"Сопоставлено inventory assets: {len(matched_assets)} из {len(assets)}."
    elif conflicts:
        status = "conflict"
        headline = "Прямых безопасных merge нет; обнаружены identity-конфликты."
    elif domain_status in {"compatible", "partial"}:
        status = "no_exact_match"
        headline = "Источники совместимы, но точных MAC/IP совпадений не найдено."
    else:
        status = "insufficient_evidence"
        headline = "Недостаточно evidence для надёжной корреляции."

    return {
        "schema": "pcap-inventory-correlation",
        "schema_version": 2,
        "status": status,
        "domain_status": domain_status,
        "headline": headline,
        "correlation_attempted": True,
        "inventory_asset_count": len(assets),
        "pcap_candidate_count": len(candidate_rows),
        "matched_asset_count": len(matched_assets),
        "matches": matches,
        "conflicts": conflicts,
        "unmatched_inventory_assets": unmatched_assets,
        "unmatched_pcap_candidates": unmatched_candidates,
        "weak_observations": weak_observations,
        "rules": {
            "exact_mac": "strong",
            "exact_ip_without_mac_conflict": "medium_or_strong",
            "name_only": "never_auto_merge",
        },
    }


__all__ = ["correlate_inventory_with_pcap"]
