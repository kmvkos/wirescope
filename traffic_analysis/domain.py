"""Conservative compatibility assessment between an audit inventory and a PCAP.

The assessment answers only whether two persisted observation sources plausibly
describe the same network domain. It does not merge assets and it deliberately
does not promote ARP request targets or arbitrary traffic destinations.
"""

from __future__ import annotations

from collections import defaultdict
import ipaddress
from typing import Any, Iterable


_STATUS_RANK = {
    "insufficient_evidence": 0,
    "different_domain": 1,
    "partial": 2,
    "compatible": 3,
}


def _ip(value: Any) -> ipaddress._BaseAddress | None:
    text = str(value or "").split("/", 1)[0].strip()
    if not text:
        return None
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def _network(value: Any) -> ipaddress._BaseNetwork | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        if "/" not in text:
            address = ipaddress.ip_address(text)
            text = f"{address}/{32 if address.version == 4 else 128}"
        return ipaddress.ip_network(text, strict=False)
    except ValueError:
        return None


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


def _unique_ips(values: Iterable[Any]) -> list[str]:
    result: set[str] = set()
    for value in values:
        parsed = _ip(value)
        if parsed is not None and not parsed.is_multicast and not parsed.is_unspecified:
            result.add(str(parsed))
    return sorted(result, key=lambda value: (ipaddress.ip_address(value).version, ipaddress.ip_address(value)))


def _inventory_identifiers(assets: list[dict[str, Any]]) -> tuple[list[str], list[str]]:
    addresses: list[Any] = []
    macs: set[str] = set()
    for asset in assets:
        addresses.extend(asset.get("addresses") or [])
        parsed_mac = _mac(asset.get("mac"))
        if parsed_mac:
            macs.add(parsed_mac)
    return _unique_ips(addresses), sorted(macs)


def _pcap_candidates(document: dict[str, Any]) -> tuple[list[str], list[str], list[dict[str, Any]]]:
    resolution = document.get("identity_resolution") or {}
    candidates = [
        item
        for item in (resolution.get("candidates") or [])
        if isinstance(item, dict) and item.get("status") in {"resolved", "provisional"}
    ]

    addresses: list[Any] = []
    macs: set[str] = set()
    normalized: list[dict[str, Any]] = []
    for candidate in candidates:
        candidate_addresses = _unique_ips(candidate.get("addresses") or [])
        parsed_mac = _mac(candidate.get("mac"))
        if not candidate_addresses and not parsed_mac:
            continue
        addresses.extend(candidate_addresses)
        if parsed_mac:
            macs.add(parsed_mac)
        normalized.append(
            {
                "candidate_id": candidate.get("candidate_id"),
                "status": candidate.get("status"),
                "confidence": candidate.get("confidence"),
                "addresses": candidate_addresses,
                "mac": parsed_mac,
                "basis": candidate.get("basis"),
            }
        )

    # Backward/degraded fallback for documents without identity_resolution.
    if not normalized:
        for item in document.get("endpoint_evidence") or []:
            if not isinstance(item, dict):
                continue
            if item.get("state") not in {"confirmed_responder", "observed_sender"}:
                continue
            parsed = _ip(item.get("endpoint"))
            if parsed is not None and not parsed.is_multicast:
                addresses.append(str(parsed))

    return _unique_ips(addresses), sorted(macs), normalized


def _inventory_ip_macs(assets: list[dict[str, Any]]) -> dict[str, set[str]]:
    result: defaultdict[str, set[str]] = defaultdict(set)
    for asset in assets:
        parsed_mac = _mac(asset.get("mac"))
        if not parsed_mac:
            continue
        for address in _unique_ips(asset.get("addresses") or []):
            result[address].add(parsed_mac)
    return dict(result)


def _pcap_ip_macs(candidates: list[dict[str, Any]]) -> dict[str, set[str]]:
    result: defaultdict[str, set[str]] = defaultdict(set)
    for candidate in candidates:
        parsed_mac = _mac(candidate.get("mac"))
        if not parsed_mac:
            continue
        for address in _unique_ips(candidate.get("addresses") or []):
            result[address].add(parsed_mac)
    return dict(result)


def _scope_networks(confirmed_scope: dict[str, Any] | None, audit_scope: dict[str, Any] | None) -> list[ipaddress._BaseNetwork]:
    raw_values: list[Any] = []
    if confirmed_scope:
        raw_values.extend(confirmed_scope.get("targets") or [])
    if not raw_values and audit_scope:
        raw_values.extend(audit_scope.get("targets") or audit_scope.get("observed") or [])
    networks: list[ipaddress._BaseNetwork] = []
    for raw in raw_values:
        parsed = _network(raw)
        if parsed is not None and parsed not in networks:
            networks.append(parsed)
    return networks


def _pcap_prefix_hints(document: dict[str, Any]) -> list[ipaddress._BaseNetwork]:
    result: list[ipaddress._BaseNetwork] = []
    for item in (document.get("observation_domain") or {}).get("private_ipv4_prefix_hints") or []:
        if not isinstance(item, dict):
            continue
        parsed = _network(item.get("prefix"))
        if parsed is not None and parsed.version == 4 and parsed not in result:
            result.append(parsed)
    return result


def _network_overlap(left: ipaddress._BaseNetwork, right: ipaddress._BaseNetwork) -> bool:
    return left.version == right.version and left.overlaps(right)


def assess_observation_domain(
    *,
    assets: list[dict[str, Any]],
    confirmed_scope: dict[str, Any] | None,
    audit_scope: dict[str, Any] | None,
    audit_interface: str | None,
    traffic_document: dict[str, Any],
) -> dict[str, Any]:
    """Assess whether an explicitly selected PCAP plausibly matches the audit.

    Exact MAC/IP matches are strongest. Confirmed scope membership is next.
    The analyzer's private /24 prefix hints are used only as compatibility hints;
    they are never presented as discovered subnet masks.
    """

    inventory_ips, inventory_macs = _inventory_identifiers(assets)
    pcap_ips, pcap_macs, pcap_candidates = _pcap_candidates(traffic_document)
    scope_networks = _scope_networks(confirmed_scope, audit_scope)
    prefix_hints = _pcap_prefix_hints(traffic_document)

    inventory_ip_set = set(inventory_ips)
    inventory_mac_set = set(inventory_macs)
    pcap_ip_set = set(pcap_ips)
    pcap_mac_set = set(pcap_macs)
    raw_exact_ips = sorted(inventory_ip_set & pcap_ip_set)
    exact_macs = sorted(inventory_mac_set & pcap_mac_set)

    inventory_ip_macs = _inventory_ip_macs(assets)
    pcap_ip_macs = _pcap_ip_macs(pcap_candidates)
    ip_mac_conflicts: list[dict[str, Any]] = []
    conflicted_ips: set[str] = set()
    for address in raw_exact_ips:
        inventory_known = inventory_ip_macs.get(address) or set()
        pcap_known = pcap_ip_macs.get(address) or set()
        if inventory_known and pcap_known and inventory_known.isdisjoint(pcap_known):
            conflicted_ips.add(address)
            ip_mac_conflicts.append(
                {
                    "ip": address,
                    "inventory_macs": sorted(inventory_known),
                    "pcap_macs": sorted(pcap_known),
                    "reason": "IP совпал, но известные MAC различаются; IP reuse не считается доказательством общего observation domain.",
                }
            )
    exact_ips = [address for address in raw_exact_ips if address not in conflicted_ips]

    pcap_in_scope = sorted(
        address
        for address in pcap_ips
        if address not in conflicted_ips
        and any(
            (parsed := _ip(address)) is not None
            and parsed.version == network.version
            and parsed in network
            for network in scope_networks
        )
    )
    inventory_in_pcap_hints = sorted(
        address
        for address in inventory_ips
        if any(
            (parsed := _ip(address)) is not None
            and parsed.version == hint.version
            and parsed in hint
            for hint in prefix_hints
        )
    )
    scope_hint_overlaps = sorted(
        {
            f"{scope} <-> {hint}"
            for scope in scope_networks
            for hint in prefix_hints
            if _network_overlap(scope, hint)
        }
    )

    source = traffic_document.get("source") or {}
    pcap_interface = str(source.get("interface") or "").strip() or None
    audit_interface_text = str(audit_interface or "").strip() or None
    interface_match = bool(
        pcap_interface and audit_interface_text and pcap_interface == audit_interface_text
    )
    interface_mismatch = bool(
        pcap_interface and audit_interface_text and pcap_interface != audit_interface_text
    )

    reasons: list[str] = []
    limitations: list[str] = [
        "Совместимость observation domain не является asset correlation: она только определяет, разумно ли сопоставлять источники напрямую.",
        "Private /24 prefix hints из PCAP используются только как эвристика группировки наблюдений и не объявляются реальной маской подсети.",
    ]

    status = "insufficient_evidence"
    confidence = "low"

    if exact_macs:
        status = "compatible"
        confidence = "high"
        reasons.append(f"Совпали MAC-идентификаторы: {len(exact_macs)}.")
        if exact_ips:
            reasons.append(f"Совпали IP-адреса без MAC-конфликта: {len(exact_ips)}.")
    elif exact_ips:
        status = "compatible"
        confidence = "medium"
        reasons.append(f"Совпали IP-адреса без противоречащего MAC evidence: {len(exact_ips)}.")
    elif pcap_in_scope:
        status = "compatible"
        confidence = "medium"
        reasons.append(
            f"В PCAP есть {len(pcap_in_scope)} локальных identity candidate внутри подтверждённого scope аудита без известного MAC-конфликта."
        )
    elif scope_hint_overlaps or inventory_in_pcap_hints:
        status = "partial"
        confidence = "low"
        reasons.append(
            "Адресные hints PCAP пересекаются со scope/inventory, но точных identity совпадений недостаточно."
        )
    else:
        enough_audit_context = bool(inventory_ips or inventory_macs or scope_networks)
        enough_pcap_context = bool(pcap_ips or pcap_macs or prefix_hints)
        if enough_audit_context and enough_pcap_context:
            # Do not call a domain different merely because one short PCAP has a
            # single unrelated peer. Require either several local candidates or
            # multiple observed prefix hints, or an explicit interface mismatch.
            strong_separation = (
                len(pcap_candidates) >= 2
                or len(prefix_hints) >= 2
                or (interface_mismatch and bool(pcap_candidates or prefix_hints))
            )
            if strong_separation:
                status = "different_domain"
                confidence = "medium"
                reasons.append(
                    "Не найдено ни одного общего MAC/IP или локального identity candidate внутри scope аудита."
                )
                if scope_networks and prefix_hints:
                    reasons.append(
                        "Наблюдаемые адресные hints PCAP не пересекаются с подтверждённым scope аудита."
                    )
            else:
                reasons.append(
                    "Есть данные с обеих сторон, но их пока недостаточно, чтобы доказать совпадение или различие observation domains."
                )
        else:
            reasons.append(
                "Недостаточно подтверждённых локальных идентификаторов или scope для сравнения источников."
            )

    if ip_mac_conflicts:
        reasons.append(
            f"Обнаружено IP/MAC конфликтов: {len(ip_mac_conflicts)}; такие IP не использовались как доказательство совместимости."
        )

    if interface_mismatch:
        reasons.append(
            f"Интерфейсы различаются: аудит={audit_interface_text}, PCAP={pcap_interface}. Само по себе это не доказывает другой сегмент."
        )
    elif interface_match:
        reasons.append(f"Имя интерфейса совпадает: {audit_interface_text}.")

    direct_correlation_recommended = status in {"compatible", "partial"}
    suppress_zero_correlation_warning = status == "different_domain"

    return {
        "schema": "observation-domain-compatibility",
        "schema_version": 1,
        "status": status,
        "confidence": confidence,
        "direct_correlation_recommended": direct_correlation_recommended,
        "suppress_zero_correlation_warning": suppress_zero_correlation_warning,
        "audit": {
            "interface": audit_interface_text,
            "scope_networks": [str(item) for item in scope_networks],
            "inventory_addresses": inventory_ips,
            "inventory_macs": inventory_macs,
        },
        "pcap": {
            "interface": pcap_interface,
            "candidate_addresses": pcap_ips,
            "candidate_macs": pcap_macs,
            "candidate_count": len(pcap_candidates),
            "private_ipv4_prefix_hints": [str(item) for item in prefix_hints],
        },
        "matches": {
            "exact_ips": exact_ips,
            "raw_ip_overlaps": raw_exact_ips,
            "exact_macs": exact_macs,
            "ip_mac_conflicts": ip_mac_conflicts,
            "pcap_candidates_in_scope": pcap_in_scope,
            "inventory_addresses_in_pcap_hints": inventory_in_pcap_hints,
            "scope_hint_overlaps": scope_hint_overlaps,
        },
        "reasons": reasons,
        "limitations": limitations,
    }


__all__ = ["assess_observation_domain"]
