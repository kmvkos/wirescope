"""Conservative identity resolution for traffic-analysis evidence.

The resolver never treats an ARP request target or a remote external peer as a
local asset by default. It groups IP observations around MAC identities only
when the evidence model supports that relationship and keeps ambiguity explicit.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any


_CONFIDENCE_RANK = {"none": 0, "low": 1, "medium": 2, "high": 3}

# These observations are emitted by a protocol spoken on/for the local
# observation domain. They are strong enough to override the generic
# `external_peer` classification of an address. This matters for routers that
# advertise a public management/WAN address in CDP/LLDP/MNDP.
_STRONG_LOCAL_EVIDENCE = {
    "arp_reply_sender",
    "cdp_advertisement",
    "lldp_management",
    "mndp_advertisement",
    "dhcp_ack_assignment",
    "dhcp_offer_assignment",
    "nd_advertisement",
    "router_advertisement",
}


def _strongest_confidence(values: list[str]) -> str:
    return max(values or ["none"], key=lambda value: _CONFIDENCE_RANK.get(value, 0))


def _evidence_total(link: dict[str, Any]) -> int:
    return sum(int(item.get("count") or 0) for item in (link.get("evidence") or []))


def _has_strong_local_evidence(link: dict[str, Any]) -> bool:
    return any(
        str(item.get("type") or "") in _STRONG_LOCAL_EVIDENCE
        and int(item.get("count") or 0) > 0
        for item in (link.get("evidence") or [])
    )


def build_identity_candidates(document: dict[str, Any]) -> dict[str, Any]:
    """Build explainable local identity candidates from evidence.

    Rules are deliberately conservative:

    * `probed_target` is not an asset candidate.
    * `external_peer` is not local unless an L2/discovery protocol explicitly
      ties that address to a local MAC identity.
    * multiple MACs claiming the same IP remain a conflict, not an automatic merge.
    * high-confidence links may produce `resolved` candidates; medium-only links
      remain `provisional` until another source confirms them.
    """

    links = list((document.get("identity_observations") or {}).get("links") or [])
    endpoint_rows = list(document.get("endpoint_evidence") or [])

    endpoint_state = {
        str(item.get("endpoint")): str(item.get("state") or "")
        for item in endpoint_rows
        if item.get("endpoint")
    }

    ip_to_macs: defaultdict[str, set[str]] = defaultdict(set)
    mac_to_links: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
    for link in links:
        ip_value = str(link.get("ip") or "")
        mac_value = str(link.get("mac") or "").lower()
        if not ip_value or not mac_value:
            continue
        ip_to_macs[ip_value].add(mac_value)
        mac_to_links[mac_value].append(link)

    conflicts = {
        ip_value: sorted(mac_values)
        for ip_value, mac_values in ip_to_macs.items()
        if len(mac_values) > 1
    }

    candidates: list[dict[str, Any]] = []
    represented_ips: set[str] = set()

    for mac_value, mac_links in sorted(mac_to_links.items()):
        addresses = sorted({str(item.get("ip")) for item in mac_links if item.get("ip")})
        represented_ips.update(addresses)
        confidence = _strongest_confidence(
            [str(item.get("confidence") or "none") for item in mac_links]
        )
        conflict_addresses = sorted(address for address in addresses if address in conflicts)
        evidence_types: Counter[str] = Counter()
        evidence_count = 0
        strongly_local_addresses: set[str] = set()

        for link in mac_links:
            address = str(link.get("ip") or "")
            evidence_count += _evidence_total(link)
            if address and _has_strong_local_evidence(link):
                strongly_local_addresses.add(address)
            for evidence in link.get("evidence") or []:
                name = str(evidence.get("type") or "unknown")
                evidence_types[name] += int(evidence.get("count") or 0)

        visible_addresses = [
            address
            for address in addresses
            if (
                endpoint_state.get(address) not in {"probed_target", "external_peer"}
                or address in strongly_local_addresses
            )
        ]
        if not visible_addresses and addresses:
            continue

        status = "resolved" if confidence == "high" else "provisional"
        if conflict_addresses:
            status = "conflict"

        candidates.append(
            {
                "candidate_id": f"mac:{mac_value}",
                "mac": mac_value,
                "addresses": visible_addresses,
                "confidence": confidence,
                "status": status,
                "conflict_addresses": conflict_addresses,
                "evidence_count": evidence_count,
                "evidence": [
                    {"type": name, "count": count}
                    for name, count in evidence_types.most_common()
                ],
                "strong_local_addresses": sorted(strongly_local_addresses),
                "basis": "mac_identity",
            }
        )

    # A sender may be visible in L3 traffic without a usable MAC observation.
    # Keep it as a provisional IP-only candidate. Destination-only peers are not
    # promoted because seeing traffic to an IP does not prove a local asset.
    for endpoint, state in sorted(endpoint_state.items()):
        if endpoint in represented_ips:
            continue
        if state != "observed_sender":
            continue
        candidates.append(
            {
                "candidate_id": f"ip:{endpoint}",
                "mac": None,
                "addresses": [endpoint],
                "confidence": "low",
                "status": "provisional",
                "conflict_addresses": [],
                "evidence_count": 1,
                "evidence": [{"type": "observed_sender", "count": 1}],
                "strong_local_addresses": [],
                "basis": "ip_sender_only",
            }
        )

    candidates.sort(
        key=lambda item: (
            item["status"] == "resolved",
            item["status"] == "provisional",
            _CONFIDENCE_RANK.get(str(item["confidence"]), 0),
            int(item["evidence_count"]),
        ),
        reverse=True,
    )

    return {
        "schema": "traffic-identity-resolution",
        "schema_version": 2,
        "candidate_count": len(candidates),
        "resolved_count": sum(1 for item in candidates if item["status"] == "resolved"),
        "provisional_count": sum(
            1 for item in candidates if item["status"] == "provisional"
        ),
        "conflict_count": sum(1 for item in candidates if item["status"] == "conflict"),
        "candidates": candidates,
        "conflicts": [
            {"ip": ip_value, "macs": mac_values, "reason": "multiple_mac_claims"}
            for ip_value, mac_values in sorted(conflicts.items())
        ],
        "excluded_states": ["probed_target", "external_peer", "observed_peer"],
        "strong_local_evidence_types": sorted(_STRONG_LOCAL_EVIDENCE),
        "limitations": [
            "Medium-confidence Ethernet/IP source links remain provisional because a routed capture may expose an immediate next-hop MAC.",
            "A globally routable IP can still belong to a locally observed router when CDP/LLDP/MNDP or another strong local protocol explicitly advertises that identity.",
            "Multiple MAC claims for one IP are preserved as a conflict; HA/VRRP, address reuse and spoofing require separate evidence.",
        ],
    }
