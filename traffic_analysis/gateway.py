"""Derive conservative L3 next-hop evidence from normalized PCAP metadata.

A routed Ethernet capture often exposes the immediate next-hop MAC even when the
IP destination is remote. If many private-source -> global-destination flows use
the same destination MAC and that MAC has a strong local IP identity (ARP reply,
CDP/LLDP/MNDP, DHCP/ND), WireScope can describe that MAC/IP as a next-hop
candidate. This is evidence, not a claim about the entire routed path.
"""

from __future__ import annotations

from collections import defaultdict
import ipaddress
from typing import Any


_STRONG_IDENTITY_TYPES = {
    "arp_reply_sender",
    "cdp_advertisement",
    "lldp_management",
    "mndp_advertisement",
    "dhcp_ack_assignment",
    "dhcp_offer_assignment",
    "nd_advertisement",
    "router_advertisement",
}


def _ip(value: Any) -> ipaddress._BaseAddress | None:
    try:
        return ipaddress.ip_address(str(value or "").strip())
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


def _is_private_source(value: Any) -> bool:
    address = _ip(value)
    return bool(address and not address.is_multicast and (address.is_private or address.is_link_local))


def _is_global_destination(value: Any) -> bool:
    address = _ip(value)
    return bool(address and address.is_global and not address.is_multicast)


def _strong_mac_identities(document: dict[str, Any]) -> dict[str, set[str]]:
    result: defaultdict[str, set[str]] = defaultdict(set)
    for link in (document.get("identity_observations") or {}).get("links") or []:
        if not isinstance(link, dict):
            continue
        mac = _mac(link.get("mac"))
        address = _ip(link.get("ip"))
        if not mac or address is None:
            continue
        evidence_types = {
            str(item.get("type") or "")
            for item in (link.get("evidence") or [])
            if isinstance(item, dict) and int(item.get("count") or 0) > 0
        }
        if evidence_types.intersection(_STRONG_IDENTITY_TYPES):
            result[mac].add(str(address))
    return dict(result)


def derive_next_hop_evidence(document: dict[str, Any]) -> dict[str, Any]:
    """Build explainable source->next-hop candidates from directional flows."""
    identities = _strong_mac_identities(document)
    groups: defaultdict[tuple[str, str], dict[str, Any]] = defaultdict(
        lambda: {
            "flows": 0,
            "packets": 0,
            "bytes": 0,
            "remote_destinations": set(),
            "protocols": set(),
            "first_seen": None,
            "last_seen": None,
        }
    )

    eligible_flows = 0
    for flow in document.get("directional_flows") or []:
        if not isinstance(flow, dict):
            continue
        source_ip = str(flow.get("src_ip") or "")
        destination_ip = str(flow.get("dst_ip") or "")
        destination_mac = _mac(flow.get("dst_mac"))
        if (
            not destination_mac
            or not _is_private_source(source_ip)
            or not _is_global_destination(destination_ip)
        ):
            continue
        eligible_flows += 1
        key = (source_ip, destination_mac)
        item = groups[key]
        item["flows"] += 1
        item["packets"] += int(flow.get("packets") or 0)
        item["bytes"] += int(flow.get("bytes") or 0)
        item["remote_destinations"].add(destination_ip)
        for protocol in flow.get("protocols") or []:
            if isinstance(protocol, dict):
                name = protocol.get("name")
            else:
                name = protocol
            if name:
                item["protocols"].add(str(name))
        first = flow.get("first_seen")
        last = flow.get("last_seen")
        if first:
            item["first_seen"] = first if not item["first_seen"] else min(str(item["first_seen"]), str(first))
        if last:
            item["last_seen"] = last if not item["last_seen"] else max(str(item["last_seen"]), str(last))

    candidates: list[dict[str, Any]] = []
    ambiguous: list[dict[str, Any]] = []
    for (source_ip, next_hop_mac), item in groups.items():
        mapped_ips = sorted(identities.get(next_hop_mac) or [])
        if len(mapped_ips) != 1:
            if len(mapped_ips) > 1:
                ambiguous.append(
                    {
                        "source_ip": source_ip,
                        "next_hop_mac": next_hop_mac,
                        "candidate_ips": mapped_ips,
                        "reason": "next_hop_mac_has_multiple_strong_ip_identities",
                    }
                )
            continue

        remote_count = len(item["remote_destinations"])
        flow_count = int(item["flows"])
        if remote_count >= 3 and flow_count >= 3:
            confidence = "high"
        else:
            confidence = "medium"

        candidates.append(
            {
                "source_ip": source_ip,
                "next_hop_ip": mapped_ips[0],
                "next_hop_mac": next_hop_mac,
                "remote_destination_count": remote_count,
                "flow_count": flow_count,
                "packets": int(item["packets"]),
                "bytes": int(item["bytes"]),
                "protocols": sorted(item["protocols"]),
                "first_seen": item["first_seen"],
                "last_seen": item["last_seen"],
                "confidence": confidence,
                "evidence": [
                    "ethernet_destination_mac_for_routed_flows",
                    "strong_ip_mac_identity_for_next_hop",
                ],
                "relation": "l3_next_hop",
            }
        )

    candidates.sort(
        key=lambda item: (
            item["confidence"] == "high",
            int(item["remote_destination_count"]),
            int(item["bytes"]),
        ),
        reverse=True,
    )
    return {
        "schema": "traffic-next-hop-evidence",
        "schema_version": 1,
        "eligible_routed_flow_count": eligible_flows,
        "candidate_count": len(candidates),
        "high_confidence_count": sum(1 for item in candidates if item["confidence"] == "high"),
        "candidates": candidates,
        "ambiguous": ambiguous,
        "limitations": [
            "Next-hop inference is limited to private/link-local source IP traffic toward globally routable destinations in this version.",
            "The evidence proves the Ethernet next hop visible at the capture point, not the complete routed path or ownership of the remote destination.",
            "A next-hop MAC must resolve to exactly one strong local IP identity; ambiguous MAC/IP mappings are not promoted.",
        ],
    }


__all__ = ["derive_next_hop_evidence"]
