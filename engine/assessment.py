"""Cautious interpretation of normalized passive observations."""

from collections import Counter
import ipaddress
from typing import Any

from engine.passive_models import (
    AssessmentConclusion,
    CaptureResult,
    CaptureStatus,
    ConfidenceLevel,
    PassiveAssessment,
    SensorResult,
)


def infer_ipv4_groups(
    relationships: list[dict[str, Any]],
) -> list[AssessmentConclusion]:
    groups: Counter[str] = Counter()
    sources: dict[str, list[str]] = {}

    for relationship in relationships:
        value = relationship.get("ipv4")
        if not value:
            continue
        try:
            address = ipaddress.ip_address(value)
            if address.version != 4:
                continue
            network = str(ipaddress.ip_network(f"{value}/24", strict=False))
        except ValueError:
            continue
        groups[network] += 1
        sources.setdefault(network, []).append(str(value))

    return [
        AssessmentConclusion(
            value={
                "candidate_group": network,
                "hosts_observed": count,
            },
            confidence=ConfidenceLevel.HINT,
            rationale=(
                "Observed ARP addresses share the same first 24 bits"
            ),
            sources=sources[network],
            limitations=[
                "The actual subnet mask was not observed",
                "/24 is grouping only and is not a discovered network",
            ],
        )
        for network, count in groups.most_common()
    ]


def build_assessment(
    capture: CaptureResult,
    sensors: dict[str, SensorResult],
) -> PassiveAssessment:
    ethernet = sensors.get("ethernet")
    vlan = sensors.get("vlan")
    arp = sensors.get("arp")
    dhcpv4 = sensors.get("dhcpv4")
    lldp = sensors.get("lldp")
    cdp = sensors.get("cdp")
    stp = sensors.get("stp")
    ipv6_ra = sensors.get("ipv6_ra")
    ipv6_nd = sensors.get("ipv6_nd")
    dhcpv6 = sensors.get("dhcpv6")

    frames = capture.frame_count
    if capture.status != CaptureStatus.COMPLETED:
        visibility = AssessmentConclusion(
            value="unknown",
            confidence=ConfidenceLevel.UNKNOWN,
            rationale="Packet capture did not complete successfully",
            limitations=["Visibility cannot be assessed from a failed capture"],
        )
    elif frames == 0:
        visibility = AssessmentConclusion(
            value="silent",
            confidence=ConfidenceLevel.HIGH,
            rationale="Capture completed and contained no frames",
            sources=["capture.frame_count"],
            limitations=[
                "No traffic during the capture window does not prove the segment is unused"
            ],
        )
    elif frames is not None and frames < 10:
        visibility = AssessmentConclusion(
            value="very-low",
            confidence=ConfidenceLevel.HIGH,
            rationale=f"Only {frames} frames were observed",
            sources=["capture.frame_count"],
            limitations=["A longer capture may reveal additional protocols"],
        )
    else:
        visibility = AssessmentConclusion(
            value="active",
            confidence=ConfidenceLevel.HIGH,
            rationale="Network traffic was observed during capture",
            sources=["capture.frame_count"],
        )

    vlan_counts = _summary_list(vlan, "vlan_frame_counts")
    tagged_vlans = [
        item["vlan_id"]
        for item in vlan_counts
        if item.get("vlan_id") is not None
    ]
    tagged_frames = _summary_int(vlan, "tagged_frames")
    ethernet_frames = ethernet.hits if ethernet else 0
    untagged_observed = ethernet_frames > tagged_frames
    port_hint = _port_type_hint(
        tagged_vlans=tagged_vlans,
        tagged_frames=tagged_frames,
        untagged_observed=untagged_observed,
        ethernet_frames=ethernet_frames,
    )

    neighbors = []
    for protocol, result in (("LLDP", lldp), ("CDP", cdp)):
        if not result:
            continue
        for item in result.observations:
            neighbors.append(
                {
                    "protocol": protocol,
                    **item.data,
                    "evidence": item.metadata.evidence.reference,
                }
            )

    arp_relationships = _summary_list(arp, "observed_ipv4_mac")
    dhcp_networks = _dhcp_network_conclusions(dhcpv4)
    candidate_groups = [
        *dhcp_networks,
        *infer_ipv4_groups(arp_relationships),
    ]

    ipv6_routers = _summary_list(ipv6_ra, "routers")
    prefixes = []
    rdnss = []
    for router in ipv6_routers:
        for prefix in router.get("prefixes", []):
            if prefix not in prefixes:
                prefixes.append(prefix)
        for server in router.get("rdnss", []):
            if server not in rdnss:
                rdnss.append(server)

    dhcpv6_dns = []
    if dhcpv6:
        for item in dhcpv6.observations:
            for server in item.data.get("dns_servers", []):
                if server not in dhcpv6_dns:
                    dhcpv6_dns.append(server)

    infrastructure = _infrastructure_hints(
        dhcpv4=dhcpv4,
        neighbors=neighbors,
    )

    return PassiveAssessment(
        visibility=visibility,
        layer2={
            "tagged_vlans_observed": tagged_vlans,
            "tagged_frame_count": tagged_frames,
            "untagged_traffic_observed": untagged_observed,
            "port_type_hint": port_hint.model_dump(mode="json"),
            "neighbors": neighbors,
            "stp": {
                "bpdus_observed": stp.hits if stp else 0,
                "root_bridge_ids": _summary_list(stp, "root_bridge_ids"),
                "bridge_ids": _summary_list(stp, "bridge_ids"),
            },
        },
        ipv4={
            "activity_observed": bool(arp and arp.detected)
            or bool(dhcpv4 and dhcpv4.detected),
            "observed_hosts": arp_relationships,
            "candidate_address_groups": [
                item.model_dump(mode="json")
                for item in candidate_groups
            ],
        },
        ipv6={
            "activity_observed": any(
                result and result.detected
                for result in (ipv6_ra, ipv6_nd, dhcpv6)
            ),
            "routers": ipv6_routers,
            "prefixes": prefixes,
            "slaac_hint": any(
                prefix.get("autonomous") is True
                for prefix in prefixes
            ),
            "dhcpv6_observed": bool(dhcpv6 and dhcpv6.detected),
            "dns_servers": sorted({*rdnss, *dhcpv6_dns}),
        },
        infrastructure=infrastructure,
    )


def _port_type_hint(
    *,
    tagged_vlans: list[int],
    tagged_frames: int,
    untagged_observed: bool,
    ethernet_frames: int,
) -> AssessmentConclusion:
    if len(set(tagged_vlans)) > 1:
        return AssessmentConclusion(
            value="trunk-like",
            confidence=ConfidenceLevel.MEDIUM,
            rationale="Frames from multiple tagged VLAN IDs were observed",
            sources=["sensor.vlan"],
            limitations=[
                "Observed tags do not reveal switch-port configuration",
                "Untagged traffic may represent a native VLAN",
            ],
        )
    if tagged_frames and untagged_observed:
        return AssessmentConclusion(
            value="tagged-with-possible-native",
            confidence=ConfidenceLevel.MEDIUM,
            rationale="Both tagged and untagged Ethernet frames were observed",
            sources=["sensor.vlan", "sensor.ethernet"],
            limitations=["The VLAN identity of untagged traffic is unknown"],
        )
    if tagged_frames:
        return AssessmentConclusion(
            value="tagged-segment",
            confidence=ConfidenceLevel.LOW,
            rationale="Tagged Ethernet frames were observed",
            sources=["sensor.vlan"],
            limitations=["One observed VLAN is insufficient to confirm a trunk"],
        )
    if ethernet_frames:
        return AssessmentConclusion(
            value="access-or-native-like",
            confidence=ConfidenceLevel.HINT,
            rationale="Traffic was observed without visible 802.1Q tags",
            sources=["sensor.ethernet"],
            limitations=[
                "Absence of observed tags does not prove that VLANs do not exist",
                "The VLAN ID of untagged traffic cannot be inferred",
            ],
        )
    return AssessmentConclusion(
        value="unknown",
        confidence=ConfidenceLevel.UNKNOWN,
        rationale="No Ethernet traffic was available for port-type inference",
    )


def _dhcp_network_conclusions(
    dhcp: SensorResult | None,
) -> list[AssessmentConclusion]:
    if not dhcp:
        return []

    conclusions = []
    seen = set()
    for item in dhcp.observations:
        address = item.data.get("offered_ip") or item.data.get("requested_ip")
        mask = item.data.get("subnet_mask")
        if not address or not mask:
            continue
        try:
            network = str(
                ipaddress.ip_network(f"{address}/{mask}", strict=False)
            )
        except ValueError:
            continue
        if network in seen:
            continue
        seen.add(network)
        conclusions.append(
            AssessmentConclusion(
                value={
                    "candidate_group": network,
                    "advertised_mask": mask,
                },
                confidence=ConfidenceLevel.HIGH,
                rationale="DHCP advertised a subnet mask for an address",
                sources=[item.metadata.evidence.reference],
                limitations=[
                    "DHCP configuration is advertised evidence, not proof of switch topology"
                ],
            )
        )
    return conclusions


def _infrastructure_hints(
    *,
    dhcpv4: SensorResult | None,
    neighbors: list[dict[str, Any]],
) -> list[AssessmentConclusion]:
    hints = []
    if dhcpv4:
        for server in dhcpv4.summary.get("servers", []):
            hints.append(
                AssessmentConclusion(
                    value={
                        "type": "dhcp_server",
                        "address": server.get("server_id"),
                    },
                    confidence=ConfidenceLevel.HIGH,
                    rationale="DHCP server identifier option was observed",
                    sources=["sensor.dhcpv4"],
                )
            )
            for router in server.get("routers", []):
                hints.append(
                    AssessmentConclusion(
                        value={
                            "type": "gateway_candidate",
                            "address": router,
                        },
                        confidence=ConfidenceLevel.HIGH,
                        rationale="DHCP router option advertised this address",
                        sources=["sensor.dhcpv4"],
                        limitations=[
                            "The address was advertised and was not actively verified"
                        ],
                    )
                )
    if neighbors:
        hints.append(
            AssessmentConclusion(
                value={
                    "type": "network_device_neighbors",
                    "count": len(neighbors),
                },
                confidence=ConfidenceLevel.HIGH,
                rationale="LLDP/CDP neighbor advertisements were observed",
                sources=["sensor.lldp", "sensor.cdp"],
            )
        )
    return hints


def _summary_list(
    result: SensorResult | None,
    key: str,
) -> list[Any]:
    if not result:
        return []
    value = result.summary.get(key, [])
    return value if isinstance(value, list) else []


def _summary_int(result: SensorResult | None, key: str) -> int:
    if not result:
        return 0
    value = result.summary.get(key, 0)
    return value if isinstance(value, int) else 0
