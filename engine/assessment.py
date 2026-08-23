import ipaddress
from collections import Counter


def infer_ipv4_groups(arp_data):
    """
    Группирует наблюдаемые IPv4 по условным /24.

    ВАЖНО:
    Это НЕ определение реальной маски сети.
    Это только удобная группировка наблюдаемых адресов.
    """

    groups = Counter()

    for entry in arp_data:

        ip = entry.get("ipv4")

        if not ip:
            continue

        try:

            address = ipaddress.ip_address(ip)

            if address.version != 4:
                continue

            network = ipaddress.ip_network(
                f"{ip}/24",
                strict=False
            )

            groups[str(network)] += 1

        except ValueError:
            continue

    return [
        {
            "network_hint": network,
            "hosts_observed": count,
            "confidence": "hint-only"
        }
        for network, count
        in groups.most_common()
    ]


def build_assessment(passive_result):

    sensors = passive_result.get(
        "sensors",
        {}
    )

    capture = passive_result.get(
        "capture",
        {}
    )

    frames = capture.get(
        "frames",
        0
    )

    macs = (
        passive_result
        .get("devices", {})
        .get("mac_addresses", [])
    )

    vlan = sensors.get(
        "vlan",
        {}
    )

    arp = sensors.get(
        "arp",
        {}
    )

    dhcp = sensors.get(
        "dhcp",
        {}
    )

    lldp = sensors.get(
        "lldp",
        {}
    )

    cdp = sensors.get(
        "cdp",
        {}
    )

    ipv6_ra = sensors.get(
        "ipv6_ra",
        {}
    )
    ra_data = ipv6_ra.get(
        "data",
        {}
    )

    ipv6_routers = ra_data.get(
        "routers",
        []
    )

    ipv6_ns = sensors.get(
        "ipv6_ns",
        {}
    )

    ipv6_na = sensors.get(
        "ipv6_na",
        {}
    )

    tagged_vlans = [
        item.get("id")
        for item in vlan.get("data", [])
        if item.get("id") is not None
    ]

    arp_data = arp.get(
        "data",
        []
    )

    ipv4_groups = infer_ipv4_groups(
        arp_data
    )

    ipv6_detected = any([
        ipv6_ra.get("detected", False),
        ipv6_ns.get("detected", False),
        ipv6_na.get("detected", False)
    ])

    #
    # Port type inference
    #

    if tagged_vlans:

        port_type = {
            "value": "trunk-like",
            "confidence": "medium",
            "reason":
                "802.1Q tagged traffic was observed"
        }

    elif frames > 0:

        port_type = {
            "value": "access-or-native",
            "confidence": "low",
            "reason":
                "Traffic was observed but no 802.1Q tags were seen"
        }

    else:

        port_type = {
            "value": "unknown",
            "confidence": "none",
            "reason":
                "No traffic was observed"
        }

    #
    # Neighbor discovery
    #

    neighbors = []

    for item in lldp.get(
        "data",
        []
    ):

        neighbors.append({
            "protocol": "LLDP",
            **item
        })

    for item in cdp.get(
        "data",
        []
    ):

        neighbors.append({
            "protocol": "CDP",
            **item
        })

    #
    # Общая видимость
    #

    if frames == 0:

        visibility = {
            "state": "silent",
            "description":
                "Capture completed successfully, "
                "but no Ethernet frames were observed"
        }

    elif frames < 10:

        visibility = {
            "state": "very-low",
            "description":
                "Very little network traffic was observed"
        }

    else:

        visibility = {
            "state": "active",
            "description":
                "Network traffic was observed"
        }

    return {

        "visibility": visibility,

        "traffic": {
            "frames_observed": frames,
            "mac_addresses_observed": len(macs)
        },

        "layer2": {
            "port_type_hint": port_type,
            "tagged_vlans": tagged_vlans,
            "neighbors": neighbors
        },

        "ipv4": {
            "detected": arp.get(
                "detected",
                False
            ),
            "arp_hosts": len(
                arp_data
            ),
            "network_hints": ipv4_groups
        },

        "ipv6": {
            "detected":
                ipv6_detected,

            "router_advertisement_observed":
                ipv6_ra.get(
                    "detected",
                    False
                 ),

            "routers":
                ipv6_routers,

            "router_count":
                len(ipv6_routers)
        },
        "services": {
            "dhcp_observed":
                dhcp.get(
                    "detected",
                    False
                )
        }
    }
