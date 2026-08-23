import re
from collections import Counter


def vlan_sensor(tshark_fields, count_frames, pcap):

    rows = tshark_fields(
        pcap,
        "vlan",
        ["vlan.id"]
    )

    vlans = Counter()

    for row in rows:

        if not row[0]:
            continue

        for value in row[0].split(","):

            value = value.strip()

            if value.isdigit():
                vlans[int(value)] += 1

    return {
        "name": "vlan",
        "detected": bool(vlans),
        "hits": sum(vlans.values()),
        "data": [
            {
                "id": vlan,
                "frames": frames
            }
            for vlan, frames
            in sorted(vlans.items())
        ]
    }


def arp_sensor(tshark_fields, count_frames, pcap):

    rows = tshark_fields(
        pcap,
        "arp",
        [
            "arp.src.proto_ipv4",
            "arp.src.hw_mac"
        ]
    )

    devices = {}

    for ip, mac in rows:

        if ip and mac:
            devices[ip] = mac.lower()

    return {
        "name": "arp",
        "detected": bool(devices),
        "hits": count_frames(pcap, "arp"),
        "data": [
            {
                "ipv4": ip,
                "mac": mac
            }
            for ip, mac
            in sorted(devices.items())
        ]
    }


def lldp_sensor(tshark_fields, count_frames, pcap):

    rows = tshark_fields(
        pcap,
        "lldp",
        [
            "lldp.tlv.system.name",
            "lldp.port.id"
        ]
    )

    neighbors = []
    seen = set()

    for name, port in rows:

        key = (name, port)

        if key in seen:
            continue

        seen.add(key)

        neighbors.append({
            "system_name": name or None,
            "port_id": port or None
        })

    return {
        "name": "lldp",
        "detected": bool(neighbors),
        "hits": count_frames(pcap, "lldp"),
        "data": neighbors
    }


def cdp_sensor(tshark_fields, count_frames, pcap):

    rows = tshark_fields(
        pcap,
        "cdp",
        [
            "cdp.deviceid",
            "cdp.portid"
        ]
    )

    neighbors = []
    seen = set()

    for device, port in rows:

        key = (device, port)

        if key in seen:
            continue

        seen.add(key)

        neighbors.append({
            "device": device or None,
            "port": port or None
        })

    return {
        "name": "cdp",
        "detected": bool(neighbors),
        "hits": count_frames(pcap, "cdp"),
        "data": neighbors
    }


def simple_sensor(name, display_filter, count_frames, pcap):

    hits = count_frames(
        pcap,
        display_filter
    )

    return {
        "name": name,
        "detected": hits > 0,
        "hits": hits,
        "data": []
    }


def run_passive_sensors(
    tshark_fields,
    count_frames,
    pcap
):

    sensors = {}

    sensors["vlan"] = vlan_sensor(
        tshark_fields,
        count_frames,
        pcap
    )

    sensors["arp"] = arp_sensor(
        tshark_fields,
        count_frames,
        pcap
    )

    sensors["lldp"] = lldp_sensor(
        tshark_fields,
        count_frames,
        pcap
    )

    sensors["cdp"] = cdp_sensor(
        tshark_fields,
        count_frames,
        pcap
    )

    sensors["stp"] = simple_sensor(
        "stp",
        "stp",
        count_frames,
        pcap
    )

    sensors["dhcp"] = dhcp_sensor(
        tshark_fields,
        count_frames,
        pcap
    )

    sensors["mdns"] = simple_sensor(
        "mdns",
        "udp.port == 5353",
        count_frames,
        pcap
    )

    sensors["llmnr"] = simple_sensor(
        "llmnr",
        "udp.port == 5355",
        count_frames,
        pcap
    )

    sensors["ssdp"] = simple_sensor(
        "ssdp",
        "udp.port == 1900",
        count_frames,
        pcap
    )

    sensors["ipv6_ra"] = ipv6_ra_sensor(
        tshark_fields,
        count_frames,
        pcap
    )
    sensors["ipv6_ns"] = simple_sensor(
        "ipv6_ns",
        "icmpv6.type == 135",
        count_frames,
        pcap
    )

    sensors["ipv6_na"] = simple_sensor(
        "ipv6_na",
        "icmpv6.type == 136",
        count_frames,
        pcap
    )

    return sensors

DHCP_MESSAGE_TYPES = {
    1: "DISCOVER",
    2: "OFFER",
    3: "REQUEST",
    4: "DECLINE",
    5: "ACK",
    6: "NAK",
    7: "RELEASE",
    8: "INFORM"
}


def first_value(value):
    if not value:
        return None

    return value.split(",")[0].strip() or None


def list_values(value):
    if not value:
        return []

    return [
        item.strip()
        for item in value.split(",")
        if item.strip()
    ]


def parse_integer(value):
    if not value:
        return None

    match = re.search(r"\d+", value)

    if not match:
        return None

    return int(match.group())


def dhcp_sensor(
    tshark_fields,
    count_frames,
    pcap
):

    fields = [
        "frame.time_epoch",
        "eth.src",
        "ip.src",
        "ip.dst",
        "dhcp.id",
        "dhcp.hw.mac_addr",
        "dhcp.ip.your",
        "dhcp.option.dhcp",
        "dhcp.option.dhcp_server_id",
        "dhcp.option.subnet_mask",
        "dhcp.option.router",
        "dhcp.option.domain_name_server",
        "dhcp.option.domain_name",
        "dhcp.option.hostname",
        "dhcp.option.ip_address_lease_time"
    ]

    rows = tshark_fields(
        pcap,
        "dhcp",
        fields
    )

    packets = []
    servers = {}

    for row in rows:

        (
            timestamp,
            eth_src,
            ip_src,
            ip_dst,
            transaction_id,
            client_mac,
            offered_ip,
            message_type_raw,
            server_id,
            subnet_mask,
            routers,
            dns_servers,
            domain_name,
            hostname,
            lease_time
        ) = row

        message_type_id = parse_integer(
            message_type_raw
        )

        message_type = DHCP_MESSAGE_TYPES.get(
            message_type_id,
            f"UNKNOWN-{message_type_id}"
            if message_type_id
            else "UNKNOWN"
        )

        server_id = first_value(server_id)

        packet = {
            "timestamp": (
                float(timestamp)
                if timestamp
                else None
            ),

            "message_type": message_type,

            "message_type_id": message_type_id,

            "transaction_id":
                first_value(transaction_id),

            "ethernet_source":
                first_value(eth_src),

            "ip_source":
                first_value(ip_src),

            "ip_destination":
                first_value(ip_dst),

            "client_mac":
                first_value(client_mac),

            "offered_ip":
                first_value(offered_ip),

            "server_id":
                server_id,

            "subnet_mask":
                first_value(subnet_mask),

            "routers":
                list_values(routers),

            "dns_servers":
                list_values(dns_servers),

            "domain_name":
                first_value(domain_name),

            "hostname":
                first_value(hostname),

            "lease_time_seconds":
                parse_integer(lease_time)
        }

        packets.append(packet)

        #
        # Отдельно агрегируем DHCP-серверы
        #

        if server_id:

            if server_id not in servers:

                servers[server_id] = {
                    "server_id": server_id,
                    "messages": [],
                    "subnet_masks": [],
                    "routers": [],
                    "dns_servers": [],
                    "domains": []
                }

            server = servers[server_id]

            if message_type not in server["messages"]:
                server["messages"].append(
                    message_type
                )

            mask = packet["subnet_mask"]

            if (
                mask
                and mask not in server["subnet_masks"]
            ):
                server["subnet_masks"].append(
                    mask
                )

            for router in packet["routers"]:

                if router not in server["routers"]:
                    server["routers"].append(
                        router
                    )

            for dns in packet["dns_servers"]:

                if dns not in server["dns_servers"]:
                    server["dns_servers"].append(
                        dns
                    )

            domain = packet["domain_name"]

            if (
                domain
                and domain not in server["domains"]
            ):
                server["domains"].append(
                    domain
                )

    hits = count_frames(
        pcap,
        "dhcp"
    )

    return {
        "name": "dhcp",
        "detected": hits > 0,
        "hits": hits,

        "data": {
            "servers": list(
                servers.values()
            ),

            "packets": packets
        }
    }

def parse_bool(value):

    if value is None:
        return None

    value = str(value).strip().lower()

    if value in (
        "1",
        "true",
        "yes",
        "set"
    ):
        return True

    if value in (
        "0",
        "false",
        "no",
        "not set"
    ):
        return False

    return None


def value_at(values, index):

    if index < len(values):
        return values[index]

    return None

def ipv6_ra_sensor(
    tshark_fields,
    count_frames,
    pcap
):

    fields = [
        "frame.time_epoch",
        "eth.src",
        "ipv6.src",

        "icmpv6.nd.ra.cur_hop_limit",
        "icmpv6.nd.ra.flag.m",
        "icmpv6.nd.ra.flag.o",
        "icmpv6.nd.ra.flag.prf",

        "icmpv6.nd.ra.router_lifetime",
        "icmpv6.nd.ra.reachable_time",
        "icmpv6.nd.ra.retrans_timer",

        "icmpv6.opt.prefix",
        "icmpv6.opt.prefix.length",
        "icmpv6.opt.prefix.flag.l",
        "icmpv6.opt.prefix.flag.a",
        "icmpv6.opt.prefix.valid_lifetime",
        "icmpv6.opt.prefix.preferred_lifetime",

        "icmpv6.opt.mtu",

        "icmpv6.opt.rdnss",
        "icmpv6.opt.rdnss.lifetime",

        "icmpv6.opt.dnssl",
        "icmpv6.opt.dnssl.lifetime"
    ]

    rows = tshark_fields(
        pcap,
        "icmpv6.type == 134",
        fields
    )

    advertisements = []

    routers = {}

    for row in rows:

        (
            timestamp,
            eth_src,
            ipv6_src,

            hop_limit,
            managed,
            other_config,
            preference,

            router_lifetime,
            reachable_time,
            retrans_timer,

            prefixes_raw,
            prefix_lengths_raw,
            prefix_l_raw,
            prefix_a_raw,
            valid_lifetimes_raw,
            preferred_lifetimes_raw,

            mtu_raw,

            rdnss_raw,
            rdnss_lifetime,

            dnssl_raw,
            dnssl_lifetime
        ) = row


        prefixes = list_values(
            prefixes_raw
        )

        prefix_lengths = list_values(
            prefix_lengths_raw
        )

        prefix_l_flags = list_values(
            prefix_l_raw
        )

        prefix_a_flags = list_values(
            prefix_a_raw
        )

        valid_lifetimes = list_values(
            valid_lifetimes_raw
        )

        preferred_lifetimes = list_values(
            preferred_lifetimes_raw
        )


        prefix_data = []

        for index, prefix in enumerate(prefixes):

            length = parse_integer(
                value_at(
                    prefix_lengths,
                    index
                )
            )

            prefix_data.append({

                "prefix": prefix,

                "length": length,

                "network": (
                    f"{prefix}/{length}"
                    if length is not None
                    else prefix
                ),

                "on_link": parse_bool(
                    value_at(
                        prefix_l_flags,
                        index
                    )
                ),

                "autonomous": parse_bool(
                    value_at(
                        prefix_a_flags,
                        index
                    )
                ),

                "valid_lifetime_seconds":
                    parse_integer(
                        value_at(
                            valid_lifetimes,
                            index
                        )
                    ),

                "preferred_lifetime_seconds":
                    parse_integer(
                        value_at(
                            preferred_lifetimes,
                            index
                        )
                    )
            })


        rdnss = list_values(
            rdnss_raw
        )

        dnssl = list_values(
            dnssl_raw
        )


        advertisement = {

            "timestamp": (
                float(timestamp)
                if timestamp
                else None
            ),

            "router_ipv6":
                first_value(ipv6_src),

            "router_mac":
                first_value(eth_src),

            "current_hop_limit":
                parse_integer(hop_limit),

            "managed_address_configuration":
                parse_bool(managed),

            "other_configuration":
                parse_bool(other_config),

            "router_preference":
                parse_integer(preference),

            "router_lifetime_seconds":
                parse_integer(
                    router_lifetime
                ),

            "reachable_time_ms":
                parse_integer(
                    reachable_time
                ),

            "retrans_timer_ms":
                parse_integer(
                    retrans_timer
                ),

            "mtu":
                parse_integer(mtu_raw),

            "prefixes":
                prefix_data,

            "rdnss":
                rdnss,

            "rdnss_lifetime_seconds":
                parse_integer(
                    rdnss_lifetime
                ),

            "dnssl":
                dnssl,

            "dnssl_lifetime_seconds":
                parse_integer(
                    dnssl_lifetime
                )
        }

        advertisements.append(
            advertisement
        )


        #
        # Агрегированный список маршрутизаторов
        #

        router_ip = advertisement[
            "router_ipv6"
        ]

        if router_ip:

            if router_ip not in routers:

                routers[router_ip] = {

                    "ipv6": router_ip,

                    "mac":
                        advertisement[
                            "router_mac"
                        ],

                    "advertisements": 0,

                    "router_lifetime_seconds":
                        advertisement[
                            "router_lifetime_seconds"
                        ],

                    "managed_address_configuration":
                        advertisement[
                            "managed_address_configuration"
                        ],

                    "other_configuration":
                        advertisement[
                            "other_configuration"
                        ],

                    "mtu":
                        advertisement["mtu"],

                    "prefixes": [],

                    "rdnss": [],

                    "dnssl": []
                }


            router = routers[
                router_ip
            ]

            router[
                "advertisements"
            ] += 1


            for prefix in prefix_data:

                if prefix not in router["prefixes"]:

                    router[
                        "prefixes"
                    ].append(prefix)


            for dns in rdnss:

                if dns not in router["rdnss"]:

                    router[
                        "rdnss"
                    ].append(dns)


            for domain in dnssl:

                if domain not in router["dnssl"]:

                    router[
                        "dnssl"
                    ].append(domain)


    hits = count_frames(
        pcap,
        "icmpv6.type == 134"
    )


    return {

        "name": "ipv6_ra",

        "detected": hits > 0,

        "hits": hits,

        "data": {

            "routers": list(
                routers.values()
            ),

            "advertisements":
                advertisements
        }
    }
