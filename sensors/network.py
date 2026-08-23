"""ARP, DHCP, and IPv6 passive protocol sensors."""

from collections import defaultdict
from typing import Any

from engine.passive_models import PacketDataset
from sensors.base import (
    boolean_value,
    dataset_errors,
    first_value,
    integer_value,
    observation,
    sensor_result,
    split_values,
    unique_dicts,
)


DHCP_MESSAGE_TYPES = {
    1: "discover",
    2: "offer",
    3: "request",
    4: "decline",
    5: "ack",
    6: "nak",
    7: "release",
    8: "inform",
}

DHCPV6_MESSAGE_TYPES = {
    1: "solicit",
    2: "advertise",
    3: "request",
    4: "confirm",
    5: "renew",
    6: "rebind",
    7: "reply",
    8: "release",
    9: "decline",
    10: "reconfigure",
    11: "information-request",
    12: "relay-forward",
    13: "relay-reply",
}


def arp_sensor(dataset: PacketDataset):
    observations = []
    relationships: list[dict[str, Any]] = []

    for packet in dataset.packets:
        if not (
            packet.has_protocol("arp")
            or packet.values("arp.opcode", "arp.src.proto_ipv4")
        ):
            continue

        opcode = integer_value(packet, "arp.opcode")
        sender_ip = first_value(packet, "arp.src.proto_ipv4")
        sender_mac = first_value(packet, "arp.src.hw_mac") or packet.source_mac
        target_ip = first_value(packet, "arp.dst.proto_ipv4")
        target_mac = first_value(packet, "arp.dst.hw_mac")

        data = {
            "opcode": opcode,
            "operation": {1: "request", 2: "reply"}.get(opcode, "other"),
            "sender_ipv4": sender_ip,
            "sender_mac": sender_mac,
            "target_ipv4": target_ip,
            "target_mac": target_mac,
        }
        observations.append(
            observation(
                "arp",
                "arp_message",
                packet,
                data,
                protocol="ARP",
            )
        )
        if sender_ip and sender_mac:
            relationships.append(
                {"ipv4": sender_ip, "mac": sender_mac.lower()}
            )

    return sensor_result(
        "arp",
        observations,
        summary={
            "observed_ipv4_mac": unique_dicts(relationships),
            "unique_ipv4_hosts": len(
                {item["ipv4"] for item in relationships}
            ),
        },
        errors=dataset_errors(dataset),
    )


def dhcpv4_sensor(dataset: PacketDataset):
    observations = []
    servers: dict[str, dict[str, Any]] = {}

    for packet in dataset.packets:
        if not (
            packet.has_protocol("dhcp", "bootp")
            or packet.values("dhcp.option.dhcp", "bootp.option.dhcp")
        ):
            continue

        message_type_id = integer_value(
            packet,
            "dhcp.option.dhcp",
            "bootp.option.dhcp",
        )
        server_id = first_value(
            packet,
            "dhcp.option.dhcp_server_id",
            "bootp.option.dhcp_server_id",
        )
        data = {
            "message_type_id": message_type_id,
            "message_type": DHCP_MESSAGE_TYPES.get(
                message_type_id,
                f"unknown-{message_type_id}" if message_type_id else "unknown",
            ),
            "transaction_id": first_value(
                packet,
                "dhcp.id",
                "bootp.id",
            ),
            "client_mac": first_value(
                packet,
                "dhcp.hw.mac_addr",
                "bootp.hw.mac_addr",
            ),
            "hostname": first_value(
                packet,
                "dhcp.option.hostname",
                "bootp.option.hostname",
            ),
            "requested_ip": first_value(
                packet,
                "dhcp.option.requested_ip_address",
                "bootp.option.requested_ip_address",
            ),
            "offered_ip": first_value(
                packet,
                "dhcp.ip.your",
                "bootp.ip.your",
            ),
            "server_id": server_id,
            "subnet_mask": first_value(
                packet,
                "dhcp.option.subnet_mask",
                "bootp.option.subnet_mask",
            ),
            "routers": split_values(
                packet.values(
                    "dhcp.option.router",
                    "bootp.option.router",
                )
            ),
            "dns_servers": split_values(
                packet.values(
                    "dhcp.option.domain_name_server",
                    "bootp.option.domain_name_server",
                )
            ),
            "domain_name": first_value(
                packet,
                "dhcp.option.domain_name",
                "bootp.option.domain_name",
            ),
            "lease_time_seconds": integer_value(
                packet,
                "dhcp.option.ip_address_lease_time",
                "bootp.option.ip_address_lease_time",
            ),
        }
        observations.append(
            observation(
                "dhcpv4",
                "dhcp_message",
                packet,
                data,
                protocol="DHCPv4",
            )
        )

        if server_id:
            server = servers.setdefault(
                server_id,
                {
                    "server_id": server_id,
                    "message_types": [],
                    "subnet_masks": [],
                    "routers": [],
                    "dns_servers": [],
                    "domains": [],
                },
            )
            for key, values in (
                ("message_types", [data["message_type"]]),
                ("subnet_masks", [data["subnet_mask"]]),
                ("routers", data["routers"]),
                ("dns_servers", data["dns_servers"]),
                ("domains", [data["domain_name"]]),
            ):
                for value in values:
                    if value and value not in server[key]:
                        server[key].append(value)

    return sensor_result(
        "dhcpv4",
        observations,
        summary={
            "servers": list(servers.values()),
            "server_count": len(servers),
        },
        errors=dataset_errors(dataset),
    )


def ipv6_ra_sensor(dataset: PacketDataset):
    observations = []
    routers: dict[str, dict[str, Any]] = {}

    for packet in dataset.packets:
        icmpv6_type = integer_value(packet, "icmpv6.type")
        if not (
            icmpv6_type == 134
            or packet.values("icmpv6.nd.ra.router_lifetime")
        ):
            continue

        prefixes = split_values(packet.values("icmpv6.opt.prefix"))
        prefix_lengths = _integer_values(
            packet.values("icmpv6.opt.prefix.length")
        )
        on_link_flags = _boolean_values(
            packet.values("icmpv6.opt.prefix.flag.l")
        )
        autonomous_flags = _boolean_values(
            packet.values("icmpv6.opt.prefix.flag.a")
        )
        valid_lifetimes = _integer_values(
            packet.values("icmpv6.opt.prefix.valid_lifetime")
        )
        preferred_lifetimes = _integer_values(
            packet.values("icmpv6.opt.prefix.preferred_lifetime")
        )

        prefix_data = []
        for index, prefix in enumerate(prefixes):
            length = _at(prefix_lengths, index)
            prefix_data.append(
                {
                    "prefix": prefix,
                    "length": length,
                    "network": (
                        f"{prefix}/{length}" if length is not None else prefix
                    ),
                    "on_link": _at(on_link_flags, index),
                    "autonomous": _at(autonomous_flags, index),
                    "valid_lifetime_seconds": _at(valid_lifetimes, index),
                    "preferred_lifetime_seconds": _at(
                        preferred_lifetimes,
                        index,
                    ),
                }
            )

        router_ipv6 = packet.source_ip or first_value(packet, "ipv6.src")
        data = {
            "router_ipv6": router_ipv6,
            "router_mac": packet.source_mac,
            "router_lifetime_seconds": integer_value(
                packet,
                "icmpv6.nd.ra.router_lifetime",
            ),
            "managed_address_configuration": boolean_value(
                packet,
                "icmpv6.nd.ra.flag.m",
            ),
            "other_configuration": boolean_value(
                packet,
                "icmpv6.nd.ra.flag.o",
            ),
            "router_preference": first_value(
                packet,
                "icmpv6.nd.ra.flag.prf",
            ),
            "current_hop_limit": integer_value(
                packet,
                "icmpv6.nd.ra.cur_hop_limit",
            ),
            "prefixes": prefix_data,
            "rdnss": split_values(packet.values("icmpv6.opt.rdnss")),
            "rdnss_lifetime_seconds": integer_value(
                packet,
                "icmpv6.opt.rdnss.lifetime",
            ),
            "dnssl": split_values(packet.values("icmpv6.opt.dnssl")),
            "dnssl_lifetime_seconds": integer_value(
                packet,
                "icmpv6.opt.dnssl.lifetime",
            ),
            "mtu": integer_value(packet, "icmpv6.opt.mtu"),
        }
        observations.append(
            observation(
                "ipv6_ra",
                "router_advertisement",
                packet,
                data,
                protocol="ICMPv6 RA",
            )
        )
        if router_ipv6:
            router = routers.setdefault(
                router_ipv6,
                {
                    "ipv6": router_ipv6,
                    "mac": packet.source_mac,
                    "advertisements": 0,
                    "prefixes": [],
                    "rdnss": [],
                    "dnssl": [],
                },
            )
            router["advertisements"] += 1
            router["prefixes"] = unique_dicts(
                [*router["prefixes"], *prefix_data]
            )
            for key in ("rdnss", "dnssl"):
                for value in data[key]:
                    if value not in router[key]:
                        router[key].append(value)

    return sensor_result(
        "ipv6_ra",
        observations,
        summary={
            "routers": list(routers.values()),
            "router_count": len(routers),
        },
        errors=dataset_errors(dataset),
    )


def ipv6_nd_sensor(dataset: PacketDataset):
    observations = []
    relationships: list[dict[str, Any]] = []

    for packet in dataset.packets:
        message_type = integer_value(packet, "icmpv6.type")
        if message_type not in {135, 136}:
            continue

        is_solicitation = message_type == 135
        target = first_value(
            packet,
            "icmpv6.nd.ns.target_address",
            "icmpv6.nd.na.target_address",
            "icmpv6.nd.target_address",
        )
        option_mac = first_value(
            packet,
            "icmpv6.opt.linkaddr",
            "icmpv6.opt.src_linkaddr",
            "icmpv6.opt.target_linkaddr",
            "icmpv6.nd.opt.src_linkaddr",
            "icmpv6.nd.opt.tgt_linkaddr",
        )
        data = {
            "message_type": "neighbor_solicitation"
            if is_solicitation
            else "neighbor_advertisement",
            "target_ipv6": target,
            "link_layer_address": option_mac,
            "router_flag": boolean_value(packet, "icmpv6.nd.na.flag.r"),
            "solicited_flag": boolean_value(packet, "icmpv6.nd.na.flag.s"),
            "override_flag": boolean_value(packet, "icmpv6.nd.na.flag.o"),
        }
        observations.append(
            observation(
                "ipv6_nd",
                data["message_type"],
                packet,
                data,
                protocol="ICMPv6 ND",
            )
        )
        address = target if not is_solicitation else packet.source_ip
        mac = option_mac or packet.source_mac
        if address and mac:
            relationships.append({"ipv6": address, "mac": mac.lower()})

    return sensor_result(
        "ipv6_nd",
        observations,
        summary={
            "observed_ipv6_mac": unique_dicts(relationships),
            "solicitations": sum(
                item.kind == "neighbor_solicitation"
                for item in observations
            ),
            "advertisements": sum(
                item.kind == "neighbor_advertisement"
                for item in observations
            ),
        },
        errors=dataset_errors(dataset),
    )


def dhcpv6_sensor(dataset: PacketDataset):
    observations = []
    server_ids: list[str] = []

    for packet in dataset.packets:
        if not (
            packet.has_protocol("dhcpv6")
            or packet.values("dhcpv6.msgtype")
        ):
            continue

        message_type_id = integer_value(packet, "dhcpv6.msgtype")
        duids = split_values(packet.values("dhcpv6.duid.bytes"))
        client_id = duids[0] if duids else None
        server_id = duids[-1] if len(duids) > 1 else None
        data = {
            "message_type_id": message_type_id,
            "message_type": DHCPV6_MESSAGE_TYPES.get(
                message_type_id,
                f"unknown-{message_type_id}" if message_type_id else "unknown",
            ),
            "transaction_id": first_value(
                packet,
                "dhcpv6.xid",
                "dhcpv6.transaction_id",
            ),
            "server_id": server_id,
            "client_id": client_id,
            "duids": duids,
            "addresses": split_values(
                packet.values(
                    "dhcpv6.iaaddr.ip",
                    "dhcpv6.iaaddr.ipv6",
                    "dhcpv6.iaprefix.prefix",
                )
            ),
            "dns_servers": split_values(
                packet.values(
                    "dhcpv6.dns_server",
                    "dhcpv6.dns_servers",
                    "dhcpv6.option.dns_servers",
                )
            ),
            "domain_search": split_values(
                packet.values(
                    "dhcpv6.client_domain",
                    "dhcpv6.domain_search_list",
                    "dhcpv6.option.domain_list",
                )
            ),
        }
        observations.append(
            observation(
                "dhcpv6",
                "dhcpv6_message",
                packet,
                data,
                protocol="DHCPv6",
            )
        )
        if server_id and server_id not in server_ids:
            server_ids.append(server_id)

    return sensor_result(
        "dhcpv6",
        observations,
        summary={
            "server_ids": server_ids,
            "server_count": len(server_ids),
        },
        errors=dataset_errors(dataset),
    )


def _integer_values(values: list[str]) -> list[int | None]:
    parsed = []
    for value in split_values(values):
        try:
            parsed.append(int(value, 0))
        except ValueError:
            digits = "".join(character for character in value if character.isdigit())
            parsed.append(int(digits) if digits else None)
    return parsed


def _boolean_values(values: list[str]) -> list[bool | None]:
    parsed = []
    for value in split_values(values):
        normalized = value.lower()
        if normalized in {"1", "true", "yes", "set"}:
            parsed.append(True)
        elif normalized in {"0", "false", "no", "not set"}:
            parsed.append(False)
        else:
            parsed.append(None)
    return parsed


def _at(values: list[Any], index: int) -> Any:
    return values[index] if index < len(values) else None
