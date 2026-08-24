"""VLAN and network-device neighbor sensors."""

from collections import Counter
import re

from engine.passive_models import PacketDataset, PacketRecord
from sensors.base import (
    dataset_errors,
    first_value,
    integer_value,
    observation,
    sensor_result,
    split_values,
)


def vlan_sensor(dataset: PacketDataset):
    observations = []
    vlan_counts: Counter[int] = Counter()

    for packet in dataset.packets:
        tags = _dot1q_ids(packet)
        for vlan_id in tags:
            vlan_counts[vlan_id] += 1

        if tags:
            observations.append(
                observation(
                    "vlan",
                    "tagged_frame",
                    packet,
                    {
                        "vlan_ids": tags,
                        "tag_count": len(tags),
                        "qinq": len(tags) > 1,
                    },
                    protocol="802.1Q",
                )
            )

    return sensor_result(
        "vlan",
        observations,
        hits=len(observations),
        summary={
            "tagged_frames": len(observations),
            "vlan_frame_counts": [
                {"vlan_id": vlan_id, "frames": count}
                for vlan_id, count in sorted(vlan_counts.items())
            ],
        },
        errors=dataset_errors(dataset),
    )


def _dot1q_ids(packet: PacketRecord) -> list[int]:
    """Return 802.1Q/QinQ IDs from tagged frames only, never LLDP/CDP PVID."""
    tags: list[int] = []
    for name, values in packet.fields.items():
        token = re.sub(r"[^a-z0-9]", "", name.lower())
        if any(part in token for part in ("lldp", "cdp", "stp", "voice", "native", "pvid")):
            continue
        if not (
            token in {"vlanid", "vlanvlanid", "ieee8021adid"}
            or (token.startswith("vlan") and token.endswith("id"))
            or (token.startswith("ieee8021ad") and token.endswith("id"))
        ):
            continue
        for value in split_values(list(values)):
            try:
                vlan_id = int(value, 0)
            except ValueError:
                continue
            if 0 <= vlan_id <= 4095:
                tags.append(vlan_id)
    return tags


def lldp_sensor(dataset: PacketDataset):
    observations = []
    for packet in dataset.packets:
        if not (
            packet.has_protocol("lldp")
            or packet.values("lldp.chassis.id", "lldp.tlv.type")
        ):
            continue

        data = {
            "chassis_id": first_value(
                packet,
                "lldp.chassis.id",
                "lldp.chassis.id.mac",
                "lldp.tlv.chassis.id",
            ),
            "system_name": first_value(packet, "lldp.tlv.system.name"),
            "system_description": first_value(
                packet,
                "lldp.tlv.system.desc",
                "lldp.tlv.system.description",
            ),
            "port_id": first_value(packet, "lldp.port.id", "lldp.tlv.port.id"),
            "port_description": first_value(
                packet,
                "lldp.tlv.port.desc",
                "lldp.tlv.port.description",
            ),
            "management_addresses": split_values(
                packet.values(
                    "lldp.mgn.addr.ip4",
                    "lldp.mgn.addr.ip6",
                    "lldp.tlv.management.addr",
                )
            ),
            "capabilities_supported": split_values(
                packet.values("lldp.tlv.system_cap")
            ),
            "capabilities_enabled": split_values(
                packet.values("lldp.tlv.enable_system_cap")
            ),
            "pvid": integer_value(
                packet,
                "lldp.ieee.802_1.port_vlan.id",
                "lldp.ieee.802_1.pvid",
            ),
            "voice_vlan": integer_value(
                packet,
                "lldp.ieee.802_1.vlan.voice",
                "lldp.med.network_policy.vid",
                "lldp.med.network_policy.vlan",
            ),
            "vlan_names": split_values(
                packet.values("lldp.ieee.802_1.vlan.name")
            ),
            "ttl_seconds": integer_value(
                packet,
                "lldp.time_to_live",
                "lldp.tlv.ttl",
            ),
        }
        observations.append(
            observation(
                "lldp",
                "neighbor_advertisement",
                packet,
                data,
                protocol="LLDP",
            )
        )

    return sensor_result(
        "lldp",
        observations,
        summary={"neighbors_observed": len(observations)},
        errors=dataset_errors(dataset),
    )


def cdp_sensor(dataset: PacketDataset):
    observations = []
    for packet in dataset.packets:
        if not (
            packet.has_protocol("cdp")
            or packet.values("cdp.deviceid", "cdp.portid")
        ):
            continue

        data = {
            "device_id": first_value(packet, "cdp.deviceid"),
            "platform": first_value(packet, "cdp.platform"),
            "software_version": first_value(
                packet,
                "cdp.software_version",
                "cdp.version",
            ),
            "port_id": first_value(packet, "cdp.portid"),
            "management_addresses": split_values(
                packet.values(
                    "cdp.nrgyz.ip_address",
                    "cdp.management_addr",
                    "cdp.address",
                )
            ),
            "capabilities": split_values(packet.values("cdp.capabilities")),
            "native_vlan": integer_value(packet, "cdp.native_vlan"),
            "voice_vlan": integer_value(
                packet,
                "cdp.voice_vlan",
                "cdp.voip.vlan",
                "cdp.spare.vlan",
            ),
            "duplex": first_value(packet, "cdp.duplex"),
            "ttl_seconds": integer_value(packet, "cdp.ttl"),
        }
        observations.append(
            observation(
                "cdp",
                "neighbor_advertisement",
                packet,
                data,
                protocol="CDP",
            )
        )

    return sensor_result(
        "cdp",
        observations,
        summary={"neighbors_observed": len(observations)},
        errors=dataset_errors(dataset),
    )


def stp_sensor(dataset: PacketDataset):
    observations = []
    for packet in dataset.packets:
        if not (
            packet.has_protocol("stp", "rstp", "mstp")
            or packet.values("stp.root.hw", "stp.bridge.hw")
        ):
            continue

        data = {
            "protocol_version": integer_value(
                packet,
                "stp.protocol.version",
                "stp.version",
            ),
            "bpdu_type": first_value(packet, "stp.type"),
            "root_bridge_id": first_value(
                packet,
                "stp.root.id",
                "stp.root.hw",
            ),
            "root_bridge_priority": integer_value(
                packet,
                "stp.root.prio",
            ),
            "root_bridge_extension": integer_value(
                packet,
                "stp.root.ext",
            ),
            "bridge_id": first_value(
                packet,
                "stp.bridge.id",
                "stp.bridge.hw",
            ),
            "bridge_priority": integer_value(
                packet,
                "stp.bridge.prio",
            ),
            "bridge_extension": integer_value(
                packet,
                "stp.bridge.ext",
            ),
            "root_path_cost": integer_value(packet, "stp.root.cost"),
            "port_id": first_value(packet, "stp.port"),
            "message_age_seconds": first_value(packet, "stp.msg_age"),
            "max_age_seconds": first_value(packet, "stp.max_age"),
            "hello_time_seconds": first_value(packet, "stp.hello"),
            "forward_delay_seconds": first_value(packet, "stp.forward"),
        }
        observations.append(
            observation(
                "stp",
                "bridge_protocol_data_unit",
                packet,
                data,
                protocol="STP",
            )
        )

    root_ids = []
    bridge_ids = []
    for item in observations:
        root_id = item.data.get("root_bridge_id")
        if root_id and root_id not in root_ids:
            root_ids.append(root_id)
        bridge_id = item.data.get("bridge_id")
        if bridge_id and bridge_id not in bridge_ids:
            bridge_ids.append(bridge_id)

    return sensor_result(
        "stp",
        observations,
        summary={
            "bpdus_observed": len(observations),
            "root_bridge_ids": root_ids,
            "bridge_ids": bridge_ids,
        },
        errors=dataset_errors(dataset),
    )
