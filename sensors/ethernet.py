"""Ethernet and source-MAC passive observations."""

from collections import Counter

from engine.passive_models import PacketDataset
from sensors.base import dataset_errors, observation, sensor_result


def _is_multicast(mac: str) -> bool:
    try:
        return bool(int(mac.split(":", 1)[0], 16) & 1)
    except (ValueError, IndexError):
        return False


def ethernet_sensor(dataset: PacketDataset):
    source_counts: Counter[str] = Counter()
    broadcast_frames = 0
    multicast_frames = 0

    for packet in dataset.packets:
        if packet.source_mac:
            source_counts[packet.source_mac.lower()] += 1
        destination = (packet.destination_mac or "").lower()
        if destination == "ff:ff:ff:ff:ff:ff":
            broadcast_frames += 1
        elif destination and _is_multicast(destination):
            multicast_frames += 1

    observations = []
    for mac, count in source_counts.most_common():
        packet = next(
            item
            for item in dataset.packets
            if (item.source_mac or "").lower() == mac
        )
        observations.append(
            observation(
                "ethernet",
                "source_mac",
                packet,
                {
                    "mac": mac,
                    "frames": count,
                    "multicast_source": _is_multicast(mac),
                },
                protocol="ethernet",
            )
        )

    return sensor_result(
        "ethernet",
        observations,
        hits=sum(source_counts.values()),
        summary={
            "unique_source_macs": len(source_counts),
            "broadcast_frames": broadcast_frames,
            "multicast_frames": multicast_frames,
        },
        errors=dataset_errors(dataset),
    )
