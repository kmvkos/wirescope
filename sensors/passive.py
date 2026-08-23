"""Registry and execution of normalized passive protocol sensors."""

from collections import OrderedDict

from engine.passive_models import (
    PacketDataset,
    PipelineError,
    PipelineErrorCode,
    SensorResult,
)
from sensors.base import Sensor
from sensors.discovery import (
    llmnr_sensor,
    mdns_sensor,
    nbns_sensor,
    ssdp_sensor,
)
from sensors.ethernet import ethernet_sensor
from sensors.layer2 import cdp_sensor, lldp_sensor, stp_sensor, vlan_sensor
from sensors.network import (
    arp_sensor,
    dhcpv4_sensor,
    dhcpv6_sensor,
    ipv6_nd_sensor,
    ipv6_ra_sensor,
)


PASSIVE_SENSORS: OrderedDict[str, Sensor] = OrderedDict(
    [
        ("ethernet", ethernet_sensor),
        ("vlan", vlan_sensor),
        ("arp", arp_sensor),
        ("dhcpv4", dhcpv4_sensor),
        ("lldp", lldp_sensor),
        ("cdp", cdp_sensor),
        ("stp", stp_sensor),
        ("ipv6_ra", ipv6_ra_sensor),
        ("ipv6_nd", ipv6_nd_sensor),
        ("dhcpv6", dhcpv6_sensor),
        ("mdns", mdns_sensor),
        ("llmnr", llmnr_sensor),
        ("nbns", nbns_sensor),
        ("ssdp", ssdp_sensor),
    ]
)


def run_passive_sensors(
    dataset: PacketDataset,
    registry: OrderedDict[str, Sensor] | None = None,
) -> dict[str, SensorResult]:
    active_registry = registry or PASSIVE_SENSORS
    results: dict[str, SensorResult] = {}

    for name, sensor in active_registry.items():
        try:
            results[name] = sensor(dataset)
        except Exception as exc:
            results[name] = SensorResult(
                name=name,
                status="error",
                errors=[
                    PipelineError(
                        code=PipelineErrorCode.SENSOR_FAILED,
                        component=f"sensor.{name}",
                        message=f"Sensor failed: {exc}",
                    )
                ],
            )

    return results
