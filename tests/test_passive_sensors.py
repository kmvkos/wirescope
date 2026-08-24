from datetime import datetime, timezone
from collections import OrderedDict

import pytest

from engine.passive_models import (
    EvidenceReference,
    Observation,
    ObservationMetadata,
    PacketDataset,
    PacketRecord,
    PipelineError,
    PipelineErrorCode,
    SensorResult,
    SensorStatus,
)
from sensors.layer2 import cdp_sensor, lldp_sensor, vlan_sensor
from sensors.discovery import llmnr_sensor, nbns_sensor
from sensors.network import dhcpv4_sensor, ipv6_ra_sensor
from sensors.passive import PASSIVE_SENSORS, run_passive_sensors
from tests.helpers import tool_result


def dataset(*packets, errors=None):
    return PacketDataset(
        packets=list(packets),
        errors=list(errors or []),
        decode_result=tool_result(tool="tshark"),
    )


def packet(number, protocols, fields, **metadata):
    return PacketRecord(
        frame_number=number,
        timestamp=datetime.now(timezone.utc),
        protocols=protocols,
        fields=fields,
        **metadata,
    )


def test_sensor_contract_rejects_error_as_absence():
    with pytest.raises(ValueError):
        SensorResult(
            name="dhcpv4",
            status=SensorStatus.ABSENT,
            errors=[
                PipelineError(
                    code=PipelineErrorCode.DECODE_FAILED,
                    component="parser",
                    message="failed",
                )
            ],
        )


def test_sensor_contract_marks_observations_with_errors_partial():
    result = SensorResult(
        name="fixture",
        status=SensorStatus.PARTIAL,
        hits=1,
        observations=[
            Observation(
                kind="fact",
                metadata=ObservationMetadata(
                    sensor="fixture",
                    evidence=EvidenceReference(
                        reference="packet:1",
                        frame_number=1,
                    ),
                ),
            )
        ],
        errors=[
            PipelineError(
                code=PipelineErrorCode.MALFORMED_INPUT,
                component="parser",
                message="one malformed packet",
            )
        ],
    )

    assert result.detected is True
    assert result.status == SensorStatus.PARTIAL


def test_vlan_sensor_handles_multiple_tags_and_vlans():
    result = vlan_sensor(
        dataset(
            packet(
                1,
                ["eth", "vlan", "vlan"],
                {"vlan_vlan_id": ["10", "20"]},
            ),
            packet(
                2,
                ["eth", "vlan"],
                {"vlan_vlan_id": ["30"]},
            ),
        )
    )

    assert result.status == SensorStatus.DETECTED
    assert result.hits == 2
    assert result.observations[0].data["qinq"] is True
    assert result.summary["vlan_frame_counts"] == [
        {"vlan_id": 10, "frames": 1},
        {"vlan_id": 20, "frames": 1},
        {"vlan_id": 30, "frames": 1},
    ]


def test_lldp_pvid_is_not_counted_as_an_8021q_tag():
    result = vlan_sensor(
        dataset(
            packet(
                1,
                ["eth", "lldp"],
                {
                    "lldp_ieee_802_1_port_vlan_id": ["10"],
                    "lldp_ieee_802_1_vlan_voice": ["40"],
                },
            )
        )
    )
    assert result.status == SensorStatus.ABSENT
    assert result.summary["vlan_frame_counts"] == []


def test_untagged_frames_do_not_invent_a_vlan_id():
    result = vlan_sensor(
        dataset(
            packet(1, ["eth", "arp"], {"eth_eth_src": ["02:00:00:00:00:01"]}),
        )
    )
    assert result.status == SensorStatus.ABSENT
    assert result.summary["tagged_frames"] == 0
    assert result.summary["vlan_frame_counts"] == []


def test_lldp_and_cdp_extract_native_voice_and_pvid():
    lldp = lldp_sensor(
        dataset(
            packet(
                1,
                ["eth", "lldp"],
                {
                    "lldp_lldp_tlv_system_name": ["switch-lldp"],
                    "lldp_lldp_port_id": ["Gi1/0/1"],
                    "lldp_ieee_802_1_port_vlan_id": ["10"],
                    "lldp_ieee_802_1_vlan_voice": ["40"],
                },
            )
        )
    )
    cdp = cdp_sensor(
        dataset(
            packet(
                2,
                ["eth", "cdp"],
                {
                    "cdp_cdp_deviceid": ["switch-cdp"],
                    "cdp_cdp_portid": ["GigabitEthernet1/0/2"],
                    "cdp_cdp_native_vlan": ["20"],
                    "cdp_cdp_voice_vlan": ["30"],
                },
            )
        )
    )
    assert lldp.status == SensorStatus.DETECTED
    assert lldp.observations[0].data["pvid"] == 10
    assert lldp.observations[0].data["voice_vlan"] == 40
    assert cdp.status == SensorStatus.DETECTED
    assert cdp.observations[0].data["native_vlan"] == 20
    assert cdp.observations[0].data["voice_vlan"] == 30


def test_dhcp_sensor_aggregates_multiple_servers():
    packets = []
    for number, server, offered in (
        (1, "192.0.2.1", "192.0.2.100"),
        (2, "192.0.2.2", "192.0.2.101"),
    ):
        packets.append(
            packet(
                number,
                ["eth", "ip", "udp", "dhcp"],
                {
                    "dhcp_dhcp_option_dhcp": ["2"],
                    "dhcp_dhcp_option_dhcp_server_id": [server],
                    "dhcp_dhcp_ip_your": [offered],
                    "dhcp_dhcp_option_subnet_mask": ["255.255.255.0"],
                    "dhcp_dhcp_option_router": [server],
                    "dhcp_dhcp_option_domain_name_server": ["192.0.2.53"],
                },
                source_ip=server,
            )
        )

    result = dhcpv4_sensor(dataset(*packets))

    assert result.status == SensorStatus.DETECTED
    assert result.summary["server_count"] == 2
    assert {
        item["server_id"]
        for item in result.summary["servers"]
    } == {"192.0.2.1", "192.0.2.2"}


def test_ipv6_ra_sensor_aggregates_multiple_routers():
    result = ipv6_ra_sensor(
        dataset(
            packet(
                1,
                ["eth", "ipv6", "icmpv6"],
                {
                    "icmpv6_icmpv6_type": ["134"],
                    "icmpv6_icmpv6_nd_ra_router_lifetime": ["1800"],
                    "icmpv6_icmpv6_opt_prefix": ["2001:db8:1::"],
                    "icmpv6_icmpv6_opt_prefix_length": ["64"],
                },
                source_ip="fe80::1",
                source_mac="02:00:00:00:00:01",
            ),
            packet(
                2,
                ["eth", "ipv6", "icmpv6"],
                {
                    "icmpv6_icmpv6_type": ["134"],
                    "icmpv6_icmpv6_nd_ra_router_lifetime": ["900"],
                    "icmpv6_icmpv6_opt_prefix": ["2001:db8:2::"],
                    "icmpv6_icmpv6_opt_prefix_length": ["64"],
                },
                source_ip="fe80::2",
                source_mac="02:00:00:00:00:02",
            ),
        )
    )

    assert result.status == SensorStatus.DETECTED
    assert result.summary["router_count"] == 2
    assert {item["ipv6"] for item in result.summary["routers"]} == {
        "fe80::1",
        "fe80::2",
    }


def test_llmnr_and_nbns_extract_names_and_addresses():
    llmnr = llmnr_sensor(
        dataset(
            packet(
                1,
                ["eth", "ip", "udp", "llmnr"],
                {
                    "udp_udp_dstport": ["5355"],
                    "llmnr_dns_qry_name": ["printer.example.test"],
                    "llmnr_dns_flags_response": ["0"],
                },
                source_ip="192.0.2.10",
            )
        )
    )
    nbns = nbns_sensor(
        dataset(
            packet(
                2,
                ["eth", "ip", "udp", "nbns"],
                {
                    "nbns_nbns_name": ["FILESERVER"],
                    "nbns_nbns_flags_response": ["1"],
                    "nbns_nbns_addr": ["192.0.2.20"],
                },
                source_ip="192.0.2.20",
            )
        )
    )

    assert llmnr.status == SensorStatus.DETECTED
    assert llmnr.summary["names"] == ["printer.example.test"]
    assert nbns.status == SensorStatus.DETECTED
    assert nbns.observations[0].data["names"] == ["FILESERVER"]


def test_sensor_registry_covers_required_protocols():
    assert list(PASSIVE_SENSORS) == [
        "ethernet",
        "vlan",
        "arp",
        "dhcpv4",
        "lldp",
        "cdp",
        "stp",
        "ipv6_ra",
        "ipv6_nd",
        "dhcpv6",
        "mdns",
        "llmnr",
        "nbns",
        "ssdp",
    ]


def test_sensor_exception_becomes_explicit_error():
    def broken_sensor(_dataset):
        raise RuntimeError("fixture failure")

    results = run_passive_sensors(
        dataset(),
        registry=OrderedDict([("broken", broken_sensor)]),
    )

    assert results["broken"].status == SensorStatus.ERROR
    assert results["broken"].errors[0].code == PipelineErrorCode.SENSOR_FAILED
