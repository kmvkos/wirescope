from dataclasses import replace

from scapy.all import ARP, Ether, PcapWriter, wrpcap

from config.settings import get_settings
from engine.passive import PassivePipeline
from engine.passive_models import (
    ConfidenceLevel,
    SensorStatus,
)
from parsers.passive import PassivePacketParser
from providers.tools import ToolRunner
from tests.fixtures.packets import write_passive_fixture


def pipeline(settings=None, runner=None):
    active_runner = runner or ToolRunner()
    return PassivePipeline(
        settings=settings or get_settings(),
        runner=active_runner,
    )


def test_generated_pcap_is_decoded_once_for_all_sensors(tmp_path):
    pcap = write_passive_fixture(tmp_path / "passive.pcap")
    result = pipeline().analyze_pcap(pcap)

    assert result.errors == []
    assert result.metrics.capture_subprocesses == 0
    assert result.metrics.decode_subprocesses == 1
    assert result.metrics.total_subprocesses == 1

    assert result.sensors["ethernet"].status == SensorStatus.DETECTED
    assert result.sensors["vlan"].summary["vlan_frame_counts"] == [
        {"vlan_id": 10, "frames": 1},
        {"vlan_id": 20, "frames": 1},
    ]
    assert result.sensors["arp"].summary["unique_ipv4_hosts"] == 2

    dhcp = result.sensors["dhcpv4"]
    assert dhcp.status == SensorStatus.DETECTED
    assert dhcp.observations[0].data["message_type"] == "offer"
    assert dhcp.observations[0].data["subnet_mask"] == "255.255.255.0"
    assert dhcp.summary["server_count"] == 1

    lldp = result.sensors["lldp"]
    assert lldp.status == SensorStatus.DETECTED
    assert lldp.observations[0].data["chassis_id"] == "02:00:00:00:00:01"
    assert lldp.observations[0].data["ttl_seconds"] == 120
    cdp = result.sensors["cdp"]
    assert cdp.observations[0].data["device_id"] == "switch-cdp-fixture"
    assert cdp.observations[0].data["native_vlan"] == 20
    assert result.sensors["stp"].status == SensorStatus.DETECTED
    assert result.sensors["ipv6_ra"].summary["router_count"] == 1
    assert result.sensors["ipv6_nd"].summary["solicitations"] == 1
    assert result.sensors["ipv6_nd"].summary["advertisements"] == 1
    dhcpv6 = result.sensors["dhcpv6"]
    assert dhcpv6.observations[0].data["message_type"] == "advertise"
    assert dhcpv6.observations[0].data["addresses"] == [
        "2001:db8:1::100"
    ]
    assert dhcpv6.observations[0].data["dns_servers"] == [
        "2001:db8:1::53"
    ]
    assert result.sensors["mdns"].status == SensorStatus.DETECTED
    assert result.sensors["ssdp"].summary["locations"] == [
        "http://192.0.2.20/device.xml"
    ]
    assert result.sensors["ethernet"].observations[0].metadata.timestamp

    port_hint = result.assessment.layer2["port_type_hint"]
    assert port_hint["value"] == "trunk-like"
    assert port_hint["confidence"] == ConfidenceLevel.MEDIUM.value
    assert (
        result.assessment.ipv4["candidate_address_groups"][0]["confidence"]
        == ConfidenceLevel.HIGH.value
    )


def test_empty_pcap_produces_absent_not_failed_sensors(tmp_path):
    pcap = tmp_path / "empty.pcap"
    writer = PcapWriter(str(pcap), sync=True)
    writer.close()

    result = pipeline().analyze_pcap(pcap)

    assert result.errors == []
    assert result.capture.frame_count == 0
    assert result.assessment.visibility.value == "silent"
    assert all(
        sensor.status == SensorStatus.ABSENT
        for sensor in result.sensors.values()
    )


def test_protocol_absence_is_distinct_from_parser_error(tmp_path):
    pcap = tmp_path / "arp-only.pcap"
    wrpcap(
        str(pcap),
        [
            Ether(
                src="02:00:00:00:00:01",
                dst="ff:ff:ff:ff:ff:ff",
            )
            / ARP(
                op=1,
                hwsrc="02:00:00:00:00:01",
                psrc="198.51.100.10",
                pdst="198.51.100.1",
            )
        ],
    )

    result = pipeline().analyze_pcap(pcap)

    assert result.sensors["arp"].status == SensorStatus.DETECTED
    assert result.sensors["dhcpv4"].status == SensorStatus.ABSENT
    assert result.sensors["dhcpv4"].errors == []


def test_missing_tshark_marks_every_sensor_as_error(tmp_path):
    pcap = write_passive_fixture(tmp_path / "passive.pcap")
    settings = replace(
        get_settings(),
        tshark_binary="/missing/wirescope-tshark",
    )

    result = pipeline(settings=settings).analyze_pcap(pcap)

    assert result.errors
    assert result.metrics.decode_subprocesses == 1
    assert all(
        sensor.status == SensorStatus.ERROR
        for sensor in result.sensors.values()
    )
    assert all(sensor.errors for sensor in result.sensors.values())


def test_malformed_ek_input_is_reported():
    packets, errors = PassivePacketParser().parse_ek_stream(
        ['{"layers": {"frame": {"frame_frame_number": ["1"]}}}\n', "{bad\n"]
    )

    assert len(packets) == 1
    assert len(errors) == 1
    assert errors[0].component == "passive_parser"


def test_malformed_pcap_becomes_decode_error(tmp_path):
    pcap = tmp_path / "malformed.pcap"
    pcap.write_bytes(b"not a pcap")

    result = pipeline().analyze_pcap(pcap)

    assert result.errors
    assert all(
        sensor.status == SensorStatus.ERROR
        for sensor in result.sensors.values()
    )
