import pytest

from parsers.nmap import NmapParseCode, NmapParseError, parse_nmap_xml
from tests.fixtures.nmap import fixture_path, fixture_text


def test_parser_linux_windows_and_appliance():
    linux = parse_nmap_xml(fixture_path("linux_host.xml"))
    windows = parse_nmap_xml(fixture_path("windows_host.xml"))
    appliance = parse_nmap_xml(fixture_path("network_appliance.xml"))
    assert linux.hosts[0].ipv4 == "192.0.2.10"
    assert linux.hosts[0].mac == "00:11:22:33:44:55"
    assert linux.hosts[0].mac_vendor == "CIMSYS Inc"
    assert linux.hosts[0].hostnames[0].name == "linux.example.test"
    assert linux.hosts[0].os_matches[0].family == "Linux"
    assert linux.hosts[0].uptime_seconds == 86400
    assert linux.hosts[0].network_distance == 1
    ssh = linux.hosts[0].ports[0]
    assert ssh.protocol == "tcp"
    assert ssh.state == "open"
    assert ssh.service.product == "OpenSSH"
    assert ssh.service.cpe[0].startswith("cpe:/a:openbsd:openssh")
    assert windows.hosts[0].os_matches[0].family == "Windows"
    assert appliance.hosts[0].mac_vendor.startswith("Cisco")
    assert appliance.hosts[0].ports[-1].protocol == "udp"


def test_parser_web_multi_service_filtered_and_ipv6():
    web = parse_nmap_xml(fixture_path("web_server.xml"))
    multi = parse_nmap_xml(fixture_path("multi_service.xml"))
    filtered = parse_nmap_xml(fixture_path("filtered_ports.xml"))
    ipv6 = parse_nmap_xml(fixture_path("ipv6_host.xml"))
    assert {port.port for port in web.hosts[0].ports} == {80, 443}
    assert web.hosts[0].ports[1].service.tunnel == "ssl"
    assert len(multi.hosts[0].ports) == 5
    assert multi.hosts[0].ipv6 == "2001:db8::15"
    assert {port.state for port in filtered.hosts[0].ports} >= {
        "filtered",
        "closed",
    }
    assert ipv6.hosts[0].ipv6 == "2001:db8::20"
    assert ipv4_missing(ipv6.hosts[0])


def ipv4_missing(host):
    return host.ipv4 is None


def test_parser_os_matches_and_multiple_cpe():
    os_doc = parse_nmap_xml(fixture_path("os_matches.xml"))
    cpe_doc = parse_nmap_xml(fixture_path("multiple_cpe.xml"))
    assert len(os_doc.hosts[0].os_matches) == 2
    assert os_doc.hosts[0].os_matches[0].accuracy == 92
    service = cpe_doc.hosts[0].ports[0].service
    assert len(service.cpe) == 2


def test_parser_empty_malformed_incomplete_and_no_response():
    empty = parse_nmap_xml(fixture_path("empty_valid.xml"))
    assert empty.hosts == []
    assert empty.hosts_up == 0
    assert empty.finished is True
    silent = parse_nmap_xml(fixture_path("no_response.xml"))
    assert silent.hosts[0].status == "down"
    assert silent.hosts[0].status_reason == "no-response"
    with pytest.raises(NmapParseError) as malformed:
        parse_nmap_xml(fixture_text("malformed.xml"))
    assert malformed.value.code == NmapParseCode.MALFORMED_XML
    with pytest.raises(NmapParseError) as incomplete:
        parse_nmap_xml(fixture_path("incomplete.xml"))
    assert incomplete.value.code == NmapParseCode.INCOMPLETE_OUTPUT
    with pytest.raises(NmapParseError) as unsupported:
        parse_nmap_xml(fixture_path("unsupported.xml"))
    assert unsupported.value.code == NmapParseCode.UNSUPPORTED_OUTPUT
