"""Generate small sanitized pcaps without using a live network."""

from pathlib import Path

from scapy.all import (
    ARP,
    BOOTP,
    DHCP,
    DNS,
    DNSQR,
    Dot1Q,
    Ether,
    ICMPv6NDOptPrefixInfo,
    ICMPv6NDOptDstLLAddr,
    ICMPv6NDOptSrcLLAddr,
    ICMPv6ND_NA,
    ICMPv6ND_NS,
    ICMPv6ND_RA,
    IP,
    IPv6,
    LLC,
    Raw,
    SNAP,
    STP,
    UDP,
    wrpcap,
)
from scapy.utils import checksum
from scapy.layers.dhcp6 import (
    DHCP6_Advertise,
    DHCP6OptClientId,
    DHCP6OptDNSDomains,
    DHCP6OptDNSServers,
    DHCP6OptIAAddress,
    DHCP6OptIA_NA,
    DHCP6OptServerId,
    DUID_LL,
)


CLIENT_MAC = "02:00:00:00:00:10"
SERVER_MAC = "02:00:00:00:00:01"


def write_passive_fixture(path: Path) -> Path:
    packets = [
        _vlan_arp_packet(),
        _arp_packet(),
        _dhcp_offer_packet(),
        _lldp_packet(),
        _cdp_packet(),
        _stp_packet(),
        _ipv6_ra_packet(),
        _ipv6_ns_packet(),
        _ipv6_na_packet(),
        _dhcpv6_packet(),
        _mdns_packet(),
        _ssdp_packet(),
    ]
    wrpcap(str(path), packets)
    return path


def _vlan_arp_packet():
    return (
        Ether(src=CLIENT_MAC, dst="ff:ff:ff:ff:ff:ff")
        / Dot1Q(vlan=10)
        / Dot1Q(vlan=20)
        / ARP(
            op=1,
            hwsrc=CLIENT_MAC,
            psrc="192.0.2.10",
            pdst="192.0.2.1",
        )
    )


def _arp_packet():
    return Ether(src=SERVER_MAC, dst=CLIENT_MAC) / ARP(
        op=2,
        hwsrc=SERVER_MAC,
        psrc="192.0.2.1",
        hwdst=CLIENT_MAC,
        pdst="192.0.2.10",
    )


def _dhcp_offer_packet():
    return (
        Ether(src=SERVER_MAC, dst="ff:ff:ff:ff:ff:ff")
        / IP(src="192.0.2.1", dst="255.255.255.255")
        / UDP(sport=67, dport=68)
        / BOOTP(
            op=2,
            yiaddr="192.0.2.100",
            siaddr="192.0.2.1",
            chaddr=bytes.fromhex(CLIENT_MAC.replace(":", "")),
            xid=0x12345678,
        )
        / DHCP(
            options=[
                ("message-type", "offer"),
                ("server_id", "192.0.2.1"),
                ("subnet_mask", "255.255.255.0"),
                ("router", "192.0.2.1"),
                ("name_server", "192.0.2.53"),
                ("domain", "example.test"),
                ("lease_time", 3600),
                "end",
            ]
        )
    )


def _lldp_packet():
    chassis = bytes.fromhex(SERVER_MAC.replace(":", ""))
    payload = b"".join(
        [
            _lldp_tlv(1, b"\x04" + chassis),
            _lldp_tlv(2, b"\x05Gi1/0/1"),
            _lldp_tlv(3, (120).to_bytes(2, "big")),
            _lldp_tlv(5, b"switch-fixture"),
            _lldp_tlv(6, b"Sanitized test switch"),
            _lldp_tlv(7, b"\x00\x14\x00\x14"),
            _lldp_tlv(0, b""),
        ]
    )
    return (
        Ether(
            src=SERVER_MAC,
            dst="01:80:c2:00:00:0e",
            type=0x88CC,
        )
        / Raw(payload)
    )


def _lldp_tlv(tlv_type: int, value: bytes) -> bytes:
    header = (tlv_type << 9) | len(value)
    return header.to_bytes(2, "big") + value


def _cdp_packet():
    tlvs = b"".join(
        [
            _cdp_tlv(1, b"switch-cdp-fixture"),
            _cdp_tlv(3, b"GigabitEthernet1/0/1"),
            _cdp_tlv(4, (0x00000009).to_bytes(4, "big")),
            _cdp_tlv(5, b"FixtureOS 1.0"),
            _cdp_tlv(6, b"FixtureSwitch"),
            _cdp_tlv(10, (20).to_bytes(2, "big")),
            _cdp_tlv(11, b"\x01"),
        ]
    )
    header = b"\x02\xb4\x00\x00"
    cdp_payload = header[:2] + checksum(header + tlvs).to_bytes(2, "big") + tlvs
    return (
        Ether(src=SERVER_MAC, dst="01:00:0c:cc:cc:cc")
        / LLC(dsap=0xAA, ssap=0xAA, ctrl=3)
        / SNAP(OUI=0x00000C, code=0x2000)
        / Raw(cdp_payload)
    )


def _cdp_tlv(tlv_type: int, value: bytes) -> bytes:
    return (
        tlv_type.to_bytes(2, "big")
        + (len(value) + 4).to_bytes(2, "big")
        + value
    )


def _stp_packet():
    return (
        Ether(
            src=SERVER_MAC,
            dst="01:80:c2:00:00:00",
            type=len(LLC() / STP()),
        )
        / LLC(dsap=0x42, ssap=0x42, ctrl=3)
        / STP(
            rootid=32768,
            rootmac=SERVER_MAC,
            bridgeid=32768,
            bridgemac=SERVER_MAC,
            portid=0x8001,
        )
    )


def _ipv6_ra_packet():
    return (
        Ether(src=SERVER_MAC, dst="33:33:00:00:00:01")
        / IPv6(src="fe80::1", dst="ff02::1")
        / ICMPv6ND_RA(M=0, O=1, routerlifetime=1800)
        / ICMPv6NDOptSrcLLAddr(lladdr=SERVER_MAC)
        / ICMPv6NDOptPrefixInfo(
            prefix="2001:db8:1::",
            prefixlen=64,
            L=1,
            A=1,
            validlifetime=86400,
            preferredlifetime=14400,
        )
    )


def _mdns_packet():
    return (
        Ether(src=CLIENT_MAC, dst="01:00:5e:00:00:fb")
        / IP(src="192.0.2.10", dst="224.0.0.251")
        / UDP(sport=5353, dport=5353)
        / DNS(
            id=0,
            qr=0,
            qd=DNSQR(qname="_services._dns-sd._udp.local", qtype="PTR"),
        )
    )


def _ipv6_ns_packet():
    return (
        Ether(src=CLIENT_MAC, dst="33:33:ff:00:00:01")
        / IPv6(src="fe80::10", dst="ff02::1:ff00:1")
        / ICMPv6ND_NS(tgt="2001:db8:1::1")
        / ICMPv6NDOptSrcLLAddr(lladdr=CLIENT_MAC)
    )


def _ipv6_na_packet():
    return (
        Ether(src=SERVER_MAC, dst=CLIENT_MAC)
        / IPv6(src="2001:db8:1::1", dst="fe80::10")
        / ICMPv6ND_NA(tgt="2001:db8:1::1", R=1, S=1, O=1)
        / ICMPv6NDOptDstLLAddr(lladdr=SERVER_MAC)
    )


def _ssdp_packet():
    payload = (
        b"NOTIFY * HTTP/1.1\r\n"
        b"HOST: 239.255.255.250:1900\r\n"
        b"NT: upnp:rootdevice\r\n"
        b"USN: uuid:wirescope-fixture::upnp:rootdevice\r\n"
        b"LOCATION: http://192.0.2.20/device.xml\r\n"
        b"SERVER: WireScopeFixture/1.0 UPnP/1.1\r\n\r\n"
    )
    return (
        Ether(src=SERVER_MAC, dst="01:00:5e:7f:ff:fa")
        / IP(src="192.0.2.20", dst="239.255.255.250")
        / UDP(sport=1900, dport=1900)
        / Raw(payload)
    )


def _dhcpv6_packet():
    return (
        Ether(src=SERVER_MAC, dst=CLIENT_MAC)
        / IPv6(src="fe80::1", dst="fe80::10")
        / UDP(sport=547, dport=546)
        / DHCP6_Advertise(trid=0x123456)
        / DHCP6OptClientId(duid=DUID_LL(lladdr=CLIENT_MAC))
        / DHCP6OptServerId(duid=DUID_LL(lladdr=SERVER_MAC))
        / DHCP6OptIA_NA(
            iaid=1,
            T1=1800,
            T2=2700,
            ianaopts=[
                DHCP6OptIAAddress(
                    addr="2001:db8:1::100",
                    preflft=3600,
                    validlft=7200,
                )
            ],
        )
        / DHCP6OptDNSServers(dnsservers=["2001:db8:1::53"])
        / DHCP6OptDNSDomains(dnsdomains=["example.test."])
    )
