"""Extended read-only SNMP topology evidence for routers and VLAN-aware devices.

The original SNMP topology provider deliberately covers a conservative switch
baseline (IF-MIB, BRIDGE-MIB, Q-BRIDGE-MIB, LLDP and legacy ARP).  This module
adds the pieces required to build a useful topology from routers as well:
interface MAC/type data, IPv4/IPv6 interface addressing, the modern
IP-MIB neighbor table and LLDP management addresses.

All network reads still go through the bounded allow-list provider and use the
same explicit operator credentials.  Nothing in this module grants active
scope or performs SNMP SET operations.
"""

from __future__ import annotations

from collections import defaultdict
import ipaddress
from typing import Any

from providers.snmp_topology import (
    SnmpTopologyProvider,
    _mac,
    _suffix,
    _unique,
)


# IF-MIB additions.
IF_TYPE = ".1.3.6.1.2.1.2.2.1.3"
IF_PHYS_ADDRESS = ".1.3.6.1.2.1.2.2.1.6"

# Legacy IPv4 interface-address table.  Still very widely implemented and a
# useful fallback when RFC 4293's version-neutral tables are absent.
IP_ADDR_ENTRY = ".1.3.6.1.2.1.4.20.1"

# RFC 4293 IP-MIB version-neutral interface address/prefix and neighbor data.
IP_ADDRESS_PREFIX_ENTRY = ".1.3.6.1.2.1.4.32.1"
IP_ADDRESS_ENTRY = ".1.3.6.1.2.1.4.34.1"
IP_NET_TO_PHYSICAL_ENTRY = ".1.3.6.1.2.1.4.35.1"

# IEEE 802.1AB remote management-address table.  The address itself is part of
# the row index, so a read-only walk is enough to recover it.
LLDP_REM_MAN_ADDR_ENTRY = ".1.0.8802.1.1.2.1.4.2.1"


_IF_TYPE_NAMES = {
    6: "ethernetCsmacd",
    23: "ppp",
    24: "softwareLoopback",
    53: "propVirtual",
    71: "ieee80211",
    131: "tunnel",
    135: "l2vlan",
    136: "l3ipvlan",
    161: "ieee8023adLag",
    209: "bridge",
}

_NEIGHBOR_TYPES = {1: "other", 2: "invalid", 3: "dynamic", 4: "static", 5: "local"}
_NEIGHBOR_STATES = {
    1: "reachable",
    2: "stale",
    3: "delay",
    4: "probe",
    5: "invalid",
    6: "unknown",
    7: "incomplete",
}


class ExtendedSnmpTopologyProvider(SnmpTopologyProvider):
    """SNMP topology provider with L3/router evidence and precise VLAN ports."""

    def collect(
        self,
        *,
        target: str,
        credentials: dict[str, Any],
        interface: str,
        cancellation_token=None,
        progress=None,
    ) -> dict[str, Any]:
        document = super().collect(
            target=target,
            credentials=credentials,
            interface=interface,
            cancellation_token=cancellation_token,
            progress=progress,
        )
        if document.get("status") == "tool_unavailable":
            document["capabilities"] = _capabilities(document)
            return document

        extra: dict[str, list[dict[str, Any]]] = {}
        walks = [
            ("if_type", IF_TYPE),
            ("if_phys", IF_PHYS_ADDRESS),
            ("ipv4_addresses", IP_ADDR_ENTRY),
            ("ip_prefixes", IP_ADDRESS_PREFIX_ENTRY),
            ("ip_addresses", IP_ADDRESS_ENTRY),
            ("ip_neighbors", IP_NET_TO_PHYSICAL_ENTRY),
            ("lldp_management", LLDP_REM_MAN_ADDR_ENTRY),
        ]
        warnings = list(document.get("warnings") or [])
        for index, (name, oid) in enumerate(walks, start=1):
            if cancellation_token is not None and cancellation_token.cancelled:
                break
            if progress:
                progress(84 + min(4, int(4 * index / len(walks))), f"SNMP read-only: {name}")
            rows, row_warnings = self._walk(
                str(ipaddress.ip_address(target)),
                credentials,
                oid,
                cancellation_token=cancellation_token,
            )
            extra[name] = rows
            warnings.extend(row_warnings)

        normalized = normalize_extended_collections(
            extra,
            interfaces=list(document.get("interfaces") or []),
            vlans=list(document.get("vlans") or []),
            legacy_arp=list(document.get("arp") or []),
            lldp_neighbors=list(document.get("lldp_neighbors") or []),
        )
        document["interfaces"] = normalized["interfaces"]
        document["interface_addresses"] = normalized["interface_addresses"]
        document["neighbors"] = normalized["neighbors"]
        document["lldp_neighbors"] = normalized["lldp_neighbors"]
        document["warnings"] = _unique(warnings + normalized["warnings"])
        document["capabilities"] = _capabilities(document)
        collection = document.setdefault("collection", {})
        collection["walks_attempted"] = int(collection.get("walks_attempted") or 0) + len(walks)
        collection["extended_l3"] = True
        collection["mib_families"] = [
            "IF-MIB",
            "IP-MIB",
            "BRIDGE-MIB",
            "Q-BRIDGE-MIB",
            "LLDP-MIB",
        ]
        if document.get("status") == "no_data" and (
            document.get("interface_addresses") or document.get("neighbors")
        ):
            document["status"] = "completed"
        return document


def normalize_extended_collections(
    collections: dict[str, list[dict[str, Any]]],
    *,
    interfaces: list[dict[str, Any]],
    vlans: list[dict[str, Any]],
    legacy_arp: list[dict[str, Any]],
    lldp_neighbors: list[dict[str, Any]],
) -> dict[str, Any]:
    """Normalize extra MIB rows without inventing topology relationships."""
    result_interfaces = [dict(item) for item in interfaces if isinstance(item, dict)]
    by_index = {
        int(item["ifindex"]): item
        for item in result_interfaces
        if isinstance(item.get("ifindex"), int)
    }

    for row in collections.get("if_type", []):
        suffix = _suffix(str(row.get("oid") or ""), IF_TYPE)
        if not suffix or not isinstance(row.get("value"), int):
            continue
        ifindex = suffix[-1]
        item = by_index.setdefault(ifindex, {"ifindex": ifindex})
        value = int(row["value"])
        item["if_type"] = value
        item["if_type_name"] = _IF_TYPE_NAMES.get(value, f"ifType-{value}")

    for row in collections.get("if_phys", []):
        suffix = _suffix(str(row.get("oid") or ""), IF_PHYS_ADDRESS)
        if not suffix:
            continue
        mac = _mac(row.get("value"))
        if not mac:
            continue
        ifindex = suffix[-1]
        item = by_index.setdefault(ifindex, {"ifindex": ifindex})
        item["mac"] = mac

    warnings: list[str] = []
    interface_addresses = _interface_addresses(collections, by_index)
    for address in interface_addresses:
        interface = by_index.setdefault(int(address["ifindex"]), {"ifindex": int(address["ifindex"])})
        rows = interface.setdefault("ip_addresses", [])
        if not any(
            item.get("address") == address["address"] and item.get("prefix_length") == address.get("prefix_length")
            for item in rows
        ):
            rows.append(dict(address))

    _decorate_vlan_port_semantics(by_index, vlans, warnings)
    neighbors = _neighbors(collections, by_index, legacy_arp)
    enriched_lldp = _lldp_management_addresses(collections, lldp_neighbors)

    return {
        "interfaces": [by_index[index] for index in sorted(by_index)],
        "interface_addresses": interface_addresses,
        "neighbors": neighbors,
        "lldp_neighbors": enriched_lldp,
        "warnings": warnings,
    }


def _interface_addresses(
    collections: dict[str, list[dict[str, Any]]],
    interfaces: dict[int, dict[str, Any]],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: set[tuple[int, str, int | None]] = set()

    # RFC 1213 / deprecated-but-common IPv4 fallback.
    legacy: dict[str, dict[str, Any]] = {}
    for row in collections.get("ipv4_addresses", []):
        suffix = _suffix(str(row.get("oid") or ""), IP_ADDR_ENTRY)
        if len(suffix) < 5:
            continue
        column = suffix[0]
        octets = suffix[-4:]
        if any(part < 0 or part > 255 for part in octets):
            continue
        address = ".".join(str(part) for part in octets)
        item = legacy.setdefault(address, {"address": address, "source": "ipAddrTable"})
        if column == 2 and isinstance(row.get("value"), int):
            item["ifindex"] = int(row["value"])
        elif column == 3:
            mask = str(row.get("value") or "").strip()
            try:
                prefix = ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
            except ValueError:
                prefix = None
            if prefix is not None:
                item["prefix_length"] = prefix

    for item in legacy.values():
        ifindex = item.get("ifindex")
        if not isinstance(ifindex, int):
            continue
        _finish_address_row(item, interfaces.get(ifindex))
        key = (ifindex, str(item["address"]), item.get("prefix_length"))
        if key not in seen:
            seen.add(key)
            rows.append(item)

    # RFC 4293 version-neutral address table.  ipAddressIfIndex is column 3;
    # address type/address are the table index and can therefore be recovered
    # from every returned row without relying on MIB-name rendering.
    modern: dict[str, dict[str, Any]] = {}
    for row in collections.get("ip_addresses", []):
        suffix = _suffix(str(row.get("oid") or ""), IP_ADDRESS_ENTRY)
        if len(suffix) < 4:
            continue
        column = suffix[0]
        address = _inet_address_from_index(suffix[1:])
        if not address:
            continue
        item = modern.setdefault(address, {"address": address, "source": "ipAddressTable"})
        if column == 3 and isinstance(row.get("value"), int):
            item["ifindex"] = int(row["value"])
        elif column == 4 and isinstance(row.get("value"), int):
            item["address_type"] = {1: "unicast", 2: "anycast", 3: "broadcast"}.get(int(row["value"]), str(row["value"]))
        elif column == 6 and isinstance(row.get("value"), int):
            item["origin"] = int(row["value"])
        elif column == 7 and isinstance(row.get("value"), int):
            item["status"] = int(row["value"])

    prefixes = _prefixes(collections)
    for item in modern.values():
        ifindex = item.get("ifindex")
        if not isinstance(ifindex, int):
            continue
        parsed = ipaddress.ip_address(str(item["address"]))
        candidates = [
            prefix
            for prefix in prefixes
            if prefix["ifindex"] == ifindex
            and ipaddress.ip_network(prefix["network"], strict=False).version == parsed.version
            and parsed in ipaddress.ip_network(prefix["network"], strict=False)
        ]
        if candidates:
            chosen = max(candidates, key=lambda prefix: int(prefix["prefix_length"]))
            item["prefix_length"] = int(chosen["prefix_length"])
        _finish_address_row(item, interfaces.get(ifindex))
        key = (ifindex, str(item["address"]), item.get("prefix_length"))
        # Prefer the modern row over a legacy duplicate because it also works
        # for IPv6 and carries address status/origin.
        if key in seen:
            for index, existing in enumerate(rows):
                if (
                    existing.get("ifindex") == ifindex
                    and existing.get("address") == item["address"]
                    and existing.get("prefix_length") == item.get("prefix_length")
                ):
                    rows[index] = item
                    break
        else:
            seen.add(key)
            rows.append(item)

    rows.sort(key=lambda item: (int(item.get("ifindex") or 0), ipaddress.ip_address(str(item["address"])).version, str(item["address"])))
    return rows


def _prefixes(collections: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    result: dict[tuple[int, str, int], dict[str, Any]] = {}
    for row in collections.get("ip_prefixes", []):
        suffix = _suffix(str(row.get("oid") or ""), IP_ADDRESS_PREFIX_ENTRY)
        if len(suffix) < 6:
            continue
        # suffix: column, ifIndex, addressType, encoded address, prefixLength.
        body = suffix[1:]
        ifindex = body[0]
        address_type = body[1]
        prefix_length = body[-1]
        address = _inet_address_from_parts(address_type, body[2:-1])
        if not address:
            continue
        try:
            network = str(ipaddress.ip_network(f"{address}/{prefix_length}", strict=False))
        except ValueError:
            continue
        result[(ifindex, network, prefix_length)] = {
            "ifindex": ifindex,
            "network": network,
            "prefix_length": prefix_length,
        }
    return sorted(result.values(), key=lambda item: (item["ifindex"], item["network"], item["prefix_length"]))


def _finish_address_row(item: dict[str, Any], interface: dict[str, Any] | None) -> None:
    address = ipaddress.ip_address(str(item["address"]))
    prefix = item.get("prefix_length")
    if isinstance(prefix, int):
        item["network"] = str(ipaddress.ip_network(f"{address}/{prefix}", strict=False))
        item["cidr"] = f"{address}/{prefix}"
    else:
        item["network"] = None
        item["cidr"] = str(address)
    item["family"] = address.version
    item["scope"] = (
        "loopback" if address.is_loopback
        else "link-local" if address.is_link_local
        else "unspecified" if address.is_unspecified
        else "multicast" if address.is_multicast
        else "global" if address.is_global
        else "private"
    )
    if interface:
        item["interface_name"] = interface.get("name") or interface.get("description")
        item["interface_mac"] = interface.get("mac")


def _neighbors(
    collections: dict[str, list[dict[str, Any]]],
    interfaces: dict[int, dict[str, Any]],
    legacy_arp: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    by_key: dict[tuple[int, str], dict[str, Any]] = {}
    for row in collections.get("ip_neighbors", []):
        suffix = _suffix(str(row.get("oid") or ""), IP_NET_TO_PHYSICAL_ENTRY)
        if len(suffix) < 5:
            continue
        column = suffix[0]
        body = suffix[1:]
        ifindex = body[0]
        address = _inet_address_from_index(body[1:])
        if not address:
            continue
        item = by_key.setdefault((ifindex, address), {"ifindex": ifindex, "ip": address, "source": "ipNetToPhysicalTable"})
        if column == 4:
            mac = _mac(row.get("value"))
            if mac:
                item["mac"] = mac
        elif column == 6 and isinstance(row.get("value"), int):
            value = int(row["value"])
            item["type"] = _NEIGHBOR_TYPES.get(value, str(value))
            item["type_id"] = value
        elif column == 7 and isinstance(row.get("value"), int):
            value = int(row["value"])
            item["state"] = _NEIGHBOR_STATES.get(value, str(value))
            item["state_id"] = value

    for item in by_key.values():
        interface = interfaces.get(int(item["ifindex"])) or {}
        item["interface_name"] = interface.get("name") or interface.get("description")

    # Keep the old IPv4 table as a fallback, but do not duplicate entries that
    # are already present in the version-neutral table.
    for row in legacy_arp:
        if not isinstance(row, dict):
            continue
        ip = str(row.get("ip") or "")
        mac = str(row.get("mac") or "")
        ifindex = row.get("ifindex")
        if not ip or not mac or not isinstance(ifindex, int):
            continue
        key = (ifindex, ip)
        if key in by_key:
            continue
        by_key[key] = {
            "ifindex": ifindex,
            "ip": ip,
            "mac": mac,
            "interface_name": row.get("interface_name") or (interfaces.get(ifindex) or {}).get("name"),
            "type": "unknown",
            "state": "unknown",
            "source": "ipNetToMediaTable",
        }

    return sorted(
        [item for item in by_key.values() if item.get("mac")],
        key=lambda item: (int(item.get("ifindex") or 0), ipaddress.ip_address(str(item["ip"])).version, str(item["ip"])),
    )


def _lldp_management_addresses(
    collections: dict[str, list[dict[str, Any]]],
    neighbors: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    by_local_port: dict[int, set[str]] = defaultdict(set)
    for row in collections.get("lldp_management", []):
        suffix = _suffix(str(row.get("oid") or ""), LLDP_REM_MAN_ADDR_ENTRY)
        if len(suffix) < 7:
            continue
        # column, timeMark, localPortNum, remIndex, addrSubtype, encoded addr
        local_port = suffix[2]
        address_type = suffix[4]
        address = _inet_address_from_parts(address_type, suffix[5:])
        if address:
            by_local_port[local_port].add(address)

    result = [dict(item) for item in neighbors if isinstance(item, dict)]
    for item in result:
        local_port = item.get("local_port_num")
        if not isinstance(local_port, int):
            continue
        addresses = sorted(by_local_port.get(local_port) or [])
        if addresses:
            item["remote_management_addresses"] = addresses
    return result


def _decorate_vlan_port_semantics(
    interfaces: dict[int, dict[str, Any]],
    vlans: list[dict[str, Any]],
    warnings: list[str],
) -> None:
    for interface in interfaces.values():
        bridge_port = interface.get("bridge_port")
        if not isinstance(bridge_port, int):
            continue
        member: set[int] = set()
        tagged: set[int] = set()
        untagged: set[int] = set()
        classification_known = False
        evidence: set[str] = set()

        for vlan in vlans:
            if not isinstance(vlan, dict) or not isinstance(vlan.get("vlan_id"), int):
                continue
            vlan_id = int(vlan["vlan_id"])
            egress = set(vlan.get("egress_ports") or []) | set(vlan.get("static_egress_ports") or [])
            has_untagged_bitmap = "untagged_ports" in vlan or "static_untagged_ports" in vlan
            untagged_ports = set(vlan.get("untagged_ports") or []) | set(vlan.get("static_untagged_ports") or [])
            if bridge_port in egress:
                member.add(vlan_id)
                evidence.add("qbridge-egress")
                if has_untagged_bitmap:
                    classification_known = True
                    if bridge_port in untagged_ports:
                        untagged.add(vlan_id)
                    else:
                        tagged.add(vlan_id)
            elif bridge_port in untagged_ports:
                # Some agents expose the untagged bitmap even when the
                # corresponding egress bitmap is unavailable.
                member.add(vlan_id)
                untagged.add(vlan_id)
                classification_known = True
                evidence.add("qbridge-untagged")

        if member:
            interface["vlan_ids"] = sorted(member)
        interface["tagged_vlans"] = sorted(tagged)
        interface["untagged_vlans"] = sorted(untagged)
        interface["vlan_membership_evidence"] = sorted(evidence)

        mode = "unknown"
        if classification_known:
            if tagged and untagged:
                mode = "hybrid"
            elif tagged and not untagged:
                mode = "trunk"
            elif not tagged and len(untagged) == 1:
                mode = "access"
            elif len(untagged) > 1:
                mode = "hybrid"
        pvid = interface.get("pvid")
        if mode == "access" and isinstance(pvid, int) and untagged and pvid not in untagged:
            warnings.append(
                f"SNMP VLAN evidence is inconsistent on ifIndex {interface.get('ifindex')}: PVID {pvid} is not the observed untagged VLAN. Port mode left unknown."
            )
            mode = "unknown"
        interface["port_mode"] = mode


def _inet_address_from_index(parts: list[int]) -> str | None:
    if len(parts) < 2:
        return None
    return _inet_address_from_parts(parts[0], parts[1:])


def _inet_address_from_parts(address_type: int, encoded: list[int]) -> str | None:
    values = list(encoded)
    expected = {1: 4, 2: 16, 3: 8, 4: 20}.get(int(address_type))
    if expected is None:
        return None
    if values and values[0] == len(values) - 1:
        values = values[1:]
    elif values and values[0] == expected and len(values) >= expected + 1:
        values = values[1:]
    octet_count = 4 if address_type in {1, 3} else 16
    if len(values) < octet_count or any(value < 0 or value > 255 for value in values[:octet_count]):
        return None
    try:
        return str(ipaddress.ip_address(bytes(values[:octet_count])))
    except ValueError:
        return None


def _capabilities(document: dict[str, Any]) -> dict[str, bool]:
    interfaces = document.get("interfaces") or []
    return {
        "system_identity": bool(document.get("system")),
        "interfaces": bool(interfaces),
        "interface_mac_type": any(item.get("mac") or item.get("if_type") for item in interfaces if isinstance(item, dict)),
        "interface_addresses": bool(document.get("interface_addresses")),
        "neighbor_cache": bool(document.get("neighbors") or document.get("arp")),
        "bridge_fdb": bool(document.get("fdb")),
        "vlans": bool(document.get("vlans")),
        "lldp": bool(document.get("lldp_neighbors")),
    }
