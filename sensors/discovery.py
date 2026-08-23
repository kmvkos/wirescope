"""Passive local naming and service advertisement sensors."""

from engine.passive_models import PacketDataset, PacketRecord
from sensors.base import (
    dataset_errors,
    first_value,
    integer_value,
    observation,
    sensor_result,
    split_values,
)


def mdns_sensor(dataset: PacketDataset):
    return _dns_like_sensor(
        dataset,
        name="mdns",
        protocol="mDNS",
        protocol_names=("mdns",),
        ports={5353},
    )


def llmnr_sensor(dataset: PacketDataset):
    return _dns_like_sensor(
        dataset,
        name="llmnr",
        protocol="LLMNR",
        protocol_names=("llmnr",),
        ports={5355},
    )


def nbns_sensor(dataset: PacketDataset):
    observations = []
    for packet in dataset.packets:
        if not (
            packet.has_protocol("nbns", "nbns")
            or _uses_udp_port(packet, {137})
            or packet.values("nbns.name")
        ):
            continue

        data = {
            "names": split_values(
                packet.values(
                    "nbns.name",
                    "nbns.queries.name",
                )
            ),
            "is_response": _is_response(packet, "nbns.flags.response"),
            "addresses": split_values(
                packet.values(
                    "nbns.addr",
                    "nbns.response.addr",
                )
            ),
        }
        observations.append(
            observation(
                "nbns",
                "name_response" if data["is_response"] else "name_query",
                packet,
                data,
                protocol="NBNS",
            )
        )

    return sensor_result(
        "nbns",
        observations,
        summary=_name_summary(observations),
        errors=dataset_errors(dataset),
    )


def ssdp_sensor(dataset: PacketDataset):
    observations = []
    for packet in dataset.packets:
        if not (
            packet.has_protocol("ssdp")
            or _uses_udp_port(packet, {1900})
        ):
            continue

        lines = split_values(
            packet.values(
                "http.request.line",
                "http.response.line",
                "ssdp",
            )
        )
        headers = _headers(lines)
        method = first_value(packet, "http.request.method")
        status_code = integer_value(packet, "http.response.code")
        message_type = (
            method
            or ("response" if status_code is not None else None)
            or _first_line_token(lines)
        )
        data = {
            "message_type": message_type,
            "status_code": status_code,
            "usn": headers.get("usn"),
            "search_target": headers.get("st"),
            "notification_type": headers.get("nt"),
            "location": (
                headers.get("location")
                or first_value(packet, "http.location")
            ),
            "server": (
                headers.get("server")
                or first_value(packet, "http.server")
            ),
            "cache_control": headers.get("cache-control"),
        }
        observations.append(
            observation(
                "ssdp",
                "service_advertisement",
                packet,
                data,
                protocol="SSDP",
            )
        )

    return sensor_result(
        "ssdp",
        observations,
        summary={
            "locations": sorted(
                {
                    item.data["location"]
                    for item in observations
                    if item.data.get("location")
                }
            ),
            "servers": sorted(
                {
                    item.data["server"]
                    for item in observations
                    if item.data.get("server")
                }
            ),
        },
        errors=dataset_errors(dataset),
    )


def _dns_like_sensor(
    dataset: PacketDataset,
    *,
    name: str,
    protocol: str,
    protocol_names: tuple[str, ...],
    ports: set[int],
):
    observations = []
    for packet in dataset.packets:
        if not (
            packet.has_protocol(*protocol_names)
            or _uses_udp_port(packet, ports)
        ):
            continue

        query_names = split_values(packet.values("dns.qry.name"))
        response_names = split_values(packet.values("dns.resp.name"))
        addresses = split_values(packet.values("dns.a", "dns.aaaa"))
        ptr_services = split_values(packet.values("dns.ptr.domain_name"))
        srv_targets = split_values(packet.values("dns.srv.target"))
        srv_ports = split_values(packet.values("dns.srv.port"))
        txt = split_values(packet.values("dns.txt"))
        is_response = _is_response(packet, "dns.flags.response")

        observations.append(
            observation(
                name,
                "name_response" if is_response else "name_query",
                packet,
                {
                    "query_names": query_names,
                    "response_names": response_names,
                    "record_types": split_values(
                        packet.values(
                            "dns.qry.type",
                            "dns.resp.type",
                        )
                    ),
                    "addresses": addresses,
                    "advertised_services": ptr_services,
                    "srv_targets": [
                        {
                            "target": target,
                            "port": (
                                srv_ports[index]
                                if index < len(srv_ports)
                                else None
                            ),
                        }
                        for index, target in enumerate(srv_targets)
                    ],
                    "txt": txt,
                    "is_response": is_response,
                },
                protocol=protocol,
            )
        )

    return sensor_result(
        name,
        observations,
        summary=_name_summary(observations),
        errors=dataset_errors(dataset),
    )


def _uses_udp_port(packet: PacketRecord, ports: set[int]) -> bool:
    values = packet.values("udp.srcport", "udp.dstport")
    for value in values:
        try:
            if int(value) in ports:
                return True
        except ValueError:
            continue
    return False


def _is_response(packet: PacketRecord, alias: str) -> bool:
    value = first_value(packet, alias)
    return value is not None and value.lower() in {"1", "true", "yes", "set"}


def _name_summary(observations):
    names = set()
    addresses = set()
    services = set()
    for item in observations:
        for key in ("query_names", "response_names", "names"):
            names.update(item.data.get(key, []))
        addresses.update(item.data.get("addresses", []))
        services.update(item.data.get("advertised_services", []))
    return {
        "names": sorted(names),
        "addresses": sorted(addresses),
        "services": sorted(services),
    }


def _headers(lines: list[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for line in lines:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers[key.strip().lower()] = value.strip()
    return headers


def _first_line_token(lines: list[str]) -> str | None:
    for line in lines:
        if ":" not in line and line.strip():
            return line.split()[0]
    return None
