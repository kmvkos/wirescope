"""Project persisted passive_result + environment into the report view."""

from __future__ import annotations

from typing import Any

from engine.segment import (
    VLAN_TAG_NOTE,
    compact_neighbors,
    had_l3_address,
    segment_note,
    segment_status,
)
from reports.models import (
    ReportDhcpSummary,
    ReportNamingSummary,
    ReportNeighbor,
    ReportPassive,
    ReportStpSummary,
)


NAMING_SENSORS = ("mdns", "llmnr", "nbns")
_MAX_VLAN_IDS = 64
_MAX_ARP_HOSTS = 32
_MAX_NAMES = 32


def project_passive(
    *,
    environment: dict[str, Any] | None,
    audit_interface: str | None,
    audit_summary: dict[str, Any] | None = None,
    passive_result: dict[str, Any] | None = None,
) -> ReportPassive:
    summary = audit_summary or {}
    capture_name = _capture_interface_name(
        audit_interface,
        summary,
        passive_result,
    )
    iface = _interface_from_environment(environment, capture_name)
    result_payload = _result_payload(passive_result)
    sensors = _sensors(result_payload)
    assessment = _assessment(result_payload)
    layer2 = assessment.get("layer2") if isinstance(assessment, dict) else {}
    if not isinstance(layer2, dict):
        layer2 = {}

    ipv4 = list(iface.get("ipv4") or [])
    ipv6 = list(iface.get("ipv6") or [])
    if result_payload:
        ipv4 = _string_list(result_payload.get("interface_ipv4")) or ipv4
        ipv6 = _string_list(result_payload.get("interface_ipv6")) or ipv6

    l3: bool | None
    if iface or result_payload:
        l3 = had_l3_address(ipv4, ipv6)
    else:
        l3 = None

    tagged_vlan_ids = _tagged_vlan_ids(layer2, sensors)
    tagged_frame_count = _int(
        layer2.get("tagged_frame_count"),
        default=_sensor_int(sensors, "vlan", "tagged_frames"),
    )
    untagged = bool(layer2.get("untagged_traffic_observed"))
    if not untagged and not tagged_vlan_ids:
        ethernet = sensors.get("ethernet") or {}
        untagged = _sensor_status_detected(ethernet) or _int(
            ethernet.get("hits"),
            default=0,
        ) > 0

    capture = result_payload.get("capture") if result_payload else None
    if not isinstance(capture, dict):
        capture = {}
    frame_count = _optional_int(
        capture.get("frame_count", summary.get("frame_count"))
    )
    duration = _optional_float(
        capture.get("duration_seconds", summary.get("duration_seconds"))
    )
    visibility = _visibility(assessment, summary)
    status = segment_status(
        frame_count=frame_count,
        tagged_vlan_ids=tagged_vlan_ids,
        untagged_traffic_observed=untagged,
    )
    if result_payload is None and frame_count is None:
        status = "unknown"

    port_hint = layer2.get("port_type_hint")
    port_hint_value = None
    if isinstance(port_hint, dict):
        port_hint_value = _optional_str(port_hint.get("value"))
    elif port_hint:
        port_hint_value = _optional_str(port_hint)

    neighbors = _neighbors(layer2, sensors)
    stp = _stp(layer2, sensors)
    dhcp = _dhcp(sensors)
    arp_hosts, arp_pairs = _arp(sensors)
    naming = _naming(sensors)
    detected = sorted(
        str(name)
        for name, payload in sensors.items()
        if isinstance(payload, dict) and _sensor_status_detected(payload)
    )

    return ReportPassive(
        available=result_payload is not None,
        capture_interface=capture_name or _optional_str(iface.get("name")),
        capture_interface_state=_optional_str(iface.get("state")),
        capture_mac=_optional_str(iface.get("mac")),
        capture_ipv4=ipv4,
        capture_ipv6=ipv6,
        had_l3_address=l3,
        duration_seconds=duration,
        frame_count=frame_count,
        visibility=_optional_str(visibility.get("value")),
        visibility_rationale=_optional_str(visibility.get("rationale")),
        segment_status=status,
        segment_note=segment_note(
            status=status,
            tagged_vlan_ids=tagged_vlan_ids,
            frame_count=frame_count,
        ),
        tagged_vlan_ids=tagged_vlan_ids,
        tagged_frame_count=tagged_frame_count,
        untagged_traffic_observed=untagged,
        port_type_hint=port_hint_value,
        vlan_tag_note=VLAN_TAG_NOTE,
        neighbors=neighbors,
        stp=stp,
        arp_host_count=arp_hosts,
        arp_bindings=arp_pairs,
        dhcp=dhcp,
        naming=naming,
        detected_sensors=detected,
    )


def _result_payload(document: dict[str, Any] | None) -> dict[str, Any] | None:
    if not document:
        return None
    result = document.get("result")
    if isinstance(result, dict):
        return result
    if isinstance(document.get("sensors"), dict):
        return document
    return None


def _sensors(result: dict[str, Any] | None) -> dict[str, Any]:
    if not result:
        return {}
    sensors = result.get("sensors")
    return sensors if isinstance(sensors, dict) else {}


def _assessment(result: dict[str, Any] | None) -> dict[str, Any]:
    if not result:
        return {}
    assessment = result.get("assessment")
    return assessment if isinstance(assessment, dict) else {}


def _capture_interface_name(
    audit_interface: str | None,
    summary: dict[str, Any],
    passive_result: dict[str, Any] | None,
) -> str | None:
    result = _result_payload(passive_result) or {}
    return (
        _optional_str(result.get("interface"))
        or _optional_str(summary.get("interface"))
        or _optional_str(audit_interface)
    )


def _interface_from_environment(
    environment: dict[str, Any] | None,
    capture_name: str | None,
) -> dict[str, Any]:
    if not environment:
        return {}
    interfaces = environment.get("interfaces") or []
    if not isinstance(interfaces, list):
        return {}
    if capture_name:
        for item in interfaces:
            if isinstance(item, dict) and item.get("name") == capture_name:
                return item
    if len(interfaces) == 1 and isinstance(interfaces[0], dict):
        return interfaces[0]
    return {}


def _tagged_vlan_ids(
    layer2: dict[str, Any],
    sensors: dict[str, Any],
) -> list[int]:
    observed = layer2.get("tagged_vlans_observed")
    ids: list[int] = []
    if isinstance(observed, list):
        for item in observed:
            vlan_id = _optional_int(item)
            if vlan_id is not None and 0 <= vlan_id <= 4095 and vlan_id not in ids:
                ids.append(vlan_id)
    if ids:
        return ids[:_MAX_VLAN_IDS]
    vlan = sensors.get("vlan") if isinstance(sensors.get("vlan"), dict) else {}
    counts = (vlan.get("summary") or {}).get("vlan_frame_counts")
    if isinstance(counts, list):
        for item in counts:
            if not isinstance(item, dict):
                continue
            vlan_id = _optional_int(item.get("vlan_id"))
            if vlan_id is not None and 0 <= vlan_id <= 4095 and vlan_id not in ids:
                ids.append(vlan_id)
    return ids[:_MAX_VLAN_IDS]


def _neighbors(
    layer2: dict[str, Any],
    sensors: dict[str, Any],
) -> list[ReportNeighbor]:
    raw: list[dict[str, Any]] = []
    listed = layer2.get("neighbors")
    if isinstance(listed, list) and listed:
        raw = [item for item in listed if isinstance(item, dict)]
    else:
        for name, protocol in (("lldp", "LLDP"), ("cdp", "CDP")):
            sensor = sensors.get(name)
            if not isinstance(sensor, dict):
                continue
            for observation in sensor.get("observations") or []:
                if not isinstance(observation, dict):
                    continue
                data = dict(observation.get("data") or {})
                data["protocol"] = protocol
                raw.append(data)
    compact = compact_neighbors(raw)
    return [
        ReportNeighbor(
            protocol=item["protocol"] or "unknown",
            name=item.get("name"),
            port_id=item.get("port_id"),
            native_vlan=item.get("native_vlan"),
            voice_vlan=item.get("voice_vlan"),
            pvid=item.get("pvid"),
        )
        for item in compact
    ]


def _stp(
    layer2: dict[str, Any],
    sensors: dict[str, Any],
) -> ReportStpSummary:
    stp_layer = layer2.get("stp")
    if not isinstance(stp_layer, dict):
        stp_layer = {}
    sensor = sensors.get("stp") if isinstance(sensors.get("stp"), dict) else {}
    summary = sensor.get("summary") if isinstance(sensor.get("summary"), dict) else {}
    bpdus = _int(
        stp_layer.get("bpdus_observed"),
        default=_int(summary.get("bpdus_observed"), default=_int(sensor.get("hits"))),
    )
    root_ids = _string_list(stp_layer.get("root_bridge_ids")) or _string_list(
        summary.get("root_bridge_ids")
    )
    bridge_ids = _string_list(stp_layer.get("bridge_ids")) or _string_list(
        summary.get("bridge_ids")
    )
    return ReportStpSummary(
        bpdus_observed=bpdus,
        root_bridge_ids=root_ids[:16],
        bridge_ids=bridge_ids[:16],
    )


def _arp(sensors: dict[str, Any]) -> tuple[int, list[dict[str, str]]]:
    arp = sensors.get("arp") if isinstance(sensors.get("arp"), dict) else {}
    summary = arp.get("summary") if isinstance(arp.get("summary"), dict) else {}
    pairs: list[dict[str, str]] = []
    observed = summary.get("observed_ipv4_mac")
    if isinstance(observed, list):
        for item in observed:
            if not isinstance(item, dict):
                continue
            ipv4 = _optional_str(item.get("ipv4"))
            mac = _optional_str(item.get("mac"))
            if ipv4 and mac:
                pairs.append({"ipv4": ipv4, "mac": mac})
            if len(pairs) >= _MAX_ARP_HOSTS:
                break
    hosts = _int(summary.get("unique_ipv4_hosts"), default=len(pairs))
    return hosts, pairs


def _dhcp(sensors: dict[str, Any]) -> ReportDhcpSummary:
    dhcp = sensors.get("dhcpv4") if isinstance(sensors.get("dhcpv4"), dict) else {}
    summary = dhcp.get("summary") if isinstance(dhcp.get("summary"), dict) else {}
    servers: list[str] = []
    routers: list[str] = []
    masks: list[str] = []
    raw_servers = summary.get("servers")
    if isinstance(raw_servers, list):
        for item in raw_servers:
            if not isinstance(item, dict):
                continue
            server_id = _optional_str(item.get("server_id"))
            if server_id and server_id not in servers:
                servers.append(server_id)
            for router in item.get("routers") or []:
                text = _optional_str(router)
                if text and text not in routers:
                    routers.append(text)
            for mask in item.get("subnet_masks") or []:
                text = _optional_str(mask)
                if text and text not in masks:
                    masks.append(text)
    return ReportDhcpSummary(
        observed=_sensor_status_detected(dhcp),
        server_count=_int(summary.get("server_count"), default=len(servers)),
        servers=servers[:16],
        routers=routers[:16],
        subnet_masks=masks[:16],
    )


def _naming(sensors: dict[str, Any]) -> list[ReportNamingSummary]:
    items: list[ReportNamingSummary] = []
    for name in NAMING_SENSORS:
        sensor = sensors.get(name)
        if not isinstance(sensor, dict):
            items.append(
                ReportNamingSummary(name=name, status="absent", hits=0)
            )
            continue
        summary = sensor.get("summary") if isinstance(sensor.get("summary"), dict) else {}
        items.append(
            ReportNamingSummary(
                name=name,
                status=_optional_str(sensor.get("status")) or "absent",
                hits=_int(sensor.get("hits")),
                names=_string_list(summary.get("names"))[:_MAX_NAMES],
                addresses=_string_list(summary.get("addresses"))[:_MAX_NAMES],
            )
        )
    return items


def _visibility(
    assessment: dict[str, Any],
    summary: dict[str, Any],
) -> dict[str, Any]:
    visibility = assessment.get("visibility")
    if isinstance(visibility, dict):
        return visibility
    value = summary.get("visibility")
    if value:
        return {"value": value}
    return {}


def _sensor_status_detected(payload: dict[str, Any]) -> bool:
    if payload.get("detected") is True:
        return True
    return payload.get("status") in {"detected", "partial"}


def _sensor_int(sensors: dict[str, Any], name: str, key: str) -> int:
    sensor = sensors.get(name)
    if not isinstance(sensor, dict):
        return 0
    summary = sensor.get("summary") if isinstance(sensor.get("summary"), dict) else {}
    return _int(summary.get(key))


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    items: list[str] = []
    for entry in value:
        text = str(entry).strip()
        if text and text not in items:
            items.append(text)
    return items


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _optional_int(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.lstrip("-").isdigit():
        return int(value)
    return None


def _optional_float(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(str(value))
    except (TypeError, ValueError):
        return None


def _int(value: Any, default: int = 0) -> int:
    parsed = _optional_int(value)
    return default if parsed is None else parsed
