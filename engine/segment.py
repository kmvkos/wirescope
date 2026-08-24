"""Honest segment status for no-IP / silent-tap captures.

VLAN IDs come only from 802.1Q tags or neighbor advertisements. Untagged
access-port traffic is never given an invented VLAN ID.
"""

from __future__ import annotations

import ipaddress
from typing import Any


VLAN_TAG_NOTE = (
    "VLAN в кадре виден только при 802.1Q; access-порт коммутатора часто "
    "без тега — тогда ID неизвестен, но трафик этой сети всё равно виден"
)

SEGMENT_STATUS_UNKNOWN = "unknown"
SEGMENT_STATUS_QUIET = "quiet"
SEGMENT_STATUS_VERY_LOW = "very_low"
SEGMENT_STATUS_TAGGED_VLANS = "tagged_vlans"
SEGMENT_STATUS_UNTAGGED_TRAFFIC = "untagged_traffic"
SEGMENT_STATUS_ACTIVE = "active"

_HEADLINE_VLAN_LIMIT = 8


def had_l3_address(
    ipv4: list[str] | None,
    ipv6: list[str] | None,
) -> bool:
    """True when the capture NIC has a usable (non-link-local) address."""
    for raw in ipv4 or []:
        text = str(raw).split("/", 1)[0].strip()
        if not text:
            continue
        try:
            address = ipaddress.ip_address(text)
        except ValueError:
            continue
        if address.is_unspecified or address.is_loopback or address.is_link_local:
            continue
        return True
    for raw in ipv6 or []:
        text = str(raw).split("/", 1)[0].strip()
        if not text:
            continue
        try:
            address = ipaddress.ip_address(text)
        except ValueError:
            continue
        if address.is_unspecified or address.is_loopback or address.is_link_local:
            continue
        return True
    return False


def segment_status(
    *,
    frame_count: int | None,
    tagged_vlan_ids: list[int],
    untagged_traffic_observed: bool,
) -> str:
    if frame_count == 0:
        return SEGMENT_STATUS_QUIET
    if tagged_vlan_ids:
        return SEGMENT_STATUS_TAGGED_VLANS
    if untagged_traffic_observed:
        return SEGMENT_STATUS_UNTAGGED_TRAFFIC
    if frame_count is None:
        return SEGMENT_STATUS_UNKNOWN
    if 0 < frame_count < 10:
        return SEGMENT_STATUS_VERY_LOW
    if frame_count > 0:
        return SEGMENT_STATUS_ACTIVE
    return SEGMENT_STATUS_UNKNOWN


def segment_note(
    *,
    status: str,
    tagged_vlan_ids: list[int] | None = None,
    frame_count: int | None = None,
) -> str:
    vlans = _format_vlan_ids(tagged_vlan_ids or [])
    if status == SEGMENT_STATUS_QUIET:
        return "The segment looked quiet: no frames were captured"
    if status == SEGMENT_STATUS_TAGGED_VLANS:
        return f"Saw tagged VLANs {vlans}"
    if status == SEGMENT_STATUS_UNTAGGED_TRAFFIC:
        return "Untagged traffic was observed; VLAN ID is unknown"
    if status == SEGMENT_STATUS_VERY_LOW:
        count = frame_count if frame_count is not None else 0
        return f"Very little traffic was observed ({count} frames)"
    if status == SEGMENT_STATUS_ACTIVE:
        return "Network traffic was observed"
    return "No passive capture is stored for this audit"


def tagged_vlan_headline(vlan_ids: list[int]) -> str:
    shown = list(vlan_ids[:_HEADLINE_VLAN_LIMIT])
    text = _format_vlan_ids(shown)
    if len(vlan_ids) > _HEADLINE_VLAN_LIMIT:
        text = f"{text}, …"
    return f"Saw tagged VLANs {text}"


def compact_neighbors(neighbors: list[dict[str, Any]]) -> list[dict[str, Any]]:
    compact: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    for item in neighbors:
        protocol = str(item.get("protocol") or "").strip()
        name = (
            _optional_str(item.get("system_name"))
            or _optional_str(item.get("device_id"))
            or _optional_str(item.get("chassis_id"))
        )
        port_id = _optional_str(item.get("port_id"))
        key = (
            protocol,
            name,
            port_id,
            item.get("native_vlan"),
            item.get("voice_vlan"),
            item.get("pvid"),
        )
        if key in seen:
            continue
        seen.add(key)
        compact.append(
            {
                "protocol": protocol,
                "name": name,
                "port_id": port_id,
                "native_vlan": _optional_int(item.get("native_vlan")),
                "voice_vlan": _optional_int(item.get("voice_vlan")),
                "pvid": _optional_int(item.get("pvid")),
            }
        )
        if len(compact) >= 32:
            break
    return compact


def _format_vlan_ids(vlan_ids: list[int]) -> str:
    return ", ".join(str(item) for item in vlan_ids)


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
    try:
        return int(str(value), 0)
    except (TypeError, ValueError):
        return None
