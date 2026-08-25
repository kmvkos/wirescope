"""High-level deterministic interpretation of a traffic-analysis document.

This layer deliberately works only with already-normalized analysis data.  It
adds operator-facing context without inventing causes: facts, visibility limits
and likely next checks remain distinct.
"""

from __future__ import annotations

import ipaddress
from typing import Any


def _observation(
    *,
    severity: str,
    category: str,
    title: str,
    fact: str,
    meaning: str,
    check: str,
) -> dict[str, str]:
    return {
        "severity": severity,
        "category": category,
        "title": title,
        "fact": fact,
        "meaning": meaning,
        "check": check,
    }


def _ip(value: Any) -> ipaddress._BaseAddress | None:
    try:
        return ipaddress.ip_address(str(value))
    except ValueError:
        return None


def _is_global_unicast(value: Any) -> bool:
    address = _ip(value)
    return bool(address and address.is_global and not address.is_multicast)


def _is_local_unicast(value: Any) -> bool:
    address = _ip(value)
    if not address or address.is_multicast:
        return False
    return bool(address.is_private or address.is_link_local)


def _protocol_names(conversation: dict[str, Any]) -> list[str]:
    return [
        str(item.get("name") or "")
        for item in (conversation.get("protocols") or [])
        if item.get("name")
    ]


def _ports(conversation: dict[str, Any]) -> list[str]:
    return [
        str(item.get("port") or "")
        for item in (conversation.get("ports") or [])
        if item.get("port")
    ]


def enrich_document(document: dict[str, Any]) -> dict[str, Any]:
    """Add human diagnostic context to an already merged traffic document."""

    observations = list(document.get("observations") or [])
    summary = document.get("summary") or {}
    tcp = document.get("tcp") or {}
    tcp_connections = document.get("tcp_connections") or {}
    dns = document.get("dns") or {}
    dns_latency = document.get("dns_latency") or {}
    bm = document.get("broadcast_multicast") or {}
    conversations = list(document.get("conversations") or [])
    protocols = document.get("protocol_distribution") or []

    total_frames = int(summary.get("frame_count") or 0)
    total_bytes = int(summary.get("byte_count") or 0)
    tcp_packets = int(tcp.get("packets") or 0)
    lost_segments = int(tcp.get("lost_segments") or 0)
    lost_percent = round(lost_segments * 100.0 / tcp_packets, 2) if tcp_packets else 0.0

    if tcp_packets >= 20 and lost_segments >= 3 and lost_percent >= 5.0:
        observations.append(
            _observation(
                severity="warning" if lost_percent >= 10.0 else "info",
                category="tcp",
                title="В захвате есть признаки пропущенных TCP-сегментов",
                fact=(
                    f"tshark отметил {lost_segments} TCP-кадров как previous/lost segment hints "
                    f"из {tcp_packets} TCP-пакетов ({lost_percent}%)."
                ),
                meaning=(
                    "Это не доказывает потери именно в сети. Такой признак также возникает, если "
                    "точка захвата не видит часть трафика, capture началcя посреди соединения, "
                    "пакеты были потеряны самим захватом или влияет offload сетевой карты."
                ),
                check=(
                    "Сначала проверьте dropped packets у dumpcap/интерфейса и полноту точки захвата. "
                    "Если capture полный, повторите захват ближе к проблемной стороне и сравните TCP-пары."
                ),
            )
        )

    streams_seen = int(tcp_connections.get("streams_seen") or 0)
    attempted = int(tcp_connections.get("attempted_streams") or 0)
    if streams_seen and attempted == 0:
        observations.append(
            _observation(
                severity="info",
                category="coverage",
                title="Начало наблюдаемых TCP-соединений не попало в захват",
                fact=(
                    f"В PCAP выделено {streams_seen} TCP-потоков, но ни для одного не наблюдался "
                    "исходный SYN, начинающий handshake."
                ),
                meaning=(
                    "Скорее всего, capture начался уже во время существующих соединений. Поэтому по этому "
                    "PCAP нельзя полноценно оценивать установление TCP-сессий."
                ),
                check="Для диагностики handshake начните захват до воспроизведения проблемного соединения.",
            )
        )

    multicast_percent = float(bm.get("multicast_percent") or 0.0)
    multicast_frames = int(bm.get("multicast_frames") or 0)
    if total_frames >= 100 and multicast_percent >= 40.0:
        contributors = bm.get("top_multicast_sources") or []
        top = ", ".join(
            f"{item.get('endpoint')} ({item.get('frames', 0)})" for item in contributors[:3]
        ) or "не выделены"
        observations.append(
            _observation(
                severity="info",
                category="multicast",
                title="Большая часть видимого трафика — multicast",
                fact=(
                    f"Multicast составляет {multicast_frames} кадров из {total_frames} "
                    f"({multicast_percent:.2f}%). Основные источники: {top}."
                ),
                meaning=(
                    "Высокая доля сама по себе не является неисправностью: IPv6 Neighbor Discovery, mDNS, "
                    "SSDP и другие discovery-протоколы используют multicast. Но она хорошо описывает характер "
                    "сегмента и может указывать на заметный фон service-discovery."
                ),
                check=(
                    "Если в сегменте есть жалобы на шум/нагрузку, проверьте конкретные multicast-протоколы и "
                    "источники. Для короткого спокойного capture такой процент может быть нормальным."
                ),
            )
        )

    dominant_flow: dict[str, Any] | None = None
    if conversations and total_bytes > 0:
        first = conversations[0]
        share = float(first.get("bytes") or 0) * 100.0 / total_bytes
        if int(first.get("bytes") or 0) >= 10 * 1024 and share >= 50.0:
            dominant_flow = {
                "endpoint_a": first.get("endpoint_a"),
                "endpoint_b": first.get("endpoint_b"),
                "bytes": int(first.get("bytes") or 0),
                "packets": int(first.get("packets") or 0),
                "percent_of_capture_bytes": round(share, 2),
                "protocols": _protocol_names(first)[:4],
                "ports": _ports(first)[:6],
            }
            proto = ", ".join(dominant_flow["protocols"]) or "не определён"
            observations.append(
                _observation(
                    severity="info",
                    category="traffic_shape",
                    title="Захват в основном занят одной парой узлов",
                    fact=(
                        f"{dominant_flow['endpoint_a']} ↔ {dominant_flow['endpoint_b']} передали около "
                        f"{dominant_flow['percent_of_capture_bytes']:.1f}% всех наблюдаемых байтов; "
                        f"основной протокол: {proto}."
                    ),
                    meaning=(
                        "Это не проблема само по себе, но означает, что выводы по PCAP сильно определяются "
                        "одним обменом и могут плохо описывать остальной сегмент."
                    ),
                    check="Если нужен обзор всей сети, повторите более длинный capture или используйте SPAN/TAP.",
                )
            )

    top_names = [str(item.get("name") or "") for item in (dns.get("top_names") or [])]
    local_names_only = bool(top_names) and all(name.endswith(".local") for name in top_names)
    if local_names_only and int(dns_latency.get("samples") or 0):
        # dns.time is also populated for mDNS by tshark.  Do not present that as
        # recursive DNS resolver latency when the observed names are only .local.
        observations = [
            item
            for item in observations
            if item.get("title") != "Повышенное время ответа DNS"
        ]
        dns_latency["interpretation"] = "local_name_resolution"
        dns_latency["note"] = (
            "В захвате наблюдались только .local имена; timing нельзя трактовать как задержку обычного DNS-резолвера."
        )
    else:
        dns_latency["interpretation"] = "dns"

    external: list[dict[str, Any]] = []
    for item in conversations:
        a = item.get("endpoint_a")
        b = item.get("endpoint_b")
        if (_is_local_unicast(a) and _is_global_unicast(b)) or (
            _is_global_unicast(a) and _is_local_unicast(b)
        ):
            external.append(
                {
                    "endpoint_a": a,
                    "endpoint_b": b,
                    "bytes": int(item.get("bytes") or 0),
                    "packets": int(item.get("packets") or 0),
                    "protocols": _protocol_names(item)[:4],
                    "ports": _ports(item)[:6],
                }
            )
    external.sort(key=lambda item: (item["bytes"], item["packets"]), reverse=True)

    discovery_names = {"mdns", "ssdp", "llmnr", "nbns"}
    discovery = [
        {
            "protocol": str(item.get("name") or ""),
            "frames": int(item.get("frames") or 0),
            "percent": float(item.get("percent") or 0.0),
        }
        for item in protocols
        if str(item.get("name") or "") in discovery_names
    ]

    # Stable ordering: warnings first, then informational observations, while
    # preserving the relative order produced by the deterministic rules.
    observations = sorted(
        observations,
        key=lambda item: 0 if item.get("severity") == "warning" else 1,
    )
    document["observations"] = observations
    document["traffic_character"] = {
        "unicast_percent": round(
            max(
                0.0,
                100.0
                - float(bm.get("broadcast_percent") or 0.0)
                - float(bm.get("multicast_percent") or 0.0),
            ),
            2,
        ),
        "broadcast_percent": float(bm.get("broadcast_percent") or 0.0),
        "multicast_percent": multicast_percent,
        "dominant_flow": dominant_flow,
        "service_discovery": discovery,
        "external_communications": external[:20],
    }

    warnings = [item for item in observations if item.get("severity") == "warning"]
    document["diagnostic_summary"] = {
        "status": "attention" if warnings else "informational" if observations else "clear",
        "warning_count": len(warnings),
        "info_count": len(observations) - len(warnings),
        "headline": (
            f"Есть сигналы, которые стоит проверить: {len(warnings)}"
            if warnings
            else "Явных неисправностей не доказано; ниже показан характер и ограничения захвата"
        ),
        "priority_titles": [item.get("title") for item in observations[:6]],
    }
    return document
