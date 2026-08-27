"""Final Traffic Analysis presentation over protocol intelligence and RTT.

The lower renderer layers intentionally remain backward-compatible. This final
layer owns product-coherence cleanup for the operator-facing TXT/Markdown view:
remove duplicated detail blocks and normalize Russian terminology without
changing the canonical traffic-analysis JSON.
"""

from __future__ import annotations

from typing import Any

from traffic_analysis.render_v4 import render_markdown as render_markdown_v4
from traffic_analysis.render_v4 import render_text as render_text_v4


_TEXT_REPLACEMENTS = (
    ("WIRESCOPE — ДИАГНОСТИКА PCAP", "WIRESCOPE — АНАЛИЗ PCAP"),
    ("КРАТКИЙ ДИАГНОЗ", "КРАТКИЙ ИТОГ"),
    ("TOP TALKERS", "САМЫЕ АКТИВНЫЕ УЗЛЫ"),
    ("capture ", "захват "),
    ("Service-discovery фон:", "Служебный трафик обнаружения сервисов:"),
    ("TCP streams:", "TCP-потоки:"),
    ("начала handshake в PCAP:", "начала TCP-рукопожатий в PCAP:"),
    ("Оценка handshake ограничена:", "Оценка TCP-рукопожатий ограничена:"),
    ("Retransmission:", "Повторные передачи:"),
    ("Previous/lost segment hints:", "Признаки пропущенных или предыдущих сегментов:"),
    ("Duplicate ACK / out-of-order:", "Дубли ACK / пакеты вне порядка:"),
    ("Zero Window / RST:", "Нулевое TCP-окно / RST:"),
    ("retrans=", "повторные передачи="),
    ("dupACK=", "дубли ACK="),
    ("ooo=", "вне порядка="),
    ("zero-window=", "нулевое окно="),
    ("SYN-retrans=", "повторные SYN="),
    ("В PCAP наблюдались только .local-имена. tshark timing здесь относится к локальному name-discovery и не трактуется как latency обычного DNS-резолвера.", "В PCAP наблюдались только .local-имена. Значения времени tshark здесь относятся к локальному разрешению имён и не интерпретируются как задержка обычного DNS-резолвера."),
    ("Достаточных timing-данных обычного DNS нет.", "Недостаточно данных о времени ответа обычного DNS."),
    ("ARP requests/replies:", "ARP-запросы/ответы:"),
    ("gratuitous ARP:", "объявляющих ARP:"),
    ("ICMP/ICMPv6 диагностических/error-сообщений:", "Диагностических ICMP/ICMPv6 и сообщений об ошибках:"),
    ("BROADCAST / MULTICAST", "ШИРОКОВЕЩАТЕЛЬНЫЙ / МНОГОАДРЕСНЫЙ ТРАФИК"),
    ("Broadcast:", "Широковещательный трафик:"),
    ("Multicast:", "Многоадресный трафик:"),
    ("Основные multicast-источники:", "Основные источники многоадресного трафика:"),
    ("ПРОТОКОЛЬНЫЙ РАЗБОР", "ПРОТОКОЛЫ И ПРИКЛАДНЫЕ МЕТАДАННЫЕ"),
    ("TLS / HTTPS metadata:", "TLS / HTTPS:"),
    ("TLS metadata в этом PCAP не выделены.", "Метаданные TLS в этом PCAP не выделены."),
    ("SNI / server names:", "SNI / имена серверов:"),
    ("Наблюдаемые TLS version metadata:", "Версии TLS:"),
    ("Requests / responses:", "Запросы / ответы:"),
    ("HTTP Host:", "Хосты HTTP:"),
    ("HTTP/1.x request/response metadata не наблюдались.", "Метаданные запросов/ответов HTTP/1.x не наблюдались."),
    ("QUIC / HTTP3:", "QUIC / HTTP/3:"),
    ("QUIC metadata не наблюдались.", "Метаданные QUIC не наблюдались."),
    ("SMB metadata не наблюдались.", "Метаданные SMB не наблюдались."),
    ("Status:", "Статусы:"),
    ("Обычный DNS (port 53, без mDNS/LLMNR):", "Обычный DNS (порт 53, без mDNS/LLMNR):"),
    ("Queries / responses:", "Запросы / ответы:"),
    ("responses с non-zero RCODE:", "ответов с ненулевым RCODE:"),
    ("Top names:", "Частые имена:"),
    ("Server identifiers:", "Идентификаторы серверов:"),
    ("DHCP message sequence в этом интервале не наблюдалась.", "Последовательность DHCP-сообщений в этом интервале не наблюдалась."),
    ("Примечание: этот раздел использует только доступные метаданные PCAP. TLS payload не расшифровывается; HTTP body/cookies и SMB filenames не извлекаются в отчёт.", "Примечание: этот раздел использует только доступные метаданные PCAP. Содержимое TLS не расшифровывается; тела HTTP, cookie и имена файлов SMB не извлекаются в отчёт."),
    ("TCP RTT / LATENCY HINTS", "TCP RTT — ЗАДЕРЖКИ"),
    ("ACK RTT samples:", "Выборка ACK RTT:"),
    ("Важно: ACK RTT — метрика видимого TCP-обмена в точке захвата. Это не latency приложения и не доказательство проблемы сети.", "Важно: ACK RTT отражает только наблюдаемый TCP-обмен в точке захвата. Это не задержка приложения и не самостоятельное доказательство проблемы сети."),
)

_MARKDOWN_REPLACEMENTS = (
    ("# WireScope — диагностика PCAP", "# WireScope — анализ PCAP"),
    ("## Краткий диагноз", "## Краткий итог"),
    ("capture ", "захват "),
    ("- Unicast / broadcast / multicast:", "- Одноадресный / широковещательный / многоадресный трафик:"),
    ("- Retransmission:", "- Повторные передачи:"),
    ("- Previous/lost segment hints:", "- Признаки пропущенных или предыдущих сегментов:"),
    ("- Duplicate ACK / out-of-order:", "- Дубли ACK / пакеты вне порядка:"),
    ("- Zero Window / RST:", "- Нулевое TCP-окно / RST:"),
    ("- Streams / начатые handshake / SYN-ACK:", "- TCP-потоки / начатые рукопожатия / SYN-ACK:"),
    ("В захвате только `.local`-имена; timing не трактуется как latency обычного DNS-резолвера.", "В захвате только `.local`-имена; эти значения времени не интерпретируются как задержка обычного DNS-резолвера."),
    ("## Broadcast / multicast", "## Широковещательный и многоадресный трафик"),
    ("- Broadcast:", "- Широковещательный трафик:"),
    ("- Multicast:", "- Многоадресный трафик:"),
    ("## Top talkers", "## Самые активные узлы"),
    ("## TCP health", "## Состояние TCP"),
    ("## TCP RTT / latency hints", "## TCP RTT — задержки"),
    ("- ACK RTT samples:", "- Выборка ACK RTT:"),
    ("- Average / p50 / p95 / max:", "- Среднее / p50 / p95 / максимум:"),
    ("| Pair | Samples | p50 ms | p95 ms | max ms |", "| Пара | Выборки | p50, мс | p95, мс | максимум, мс |"),
    ("- RTT not evaluated: insufficient/unsupported ACK RTT metadata in this PCAP.", "- RTT не оценён: в PCAP недостаточно данных ACK RTT или установленный tshark их не предоставляет."),
    ("> ACK RTT is a capture-side TCP observation. It is not application latency and does not by itself prove a network fault.", "> ACK RTT отражает только наблюдаемый TCP-обмен в точке захвата. Это не задержка приложения и не самостоятельное доказательство проблемы сети."),
    ("### TLS / HTTPS metadata", "### TLS / HTTPS"),
    ("- TLS frames:", "- Кадры TLS:"),
    ("- TLS versions:", "- Версии TLS:"),
    ("- Requests/responses:", "- Запросы/ответы:"),
    ("- Hosts:", "- Хосты:"),
    ("- QUIC frames:", "- Кадры QUIC:"),
    ("- SMB frames:", "- Кадры SMB:"),
    ("non-zero NT status frames", "кадров с ненулевым NT status"),
    ("- SMB commands:", "- Команды SMB:"),
    ("- Error responses:", "- Ответы с ошибкой:"),
    ("- Servers:", "- Серверы:"),
    ("- Messages:", "- Сообщения:"),
    ("- Transactions / complete DORA:", "- Транзакции / полный DORA:"),
    ("> Protocol Intelligence использует только метаданные PCAP; TLS payload не расшифровывается, HTTP body/cookies и SMB filenames не экспортируются.", "> Протокольный анализ использует только метаданные PCAP; содержимое TLS не расшифровывается, тела HTTP, cookie и имена файлов SMB не экспортируются."),
)


def _rtt_text(document: dict[str, Any]) -> str:
    latency = document.get("tcp_latency") or {}
    overall = latency.get("overall") or {}
    status = str(latency.get("status") or "unavailable")
    lines = ["TCP RTT — ЗАДЕРЖКИ", "-" * 52]
    if status == "measured":
        lines.append(
            f"Выборка ACK RTT: {overall.get('samples', 0)}; среднее {float(overall.get('average_ms') or 0):.1f} мс; "
            f"p50 {float(overall.get('p50_ms') or 0):.1f} мс; p95 {float(overall.get('p95_ms') or 0):.1f} мс; "
            f"максимум {float(overall.get('max_ms') or 0):.1f} мс."
        )
        pairs = latency.get("top_pairs") or []
        if pairs:
            lines.append("Пары с наибольшим наблюдаемым p95 ACK RTT:")
            for item in pairs[:10]:
                lines.append(
                    f"  {item.get('endpoint_a', '—')} ↔ {item.get('endpoint_b', '—')}: "
                    f"выборок {item.get('samples', 0)}, p50 {float(item.get('p50_ms') or 0):.1f} мс, "
                    f"p95 {float(item.get('p95_ms') or 0):.1f} мс, максимум {float(item.get('max_ms') or 0):.1f} мс"
                )
    elif status == "insufficient":
        lines.append("RTT не оценён: в PCAP меньше трёх подтверждённых значений tcp.analysis.ack_rtt.")
    else:
        lines.append("RTT не оценён: установленный tshark не предоставил tcp.analysis.ack_rtt или слой анализа недоступен.")
    lines.append(
        "Важно: ACK RTT отражает только наблюдаемый TCP-обмен в точке захвата. Это не задержка приложения и не самостоятельное доказательство проблемы сети."
    )
    return "\n".join(lines) + "\n\n"


def _deduplicate_text(base: str) -> str:
    """Remove detail blocks already owned by Protocol Intelligence."""

    lines = base.splitlines()
    result: list[str] = []
    skip_indented = False

    for line in lines:
        stripped = line.strip()

        if stripped == "Наиболее частые наблюдаемые имена:":
            skip_indented = True
            continue
        if stripped == "DHCP server hints:":
            skip_indented = True
            continue
        if stripped == "DHCP server hints в этом интервале не выделены.":
            continue

        if skip_indented:
            if line.startswith("  "):
                continue
            skip_indented = False

        if stripped == "ARP / DHCP / ICMP":
            line = line.replace("ARP / DHCP / ICMP", "ARP / ICMP")

        result.append(line)

    return "\n".join(result).rstrip() + "\n"


def _polish_text(value: str) -> str:
    result = value
    for old, new in _TEXT_REPLACEMENTS:
        result = result.replace(old, new)

    polished: list[str] = []
    for line in result.splitlines(keepends=True):
        ending = "\n" if line.endswith("\n") else ""
        body = line[:-1] if ending else line
        stripped = body.lstrip()
        indent = body[: len(body) - len(stripped)]
        if stripped.startswith("DNS timing: samples "):
            stripped = stripped.replace("DNS timing: samples ", "Время ответа DNS: выборок ", 1)
            stripped = stripped.replace("; avg ", "; среднее ", 1)
            stripped = stripped.replace("; max ", "; максимум ", 1)
        elif stripped.endswith(" requests") and " — " in stripped:
            stripped = stripped[:-9] + " запросов"
        polished.append(indent + stripped + ending)
    return "".join(polished)


def _polish_markdown(value: str) -> str:
    result = value
    for old, new in _MARKDOWN_REPLACEMENTS:
        result = result.replace(old, new)

    polished: list[str] = []
    for line in result.splitlines(keepends=True):
        ending = "\n" if line.endswith("\n") else ""
        body = line[:-1] if ending else line
        stripped = body.lstrip()
        indent = body[: len(body) - len(stripped)]
        if stripped.startswith("DNS timing: samples "):
            stripped = stripped.replace("DNS timing: samples ", "Время ответа DNS: выборок ", 1)
            stripped = stripped.replace(", max ", ", максимум ", 1)
        polished.append(indent + stripped + ending)
    return "".join(polished)


def render_text(document: dict[str, Any]) -> str:
    base = _deduplicate_text(render_text_v4(document))
    block = _rtt_text(document)
    marker = "ПРОТОКОЛЬНЫЙ РАЗБОР\n"
    if marker in base:
        rendered = base.replace(marker, block + marker, 1)
    else:
        rendered = base.rstrip() + "\n\n" + block
    return _polish_text(rendered)


def _rtt_markdown(document: dict[str, Any]) -> str:
    latency = document.get("tcp_latency") or {}
    overall = latency.get("overall") or {}
    status = str(latency.get("status") or "unavailable")
    lines = ["## TCP RTT — задержки", ""]
    if status == "measured":
        lines.extend([
            f"- Выборка ACK RTT: {overall.get('samples', 0)}",
            f"- Среднее / p50 / p95 / максимум: {float(overall.get('average_ms') or 0):.1f} / {float(overall.get('p50_ms') or 0):.1f} / {float(overall.get('p95_ms') or 0):.1f} / {float(overall.get('max_ms') or 0):.1f} мс",
            "",
        ])
        pairs = latency.get("top_pairs") or []
        if pairs:
            lines.extend([
                "| Пара | Выборки | p50, мс | p95, мс | максимум, мс |",
                "|---|---:|---:|---:|---:|",
            ])
            for item in pairs[:15]:
                lines.append(
                    f"| `{item.get('endpoint_a', '—')}` ↔ `{item.get('endpoint_b', '—')}` | "
                    f"{item.get('samples', 0)} | {float(item.get('p50_ms') or 0):.1f} | "
                    f"{float(item.get('p95_ms') or 0):.1f} | {float(item.get('max_ms') or 0):.1f} |"
                )
            lines.append("")
    else:
        lines.extend(["- RTT не оценён: в PCAP недостаточно данных ACK RTT или установленный tshark их не предоставляет.", ""])
    lines.extend([
        "> ACK RTT отражает только наблюдаемый TCP-обмен в точке захвата. Это не задержка приложения и не самостоятельное доказательство проблемы сети.",
        "",
    ])
    return "\n".join(lines)


def render_markdown(document: dict[str, Any]) -> str:
    base = render_markdown_v4(document)
    block = _rtt_markdown(document)
    marker = "## Протокольный разбор"
    if marker in base:
        rendered = base.replace(marker, block + marker, 1)
    else:
        rendered = base.rstrip() + "\n\n" + block
    return _polish_markdown(rendered)
