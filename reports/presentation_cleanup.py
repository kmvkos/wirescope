"""Presentation-only terminology cleanup for human report exports.

Canonical audit-report JSON is intentionally untouched. Replacements here are
limited to static WireScope labels and deterministic narrative phrases so an
old stored report immediately receives the same polished wording when exported.
"""

from __future__ import annotations


_REPLACEMENTS = (
    ("Все findings", "Все проблемы"),
    ("Evidence-артефакты", "Артефакты доказательств"),
    ("**Evidence:**", "**Доказательства:**"),
    ("Evidence / доказательства", "Доказательства"),
    ("В evidence", "В артефактах доказательств"),
    ("Scope подтверждён оператором", "Границы проверки подтверждены оператором"),
    ("Scope подтверждён", "Границы проверки подтверждены"),
    ("подтверждённом scope", "подтверждённых границах проверки"),
    ("подтверждённого scope", "подтверждённых границ проверки"),
    ("подтверждённому scope", "подтверждённым границам проверки"),
    ("в подтверждённом scope", "в подтверждённых границах проверки"),
    ("Snapshot scope", "Снимок границ проверки"),
    ("Исходный audit scope", "Исходные границы аудита"),
    ("audit scope", "границы аудита"),
    ("Source hash", "Хэш исходных данных"),
    ("source hash", "хэш исходных данных"),
    ('<span class="mono">source ', '<span class="mono">хэш '),
    ("Access-порт / нетегированный сегмент", "Порт доступа / нетегированный сегмент"),
    ("access-порта", "порта доступа"),
    ("Trunk / несколько VLAN", "Транковый порт / несколько VLAN"),
    ("trunk / несколько VLAN", "транковый порт / несколько VLAN"),
    ("Native VLAN", "Нативный VLAN"),
    ("Voice VLAN", "Голосовой VLAN"),
    ("Политика таймингов", "Режим таймингов"),
    ("Открытых слабых мест нет", "Открытых проблем безопасности не зафиксировано"),
    ("Открытых слабых мест:", "Открытых проблем:"),
    ("Пустой список слабых мест при видимых хостах — это не «всё чисто»", "Отсутствие зафиксированных проблем при видимых устройствах не означает, что «всё чисто»"),
    ("инвентарь без найденных слабых протоколов не доказывает отсутствие риска", "инвентаризация без найденных проблем не доказывает отсутствие риска"),
    ("Оценка слабых мест не выполнялась", "Оценка проблем безопасности не выполнялась"),
    ("отсутствие слабых мест не означает безопасную конфигурацию", "отсутствие зафиксированных проблем не означает безопасную конфигурацию"),
    ("Активных хостов не зафиксировано", "Активных устройств не зафиксировано"),
    ("активный хост", "активное устройство"),
    ("активных хоста", "активных устройства"),
    ("активных хостов", "активных устройств"),

    # Persisted source warnings are stable machine strings. Translate them only
    # in human-facing HTML/Markdown exports; canonical JSON remains unchanged.
    ("Asset list exceeded the report input limit", "Список устройств превышает лимит данных отчёта; показана только допустимая часть."),
    ("Service list exceeded the report input limit", "Список служб превышает лимит данных отчёта; показана только допустимая часть."),
    ("Finding list exceeded the report input limit", "Список проблем превышает лимит данных отчёта; показана только допустимая часть."),
    ("Evidence reference list exceeded the report input limit", "Список артефактов доказательств превышает лимит отчёта; показана только допустимая часть."),
    ("Environment snapshot artifact was not found", "Снимок окружения не найден; часть сведений об окружении недоступна."),
    ("Environment snapshot could not be read", "Снимок окружения не удалось прочитать; часть сведений об окружении недоступна."),
    ("Environment snapshot did not contain an object", "Снимок окружения имеет неожиданный формат; часть сведений об окружении недоступна."),
    ("Passive result artifact could not be read", "Результат пассивного анализа не удалось прочитать; пассивные данные в отчёте могут быть неполными."),
)


def polish_human_report(value: str) -> str:
    result = value
    for old, new in _REPLACEMENTS:
        result = result.replace(old, new)
    return result


__all__ = ["polish_human_report"]
