# Отчёты WireScope

**Русский** · [English](en/REPORTING_MODEL.md)

Отчёт WireScope строится только из уже сохранённого состояния аудита. Генерация и экспорт отчёта не запускают Nmap, protocol modules или passive capture повторно.

```text
audit metadata
+ environment snapshot
+ confirmed scope
+ passive result / assessment
+ inventory
+ findings
+ artifact metadata
        ↓
audit-report v1 JSON   ← канонический документ
        ↓
        ├── HTML для человека
        └── Markdown для Git/wiki/тикетов
```

Schema канонического документа:

```text
reports/schema/audit-report-v1.json
```

## Главный принцип

JSON содержит стабильные machine values и является source of truth. Человекоориентированные HTML/Markdown представления могут улучшаться без изменения схемы и без изменения `source_hash` исходного отчёта.

Например, machine value `high` остаётся `high` в JSON, но в HTML оператор видит **«Высокая»**. Аналогично локализуются профили, статусы, confidence, классы устройств и headline.

Это позволяет улучшать интерфейс отчёта, не ломая API-контракт и интеграции.

## Что видит оператор

HTML отчёт построен в порядке принятия решения:

1. **Результат аудита** — краткий итог, уровень наиболее серьёзной открытой проблемы и основные счётчики.
2. **Обнаруженные проблемы** — каждая finding объясняется по схеме:
   - что обнаружено;
   - почему это важно;
   - что рекомендуется сделать.
3. **План действий** — рекомендации в порядке важности.
4. **Scope** — что именно было разрешено проверять.
5. **Устройства и службы** — инвентаризация.
6. **Пассивное наблюдение** — что WireScope реально видел в сегменте.
7. **Технические данные** — evidence, hashes, metadata и warnings.

Evidence и служебные UUID не выносятся в начало отчёта и не мешают чтению результата, но остаются доступны для проверки воспроизводимости.

## Executive summary

Содержит:

- число assets/services/findings;
- количество открытых findings;
- highest open severity;
- headline;
- детерминированное русское заключение;
- основные passive показатели.

Narrative строится из persisted data. LLM не используется для придумывания CVE, причин или отсутствующих фактов.

Если findings отсутствуют, отчёт отдельно предупреждает, что это относится только к фактически выполненным проверкам и не доказывает абсолютную безопасность сети.

## Scope и passive data

Отчёт фиксирует environment snapshot, capture interface и подтверждённый active scope.

В passive-раздел попадают frame count, visibility/segment state, реально увиденные 802.1Q tags, ARP/DHCP и другие нормализованные observations.

Untagged traffic не получает выдуманный VLAN ID. В отчёте это объясняется человеческим текстом.

## Inventory

Assets и services берутся из persisted inventory вместе с доступными vendor/OS/device-class hints.

Человеческие представления переводят, например:

```text
server-like          → Сервер
workstation-like     → Рабочая станция
network-device-like  → Сетевое устройство
printer-like         → Принтер / МФУ
iot-like             → IoT / встроенное устройство
```

Machine values в JSON при этом не меняются.

## Findings

В canonical report сохраняются open, suppressed и accepted-risk findings, чтобы не терять решения оператора.

HTML и Markdown показывают severity/confidence/status понятными русскими словами и отделяют:

- описание факта;
- объяснение риска;
- рекомендацию.

Raw provider stdout в finding body не вставляется.

## Evidence references

PCAP/XML/stdout не встраиваются в основной narrative. Сохраняются metadata:

- artifact id;
- artifact type;
- content type;
- size;
- SHA-256.

Внешний report не раскрывает filesystem `relative_path`.

## Генерация

```text
POST /api/v1/audits/{id}/reports
```

создаёт durable job `report_generation`.

Worker:

1. загружает persisted audit state;
2. строит `audit-report` v1;
3. валидирует JSON;
4. формирует self-contained HTML;
5. сохраняет JSON и HTML как report artifacts;
6. регистрирует report history;
7. сохраняет `source_hash`.

Report generation не использует network/interface lock.

## Export API

```text
GET /api/v1/audits/{id}/reports/{report_id}/export?format=json
GET /api/v1/audits/{id}/reports/{report_id}/export?format=html
GET /api/v1/audits/{id}/reports/{report_id}/export?format=markdown
```

`format=md` — alias для Markdown.

### JSON

Отдаётся канонический сохранённый `audit-report v1`.

### HTML

HTML при открытии рендерится из сохранённого canonical JSON текущим human-presentation renderer. Поэтому **старые отчёты автоматически получают актуальный дизайн и локализацию без повторного аудита**.

Исторический HTML artifact, созданный в момент report job, при этом не переписывается и остаётся immutable evidence/history artifact.

HTML self-contained, адаптивный, печатаемый и не требует frontend bundle. Все network-derived значения экранируются перед вставкой.

### Markdown

Markdown также рендерится из canonical JSON и полностью ориентирован на русскоязычного оператора. Он подходит для Git, issue trackers, wiki и технической документации.

## `source_hash`

`source_hash` зависит от исходного persisted audit state, а не от CSS, перевода, report id или времени экспорта.

Изменение только внешнего представления не меняет фактический результат аудита.

## Безопасность HTML

Hostname, service banner, certificate subject, finding title и другие данные могут происходить из недоверенной сети. Поэтому renderer экранирует dynamic content и не вставляет raw provider output как HTML.

Тесты отдельно проверяют XSS escaping и отсутствие внутренних filesystem paths.

## PDF

PDF пока не реализован:

```text
format=pdf → 422 pdf_not_available
```

Он не является блокирующим условием для v1.0: HTML уже содержит print layout и может штатно печататься средствами браузера.
