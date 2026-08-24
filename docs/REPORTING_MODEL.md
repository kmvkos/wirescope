# Отчёты WireScope

**Русский** · [English](en/REPORTING_MODEL.md)

Отчёт WireScope строится только из уже сохранённого состояния аудита. Генерация report не запускает Nmap, protocol modules или passive capture повторно.

```text
audit metadata
+ environment snapshot
+ confirmed scope
+ passive result / assessment
+ inventory
+ protocol observations
+ findings
+ artifact metadata
        ↓
audit-report v1
        ↓
JSON
├── self-contained HTML
└── Markdown
```

JSON `audit-report` v1 остаётся каноническим документом. HTML и Markdown — представления над тем же persisted state.

Schema:

```text
reports/schema/audit-report-v1.json
```

## Содержимое report

### Executive summary

Содержит:

- число assets/services/findings;
- open findings;
- highest open severity;
- headline и короткое summary;
- базовые passive показатели.

Narrative генерируется детерминированно из persisted data. LLM не используется для придумывания CVE или недостающих фактов.

### Environment и scope

Report фиксирует environment snapshot, capture interface и подтверждённый active scope. Отсутствующий L3 path не делает passive-only report невалидным.

### Passive data

Включаются frame count, visibility/segment notes, действительно увиденные 802.1Q tags, LLDP/CDP, STP, ARP/DHCP и другие нормализованные passive observations.

Untagged traffic не получает выдуманный VLAN ID. LLDP/CDP native/voice VLAN остаётся neighbor metadata.

### Inventory

Assets и services берутся из persisted inventory вместе с доступными vendor/OS/device-class hints.

### Findings

В report входят open, suppressed и accepted-risk findings, чтобы экспорт не терял контекст решений оператора. Recommendations строятся из текущих findings.

### Evidence references

Raw PCAP/XML/stdout не встраиваются в основной report. Сохраняются ссылки и metadata:

- artifact id;
- artifact type;
- content type;
- size;
- SHA-256.

Внешний report не раскрывает внутренний filesystem `relative_path`.

## Генерация

Запрос:

```text
POST /api/v1/audits/{id}/reports
```

создаёт durable job `report_generation`.

Worker:

1. загружает persisted audit state;
2. строит `audit-report` v1;
3. валидирует документ;
4. рендерит self-contained HTML;
5. пишет JSON и HTML через `EvidenceStore`;
6. регистрирует report history row;
7. сохраняет `source_hash`.

Report generation не требует interface lock, потому что сеть не используется.

## `source_hash`

`source_hash` зависит от содержимого исходного persisted state, а не от report id, generation timestamp или job id.

Если inventory, findings, scope и evidence не изменились, повторная генерация должна иметь тот же source hash.

## Export API

```text
GET /api/v1/audits/{id}/reports/{report_id}/export?format=json
GET /api/v1/audits/{id}/reports/{report_id}/export?format=html
GET /api/v1/audits/{id}/reports/{report_id}/export?format=markdown
```

`format=md` принимается как alias для Markdown.

PDF пока не реализован:

```text
format=pdf → 422 pdf_not_available
```

## HTML

HTML self-contained и не требует frontend bundle или дополнительных API requests для просмотра. Динамические значения экранируются перед вставкой, чтобы hostname, HTTP title, certificate subject и другие данные из сети не могли стать HTML/JS injection.

## JSON

JSON — стабильный машинно-читаемый `audit-report` v1 и source of truth для остальных export formats.

Ключи schema и rule IDs остаются стабильными. Человекоориентированные title/description/recommendation могут быть русскими.

## Markdown

Markdown формируется из сохранённого JSON report и не регистрирует новую scanner stage.

Он содержит:

- audit metadata;
- executive summary;
- scope;
- passive summary;
- assets;
- services;
- findings;
- recommendations;
- evidence references.

Markdown предназначен для Git, тикетов, wiki/Confluence-подобных систем и ручного включения в техническую документацию.

## Evidence access

Evidence можно просматривать отдельно от report через audit-scoped API:

```text
GET /api/v1/audits/{audit_id}/findings/{finding_id}/evidence
GET /api/v1/audits/{audit_id}/artifacts/{artifact_id}
```

Backend проверяет принадлежность artifact конкретному audit перед выдачей. Ответ содержит `X-WireScope-SHA256`.

## История reports

Новая генерация не перезаписывает старую запись. Report history позволяет сравнивать экспорты после re-evaluation findings, изменения accepted-risk состояния, inventory или evidence.

## Тестирование

Reporting tests не требуют live network. Проверяются schema, HTML escaping, evidence path boundary, source hash и Markdown rendering.

## Ограничения

Сейчас не реализованы:

- PDF export;
- отдельная многоязычная template-система report;
- embedding всех raw evidence внутрь одного файла — report намеренно ссылается на artifacts по id/hash.
