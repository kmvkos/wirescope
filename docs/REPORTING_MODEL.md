# Отчёты WireScope

**Русский** · [English](en/REPORTING_MODEL.md)

Отчёт WireScope строится из уже сохранённых данных аудита. Генерация отчёта не запускает Nmap, protocol modules или passive capture повторно.

Это важно: report должен быть воспроизводимым представлением audit state, а не ещё одной скрытой стадией сканирования.

## Откуда берутся данные

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
report view model
schema: audit-report v1
        ↓
HTML + JSON
        ↓
EvidenceStore + reports history
```

JSON schema находится здесь:

```text
reports/schema/audit-report-v1.json
```

## Что входит в report

### Итоговая сводка

Содержит основные цифры и короткое текстовое резюме:

- число assets/services/findings;
- количество кадров passive capture;
- был ли L3 address на capture NIC;
- реально увиденные 802.1Q VLAN IDs;
- segment note;
- highest open severity;
- headline/summary.

Русская narrative-сводка детерминированная. Она строится из persisted data и не использует LLM для «додумывания» текста или CVE.

### Environment

- hostname;
- capture interface;
- L3 presence;
- обнаруженные interfaces;
- default route;
- DNS.

### Passive assessment

- duration и frame count;
- 802.1Q tags, которые действительно были в кадрах;
- LLDP/CDP neighbors;
- STP;
- ARP;
- DHCP;
- mDNS/LLMNR/NBNS summaries;
- assessment conclusions с confidence.

### Scope

Отдельно сохраняются audit scope и confirmed active-scan snapshot.

### Inventory

Assets и services из persisted inventory.

### Findings

В report попадают как open, так и `suppressed`/`accepted_risk` findings, чтобы отчёт не терял контекст принятого решения.

Recommendations строятся по открытым findings.

### Evidence references

Основной report не встраивает сырые PCAP/XML/stdout.

Для evidence показываются metadata:

- artifact id;
- type;
- content type;
- size;
- SHA-256.

Внешнему JSON не отдаётся внутренний filesystem `relative_path`.

## Генерация

Запрос:

```text
POST /api/audits/{id}/reports
```

создаёт durable job:

```text
report_generation
```

Worker:

1. загружает audit/inventory/findings/artifact metadata;
2. строит `audit-report` v1;
3. валидирует JSON по опубликованной schema;
4. рендерит self-contained HTML;
5. экранирует значения перед вставкой в HTML;
6. пишет JSON и HTML через `EvidenceStore`;
7. регистрирует report history row;
8. сохраняет `source_hash`.

Report job использует audit-level lock и `report` resource group. Interface lock ему не нужен: сеть он не использует.

## `source_hash`

`source_hash` отражает содержимое исходного persisted state, а не случайные поля конкретной генерации.

Если inventory, findings, scope и evidence не изменились, повторная генерация должна получать тот же source hash, даже если меняются:

- report id;
- generation timestamp;
- job id;
- runtime metadata.

Это позволяет понять, был ли отчёт реально построен по другому состоянию аудита.

## Export API

Основные endpoints:

```text
POST /api/audits/{id}/reports
GET  /api/audits/{id}/reports
GET  /api/audits/{id}/reports/{report_id}
GET  /api/audits/{id}/reports/{report_id}/export?format=json
GET  /api/audits/{id}/reports/{report_id}/export?format=html
```

PDF пока не реализован:

```text
format=pdf → 422 pdf_not_available
```

Export разрешает файл только через artifact id, зарегистрированный в report row. `EvidenceStore.path_for` проверяет, что реальный путь остаётся внутри evidence root.

## HTML

HTML self-contained: для просмотра не требуется отдельный frontend bundle или API call за содержимым отчёта.

Все динамические значения экранируются, чтобы data из сети — hostname, HTTP title, certificate subject и т. п. — не могла превратиться в HTML/JS injection внутри report.

## JSON

JSON — машинно-читаемый export того же audit state.

Ключи и rule IDs остаются английскими и стабильными. Человекоориентированные finding title/description/recommendation могут быть русскими, поскольку текущий operator GUI и основной report ориентированы на русскоязычного оператора.

## Silent tap и interface без IP

Passive report остаётся полезным, даже если capture interface не получил IPv4/IPv6 адрес.

`dumpcap` не требует L3 address, поэтому можно получить:

- frame count;
- quiet/active segment indication;
- реально присутствующие 802.1Q tags;
- LLDP/CDP;
- STP;
- ARP;
- DHCP;
- mDNS/LLMNR/NBNS.

### VLAN на access port

Если switch access-port отправляет untagged frames, WireScope не может честно определить VLAN ID только из этих кадров.

Поэтому report не делает что-то вроде:

```text
VLAN 10 detected
```

если `10` не присутствовал как 802.1Q tag или отдельный neighbor fact.

Уntagged traffic всё равно анализируется, просто VLAN ID остаётся неизвестен.

LLDP/CDP advertised native/voice VLAN — это neighbor metadata, а не доказательство 802.1Q tag в самом traffic stream. В report эти вещи не смешиваются.

## Active data в report

Nmap inventory появляется в report только если active discovery действительно запускался и сохранял результаты.

Если L3 path отсутствует, passive-only audit остаётся валидным. Report не пытается «достроить» отсутствующие active данные.

## История reports

Повторная генерация не перезаписывает старый report. В `reports` хранится history.

Это полезно, если:

- findings были re-evaluated;
- finding перевели в accepted risk;
- inventory изменился;
- появился новый evidence artifact;
- нужен предыдущий export для сравнения.

## Тестирование

Reporting тестируется fixture-based.

Report generation:

- не требует live network;
- не вызывает scanner providers;
- проверяет JSON schema;
- проверяет HTML escaping;
- проверяет path boundary evidence store;
- проверяет стабильность source hash.

Обычный `pytest` не должен касаться живой сети ради генерации report.

## Ограничения

На текущей версии:

- PDF нет;
- отдельного шаблонизатора/локализации report на несколько языков пока нет: основной человекочитаемый output русскоязычный;
- report не заменяет raw evidence: он ссылается на него по artifact id/hash, но не пытается включить всё содержимое в один файл.
