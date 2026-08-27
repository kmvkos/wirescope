# Модель Global Correlation Analysis

[English](en/GLOBAL_ANALYSIS_MODEL.md)

Global Analysis объединяет уже сохранённые результаты WireScope в один воспроизводимый аналитический документ. Он не запускает scanner, не перечитывает PCAP и не выполняет новый network I/O.

```text
persisted inventory/findings
          +
explicit traffic-analysis result
          +
canonical network-topology
          ↓
     global-analysis v1
```

## Главные правила

- identity между inventory и traffic строится только по exact IP или exact MAC;
- hostname сам по себе не склеивает сущности;
- отсутствие asset в выбранном PCAP не означает отсутствие asset в сети;
- private endpoint вне известного topology segment не объявляется Internet/external автоматически;
- partial/missing source state наследуется результатом;
- confidence correlation не может быть сильнее исходного evidence;
- evidence lineage содержит ID/hash/type/schema, но не filesystem path;
- preview, durable execution и rebuild используют один canonical correlation contract;
- rebuild создаёт новый immutable job/artifact и никогда не переписывает предыдущий результат.

## API

### Offline preview

```text
GET /api/v1/audits/{audit_id}/global-analysis?traffic_analysis_job_id={job_id}
```

Preview строит документ из текущих persisted sources без создания нового artifact.

### Durable stage

```text
POST /api/v1/audits/{audit_id}/global-analysis
{
  "traffic_analysis_job_id": "...",
  "priority": 0
}
```

Worker сохраняет canonical result как:

```text
artifact_type  = global_analysis_result
schema         = global-analysis
schema_version = 1
retention      = audit
```

### История и чтение результата

```text
GET /api/v1/audits/{audit_id}/global-analysis/history
GET /api/v1/jobs/{job_id}/global-analysis
GET /api/v1/jobs/{job_id}/global-analysis/export?format=json
GET /api/v1/jobs/{job_id}/global-analysis/export?format=text
GET /api/v1/jobs/{job_id}/global-analysis/export?format=markdown
```

History показывает durable jobs конкретного audit, включая queued/running/failed/cancelled/interrupted. Канонический result читается только для completed job с валидным зарегистрированным `global_analysis_result`.

### Rebuild

```text
POST /api/v1/audits/{audit_id}/global-analysis
{
  "traffic_analysis_job_id": "...",
  "rebuild_of_job_id": "previous-global-analysis-job-id"
}
```

Rebuild создаёт новый job. Старый artifact остаётся неизменным. `rebuild_of_job_id` допустим только для Global Analysis того же audit, а `traffic_analysis_job_id` должен совпадать с source Traffic Analysis предыдущего результата. Это не stage resume и не in-place update.

## Canonical contract

```text
global-analysis v1
├── inputs
├── execution
├── summary
├── asset_traffic_identity
├── service_usage
├── finding_traffic_relevance
├── external_communications
├── unclassified_communications
├── infrastructure_consistency
├── coverage
├── source_health
├── evidence_references
├── operator_summary
├── partial
└── warnings
```

Каждая correlation row имеет deterministic ID и versioned `rule_id`. Durable `execution` добавляет job/rebuild lineage, но не меняет identity/correlation semantics.

## Asset ↔ traffic identity

Rule:

```text
GA-ASSET-IDENTITY-001
```

Порядок совпадения:

1. exact canonical IP;
2. exact canonical MAC;
3. иначе `unmatched`.

Hostname, vendor, похожий MAC prefix или device class не используются как identity key.

Если несколько assets неожиданно претендуют на один exact identifier, WireScope возвращает `identity_conflict`, помечает analysis как `partial` и не выполняет автоматический merge.

## Классификация traffic endpoint

Endpoint получает один из conservative классов:

- `internal_asset` — exact match с inventory asset;
- `internal_segment` — IP находится в известном topology segment, но asset не сопоставлен;
- `external_global` — глобально маршрутизируемый IP вне известных внутренних segments;
- `private_unknown` — private IP вне известных segments;
- `special` — multicast/link-local/unspecified/broadcast;
- `unknown` — классификации недостаточно.

`private_unknown` специально не называется external: отсутствие текущего inventory/topology evidence не доказывает границу организации или Internet.

## Service ↔ observed traffic

Rule:

```text
GA-SERVICE-USAGE-001
```

Текущий contract использует pair-level `communications_graph` из `traffic-analysis` v1.

Если endpoint пары exact-match'ится с asset, inventory содержит service `(protocol, port)` этого asset и такой `protocol/port` присутствует среди агрегированных destination ports пары, service получает `observed_in_selected_traffic=true`.

### Ограничение направления

Текущий `communications_graph` агрегирует destination ports по паре и не сохраняет, какой endpoint владел совпавшим портом. Поэтому match basis называется:

```text
observed_pair_destination_port
```

и имеет confidence `observed`, а не `confirmed`.

Этот вывод означает «сервисный порт наблюдался в communication pair с данным asset», но пока не доказывает направление client → конкретный server socket. Более сильная directional service-use модель потребует расширения traffic-analysis contract.

## Finding ↔ traffic relevance

Rule:

```text
GA-FINDING-TRAFFIC-RELEVANCE-001
```

Состояния:

- `service_traffic_observed` — finding связан с service, чей порт наблюдался в выбранном PCAP;
- `asset_traffic_observed` — service-level match отсутствует, но asset exact-match'ится с traffic endpoint;
- `uncorrelated` — выбранный PCAP не дал такой связи.

`uncorrelated` **не означает**, что finding неважен или ложен. Это только отсутствие связи с visibility выбранного capture.

## Inventory ↔ Traffic coverage

Rule:

```text
GA-INVENTORY-TRAFFIC-COVERAGE-001
```

WireScope отдельно показывает inventory assets, exact-correlated с traffic; inventory assets, не наблюдавшиеся в выбранном capture; и traffic endpoints, не сопоставленные с inventory.

Это visibility comparison, а не оценка полноты реальной сети.

## Internal ↔ external communications

Rule:

```text
GA-EXTERNAL-COMMUNICATION-001
```

External communication создаётся только когда одна сторона exact-match'ится с inventory asset, а другая классифицирована как `external_global`.

Сохраняются internal asset ID, external endpoint, packets/bytes, protocols/ports из persisted Traffic Analysis и ссылка на deterministic conversation ID. Private unknown communications выводятся отдельно в `unclassified_communications`.

## Infrastructure consistency

Rules:

```text
GA-GATEWAY-CONSISTENCY-001
GA-DHCP-CONSISTENCY-001
GA-DNS-CONSISTENCY-001
```

Global Analysis сравнивает независимые persisted observations:

- gateway: interface-specific environment/default route + passive DHCP router + canonical topology;
- DHCP server: local DHCP lease + passive DHCP + selected Traffic Analysis;
- DNS server: interface DHCP/environment DNS + selected Traffic Analysis + topology role evidence.

Статусы:

- `consistent` — два или более доступных источника имеют общее значение;
- `divergent` — два или более источника есть, но общего значения нет;
- `insufficient` — для сравнения меньше двух независимых sources.

Расхождение не превращает документ в `partial`: это самостоятельный результат корреляции. `partial` относится к недостаточности/повреждению входных evidence.

## Evidence lineage

`evidence_references` связывает результат с audit, выбранным traffic-analysis job/artifact, inventory asset/service IDs, finding IDs и route/SNMP/SSH topology artifacts.

Для artifacts сохраняются безопасные metadata: ID, type, content type, size, SHA-256, schema/version, timestamp. Internal relative/absolute filesystem paths в canonical document не помещаются.

Correlation rows также получают компактные `evidence_refs`.

## Operator summary и exports

`operator_summary` — русская deterministic сводка поверх canonical data. TXT и Markdown exports строятся из того же persisted JSON и не запускают повторный анализ.

В summary отражаются:

- сколько inventory assets сопоставилось с выбранным PCAP;
- сколько service ports наблюдалось;
- finding ↔ traffic relevance;
- external communications exact-correlated assets;
- gateway/DHCP/DNS consistency;
- partial/source-health ограничения.

## Operator GUI

На домашнем экране WireScope появляется действие **«Глобальный анализ»**. Workspace позволяет:

- выбрать сохранённый audit;
- явно выбрать completed Traffic Analysis;
- запустить durable Global Analysis (auditor);
- видеть queued/running progress и остановить job;
- просматривать историю результатов (auditor/viewer);
- открыть прошлый immutable result;
- пересобрать result с тем же Traffic Analysis, сохранив `rebuild_of_job_id`;
- экспортировать JSON/TXT/Markdown;
- видеть summary, infrastructure consistency, coverage/source health, finding relevance, external communications, warnings и evidence lineage.

GUI не изменяет active scope и не инициирует сетевой I/O.

## Source health и partial

Примеры:

- truncated report/inventory source → `inventory=partial`;
- topology `partial=true` → `topology=partial`;
- отсутствующий communications graph → `traffic=missing`;
- identity conflict → `identity=partial`.

Итоговый `partial=true` означает, что документ остаётся пригодным, но часть утверждений ограничена состоянием sources.

## Что остаётся до закрытия v1.3

- automated regression и installed-wheel smoke для history/rebuild/UI contract;
- live install/upgrade на WireScope VM;
- запуск реального durable Global Analysis поверх существующего Deep audit и сохранённого Traffic Analysis;
- проверка operator GUI, history, rebuild и exports на установленном appliance;
- при необходимости отдельная directional traffic projection для более сильного service-use вывода — это улучшение, но не условие безопасности текущего contract.

AI в v1.3 не используется и автоматические findings из correlation result не создаются. AI-assisted слой остаётся отдельным v1.4.
