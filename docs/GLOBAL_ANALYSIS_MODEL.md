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
- результат полностью offline и deterministic.

## API

```text
GET /api/v1/audits/{audit_id}/global-analysis?traffic_analysis_job_id={job_id}
```

`audit_id` задаёт inventory/findings/topology audit. `traffic_analysis_job_id` выбирается оператором явно и должен указывать на завершённый `traffic_analysis` job с зарегистрированным `traffic_analysis_result`.

## Canonical contract

Первый contract имеет:

```text
global-analysis v1
├── inputs
├── summary
├── asset_traffic_identity
├── service_usage
├── finding_traffic_relevance
├── external_communications
├── unclassified_communications
├── coverage
├── source_health
├── partial
└── warnings
```

Каждая correlation row имеет deterministic ID и versioned `rule_id`.

## Asset ↔ traffic identity

Текущий rule:

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

Первый slice использует pair-level `communications_graph` из `traffic-analysis` v1.

Если:

- endpoint пары exact-match'ится с asset;
- inventory содержит service `(protocol, port)` этого asset;
- такой `protocol/port` присутствует среди агрегированных destination ports пары,

service получает `observed_in_selected_traffic=true`.

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

WireScope отдельно показывает:

- inventory assets, exact-correlated с traffic;
- inventory assets, не наблюдавшиеся в выбранном capture;
- traffic endpoints, не сопоставленные с inventory.

Это visibility comparison, а не оценка полноты реальной сети.

## Internal ↔ external communications

Rule:

```text
GA-EXTERNAL-COMMUNICATION-001
```

External communication создаётся только когда одна сторона exact-match'ится с inventory asset, а другая классифицирована как `external_global`.

Сохраняются:

- internal asset ID;
- external endpoint;
- packets/bytes;
- protocols/ports из persisted Traffic Analysis;
- ссылка на deterministic conversation ID.

Private unknown communications выводятся отдельно в `unclassified_communications`.

## Source health и partial

Global Analysis наследует качество входов.

Например:

- truncated report/inventory source → `inventory=partial`;
- topology `partial=true` → `topology=partial`;
- отсутствующий communications graph → `traffic=missing`;
- identity conflict → `identity=partial`.

Итоговый `partial=true` означает, что документ всё ещё пригоден, но часть корреляционных утверждений ограничена состоянием sources.

## Что первый slice пока не делает

- не сохраняет отдельный durable `global_analysis_result` artifact;
- не имеет собственного job lifecycle;
- не перечитывает PCAP для более точного directional service mapping;
- не использует hostname-only identity;
- не использует AI;
- не создаёт новые findings автоматически.

Следующий slice может добавить durable artifact/job contract поверх уже стабильного `global-analysis v1`, не меняя safety-модель.
