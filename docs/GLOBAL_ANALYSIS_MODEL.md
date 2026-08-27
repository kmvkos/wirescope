# Корреляция результатов — v1.3

[English](en/GLOBAL_ANALYSIS_MODEL.md)

В пользовательском интерфейсе функция называется **«Корреляция результатов»** (`Correlated Assessment`). Исторический технический контракт сохраняет имена `global_analysis`, `global-analysis` и `/global-analysis` для совместимости с уже созданными jobs, artifacts и API-клиентами.

## Назначение

Корреляция результатов отвечает на один практический вопрос:

> Что нового становится видно, если сопоставить уже сохранённые результаты аудита, PCAP Traffic Analysis и Network Topology?

Это **не** SIEM, NDR, UEBA, anomaly detector и не «глубокий глобальный анализ» поведения сети. WireScope не пытается угадывать намерения узлов, строить долговременные behavioral baselines или заменять SOC-платформу.

```text
persisted audit / inventory / findings
                 +
explicitly selected Traffic Analysis
                 +
canonical Network Topology
                 ↓
        Correlated Assessment
   technical schema: global-analysis v1
```

Корреляция полностью offline: она не запускает scanner, не перечитывает PCAP и не выполняет новый network I/O.

## Главный presentation contract

Корреляция результатов **не должна повторять исходные отчёты**.

Она может показывать факт из Audit Report или Traffic Analysis только тогда, когда этот факт нужен для объяснения связи между источниками. Полная информация остаётся у исходного source-of-truth.

Примеры допустимых выводов:

- service найден аудитом и его port наблюдался в выбранном PCAP;
- finding относится к asset/service, который был виден в traffic;
- inventory asset не наблюдался в выбранном capture window;
- traffic endpoint не удалось exact-сопоставить с inventory;
- exact-correlated internal asset общался с globally routable endpoint;
- gateway/DHCP/DNS observations из независимых sources согласуются или расходятся.

Корреляция **не должна** заново печатать полный inventory, полный список services, полный finding с rationale/recommendation или полный Traffic Analysis.

## Correlation domains

### 1. Asset ↔ traffic identity

Rule: `GA-ASSET-IDENTITY-001`.

Identity строится только по:

1. exact canonical IP;
2. exact canonical MAC.

Hostname, vendor, device class и похожий MAC prefix не являются основанием для merge. Если одному exact identifier соответствуют несколько assets, возвращается `identity_conflict`, документ становится `partial`, автоматического merge нет.

### 2. Service ↔ observed traffic

Rule: `GA-SERVICE-USAGE-001`.

Если endpoint пары exact-match'ится с inventory asset, а `(protocol, port)` найденного service присутствует в persisted `communications_graph`, service получает `observed_in_selected_traffic=true`.

Ограничение `traffic-analysis` v1: destination ports агрегируются по communication pair, поэтому basis остаётся `observed_pair_destination_port`. Это подтверждает присутствие service port в паре с asset, но не доказывает направление client → конкретный server socket.

Directional flow projection может быть добавлен позже как улучшение Traffic Analysis; для закрытия v1.3 он не требуется.

### 3. Finding ↔ observed traffic

Rule: `GA-FINDING-TRAFFIC-RELEVANCE-001`.

Состояния:

- `service_traffic_observed`;
- `asset_traffic_observed`;
- `uncorrelated`.

`uncorrelated` означает только отсутствие связи с visibility выбранного PCAP. Это не меняет severity finding и не означает, что finding ложный или неважный.

### 4. Inventory ↔ Traffic visibility

Rule: `GA-INVENTORY-TRAFFIC-COVERAGE-001`.

Отдельно показываются:

- inventory assets, exact-correlated с traffic;
- inventory assets, не наблюдавшиеся в выбранном capture;
- traffic endpoints без exact inventory identity.

Это сравнение visibility, а не процент «изученности реальной сети».

### 5. Internal ↔ global endpoints

Rule: `GA-EXTERNAL-COMMUNICATION-001`.

Строка создаётся только если одна сторона exact-match'ится с inventory asset, а вторая классифицирована как `external_global`.

Private address вне известных topology segments остаётся `private_unknown`, а не объявляется Internet/external автоматически.

### 6. Infrastructure consistency

Rules:

```text
GA-GATEWAY-CONSISTENCY-001
GA-DHCP-CONSISTENCY-001
GA-DNS-CONSISTENCY-001
```

Сопоставляются независимые persisted observations из environment/passive/Traffic Analysis/topology. Статусы:

- `consistent` — два или более sources имеют общее значение;
- `divergent` — два или более sources доступны, но общего значения нет;
- `insufficient` — независимых sources недостаточно для сравнения.

### 7. Evidence quality

Partial/missing state исходных sources наследуется. Confidence корреляции не может быть выше confidence исходного evidence.

`evidence_references` содержит безопасные ID/type/hash/schema/timestamp references, но не filesystem paths.

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

Technical schema name оставлен неизменным ради backward compatibility. Внешний продуктовый термин — **«Корреляция результатов»**.

## Durable execution и API

Preview:

```text
GET /api/v1/audits/{audit_id}/global-analysis?traffic_analysis_job_id={job_id}
```

Durable run:

```text
POST /api/v1/audits/{audit_id}/global-analysis
{
  "traffic_analysis_job_id": "...",
  "priority": 0
}
```

Persisted result:

```text
job_type       = global_analysis
artifact_type  = global_analysis_result
schema         = global-analysis
schema_version = 1
retention      = audit
```

History/read/export:

```text
GET /api/v1/audits/{audit_id}/global-analysis/history
GET /api/v1/jobs/{job_id}/global-analysis
GET /api/v1/jobs/{job_id}/global-analysis/export?format=json
GET /api/v1/jobs/{job_id}/global-analysis/export?format=text
GET /api/v1/jobs/{job_id}/global-analysis/export?format=markdown
```

Rebuild создаёт новый immutable job/artifact и сохраняет `rebuild_of_job_id`. Старый result никогда не переписывается; source Traffic Analysis должен совпадать.

## Operator GUI

На домашнем экране функция отображается как **«Корреляция результатов»**.

Workspace позволяет выбрать audit и конкретный completed Traffic Analysis, запустить durable correlation, увидеть progress/history, открыть immutable previous result, выполнить rebuild и экспортировать JSON/TXT/Markdown.

Presentation ориентирован на связи между sources:

- сводка сопоставления;
- что источники дополнили друг в друге;
- infrastructure consistency;
- coverage/source health;
- findings ↔ observed traffic;
- internal assets ↔ global endpoints;
- ограничения интерпретации;
- evidence lineage.

## Non-goals

v1.3 намеренно **не включает**:

- behavioral/anomaly baselines;
- inference намерений или атак;
- threat intelligence/reputation scoring;
- большой pattern/rule library поверх traffic behavior;
- автоматическое повышение/понижение severity исходных findings;
- автоматическое создание новых security findings из correlation result;
- AI-анализ;
- повтор исходных Audit/Traffic/Topology reports.

Если WireScope когда-либо получит отдельные функции этих классов, это будет новый явно ограниченный feature, а не скрытое расширение Correlated Assessment.

## Статус v1.3

**Feature complete / closed.**

Реализованы deterministic correlation, durable storage, evidence lineage, consistency checks, history/rebuild/exports и operator GUI. Automated regression прошёл compile/pytest/JS syntax/wheel/installed-wheel gates; функция также была проверена на установленной WireScope VM.

Следующий продуктовый этап — не расширение корреляции, а **ревизия всех представлений и отчётов WireScope на дублирование данных и ясное разделение source-of-truth**.
