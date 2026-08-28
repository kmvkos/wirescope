# Корреляция результатов — v1.3

[English](en/GLOBAL_ANALYSIS_MODEL.md)

В пользовательском интерфейсе функция называется **«Корреляция результатов»** (`Correlated Assessment`). Исторический технический контракт сохраняет имена `global_analysis`, `global-analysis` и `/global-analysis` для совместимости с уже созданными jobs, artifacts и API-клиентами.

## Назначение

Корреляция результатов отвечает на два практических вопроса:

> Что нового становится видно, если сопоставить уже сохранённые результаты аудита, PCAP Traffic Analysis и Network Topology?

> Если имеющихся данных недостаточно для более сильного вывода — чего именно не хватает и как оператор может добрать эти данные?

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
                 ↓
      relationships + evidence gaps
```

Корреляция полностью offline: она не запускает scanner, не перечитывает PCAP и не выполняет новый network I/O. Предложения по добору данных — это только инструкции оператору; сами действия никогда не запускаются автоматически.

## Главный presentation contract

Корреляция результатов **не должна повторять исходные отчёты**.

Она может показывать факт из Audit Report, Traffic Analysis или Topology только тогда, когда этот факт нужен для объяснения связи между источниками либо для объяснения, почему конкретный вывод пока нельзя подтвердить. Полная информация остаётся у исходного source-of-truth.

Допустимые примеры:

- service найден аудитом и его port наблюдался в выбранном PCAP;
- finding относится к asset/service, который был виден в traffic;
- inventory asset не наблюдался в выбранном capture window;
- traffic endpoint не удалось exact-сопоставить с inventory;
- exact-correlated internal asset общался с globally routable endpoint;
- gateway/DHCP/DNS observations из независимых sources согласуются или расходятся;
- один источник показывает gateway, но второго независимого подтверждения нет — WireScope показывает, чего не хватает и как получить дополнительный evidence.

Корреляция **не должна** заново печатать полный inventory, полный список services, полный finding с rationale/recommendation или полный Traffic Analysis.

## Correlation domains

### 1. Asset ↔ traffic identity

Rule: `GA-ASSET-IDENTITY-001`.

Identity строится только по exact canonical IP и exact canonical MAC. Hostname, vendor, device class и похожий MAC prefix не являются основанием для merge. Если одному exact identifier соответствуют несколько assets, возвращается `identity_conflict`, документ становится `partial`, автоматического merge нет.

### 2. Service ↔ observed traffic

Rule: `GA-SERVICE-USAGE-001`.

Если endpoint пары exact-match'ится с inventory asset, а `(protocol, port)` найденного service присутствует в persisted `communications_graph`, service получает `observed_in_selected_traffic=true`.

Ограничение `traffic-analysis` v1: destination ports агрегируются по communication pair, поэтому basis остаётся `observed_pair_destination_port`. Это подтверждает присутствие service port в паре с asset, но не доказывает направление client → конкретный server socket.

При таком случае evidence-gap слой прямо сообщает, что для строгого подтверждения направления нужен двусторонний flow/handshake либо другой пригодный направленный evidence.

### 3. Finding ↔ observed traffic

Rule: `GA-FINDING-TRAFFIC-RELEVANCE-001`.

Состояния:

- `service_traffic_observed`;
- `asset_traffic_observed`;
- `uncorrelated`.

`uncorrelated` означает только отсутствие связи с visibility выбранного PCAP. Это не меняет severity finding и не означает, что finding ложный или неважный. Если для finding не хватает traffic corroboration, gap может предложить более подходящий capture window/segment или сначала добрать identity evidence.

### 4. Inventory ↔ Traffic visibility

Rule: `GA-INVENTORY-TRAFFIC-COVERAGE-001`.

Отдельно показываются inventory assets, exact-correlated с traffic; assets, не наблюдавшиеся в выбранном capture; и traffic endpoints без exact inventory identity. Это сравнение visibility, а не процент «изученности реальной сети».

### 5. Internal ↔ global endpoints

Rule: `GA-EXTERNAL-COMMUNICATION-001`.

Строка создаётся только если одна сторона exact-match'ится с inventory asset, а вторая классифицирована как `external_global`. Private address вне известных topology segments остаётся `private_unknown`, а не объявляется Internet/external автоматически.

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

### 7. Evidence gaps — чего не хватает для подтверждения

Rule family: `GA-EVIDENCE-GAP-001`.

`evidence_gaps` — это **не findings и не warnings**. Gap создаётся, когда уже существует хотя бы некоторый исходный evidence или конфликт между источниками, но его недостаточно для более сильного cross-source вывода.

Если для инфраструктурной проверки нет вообще ни одного исходного факта, отдельная карточка gap не создаётся: отсутствие source data остаётся responsibility `source_health`/coverage. Это защищает интерфейс от бессмысленного списка «мы ничего не знаем».

Каждый gap содержит:

```text
id
rule_id
category
status                  needs_evidence | conflicting_evidence
priority                high | medium | low
title
known_evidence          что уже известно
missing_evidence        чего не хватает и почему
collection_options      конкретные способы добора
safe_conclusion         что корректно утверждать сейчас
affected                агрегированные затронутые объекты
evidence_refs           ссылки на сохранённый evidence
related_rule_ids
```

Gap'ы намеренно агрегируются: WireScope не создаёт по отдельной карточке на каждый хост, если несколько объектов имеют одинаковую причину недостаточности evidence.

Типовые категории:

- недостаточно/конфликтует evidence для gateway, DHCP или DNS;
- неоднозначная IP/MAC identity;
- внутренний/private endpoint PCAP не сопоставлен с inventory;
- service port наблюдался на уровне communication pair, но направление server/client не доказано;
- сервис обнаружен аудитом, но его использование не наблюдалось в выбранном PCAP;
- finding не получил дополнительного traffic corroboration;
- устройство аудита не видно в выбранном capture window;
- topology partial;
- отсутствует пригодный communications graph Traffic Analysis.

`collection_options` могут предлагать более длинный/правильно расположенный PCAP, DHCP/ARP observation, SPAN/зеркалирование нужного VLAN, active discovery **только внутри уже подтверждённого scope**, либо SNMP/SSH topology enrichment. Эти рекомендации никогда не расширяют authorization и ничего не запускают сами.

`safe_conclusion` обязателен: до получения нового evidence WireScope явно формулирует максимально сильный вывод, который поддерживают текущие данные, и не делает следующий логический шаг без доказательств.

### 8. Evidence quality

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
├── evidence_gaps
├── coverage
├── source_health
├── evidence_references
├── operator_summary
├── partial
└── warnings
```

Добавление `evidence_gaps` является additive evolution `global-analysis v1`: исторические identifiers и API paths не меняются.

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

Главный человеческий блок после краткого итога — **«Что ещё нужно подтвердить»**. Для каждого evidence gap UI показывает:

1. что уже есть;
2. чего не хватает;
3. как добрать данные;
4. что пока корректно утверждать.

Затем идут низкоуровневые correlation sections: consistency, coverage/source health, findings ↔ traffic, external communications и evidence lineage.

TXT/Markdown exports используют ту же структуру; JSON сохраняет deterministic machine contract.

## Non-goals

Корреляция намеренно **не включает**:

- behavioral/anomaly baselines;
- inference намерений или атак;
- threat intelligence/reputation scoring;
- большой pattern/rule library поверх traffic behavior;
- автоматическое повышение/понижение severity исходных findings;
- автоматическое создание новых security findings из correlation result;
- AI-анализ;
- автоматический запуск рекомендуемого сбора данных;
- повтор исходных Audit/Traffic/Topology reports.

Evidence gaps не меняют эту границу: они объясняют недостаточность уже имеющихся доказательств и предлагают оператору безопасные варианты дальнейшего сбора.

## Статус

Базовая v1.3 Correlated Assessment закрыта. v1.3.3 — ограниченное additive-улучшение operator guidance: deterministic evidence gaps без расширения network activity, authorization или аналитического scope WireScope.
