# Архитектура WireScope

[English](en/ARCHITECTURE.md)

WireScope — локальный modular monolith для сетевой инвентаризации, диагностики и аудита. Он рассчитан на один Linux-хост, ВМ или ARM64-appliance: API, worker, SQLite, evidence store и браузерный интерфейс работают как части одного устройства без Redis, Celery и внутренних сетевых микросервисов.

Главный принцип: **сначала сохраняется факт, затем делается вывод**. Packet sensors, Nmap, protocol providers и management-plane providers создают observations/evidence. Inventory, topology, assessment, classification, findings и reports интерпретируют уже сохранённые данные.

## Общая схема

```text
browser / kiosk
      │
      ▼
FastAPI /api/v1
      │
      ├── auth / network / scope
      ├── audits / jobs / captures
      ├── inventory / protocol / findings / reports
      ├── traffic analysis / topology
      ├── diagnostics / lifecycle / audit log
      │
      ├──────── SQLite WAL
      │
      └──────── evidence store
                    ▲
                    │
                  worker
                    ├── passive discovery
                    ├── packet capture
                    ├── active discovery
                    ├── protocol audits
                    ├── traffic analysis
                    ├── SNMP/SSH topology enrichment
                    ├── findings evaluation
                    └── report generation
```

API и worker — отдельные процессы. Browser/kiosk — клиент durable API. Reload или restart Chromium не меняют job lifecycle.

## Backend composition

`backend/app.py` — composition root: создаёт application services, собирает их в `AppServices`, подключает routers, middleware и static frontend.

Канонический HTTP API:

```text
/api/v1/...
```

`/api/...` остаётся compatibility alias и использует те же handlers, models, auth и scope checks.

## Router layout

Основные предметные routers находятся в `backend/routers/`:

```text
auth.py
system.py
operations.py
audits.py
captures.py
inventory.py
protocol.py
findings.py
reports.py
jobs.py
topology.py
```

`topology.py` предоставляет read-only canonical/global/history topology и auditor-only management enrichment через SNMP/SSH.

## Environment, interfaces и scope

`engine/environment.py` собирает состояние Linux-хоста, включая interface context, routes и доступные DHCP lease hints. `engine/interfaces.py` обнаруживает и валидирует интерфейсы. `engine/routes.py` проверяет route/source для active target. `engine/network.py` и `netctl` отвечают за контролируемые изменения сетевой конфигурации.

Observed network data и authorized scope всегда разделены:

```text
passive/environment evidence
        ↓
scope proposal
        ↓
operator confirmation
        ↓
immutable confirmed scope
        ↓
worker revalidation
        ↓
active provider
```

Пассивно увиденный ARP host, DHCP server, LLDP neighbour, VLAN tag или SNMP-discovered subnet не становится автоматически разрешённой active target.

## Passive pipeline

```text
validated interface
      ↓
dumpcap → bounded PCAP
      ↓
tshark -T ek
      ↓
normalized PacketRecord
      ↓
in-process sensors
      ↓
assessment + inventory observations
```

Один PCAP декодируется один раз. Сенсоры не запускают отдельный `tshark` на каждый протокол.

## Traffic Analysis

Сохранённый PCAP может быть проанализирован отдельной durable job без нового захвата.

Результат `traffic-analysis` содержит diagnostics и normalized communications graph. Этот graph может быть явно подключён к Network Topology через `traffic_analysis_job_id`, но последний PCAP не подмешивается автоматически.

## Network Topology

Topology является отдельным доменом поверх persisted evidence, а не состоянием frontend.

```text
persisted inventory / environment / passive / management / traffic
                         ↓
                 canonical topology
                         ↓
              coverage / claimability
                         ↓
       structural · L2 · L3 · Traffic · all evidence
```

Основные модули находятся в `topology/` и выполняют разные задачи:

- canonical graph assembly;
- upstream/route projection;
- SNMP projection;
- read-only SSH management projection;
- source health;
- coverage/claimability;
- structural presentation metadata;
- global retained-audit topology;
- historical comparison.

### Canonical graph и presentation

Canonical topology хранит полный evidence graph. Structural presentation не переписывает source of truth и может скрывать/группировать directed broadcast, link-local noise и PCAP-only external endpoints, чтобы основной экран оставался инфраструктурной схемой.

Это позволяет одновременно иметь:

- удобную операторскую карту;
- полный JSON для диагностики;
- отдельные L2/L3/Traffic/All Evidence views.

### Evidence sufficiency

`coverage` не является процентом «обнаруженной сети». Он отвечает, достаточно ли retained evidence для утверждений об inventory, L3, L2, traffic, VLAN, Wi-Fi и hypervisor context.

Статусы:

```text
sufficient
partial
missing
```

`missing` означает «WireScope не может доказать этот класс связи», а не «такой связи не существует».

### L3 и multi-homed host

Gateway выбранного audit interface определяется только из interface-specific persisted evidence:

- per-interface default route;
- DHCP router option;
- management-plane evidence;
- bounded route trace.

Host-wide default route другого NIC не переносится на выбранную audit network. Адреса `.1`, `.254`, `.11` не угадываются.

### Management-plane enrichment

SNMP и SSH — optional active management sources и требуют operator-confirmed scope.

SNMP использует стандартные IF/IP/BRIDGE/Q-BRIDGE/LLDP MIB там, где устройство их предоставляет.

SSH provider предназначен для Linux/OpenWrt-подобных devices и не является generic shell: remote commands находятся в фиксированном allowlist `ip/bridge/iw`, включена strict host-key verification, arbitrary operator command отсутствует.

Credentials для SNMP/SSH проходят через consume-once runtime spool и не сохраняются в topology evidence как plaintext.

Management-discovered subnet всегда остаётся `active_scope=false`.

### Source health

Если ожидаемый job-backed route/SNMP/SSH artifact не удалось включить в topology, запрос карты не обязан падать целиком. Вместо этого результат становится:

```json
{
  "partial": true,
  "source_errors": []
}
```

Ошибки sanitised: без credentials, filesystem paths и exception text.

Подробности: [TOPOLOGY_MODEL.md](TOPOLOGY_MODEL.md).

## Jobs, persistence и recovery

Долгие операции представлены durable jobs:

```text
queued → running → completed
   │        ├────→ failed
   │        ├────→ cancelled
   │        └────→ interrupted
   └─────────────→ cancelled
```

`JobService` владеет transitions. Worker атомарно claim'ит job. Resource locks и heartbeat находятся в SQLite.

После restart running job становится `interrupted`, stale locks освобождаются. Explicit retry создаёт новую durable job, а source history не переписывается.

Credentialed `snmp_topology` и `ssh_topology` являются исключением из generic retry: старый consume-once credential reference не переиспользуется, оператор запускает enrichment заново со свежими credentials.

SQLite — system of record для audits, jobs/events, scopes, inventory, observations, findings, reports, users/sessions, operational events и artifact metadata. Используются WAL, foreign keys, busy timeout и короткие transactions.

## Evidence store и retention

PCAP, Nmap XML, protocol raw output, management results и generated reports находятся в filesystem evidence store, а metadata — в SQLite.

Artifact записывается атомарно, получает UUID, size и SHA-256. API-клиент не выбирает filesystem path.

Каноническая выдача:

```text
GET /api/v1/audits/{audit_id}/artifacts/{artifact_id}
```

Aged raw artifacts удаляются только через явный retention/cleanup flow. Normalized inventory/findings/reports автоматически не удаляются.

## Inventory, correlation и classification

Identity correlation остаётся консервативной:

1. exact MAC;
2. exact IP;
3. конфликт сохраняется, а не скрывается агрессивным merge.

Hostname — дополнительный signal/provenance, но не достаточное основание для identity merge.

Device classification (`server-like`, `workstation-like`, `network-device-like`, `printer-like`, `iot-like`, `unknown`) остаётся explainable hint, а не finding.

## Findings и reports

Findings engine читает normalized observations/inventory, применяет versioned rules и создаёт findings с severity, confidence, rationale, recommendation и evidence links.

Report generation не обращается к сети. Канонический документ — `audit-report v1` JSON, из которого строятся HTML и Markdown.

## Operational audit log

Operational events отделены от job events. Записываются actor/role, action, normalized path, HTTP status, client IP и audit id.

Request body, password, session token/cookie и provider stdout не копируются в operational log.

## Capabilities, readiness и diagnostics

`backend/capabilities.py` разделяет core readiness и optional providers.

Core readiness требует:

- SQLite/migrations;
- healthy worker;
- базовые packet-capture tools.

Отсутствие SNMP/SSH или другого optional provider не делает весь appliance `not_ready`.

```text
GET /api/v1/capabilities
GET /api/v1/diagnostics
GET /api/v1/ready
```

## Frontend

Frontend остаётся без build framework. Основной wizard живёт в `frontend/app.js`, дополнительные функции вынесены в отдельные modules.

Topology UI состоит из базового renderer и hardening/presentation extensions. Browser хранит только UI state; source of truth остаётся backend/SQLite/evidence.

Root page отдаётся с cache-busting version query strings, чтобы kiosk Chromium после upgrade не использовал старый topology JS/CSS.

## Backup / restore

`appliance/backup.py` использует SQLite backup API, поэтому snapshot корректен для WAL database. Evidence может копироваться вместе с БД.

Restore проверяет backup через `PRAGMA integrity_check`, затем заменяет working database.

## Privilege boundary

```text
unprivileged wirescope-api
unprivileged wirescope-worker
          │
          ▼
/usr/bin/dumpcap
root:wireshark 0750
cap_net_admin,cap_net_raw=eip
```

Python backend не получает packet-capture capabilities. Nmap не повышается самим WireScope. SNMP/SSH management providers также выполняются worker-ом без превращения API в root process.

## Deployment

Нормальный appliance слушает:

```text
0.0.0.0:8000
```

Локальный kiosk использует `http://127.0.0.1:8000/`. Loopback-only deployment задаётся явно.

## CI и текущая граница

GitHub Actions на Python 3.11 выполняет compileall, default pytest suite, Chromium regression, wheel build и smoke install wheel вне source tree.

Network Topology v1.2 прошла live smoke на обновлённой WireScope VM. SNMP/SSH vendor-specific interoperability остаётся дополнительной эксплуатационной проверкой по мере появления managed devices и не меняет правило: отсутствующий management evidence должен быть виден как `missing/partial`, а не компенсироваться догадками.

Следующая крупная подсистема — **v1.3 Global Correlation Analysis**: детерминированная корреляция persisted inventory/findings/Traffic Analysis/Network Topology без повторного network I/O.

## Дальнейшая работа

Не блокирует текущую линию:

- PDF export;
- дополнительные protocol modules;
- CVE enrichment;
- scheduled audits;
- cross-site topology history;
- hypervisor-specific topology providers;
- vendor-specific management adapters;
- дальнейшая frontend decomposition;
- полный отказ от `/api/*` compatibility alias;
- расширенная distro/architecture/tshark CI matrix.