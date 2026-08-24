# Архитектура WireScope

[English](en/ARCHITECTURE.md)

WireScope — локальный modular monolith для сетевой инвентаризации, диагностики и аудита. Он рассчитан на один Linux-хост, ВМ или ARM64-appliance: API, worker, SQLite, evidence store и браузерный интерфейс работают как части одного устройства без Redis, Celery и внутренних сетевых микросервисов.

Главный принцип: **сначала собирается факт, затем делается вывод**. Packet sensors, Nmap и protocol providers создают observations/evidence. Assessment, classification и findings уже интерпретируют сохранённые данные.

## Общая схема

```text
browser / kiosk
      │
      ▼
FastAPI /api/v1
      │
      ├── routers
      │    ├── auth / system / network / scope
      │    ├── audits / jobs / captures
      │    ├── inventory / protocol / findings / reports
      │    └── insights
      │
      ├── domain services
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
                    ├── findings evaluation
                    └── report generation
```

API и worker — отдельные процессы. Browser/kiosk — клиент durable API. Reload или restart Chromium не меняет job lifecycle.

## Backend composition

`backend/app.py` — composition root: создаёт application services, собирает их в `AppServices`, подключает routers и static frontend.

`backend/dependencies.py` хранит runtime dependency container. Router получает готовые сервисы через `Depends(get_services)` и не создаёт собственный второй domain layer.

Канонический HTTP API публикуется под:

```text
/api/v1/...
```

`/api/...` временно остаётся compatibility alias и использует те же handlers, models, auth и scope checks. Legacy alias скрыт из OpenAPI.

## Router layout

```text
backend/routers/
├── auth.py
├── system.py
├── audits.py
├── captures.py
├── inventory.py
├── protocol.py
├── findings.py
├── reports.py
├── jobs.py
└── insights.py
```

`insights.py` не хранит отдельное состояние. Он предоставляет read-only представления над существующими stores:

- `/capabilities`;
- `/scan-profiles`;
- audit dashboard/pipeline;
- passive/active correlations;
- audit-to-audit diff;
- audit-scoped evidence access.

## Environment, interface и scope

`engine/environment.py` собирает состояние Linux-хоста. `engine/interfaces.py` обнаруживает и валидирует интерфейсы. `engine/routes.py` проверяет реальный route/source для active target. `engine/network.py` и `netctl` отвечают за управляемые изменения сетевой конфигурации.

Observed network data и authorized scope разделены. Пассивно увиденный ARP host, DHCP server, LLDP/CDP neighbour или VLAN tag не становится автоматически разрешённой active target.

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
Nmap provider
```

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

Один PCAP декодируется один раз. Сенсоры не запускают отдельный tshark на каждый протокол.

## Jobs и persistence

Долгие операции — durable jobs:

```text
queued → running → completed
   │        ├────→ failed
   │        ├────→ cancelled
   │        └────→ interrupted
   └─────────────→ cancelled
```

`JobService` владеет transitions. Worker атомарно claim'ит job. Locks и worker leases находятся в SQLite.

SQLite — system of record для audits, jobs/events, scopes, inventory, observations, findings, users/sessions, reports и artifact metadata. Используются WAL, foreign keys, busy timeout и короткие транзакции; scanner process не держит открытую SQL transaction.

## Evidence store

PCAP, Nmap XML, raw provider stdout/stderr, passive-result JSON и generated reports находятся в filesystem evidence store, а не BLOB в основных таблицах.

Artifact записывается атомарно, получает UUID, size и SHA-256. API-клиент не выбирает filesystem path.

Каноническая выдача evidence audit-scoped:

```text
GET /api/v1/audits/{audit_id}/artifacts/{artifact_id}
```

## Inventory, correlation и classification

Identity correlation остаётся консервативной:

1. exact MAC;
2. exact IP;
3. конфликт сохраняется как observation, а не скрытый merge.

Hostname используется как дополнительный signal/provenance, но не как достаточное основание агрессивно склеивать assets.

Device classification использует OS hints, vendor, services/ports и naming sources. Результат хранится как `device_class_hint` + confidence + explainable signal sources, а не как security finding.

## Active scan profiles

Активные профили описаны декларативно в `config/active_profiles.json` и загружаются через `engine/active_profiles.py`.

API отдаёт фактически загруженный каталог:

```text
GET /api/v1/scan-profiles
```

Профиль определяет timing, TCP/UDP coverage, service/version detection, OS detection и timeout. Пользователь не передаёт произвольный Nmap argv.

## Capabilities и readiness

`backend/capabilities.py` строит runtime inventory внешних инструментов: capture/decode, Nmap и protocol providers.

Core readiness требует базовые компоненты, необходимые для работоспособности appliance. Optional provider может быть недоступен без перевода всего WireScope в `not_ready`.

GUI получает capabilities через:

```text
GET /api/v1/capabilities
```

Там же виден effective web listener: bind host/port, TLS и trust-proxy state.

## Dashboard и pipeline

Dashboard не имеет собственной таблицы. Он агрегирует существующие jobs, inventory и findings.

```text
GET /api/v1/audits/{audit_id}/dashboard
```

Pipeline:

```text
passive → discovery → protocol → findings → report
```

Каждая стадия выводится из durable jobs.

## Audit diff

Сравнение двух audits вычисляется на чтении из persisted state:

```text
GET /api/v1/audits/{new_id}/diff?against={old_id}
```

Сравниваются assets, открытые services и findings. Для identity между аудитами используется стабильный доступный signal — прежде всего MAC, затем IP/name fallback.

## Findings и reports

Findings engine читает normalized observations и inventory, применяет versioned rules и создаёт finding с severity, confidence, rationale, recommendation и evidence links.

Report generation не обращается к сети. Канонический документ — `audit-report v1` JSON. Из него строятся self-contained HTML и Markdown. PDF пока не реализован.

## Frontend

Основной wizard остаётся в `frontend/app.js`. Новая operator-insights панель вынесена в `frontend/enhancements.js` и `enhancements.css`, чтобы не раздувать основной workflow.

Она показывает:

- dashboard/pipeline;
- capabilities и listener;
- scan profiles;
- audit diff;
- evidence viewer.

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

Python backend не получает packet-capture capabilities. Nmap не повышается самим WireScope.

## Deployment

Нормальный appliance должен быть доступен оператору через любой настроенный интерфейс, поэтому application settings, installer и upgrade path по умолчанию используют:

```text
0.0.0.0:8000
```

Локальный kiosk при этом открывает `http://127.0.0.1:8000/`.

Loopback-only deployment остаётся явной опцией:

```bash
sudo ./packaging/install.sh --bind-host 127.0.0.1
```

Firewall, direct TLS и reverse proxy могут применяться по требованиям конкретной сети; они не меняют внутреннюю архитектуру WireScope.

## CI и тестирование

GitHub Actions на Python 3.11 устанавливает проект, компилирует Python sources и запускает default `pytest` suite. Live-network и browser-specific проверки остаются opt-in там, где это требуется.

## Оставшийся technical debt

- PDF export;
- отдельная security audit-log таблица;
- policy-driven retention/deletion завершённых audits/evidence;
- автоматический retry terminal/interrupted jobs;
- release-проверка tshark/provider compatibility на пакетных версиях поддерживаемых дистрибутивов.
