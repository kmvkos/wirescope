# Архитектура WireScope

[English](en/ARCHITECTURE.md)

WireScope — локальный modular monolith для сетевой инвентаризации, диагностики и аудита. Он рассчитан на один Linux-хост, ВМ или ARM64-appliance: API, worker, SQLite, evidence store и браузерный интерфейс работают как части одного устройства без Redis, Celery и внутренних сетевых микросервисов.

Главный принцип: **сначала сохраняется факт, затем делается вывод**. Packet sensors, Nmap и protocol providers создают observations/evidence. Assessment, classification и findings интерпретируют уже собранные данные.

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
      │    ├── insights
      │    └── operations
      │
      ├── domain / lifecycle services
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

`backend/app.py` — composition root: создаёт application services, собирает их в `AppServices`, подключает routers, operational middleware и static frontend.

`backend/dependencies.py` хранит runtime dependency container. Routers получают готовые сервисы через `Depends(get_services)`.

Канонический HTTP API:

```text
/api/v1/...
```

`/api/...` пока остаётся скрытым compatibility alias и использует те же handlers, models, auth и scope checks.

## Router layout

```text
backend/routers/
├── auth.py
├── system.py
├── insights.py
├── operations.py
├── audits.py
├── captures.py
├── inventory.py
├── protocol.py
├── findings.py
├── reports.py
└── jobs.py
```

`insights.py` создаёт read-only представления над существующими stores: capabilities, profiles, dashboard, correlations, diff и evidence access.

`operations.py` отвечает за эксплуатационный контур: diagnostics, operational audit log, retention/cleanup и durable job retry.

## Environment, interface и scope

`engine/environment.py` собирает состояние Linux-хоста. `engine/interfaces.py` обнаруживает и валидирует интерфейсы. `engine/routes.py` проверяет route/source для active target. `engine/network.py` и `netctl` отвечают за управляемые изменения сетевой конфигурации.

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

## Jobs, persistence и recovery

Долгие операции — durable jobs:

```text
queued → running → completed
   │        ├────→ failed
   │        ├────→ cancelled
   │        └────→ interrupted
   └─────────────→ cancelled
```

`JobService` владеет transitions. Worker атомарно claim'ит job. Resource locks и worker heartbeat находятся в SQLite.

Если process restart прерывает running job, recovery переводит её в `interrupted` и освобождает stale locks. Terminal job не переписывается обратно в queued. Explicit retry создаёт новую durable job с теми же parameters:

```text
failed/interrupted/cancelled job
        │ operator retry
        ▼
new queued job
```

Связь между source и replacement сохраняется в job events. Это stage-level recovery, а не восстановление внутреннего состояния subprocess.

SQLite — system of record для audits, jobs/events, scopes, inventory, observations, findings, users/sessions, reports, operational events и artifact metadata. Используются WAL, foreign keys, busy timeout и короткие transactions.

## Operational audit log

`backend/audit_log.py` хранит append-only operational events отдельно от job events.

Middleware классифицирует значимые mutating HTTP requests и после выполнения записывает:

- actor/role;
- action;
- normalized API path;
- HTTP status;
- client IP;
- audit id, если он определяется из URL.

Request body, password, cookie/session token и provider output в operational table не записываются.

Ошибки записи журнала не превращают успешную operator action в outage: database/migration health отдельно виден в diagnostics.

## Evidence store и retention

PCAP, Nmap XML, protocol raw output, passive-result JSON и generated reports находятся в filesystem evidence store, а не BLOB в основных таблицах.

Artifact записывается атомарно, получает UUID, size и SHA-256. API-клиент не выбирает filesystem path.

Каноническая выдача evidence audit-scoped:

```text
GET /api/v1/audits/{audit_id}/artifacts/{artifact_id}
```

`backend/lifecycle.py` разделяет нормализованную историю и тяжёлые raw artifacts. Normalized inventory/findings/reports автоматически не удаляются. Aged PCAP/Nmap XML/protocol raw output становятся cleanup candidates, но удаляются только после явного confirmation.

Cleanup удаляет и filesystem file, и соответствующую metadata row. Preview ничего не меняет.

## Inventory, correlation и classification

Identity correlation остаётся консервативной:

1. exact MAC;
2. exact IP;
3. конфликт сохраняется как observation, а не скрытый merge.

Hostname используется как дополнительный signal/provenance, но не как достаточное основание агрессивно склеивать assets.

Device classification использует OS hints, vendor, services/ports и naming sources. Результат хранится как `device_class_hint` + confidence + explainable signal sources, а не как security finding.

## Active scan profiles

Активные профили описаны декларативно в `config/active_profiles.json` и загружаются через `engine/active_profiles.py`.

```text
GET /api/v1/scan-profiles
```

Профиль определяет timing, TCP/UDP coverage, service/version detection, OS detection и timeout. Пользователь не передаёт произвольный Nmap argv.

## Capabilities, readiness и diagnostics

`backend/capabilities.py` строит runtime inventory внешних инструментов. Core readiness требует SQLite/migrations, worker и базовые packet-capture tools. Optional provider может быть недоступен без перевода всего WireScope в `not_ready`.

```text
GET /api/v1/capabilities
GET /api/v1/diagnostics
```

Diagnostics дополняет capabilities состоянием SQLite `quick_check`, disk/evidence usage, retention, platform/runtime checks и recent operational events.

## Dashboard и diff

Dashboard не имеет собственной таблицы. Он агрегирует существующие jobs, inventory и findings.

```text
GET /api/v1/audits/{audit_id}/dashboard
```

Pipeline:

```text
passive → discovery → protocol → findings → report
```

Audit diff также вычисляется на чтении из persisted state:

```text
GET /api/v1/audits/{new_id}/diff?against={old_id}
```

Сравниваются assets, открытые services и findings.

## Findings и reports

Findings engine читает normalized observations/inventory, применяет versioned rules и создаёт findings с severity, confidence, rationale, recommendation и evidence links.

Report generation не обращается к сети. Канонический документ — `audit-report v1` JSON. Из него строятся self-contained HTML и Markdown.

## Frontend

Основной wizard остаётся в `frontend/app.js`. Дополнительные функции вынесены из него:

```text
frontend/enhancements.js   dashboard / diff / evidence / Markdown
frontend/operations.js     diagnostics / retention / retry / audit log
```

Это позволяет развивать operator views без переписывания основного audit wizard.

## Backup / restore

`appliance/backup.py` использует SQLite backup API, поэтому snapshot создаётся корректно и для WAL database. Evidence при необходимости копируется вместе с БД.

Restore сначала проверяет backup через `PRAGMA integrity_check`, затем атомарно заменяет database file; evidence восстанавливается отдельно.

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

Нормальный appliance доступен через любой настроенный интерфейс, поэтому application settings, argparse, installer и upgrade path используют по умолчанию:

```text
0.0.0.0:8000
```

Локальный kiosk открывает `http://127.0.0.1:8000/`.

Loopback-only deployment остаётся явной опцией:

```bash
sudo ./packaging/install.sh --bind-host 127.0.0.1
```

## CI и release boundary

GitHub Actions на Python 3.11 устанавливает проект, компилирует Python sources и запускает default `pytest` suite. Live-network/browser/platform checks остаются opt-in там, где это необходимо.

Архитектурный финиш первой версии определён не отсутствием новых идей, а release gate в [RELEASE_READINESS.md](RELEASE_READINESS.md). После зелёного CI последней обязательной проверкой остаётся smoke-test на реально обновлённом appliance.

## Post-1.0 technical work

Не блокируют первую стабильную версию:

- PDF export;
- дополнительные protocol modules;
- topology graph / CVE enrichment;
- scheduled audits;
- deeper cross-audit identity history;
- дальнейшая frontend decomposition;
- полный отказ от `/api/*` compatibility alias;
- расширенная distro/architecture CI matrix.
