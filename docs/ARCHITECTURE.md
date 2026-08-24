# Архитектура WireScope

[English](en/ARCHITECTURE.md)

WireScope — локальный modular monolith для сетевой инвентаризации, диагностики и аудита. Он рассчитан на один Linux-хост или ВМ: API, worker, SQLite, evidence store и браузерный интерфейс работают как части одного appliance, без Redis, Celery и сетевых микросервисов между внутренними компонентами.

Главный принцип проекта: **сначала собирается факт, затем делается вывод**. Пакетный сенсор, Nmap или протокольный provider создаёт observation/evidence. Assessment и findings engine уже интерпретируют эти данные.

## Общая схема

```text
browser / kiosk
      │ HTTP + session cookie
      ▼
FastAPI
      │
      ├── backend/routers/
      │      ├── auth
      │      ├── system / network / scope
      │      ├── audits
      │      ├── captures
      │      ├── inventory
      │      ├── protocol audits
      │      ├── findings
      │      ├── reports
      │      └── jobs
      │
      ├── domain services
      │      ├── JobService
      │      ├── InventoryService
      │      ├── AuthService
      │      ├── NetworkService
      │      └── stores
      │
      ├──────────── SQLite WAL
      │
      └──────────── evidence store
                        ▲
                        │
                     worker
                        │
                        ├── passive discovery
                        ├── packet capture
                        ├── active discovery
                        ├── protocol audits
                        ├── findings evaluation
                        └── report generation
```

API и worker — отдельные процессы. Browser/kiosk — отдельный клиент. Перезапуск Chromium не влияет на job, а рестарт API не уничтожает уже записанное состояние заданий.

## Backend

### `backend/app.py`

`backend/app.py` — composition root. В нём больше нет большого набора route handlers.

Он отвечает за четыре вещи:

1. создать или получить application services;
2. собрать их в `AppServices`;
3. подключить API routers;
4. подключить static frontend и `/`.

Зависимости сохраняются в `application.state.services`. Старые `application.state.jobs`, `.inventory`, `.evidence` и другие атрибуты пока также остаются для совместимости с тестами и in-process integrations.

### `backend/dependencies.py`

`AppServices` — контейнер runtime-зависимостей FastAPI. Router получает его через `Depends(get_services)` вместо того, чтобы заново собирать сервисы или импортировать глобальные singleton-объекты.

Это не dependency-injection framework. Контейнер нужен только для явной передачи уже созданных сервисов в HTTP слой.

### `backend/routers/`

HTTP surface разделён по предметным областям:

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
└── jobs.py
```

Router не должен становиться вторым domain layer. Его задача — разобрать HTTP request, вызвать существующий сервис и вернуть API model/error.

Общие преобразования HTTP ошибок и response models вынесены в `backend/http.py`; общий authorization guard находится в `backend/security.py`.

## Версионирование API

Канонический API публикуется как:

```text
/api/v1/...
```

Например:

```text
GET  /api/v1/health
POST /api/v1/audits
GET  /api/v1/jobs/{job_id}
```

Для плавного перехода тот же `api_router` дополнительно подключён под `/api`. Legacy prefix остаётся рабочим для текущего frontend и существующих клиентов, но не включается в OpenAPI schema.

Таким образом нет двух реализаций API:

```text
/api/v1 ─┐
         ├── same routers / same handlers / same services
/api    ─┘
```

Authorization guard нормализует оба prefix и применяет одинаковую public/auditor policy. Подробнее: [API.md](API.md).

## Environment, interfaces и network

`engine/environment.py` собирает состояние Linux-хоста из обычных системных источников: `ip -j addr`, `ip -j route`, `/sys/class/net`, resolver configuration и hostname.

`engine/interfaces.py` отвечает за обнаружение и validation интерфейсов. Неизвестный, запрещённый policy или down-интерфейс отбрасывается до запуска capture/scanner.

`engine/network.py` и appliance `netctl` отвечают за управляемое изменение сетевой конфигурации. API не выполняет произвольные shell-команды пользователя.

`engine/routes.py` проверяет, через какой interface/source реально маршрутизируется подтверждённая цель.

## Scope

Observed network data и authorized scope — разные сущности.

Пассивный анализ может увидеть ARP-адрес, DHCP server, LLDP/CDP neighbour или VLAN tag. Это наблюдение не является разрешением сканировать найденную сеть.

Active discovery проходит цепочку:

```text
operator request
      ↓
ScopeValidator
      ↓
address-count / prohibited-range checks
      ↓
route + interface validation
      ↓
immutable confirmed scope
      ↓
worker
      ↓
Nmap provider
```

`0.0.0.0/0`, `::/0`, multicast и бесконтрольное расширение IPv6 запрещены. Лимиты зависят от профиля.

## Passive pipeline

Обычный passive audit использует фиксированный pipeline:

```text
validated interface
      ↓
dumpcap → bounded PCAP
      ↓
tshark -T ek → line-oriented decode
      ↓
normalized PacketRecord
      ↓
in-process sensors
      ↓
assessment
```

`dumpcap` только захватывает пакеты. `tshark` только декодирует уже созданный PCAP. Сенсоры не запускают внешние команды.

Один PCAP не декодируется отдельным tshark-процессом для каждого протокола. Это важно для небольших appliance и ARM64.

Sensor result различает `absent`, `detected`, `partial` и `error`. Ошибка parser/tool не превращается в «протокол отсутствует».

## Jobs и worker

Долгие операции выполняются не внутри HTTP request, а как durable jobs.

Основные состояния:

```text
queued → running → completed
   │        ├────→ failed
   │        ├────→ cancelled
   │        └────→ interrupted
   └─────────────→ cancelled
```

`JobService` владеет state transitions. Worker атомарно claim'ит queued job и передаёт его handler из registry.

Resource locks находятся в SQLite. Например, passive capture и active discovery не могут одновременно захватить один и тот же `interface:<name>`.

При рестарте worker ранее running jobs становятся `interrupted` с `application_restart`; queued jobs остаются в очереди. Автоматического resume/retry произвольного scanner process нет.

## Persistence

SQLite — локальный system of record. Используются SQLAlchemy 2 и Alembic.

Рабочие connection settings включают:

- foreign keys;
- WAL;
- busy timeout;
- короткие транзакции;
- `synchronous=FULL` по умолчанию для appliance deployment.

Scanner/capture не выполняется внутри открытой SQL transaction.

В SQLite лежат audits, jobs/events, locks/workers, confirmed scopes, inventory, protocol observations, findings, users/sessions, reports и metadata evidence artifacts.

## Evidence store

Большие и сырые данные не кладутся BLOB'ами в основные таблицы:

- PCAP;
- Nmap XML;
- raw stdout/stderr provider'ов;
- passive result JSON;
- HTML/JSON reports.

Файл создаётся под контролируемым evidence root, записывается через temporary path, flush/fsync и atomic rename, затем получает SHA-256 и metadata row в SQLite.

Клиент API не выбирает filesystem path.

## Inventory и correlation

`InventoryService` хранит assets, addresses, names, services и evidence provenance.

Корреляция identity идёт консервативно: точный MAC имеет приоритет, затем точный IP. Если MAC identity и IP identity конфликтуют, данные не склеиваются молча.

Hostnames из DHCP, PTR, mDNS, LLMNR, NBNS и Nmap могут сосуществовать. Более поздний источник не стирает предыдущий.

Device/OS classification остаётся hint с confidence, а не подтверждённым фактом.

## Protocol audits

`protocol_audits/` — registry-driven слой проверок найденных сервисов.

Модуль определяет:

- service predicate;
- required tool;
- safety class;
- argv-only command builder;
- parser;
- timeout/resource budget.

Сейчас используются SSH, TLS, HTTP, DNS, SMB, SNMP и LDAP providers. Они запускаются только для inventory addresses внутри confirmed scope.

NSE, brute-force и credential guessing не являются частью default path.

## Findings

Findings engine не запускает сканеры и не парсит raw stdout.

Он читает normalized observations, inventory и passive-result artifacts и применяет versioned rules. Finding содержит severity, confidence, rationale, recommendation и evidence links.

`suppressed` и `accepted_risk` сохраняются при re-evaluation; изменения состояния пишутся в отдельную историю.

## Reporting

Report generation также не обращается к сети. Он собирает persisted state в versioned `audit-report` model и создаёт self-contained HTML и JSON artifacts.

Raw provider output не встраивается целиком в основной отчёт: используются evidence references и hashes.

## Auth

Локальные роли — `auditor` и `viewer`.

Session cookie содержит случайный token; SQLite хранит его SHA-256 digest. Mutating operational routes требуют `auditor`. Viewer может читать результаты, но не запускать/отменять работу.

Health/readiness и login остаются публичными, чтобы appliance мог показать состояние до входа.

## Privilege boundary

Production process model:

```text
unprivileged wirescope-api
unprivileged wirescope-worker
          │
          ▼
/usr/bin/dumpcap
root:wireshark 0750
cap_net_admin,cap_net_raw=eip
```

Python backend не получает `CAP_NET_RAW`/`CAP_NET_ADMIN`.

Nmap не повышается автоматически. При отсутствии raw-socket privileges provider использует допустимый fallback и фиксирует пропущенные возможности.

Внешние инструменты запускаются argv-массивами; `shell=True` не используется.

## Deployment

По умолчанию application и appliance installer слушают `127.0.0.1:8000`.

Для локального kiosk этого достаточно. Для LAN предпочтительная схема:

```text
browser → HTTPS 443 → Caddy/nginx → 127.0.0.1:8000
```

Прямой `0.0.0.0` требует явного `--bind-host 0.0.0.0` и должен сопровождаться TLS или осознанной firewall policy.

## Что пока остаётся

К заметному техническому долгу относятся:

- frontend всё ещё использует compatibility `/api/*` и будет переведён на `/api/v1` отдельно;
- response-generated URLs пока также могут возвращать `/api/*`;
- PDF export не реализован;
- нет отдельной security audit-log таблицы;
- нет policy-driven удаления завершённых audits/evidence;
- terminal jobs не имеют автоматического retry;
- tshark compatibility нужно проверять на пакетных версиях поддерживаемых дистрибутивов.
