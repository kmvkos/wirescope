# Архитектура WireScope

**Русский** · [English](en/ARCHITECTURE.md)

Этот документ описывает то, как WireScope устроен **сейчас**. История перехода от прототипа к текущей схеме вынесена в [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md).

## Общая идея

WireScope — локальный сетевой аудитор. Он рассчитан на один Linux-хост или ВМ и поэтому намеренно не тянет за собой Redis, Celery, PostgreSQL и отдельные микросервисы.

Основная схема такая:

```text
браузер / локальный Chromium kiosk
                │
                │ HTTP + session cookie
                ▼
          FastAPI backend
                │
       ┌────────┼─────────────┐
       │        │             │
      auth   audits/jobs   read APIs
                │
                ▼
             SQLite
                ▲
                │
        wirescope-worker
                │
   ┌────────────┼───────────────────────────┐
   │            │           │               │
passive      active      protocol        findings /
capture      discovery    audits          reports
   │            │           │
   ▼            ▼           ▼
dumpcap/      Nmap       ssh-audit, openssl,
tshark                  curl, dig, smbclient,
                         snmpget, ldapsearch
                │
                ▼
          evidence store
```

Это **модульный монолит**: границы проходят по Python-модулям, сервисам и моделям данных, а не по сети.

API и worker разделены на два процесса. Они работают с одной SQLite-базой и одним контролируемым каталогом evidence. GUI — третий, полностью независимый клиент: обычный браузер или Chromium в kiosk-режиме.

## Основные правила архитектуры

В проекте есть несколько принципов, от которых зависит большая часть реализации.

1. **Наблюдение и вывод — разные вещи.** Сенсор или scanner сначала сохраняет факт. Assessment и finding уже интерпретируют этот факт.
2. **Долгие операции — только через durable jobs.** Перезапуск браузера не должен убивать Nmap или захват трафика.
3. **Scope проверяется сервером.** Увиденный адрес или маршрут сам по себе не становится разрешением на сканирование.
4. **Внешние инструменты запускаются без shell.** Команды строятся как argv-массивы; `shell=True` на этом пути не используется.
5. **Исходные данные отделены от нормализованных.** PCAP, XML и stdout/stderr лежат в evidence store, а не большими BLOB в SQLite.
6. **Backend и worker непривилегированные.** Packet-capture capabilities принадлежат `dumpcap`, а не Python-процессу.
7. **Ошибка инструмента не означает отсутствие протокола.** `tool_missing`, timeout или parser error сохраняются как ошибка/неполный результат, а не превращаются в `detected=false`.
8. **Один appliance — одна локальная база.** SQLite здесь не компромисс «на первое время», а осознанный выбор для автономного устройства.

## Каталоги и ответственность модулей

### `backend/`

`backend/app.py` собирает FastAPI-приложение, зависимости и HTTP-маршруты. Сейчас файл всё ещё крупный и содержит значительную часть route wiring напрямую; отдельный слой API routers пока не выделен.

Backend:

- проверяет сессию и роль;
- валидирует входные параметры;
- создаёт audits и jobs;
- читает inventory/findings/reports;
- отдаёт frontend;
- публикует health/readiness;
- через контролируемый `NetworkService` обслуживает сетевые настройки хоста.

Backend **не владеет временем жизни job**. После enqueue задача существует независимо от HTTP-запроса и браузера.

### `config/`

`config/settings.py` — единая точка runtime-настроек. Отсюда берутся пути, лимиты захвата, concurrency, Nmap timeouts, scope caps, имена внешних binary, cookie/TLS параметры и прочая политика.

Без appliance installer приложение само по себе по умолчанию использует `127.0.0.1:8000`. У installer CLI сейчас отдельный default `--bind-host 0.0.0.0`, поэтому production-команды в документации задают bind явно.

### `engine/`

Это сетевой и пассивный core без привязки к HTTP.

Ключевые файлы:

- `environment.py` — hostname, адреса, маршруты, DNS и общая информация о хосте;
- `interfaces.py` — discovery и policy-проверка интерфейсов;
- `network.py` / `segment.py` — сетевой контекст и изменение конфигурации через appliance boundary;
- `routes.py` — проверка реального маршрута до активных targets;
- `scope.py` — canonical scope, caps и запреты;
- `active_profiles.py` — Discovery / Standard / Deep;
- `passive.py` — pipeline захвата и разбора PCAP;
- `assessment.py` — интерпретация пассивных наблюдений.

### `providers/`

Здесь находятся адаптеры к внешним программам и общий runner.

Важный принцип: provider отвечает за запуск и получение исходного результата, но не должен решать, является ли результат security finding.

Например, Nmap provider возвращает нормализованные hosts/services и сохраняет XML; rule engine позже решает, что из данных действительно заслуживает finding.

### `sensors/` и `parsers/`

`tshark` декодирует PCAP один раз в line-oriented EK-поток. Parser превращает его в нормализованные packet records, после чего пассивные сенсоры работают в Python и не запускают дополнительные subprocess.

Пассивные сенсоры сейчас покрывают:

- Ethernet/source MAC;
- VLAN/QinQ;
- ARP;
- LLDP/CDP;
- STP;
- DHCPv4/DHCPv6;
- IPv6 RA/NS/NA;
- mDNS/LLMNR/NBNS;
- SSDP.

### `jobs/`

Job subsystem — фактический orchestration layer WireScope.

Сейчас зарегистрированы handlers для:

- `passive_discovery`;
- `packet_capture`;
- `active_discovery`;
- `protocol_audit`;
- `findings_evaluation`;
- `report_generation`.

`JobService` — единственный доменный слой, который должен менять состояние audit/job. `JobWorker` atomically claim'ит очередь и передаёт job подходящему handler через registry.

Нет центрального `if job.type == ... elif ...` в worker: новые handlers регистрируются отдельно.

### `persistence/`

SQLAlchemy 2 + Alembic. Production schema создаётся migrations, а не `Base.metadata.create_all()`.

SQLite соединения используют:

- WAL;
- foreign keys;
- configurable busy timeout;
- `synchronous=FULL` по умолчанию;
- короткие транзакции.

Scanner или packet capture никогда не должен выполняться внутри открытой DB-транзакции.

### `storage/`

`EvidenceStore` отвечает за файлы, которые не стоит класть в SQLite.

Запись идёт через временный файл, `fsync`, atomic rename и SHA-256. В БД сохраняются metadata, тип артефакта, размер, hash, schema/version и внутренний relative path.

Клиент API не может передать произвольный filesystem path для evidence.

### `inventory/`

Inventory хранит assets, addresses, names, services и provenance.

Корреляция детерминированная:

1. точное совпадение MAC;
2. затем точное совпадение IP.

Если MAC-identity и IP-identity противоречат друг другу, WireScope не склеивает два объекта молча. Конфликт сохраняется как наблюдение.

Hostname provenance сохраняется: PTR, DHCP, mDNS, LLMNR, NBNS и Nmap не перетирают друг друга как «последняя истина».

### `protocol_audits/`

Протокольные проверки организованы как registry модулей.

Каждый модуль описывает:

- service predicates;
- требуемый binary;
- safety class;
- argv builder;
- parser;
- timeout;
- типы нормализованных observations.

Текущие модули: SSH, TLS, HTTP, DNS, SMB, SNMP, LDAP.

Orchestrator запускает модуль только если service из inventory подходит по predicate и выбранный адрес остаётся внутри подтверждённого scope.

### `findings/`

Rule engine не запускает scanners и не парсит raw stdout. Он читает:

- `protocol_observations`;
- inventory services;
- сохранённые passive-result artifacts.

Finding содержит rule/version, severity, confidence, affected asset/service, rationale, recommendation и evidence links.

Состояния: `open`, `suppressed`, `accepted_risk`. История изменений хранится отдельно.

### `reports/`

Reporting строит версионированное представление `audit-report` v1 из уже сохранённых данных.

Генератор делает HTML и JSON, записывает их в evidence store и добавляет запись в историю reports. Никаких повторных сетевых проверок при генерации отчёта нет.

### `auth/`

Локальные пользователи живут в SQLite.

Роли:

- `auditor` — read/write;
- `viewer` — read-only для operational workflow.

Session token случайный. В cookie хранится сам token, в SQLite — только SHA-256 digest. Cookie: HttpOnly, `SameSite=strict`; `Secure` включается при TLS/trusted reverse proxy.

### `frontend/`

Frontend остаётся на vanilla HTML/CSS/JavaScript.

Это уже не «страница с несколькими кнопками»: `app.js` обслуживает wizard аудита, job polling, inventory, findings, report preview, сетевые настройки, смену пароля и listen/record flow. Но отдельный frontend framework пока не нужен для сборки или runtime.

Базовый kiosk viewport — 480×320. При ширине от 900px интерфейс становится плотнее и удобнее для ноутбука/desktop.

### `appliance/` и `packaging/`

Это слой превращения Python-проекта в готовый Linux appliance.

Здесь находятся:

- distro/architecture detection;
- package mapping для apt/dnf/yum/zypper;
- installer;
- systemd unit generation;
- dumpcap capability setup/verification;
- kiosk;
- backup/restore;
- dependency inventory;
- TLS helper;
- network control helper;
- checksums/release helpers.

Installer запускается из Git checkout. Runtime-данные при system install находятся в `/var/lib/wirescope`, конфигурация — в `/etc/wirescope`.

## Пассивный pipeline

```text
validated interface
        ↓
dumpcap: bounded capture
        ↓
temporary PCAP
        ↓
tshark -T ek -l -n
        ↓
line-oriented decode
        ↓
PacketRecord
        ↓
passive sensors
        ↓
SensorResult[]
        ↓
assessment
```

Для обычного live passive audit это два subprocess: один `dumpcap` и один `tshark`. Число сенсоров не увеличивает число tshark-процессов.

### `SensorResult`

Каждый сенсор возвращает:

- `name`;
- `status`;
- `hits`;
- observations;
- summary;
- warnings;
- structured errors;
- compatibility-флаг `detected`.

Статусы:

- `absent` — разбор прошёл нормально, совпадений нет;
- `detected` — есть нормальные observations;
- `partial` — данные есть, но часть анализа завершилась с ошибкой;
- `error` — нельзя надёжно сказать, присутствовал протокол или нет.

Parser error поэтому не превращается в `absent`.

## Модель confidence

Assessment и findings используют уровни:

- `confirmed`;
- `high`;
- `medium`;
- `low`;
- `hint`;
- `unknown`.

`confirmed` используется осторожно. Например, LLDP advertisement — хороший прямой факт, а предполагаемый тип устройства по набору сервисов остаётся heuristic hint.

## Active discovery

Active discovery имеет отдельную safety boundary:

```text
observed network data
        ≠
authorized scope
```

Перед Nmap backend:

1. canonicalize'ит targets через `ipaddress`;
2. проверяет size limits;
3. запрещает unspecified/multicast ranges;
4. валидирует интерфейс;
5. делает `ip route get` для целей;
6. проверяет source address и route device;
7. сохраняет immutable confirmed-scope snapshot;
8. worker повторно проверяет snapshot перед запуском provider.

Подробнее: [SCANNING_MODEL.md](SCANNING_MODEL.md).

## Jobs и восстановление после перезапуска

Состояния job:

```text
queued  → running
queued  → cancelled
running → completed | failed | cancelled | interrupted
```

Terminal state обратно в `running` не переходит.

Если worker умер во время выполнения, при следующем startup оставшиеся `running` jobs становятся `interrupted` с кодом `application_restart`. Они не продолжаются «с середины» и не retry'ятся автоматически.

`queued` jobs сохраняются и могут быть взяты новым worker.

Cancellation running-job сначала сохраняется в БД, затем worker-side monitor передаёт cooperative cancellation token в handler/ToolRunner, который завершает subprocess group.

### Resource locks

Locks лежат в SQLite, поэтому ограничения работают между worker threads, а не только внутри одного Python-объекта.

Примеры:

- packet capture и active discovery используют `interface:<name>`;
- глобальное число capture/Nmap jobs ограничивается resource groups;
- protocol audit сериализуется на уровне audit/group;
- findings и reports сериализуются на уровне audit, но интерфейсный lock им не нужен.

По умолчанию worker concurrency и основные network job limits равны 1 — это консервативный режим для небольшого appliance.

## Persistence

Основные таблицы:

- `audits`;
- `jobs`;
- `job_events`;
- `artifacts`;
- `resource_locks`;
- `workers`;
- `confirmed_scopes`;
- `assets`, `asset_addresses`, `asset_names`, `services`, `asset_observations`;
- `protocol_observations`;
- `findings`, `finding_state_events`;
- `reports`;
- `users`, `sessions`.

Raw scanner output не используется как event log. `job_events` — это lifecycle/progress события, а исходный stdout/stderr регистрируется как evidence.

## Привилегии

Production boundary должна выглядеть так:

```text
wirescope-api        wirescope-worker
   uid=wirescope        uid=wirescope
        │                    │
        └────────┬───────────┘
                 │
                 ▼
             dumpcap
 root:wireshark 0750 + file capabilities
```

Python interpreter, Uvicorn и worker не получают `CAP_NET_RAW`/`CAP_NET_ADMIN`.

Для Nmap действует отдельное правило: provider использует raw-socket возможности только если они уже доступны процессу. Если нет — применяется TCP connect fallback, а UDP/OS detection и другие требующие privilege функции пропускаются и отражаются в результате.

В user-systemd режиме доступ к группе `wireshark` восстанавливается через `sg wireshark`; в system units используется `SupplementaryGroups=wireshark`.

## Kiosk и процессные границы

Kiosk не является частью backend lifecycle.

```text
systemd
├── wirescope-api
├── wirescope-worker
└── wirescope-kiosk   (optional)
```

Перезапуск Chromium не отменяет job. Ошибка kiosk может вернуть `getty@tty1`, не останавливая API/worker.

На VMware kiosk использует Xorg/xinit. На подходящем железе предпочтителен Cage/Wayland; fallback — xinit.

## Что пока остаётся техническим долгом

На текущей ветке:

- PDF export не реализован;
- отдельной security audit-log таблицы нет;
- policy-driven удаление завершённых audits/evidence не реализовано;
- manual/automatic retry terminal jobs отсутствует;
- `backend/app.py` остаётся крупным и со временем потребует разбиения route layer;
- tshark compatibility нужно проверять на версиях, поставляемых конкретными дистрибутивами;
- hardware-specific Raspberry Pi kiosk smoke tests остаются optional.

Это не скрытые TODO: они перечислены в [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md).
