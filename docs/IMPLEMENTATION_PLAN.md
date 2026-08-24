# План развития WireScope

**Русский** · [English](en/IMPLEMENTATION_PLAN.md)

Этот файл нужен как история развития проекта и актуальный roadmap. Описание того, **как WireScope работает сейчас**, находится в [ARCHITECTURE.md](ARCHITECTURE.md), [SCANNING_MODEL.md](SCANNING_MODEL.md), [SECURITY_MODEL.md](SECURITY_MODEL.md) и остальных профильных документах.

## Текущее состояние

WireScope прошёл восемь крупных этапов разработки.

```text
M0  стабилизация прототипа              ✓
M1  passive foundation                  ✓
M2  jobs + persistence                  ✓
M3  active discovery                    ✓
M4  service-aware protocol audits       ✓
M5  findings engine                     ✓
M6  reporting                           ✓
M7  operator GUI + local auth           ✓
M8  generic Linux appliance             в активной доработке
```

M0–M7 реализованы и используются текущей веткой. M8 уже содержит большую часть appliance-функциональности — installer, systemd, kiosk, backup/restore, distro detection, network helper и deployment hardening — но этот этап ещё не стоит считать полностью закрытым до cross-distro release verification и оставшихся эксплуатационных работ.

Текущая рабочая ветка:

```text
milestone-8-appliance
```

## Общие правила проекта

Независимо от milestone сохраняются несколько базовых ограничений:

- Python 3.11+;
- generic Linux, `amd64` и `arm64`;
- backend и worker не запускаются от root;
- `shell=True` не используется для provider execution;
- packet capture privileges принадлежат только `dumpcap`;
- активное сканирование выполняется только внутри подтверждённого scope;
- raw evidence отделено от normalized data;
- live-network tests включаются только явно;
- provider/parser failure не трактуется как «протокол отсутствует»;
- новая функциональность должна иметь fixture/unit/API tests;
- изменения runtime behavior должны отражаться в профильной документации.

---

# M0 — Стабилизация прототипа ✓

Первый этап был не про новые возможности, а про превращение раннего прототипа в кодовую базу, которую можно безопасно развивать дальше.

Что было сделано:

- исправлены syntax/import errors;
- убраны очевидные дубли и мёртвый код;
- пути вынесены в централизованные settings;
- добавлен `pyproject.toml`;
- появился воспроизводимый virtualenv/dependency setup;
- добавлены первые API/settings/environment/sensor tests;
- зафиксированы исходная и целевая архитектуры;
- создан roadmap дальнейшей разработки.

Итог M0: проект перестал зависеть от случайного состояния конкретной VM и получил нормальную тестируемую базу.

---

# M1 — Passive foundation ✓

На M1 ранний passive scanner был переработан в ограниченный и воспроизводимый pipeline.

## Tool runner

Появился общий controlled runner:

- argv arrays вместо shell command strings;
- timeout;
- cancellation;
- exit code/stdout/stderr;
- tool version;
- structured error categories;
- bounded output.

## Interface policy

Интерфейс сначала обнаруживается и проходит backend validation. Неизвестный, loopback или policy-denied interface не передаётся напрямую в `dumpcap`.

## Capture/decode pipeline

Текущая схема появилась именно здесь:

```text
interface
   ↓
dumpcap → bounded PCAP
   ↓
tshark -T ek
   ↓
PacketRecord
   ↓
passive sensors
   ↓
assessment
```

Один live passive audit использует один `dumpcap` и один `tshark`, а не отдельный tshark process на каждый protocol sensor.

## Sensors

Были реализованы текущие пассивные сенсоры:

- Ethernet/MAC;
- VLAN/QinQ;
- ARP;
- DHCPv4;
- LLDP/CDP;
- STP;
- IPv6 RA/ND;
- DHCPv6;
- mDNS;
- LLMNR;
- NBNS;
- SSDP.

## Assessment

Появилась confidence model и принцип «не делать вывод сильнее, чем позволяют evidence».

Например:

- ARP `/24` grouping — только hint;
- untagged traffic не получает выдуманный VLAN ID;
- LLDP/CDP PVID не считается 802.1Q tag в capture.

Подробнее: [ARCHITECTURE.md](ARCHITECTURE.md).

---

# M2 — Durable jobs и persistence ✓

M2 убрал process-local job state и сделал audit workflow устойчивым к перезапускам API/browser.

## SQLite

Добавлены SQLAlchemy 2 + Alembic и appliance-local SQLite.

База работает с:

- WAL;
- foreign keys;
- busy timeout;
- короткими транзакциями;
- `synchronous=FULL` по умолчанию.

## Job model

Появились durable states:

```text
queued
running
completed
failed
cancelled
interrupted
```

Job metadata, progress, events, cancellation request и result reference сохраняются в БД.

## API / worker split

Production model стал двухпроцессным:

```text
wirescope-api
wirescope-worker
```

API enqueue'ит работу. Worker claim'ит и выполняет её.

Перезапуск GUI или API больше не является владельцем job lifetime.

## Recovery и locks

Добавлены:

- worker heartbeat;
- supervisor lease;
- restart recovery;
- resource locks;
- atomic artifact storage;
- startup cleanup временных/orphan files.

Running job после падения worker становится `interrupted`, а queued остаётся queued.

---

# M3 — Active discovery ✓

На этом этапе WireScope получил контролируемый Nmap discovery и persistent asset/service inventory.

## Authorized scope

Ключевое изменение: observed network hints были отделены от разрешения сканировать.

Перед Nmap:

- targets canonicalize'ятся через `ipaddress`;
- проверяются caps;
- запрещаются unspecified/multicast targets;
- валидируется interface;
- проверяется реальный route;
- сохраняется immutable confirmed-scope snapshot.

## Nmap provider

Добавлен единый Nmap execution path с XML evidence и normalized parsing.

Профили:

- Discovery;
- Standard;
- Deep.

Raw-socket capabilities не выдаются backend специально ради Nmap. При их отсутствии provider использует TCP connect fallback.

NSE/`-sC`/vuln/brute/exploit/DoS в discovery path не включены.

## Inventory

Появились:

- assets;
- addresses;
- names + provenance;
- services;
- OS/device hints;
- passive/active correlation.

Корреляция идёт по exact MAC, затем exact IP. Конфликт identities не скрывается автоматическим merge.

Подробнее: [SCANNING_MODEL.md](SCANNING_MODEL.md).

---

# M4 — Service-aware protocol audits ✓

После обычной инвентаризации появилась возможность проверять найденные сервисы отдельными специализированными tools.

Текущие modules:

| Protocol | Tool |
| --- | --- |
| SSH | `ssh-audit` |
| TLS | `openssl s_client` |
| HTTP/HTTPS | `curl` |
| DNS | `dig` |
| SMB | `smbclient` |
| SNMP | `snmpget` |
| LDAP | `ldapsearch` |

Каждый module имеет:

- service predicates;
- safety class;
- required binary;
- argv builder;
- parser;
- normalized observations;
- timeout;
- fixtures.

Protocol module не запускается просто потому, что «такой tool установлен». Сначала должен быть соответствующий service в inventory и address внутри authorized scope.

Credential guessing, SNMP community brute force и агрессивные default scanners не добавлялись.

`testssl.sh`, Nikto и Nuclei оставлены как `never-default` stubs.

---

# M5 — Findings engine ✓

M5 отделил security interpretation от scanner/provider output.

```text
observations
     ↓
versioned rules
     ↓
findings
```

Rules читают normalized data и не парсят stdout внешних tools.

Добавлены:

- severity;
- confidence;
- recommendations;
- evidence links;
- deduplication;
- `suppressed`;
- `accepted_risk`;
- state audit trail.

Первые rule families покрывают SSH, TLS, HTTP, SMB, DNS, SNMP, LDAP, insecure management protocols и часть infrastructure observations.

Подробнее: [FINDINGS_MODEL.md](FINDINGS_MODEL.md).

---

# M6 — Reporting ✓

На M6 появился воспроизводимый audit report из persisted state.

Schema:

```text
audit-report v1
```

Exports:

- self-contained HTML;
- normalized JSON.

Report generation не запускает scanners и не читает произвольные filesystem paths.

Добавлены:

- executive summary;
- environment;
- passive assessment;
- scope;
- inventory;
- findings;
- recommendations;
- evidence metadata;
- history;
- `source_hash`.

PDF намеренно не был включён до стабилизации HTML/report contract и до сих пор остаётся не реализован.

Подробнее: [REPORTING_MODEL.md](REPORTING_MODEL.md).

---

# M7 — GUI и local auth ✓

M7 сделал WireScope инструментом, которым оператор может пользоваться без shell.

Основной flow:

```text
login
→ new audit
→ interface/network/scope
→ profile
→ passive/active/protocol jobs
→ summary
→ assets/observations/assessment/findings
→ report
```

Добавлены:

- роли `auditor` и `viewer`;
- local SQLite users;
- session cookies;
- password change;
- role enforcement на API;
- kiosk-friendly 480×320 layout;
- более плотный laptop layout;
- durable polling и recovery после page reload;
- отдельные экраны observations/assessment/findings.

Позже в ту же GUI foundation добавились:

- сетевые настройки appliance;
- **Прослушивание / Listen & Record** с сохранением PCAP;
- BPF filter;
- capture progress и download.

Подробнее: [GUI_MODEL.md](GUI_MODEL.md).

---

# M8 — Generic Linux appliance ◐

M8 — текущий этап. Его задача не добавить ещё один scanner, а превратить уже работающий WireScope в нормально устанавливаемый и обслуживаемый Linux appliance.

## Что уже реализовано

### Generic Linux installer

Installer умеет определять:

- `apt`;
- `dnf`;
- `yum`;
- `zypper`;
- `amd64`;
- `arm64`.

Raspberry Pi-specific OS не требуется.

Поддерживаются system install и `--user-install`.

### Service account и paths

System install использует непривилегированного пользователя `wirescope` и разделяет:

```text
Git checkout      /opt/wirescope        recommended
configuration     /etc/wirescope
mutable data      /var/lib/wirescope
```

### dumpcap least privilege

Installer настраивает `dumpcap`, группу `wireshark` и file capabilities, не выдавая capabilities Python interpreter/backend.

### systemd

Есть отдельные units для:

- API;
- worker;
- optional kiosk.

System install использует `SupplementaryGroups=wireshark`. User units используют `sg wireshark`.

### Kiosk

Автономный режим работает без полноценного desktop environment.

System kiosk:

- занимает `tty1`;
- ждёт API;
- открывает Chromium;
- использует Cage либо Xorg/xinit;
- на VMware выбирает Xorg path;
- не отменяет jobs при restart browser process.

### Local и remote operator modes

Поддерживаются:

- loopback kiosk;
- local browser;
- reverse proxy через Caddy/nginx;
- direct TLS через Uvicorn;
- explicit LAN bind.

### Backup / restore

Есть appliance CLI для backup/restore SQLite и evidence.

### Upgrade

Есть `packaging/upgrade.sh`, повторная установка/upgrade сохраняет рабочие data/config и применяет migrations.

### Host/network support

Добавлены:

- host/distro detection;
- dependency inventory;
- network control helper;
- readiness/verification helpers;
- self-signed TLS helper;
- release checksums;
- proxy/firewall examples.

### Listen / Record

M8-era GUI/runtime также получил отдельный `packet_capture` workflow с promiscuous `dumpcap`, optional BPF filter, duration/filesize limits и сохранением PCAP как evidence.

## Что ещё нужно закрыть для завершения M8

### 1. Cross-distro release verification

Fixture detection уже есть, но перед стабильным release нужны реальные smoke installs минимум на:

- Debian/Ubuntu;
- одной Fedora/RHEL/Rocky системе;
- openSUSE желательно как отдельный verification target;
- `amd64` и хотя бы одном реальном `arm64` host.

Нужно проверить не только installer exit code, но и полный путь:

```text
install
→ migration
→ worker ready
→ login
→ passive fixture/live capture smoke
→ active discovery smoke
→ report
→ reboot
→ recovery
```

### 2. tshark compatibility matrix

Parser fixtures ориентируются на проверенную версию tshark 4.x, но дистрибутивы могут поставлять разные field layouts/versions.

Перед release нужна зафиксированная compatibility matrix и smoke tests для package versions поддерживаемых OS.

### 3. Retention policy

Startup maintenance уже удаляет controlled temp/orphan files, но полноценной policy-driven очистки завершённых audits и зарегистрированных evidence пока нет.

Нужно определить:

- срок хранения audit metadata;
- срок хранения PCAP/raw evidence;
- поведение с reports;
- safe delete transaction;
- operator override/export-before-delete.

### 4. Security audit log

Operational structured logs есть, finding state events есть, job events есть, но отдельной security audit-log таблицы для чувствительных действий пока нет.

Нужно решить, какие действия фиксировать как security events, например:

- login failures;
- password changes/resets;
- network configuration changes;
- scope confirmations;
- finding state changes;
- report exports;
- privileged helper failures.

### 5. Explicit retry workflow

Terminal jobs сейчас не retry'ятся автоматически, что является правильным безопасным default.

Можно добавить **manual retry** как новый job с явной связью с предыдущей попыткой, не меняя terminal state старого job.

### 6. API route decomposition

`backend/app.py` уже стал большим. Runtime architecture от этого не ломается, но дальнейшее развитие будет проще после разбиения маршрутов на routers/domain-facing dependencies.

Это рефакторинг, а не блокирующая функциональная ошибка.

### 7. Optional Raspberry Pi hardware validation

Raspberry Pi больше не является primary platform, но реальный ARM64/Pi kiosk smoke остаётся полезным дополнительным release test:

- display/touch;
- Chromium kiosk;
- dumpcap;
- thermal/resource behavior;
- reboot recovery.

Он не должен превращаться обратно в требование Raspberry Pi OS для всего проекта.

---

# После M8

Следующий milestone пока не зафиксирован как обязательный номер. После стабилизации appliance разумно выбирать новые функции по реальным audit use cases, а не добавлять scanners ради количества.

Кандидаты:

## Расширение protocol coverage

Возможные modules:

- FTP;
- SMTP;
- RDP;
- Redis;
- PostgreSQL;
- MySQL/MariaDB;
- MSSQL;
- MongoDB;
- Elasticsearch;
- MQTT;
- UPnP;
- IPMI;
- NTP;
- TFTP;
- Telnet;
- VNC;
- Docker API;
- Kubernetes API.

Для каждого сначала нужен безопасный observation contract, а уже потом finding rules.

## PDF

PDF имеет смысл добавлять только поверх уже стабильного HTML/report model. PDF renderer не должен становиться новым источником сетевых данных или отдельной truth model.

## Authenticated audits

Сейчас WireScope почти полностью работает без credentials. Если появятся authenticated SSH/LDAP/AD/SMB/API checks, потребуется отдельная credential/security model до реализации provider'ов.

## Better asset identity

Текущая correlation намеренно консервативна. В будущем можно добавить более богатую identity model, но она не должна автоматически merge'ить hosts по слабым heuristic signals.

## Export/API versioning

По мере появления внешних integrations потребуется явное versioning публичных API contracts, а не только report schemas.

---

# Когда задача считается готовой

Для нового runtime behavior ожидаются:

- реализация;
- migration, если меняется schema;
- unit/fixture/API tests;
- понятное failure behavior;
- cancellation/timeout там, где запускаются external tools;
- отсутствие secrets в логах/units;
- обновление соответствующей документации;
- отсутствие случайных live-network tests в default pytest;
- reviewable commit без runtime artifacts.

Главный критерий остаётся простым: WireScope должен делать ровно то, что показывает оператору, и не должен тихо превращать недостаток evidence в уверенный вывод.
