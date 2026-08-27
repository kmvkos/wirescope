# WireScope

**Русский** · [English](README.en.md)

WireScope — автономный сетевой аудитор для Linux. Его можно установить на отдельный ПК, ноутбук, сервер, виртуальную машину или ARM64-устройство и использовать как переносной прибор для разбора незнакомого сетевого сегмента.

WireScope сначала наблюдает сеть пассивно, затем оператор явно подтверждает разрешённый active scope. После этого система строит inventory, выполняет active discovery и protocol audits, формирует findings, анализирует сохранённый PCAP, строит topology и позволяет сопоставить результаты разных источников. Достижимая с хоста сеть сама по себе не считается разрешённой для сканирования.

Поддерживаются Debian/Ubuntu, Fedora/RHEL/Rocky и openSUSE на `amd64` и `arm64`. Raspberry Pi подходит как одна из аппаратных платформ, но не является обязательным.

## Как проходит работа

```text
подключение к сети
        ↓
состояние хоста и интерфейсов
        ↓
пассивное наблюдение
        ↓
подтверждение оператором active scope
        ↓
Discovery / Standard / Deep
        ↓
inventory + services
        ↓
protocol audits
        ↓
findings + evidence
        ↓
Audit Report

отдельный retained PCAP
        ↓
Traffic Analysis
        ↓
опционально: Network Topology overlay / Корреляция результатов
```

Есть отдельный режим **«Прослушивание»** для сохранения PCAP: выбирается интерфейс, optional BPF/tcpdump filter, время и максимальный размер файла.

## Основные возможности

### Пассивный анализ

`dumpcap` выполняет bounded capture, после чего PCAP разбирается через `tshark`. WireScope извлекает Ethernet/MAC, VLAN/QinQ, ARP, DHCPv4/v6, LLDP, CDP, STP, IPv6 RA/ND, mDNS, LLMNR, NBNS и SSDP observations.

Наблюдения отделены от предположений: ARP не доказывает маску сети, а untagged traffic не получает выдуманный VLAN ID.

### Active discovery

Nmap запускается только внутри operator-confirmed scope. Профили `discovery`, `standard` и `deep` описаны декларативно в `config/active_profiles.json`; arbitrary Nmap command line через API не принимается.

### Inventory

Passive и active observations сходятся в нормализованный inventory. Identity correlation консервативна: MAC/IP используются как evidence, hostname сам по себе не является основанием для merge. При конфликте сохраняется `identity_conflict`.

Для assets рассчитывается device-class hint (`server-like`, `workstation-like`, `network-device-like`, `printer-like`, `iot-like`, `unknown`) с confidence и источниками сигнала. Это inventory hint, а не finding.

### Protocol audits и Findings

После discovery запускаются только подходящие найденным сервисам read-only/diagnostic modules: SSH, TLS, HTTP/HTTPS, SMB, DNS, SNMP и LDAP.

Protocol modules сохраняют observations. Отдельный rule engine строит findings поверх нормализованных фактов. Finding содержит severity, confidence, asset/service, rationale, recommendation и evidence references.

### Audit Report

Audit Report — source-of-truth для результатов самого аудита:

- inventory;
- discovered services;
- protocol-audit results;
- findings;
- rationale/recommendations;
- audit evidence.

Доступны self-contained HTML, canonical JSON `audit-report` v1 и Markdown. Report строится из persisted data без повторного сканирования.

### PCAP Traffic Analysis

Retained PCAP анализируется отдельной durable job без нового capture и без обращения к сети.

Traffic Analysis отвечает за **то, что наблюдалось в конкретном capture window**:

- duration/frames/bytes/rates;
- top talkers и communications graph;
- TCP health;
- DNS latency/errors;
- ARP/DHCP/ICMP diagnostics;
- broadcast/multicast contributors;
- TLS/HTTP/QUIC/SMB metadata без payload decryption;
- ACK RTT summaries;
- сравнение сохранённых анализов.

Canonical результат — `traffic-analysis` JSON. Последний PCAP автоматически не подмешивается ни в topology, ни в другие результаты.

### Network Topology

WireScope строит explainable topology из persisted evidence. Доступны Structural, L2, L3, Traffic, All Evidence, VLAN focus и historical compare.

Источники включают inventory, ARP/ND, routes, DHCP, LLDP/CDP, STP, VLAN/QinQ, active discovery, явно выбранный Traffic Analysis и optional read-only SNMP/SSH enrichment.

`coverage` / claimability показывает `sufficient / partial / missing`. Если evidence недостаточно, WireScope сообщает ограничение вместо того, чтобы угадывать gateway, physical link, VLAN или Wi-Fi attachment.

Management-discovered topology не расширяет active scope.

Подробности: [docs/TOPOLOGY_MODEL.md](docs/TOPOLOGY_MODEL.md).

### Корреляция результатов — v1.3

Функция **«Корреляция результатов»** (`Correlated Assessment`) сопоставляет уже сохранённый audit с явно выбранным Traffic Analysis и topology.

Она показывает только межисточниковые связи, например:

- какие inventory assets exact-сопоставились с traffic;
- какие найденные service ports наблюдались в выбранном capture;
- какие findings относятся к asset/service, видимым в traffic;
- какие traffic endpoints не сопоставились с inventory;
- какие exact-correlated internal assets общались с globally routable endpoints;
- согласуются ли gateway/DHCP/DNS observations между независимыми sources.

Это **не второй Audit Report и не второй Traffic Analysis**. Correlated Assessment не должен копировать полные source reports; факт источника показывается только когда он нужен для объяснения связи.

Функция полностью offline: scanner не запускается, PCAP повторно не читается, network I/O не выполняется.

Для backward compatibility внутренний job/schema/API пока называются `global_analysis`, `global-analysis` и `/global-analysis`.

Подробности: [docs/GLOBAL_ANALYSIS_MODEL.md](docs/GLOBAL_ANALYSIS_MODEL.md).

## Web/kiosk и эксплуатация

GUI показывает durable pipeline и сохранённые audits. Для auditor доступны diagnostics, operational audit log, retention preview/cleanup, job recovery и backup/restore. Viewer может читать разрешённые persisted results без запуска mutating jobs.

Ключевые runtime endpoints:

```text
GET /api/v1/health
GET /api/v1/ready
GET /api/v1/capabilities
GET /api/v1/diagnostics
```

Обычная appliance-установка слушает `0.0.0.0:8000`; kiosk открывает `http://127.0.0.1:8000/`. Firewall, loopback-only bind, reverse proxy и TLS остаются deployment controls.

## Recovery и lifecycle

Если worker перезапускается во время job, running job становится `interrupted`, stale resource locks освобождаются. Explicit retry создаёт новую durable job и не переписывает историю.

Credentialed `snmp_topology` и `ssh_topology` не переиспользуют consume-once credentials. Retention консервативный: raw evidence удаляется только через explicit preview/confirm cleanup.

Backup/restore SQLite + evidence входит в appliance CLI.

Подробнее: [docs/OPERATIONS.md](docs/OPERATIONS.md).

## Архитектура

WireScope — modular monolith. API и worker работают отдельными процессами, используя одну локальную модель состояния.

```text
browser / kiosk
      │
      ▼
FastAPI /api/v1
      │
      ├── audits / durable jobs
      ├── inventory / findings / reports
      ├── traffic analysis / topology
      ├── correlated assessment
      └── diagnostics / lifecycle
      │
      ▼
SQLite + evidence store
      ▲
      │
worker
      ├── passive / capture
      ├── active discovery
      ├── protocol audits
      ├── traffic analysis
      ├── SNMP/SSH topology enrichment
      ├── correlated assessment
      └── findings / reports
```

`wirescope-api` и `wirescope-worker` работают без root. Packet-capture privileges получает только `dumpcap`. External commands формируются как argv, без `shell=True`.

Подробнее: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Быстрая установка

Репозиторий приватный, поэтому нужен доступ GitHub SSH/token.

```bash
git clone git@github.com:kmvkos/wirescope.git
cd wirescope

# Для воспроизводимого deployment переключитесь на нужный checkpoint/tag.

cd ..
sudo mv wirescope /opt/wirescope
cd /opt/wirescope

sudo ./packaging/install.sh \
  --generate-admin-password \
  --with-kiosk \
  --enable-kiosk
```

Основные пути:

```text
/opt/wirescope       code + .venv
/etc/wirescope       configuration
/var/lib/wirescope   SQLite, runtime, evidence, backups
```

Полная инструкция: [docs/INSTALLATION.md](docs/INSTALLATION.md).

## Разработка и CI

Нужен Python 3.11+.

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/alembic upgrade head
.venv/bin/pytest
```

GitHub Actions выполняет compileall, default pytest suite, browser regression, JavaScript syntax checks для feature UI, wheel build и installed-wheel smoke вне source tree.

## Текущий этап

**v1.3 Correlated Assessment / «Корреляция результатов» завершён и live-проверен.**

Следующий этап — **Product Coherence Review**: пройти по Audit Report, Traffic Analysis, Network Topology, Correlated Assessment и dashboard/operator views, определить source-of-truth для каждого типа данных и убрать повторяющиеся отчётные блоки.

Импорт внешнего PCAP рассматривается как отдельная будущая функция и пока намеренно не специфицирован.

Подробнее: [docs/ROADMAP.md](docs/ROADMAP.md).

## Документация

| Документ | Что внутри |
| --- | --- |
| [API](docs/API.md) | `/api/v1`, jobs, evidence, topology, correlation |
| [Установка](docs/INSTALLATION.md) | install, kiosk, bind, TLS, upgrade/rollback |
| [Архитектура](docs/ARCHITECTURE.md) | modules, data flow, jobs, persistence |
| [Network Topology](docs/TOPOLOGY_MODEL.md) | evidence graph, coverage, L2/L3/VLAN, SNMP/SSH |
| [Корреляция результатов](docs/GLOBAL_ANALYSIS_MODEL.md) | cross-source correlation и границы v1.3 |
| [Эксплуатация](docs/OPERATIONS.md) | diagnostics, recovery, retention, backup/restore |
| [Модель сканирования](docs/SCANNING_MODEL.md) | scope, profiles, inventory, protocol audits |
| [Модель безопасности](docs/SECURITY_MODEL.md) | trust boundaries, auth, evidence, privileges |
| [Findings](docs/FINDINGS_MODEL.md) | rules, severity/confidence, state model |
| [Отчёты](docs/REPORTING_MODEL.md) | `audit-report` v1 и presentation rules |
| [GUI](docs/GUI_MODEL.md) | wizard, dashboard, evidence/operator views |
| [Roadmap](docs/ROADMAP.md) | текущий статус и следующие этапы |
