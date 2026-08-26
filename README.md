# WireScope

**Русский** · [English](README.en.md)

WireScope — автономный сетевой аудитор для Linux. Его можно поставить на отдельный ПК, ноутбук, сервер, виртуальную машину или ARM64-устройство и использовать как переносной прибор для разбора незнакомого сетевого сегмента.

WireScope сначала наблюдает сеть пассивно, затем оператор явно подтверждает разрешённый active scope. После этого система строит inventory, выполняет активное обнаружение и protocol audits, формирует findings, анализирует PCAP, строит topology и собирает отчёт. Достижимая с хоста сеть сама по себе не считается разрешённой для сканирования.

Поддерживаются Debian/Ubuntu, Fedora/RHEL/Rocky и openSUSE на `amd64` и `arm64`. Raspberry Pi подходит как одна из аппаратных платформ, но не является обязательным.

## Как проходит аудит

```text
подключение к сети
        ↓
состояние хоста и интерфейсов
        ↓
пассивный захват
        ↓
ARP / DHCP / VLAN / LLDP / CDP / STP / IPv6 / mDNS / LLMNR / NBNS / SSDP
        ↓
подтверждение оператором разрешённого scope
        ↓
активное обнаружение
        ↓
assets + services
        ↓
protocol audits
        ↓
findings + evidence
        ↓
report / traffic analysis / topology
```

Есть отдельный режим **«Прослушивание»** для сохранения PCAP: выбирается интерфейс, optional BPF/tcpdump filter, время и максимальный размер файла.

## Что умеет WireScope

### Пассивный анализ

`dumpcap` выполняет bounded capture, после чего PCAP один раз разбирается через `tshark -T ek`. Нормализованные packet records обрабатываются сенсорами внутри Python-процесса.

Поддерживаются Ethernet/MAC, 802.1Q/QinQ, ARP, DHCPv4/v6, LLDP, CDP, STP, IPv6 RA/ND, mDNS, LLMNR, NBNS и SSDP.

WireScope отделяет наблюдения от предположений: ARP-адрес не считается доказательством маски сети, а untagged traffic не получает выдуманный VLAN ID.

### Активное обнаружение

Nmap запускается только внутри operator-confirmed scope. Произвольные Nmap flags через API не принимаются.

Профили `discovery`, `standard` и `deep` описаны декларативно в `config/active_profiles.json`. Нельзя передать через API `-sC`, `--script vuln` или arbitrary command line.

### Inventory и корреляция

Passive и active observations сходятся в одном inventory. Базовый приоритет идентичности — MAC, затем IP. При конфликте WireScope сохраняет `identity_conflict`, а не молча склеивает устройства. Hostname сам по себе основанием для merge не является.

Для assets рассчитывается device-class hint с confidence и источниками сигнала:

- `server-like`;
- `workstation-like`;
- `network-device-like`;
- `printer-like`;
- `iot-like`;
- `unknown`.

Это inventory hint, а не security finding.

### PCAP Traffic Analysis

Сохранённый PCAP можно анализировать отдельной durable job без нового захвата.

Traffic Analysis даёт:

- top talkers и communications graph;
- packets/bytes/rate;
- TCP health;
- DNS latency/errors;
- ARP/DHCP/ICMP diagnostics;
- broadcast/multicast contributors;
- TLS/HTTP/QUIC/SMB metadata;
- ACK RTT summaries;
- сравнение двух сохранённых анализов.

Canonical результат — `traffic-analysis` JSON. Communications graph может быть **явно** подключён к Network Topology; последний PCAP автоматически не подмешивается.

### Network Topology

WireScope строит topology как аудитор: сохраняет полный evidence graph, а оператору показывает отдельную structural / infrastructure-first схему.

Основные представления:

- Structural;
- L2;
- L3;
- Traffic;
- All evidence;
- VLAN focus;
- historical topology diff.

Источники включают inventory, ARP/ND, interface routes, DHCP, LLDP/CDP, STP, VLAN/QinQ, active discovery, Traffic Analysis и optional read-only management enrichment через SNMP/SSH.

Topology содержит `coverage` / claimability для `inventory`, `l3`, `l2`, `traffic`, `vlan`, `wifi`, `hypervisor` со статусами:

```text
sufficient
partial
missing
```

Это не «процент изученности сети». Если данных не хватает, WireScope показывает, **какого evidence не хватает**, а не дорисовывает физические связи или VLAN по догадке.

Поддерживаются JSON/SVG/PNG export, subnet regions, zoom/pan/fit, asset/edge details, findings и global retained-audit topology.

Подробности: [docs/TOPOLOGY_MODEL.md](docs/TOPOLOGY_MODEL.md).

### Management-plane enrichment

Для подходящих managed devices topology можно обогащать read-only источниками:

- SNMPv2c/v3: IF/IP/BRIDGE/Q-BRIDGE/LLDP MIB;
- SSH для Linux/OpenWrt-подобных устройств: фиксированный allowlist `ip/bridge/iw`.

SNMP/SSH target обязан находиться внутри confirmed scope. SSH использует strict host-key verification и не принимает arbitrary remote command. Credentials передаются через ephemeral consume-once spool и не сохраняются в topology evidence как plaintext.

Management-discovered subnet расширяет знания о topology, но остаётся `active_scope=false`.

### Протокольные проверки

После discovery запускаются только модули, подходящие найденным сервисам:

- SSH — `ssh-audit`;
- TLS — `openssl s_client`;
- HTTP/HTTPS — `curl`;
- SMB — `smbclient`;
- DNS — `dig`;
- SNMP — консервативный SNMP probe;
- LDAP — anonymous base DSE через `ldapsearch`.

Пароли и community strings автоматически не перебираются. `testssl.sh`, Nikto и Nuclei остаются `never-default`.

### Findings, evidence и отчёты

Protocol modules сохраняют observations. Отдельный rule engine строит findings поверх нормализованных фактов — scanner output и выводы не смешиваются.

Finding содержит severity, confidence, asset/service, rationale, recommendation и ссылки на evidence.

Отчёты строятся из persisted data без повторного сканирования:

- self-contained HTML;
- JSON `audit-report` v1;
- Markdown.

## Обзор и эксплуатация

GUI показывает durable pipeline и сохранённые audits. Для auditor доступны diagnostics, operational audit log, retention preview/cleanup, job recovery и backup/restore.

Ключевые runtime endpoints:

```text
GET /api/v1/health
GET /api/v1/ready
GET /api/v1/capabilities
GET /api/v1/diagnostics
```

## Recovery и lifecycle

Если worker перезапустился во время job, running job становится `interrupted`, а stale resource locks освобождаются. Explicit retry создаёт **новую** durable job; старая история не переписывается.

Credentialed `snmp_topology` и `ssh_topology` не переиспользуют старые одноразовые credentials: enrichment запускается заново со свежими credentials.

Retention консервативный. Raw evidence не удаляется неожиданно в фоне: auditor сначала видит preview и отдельно подтверждает cleanup.

Backup/restore SQLite + evidence входит в appliance CLI.

Подробнее: [docs/OPERATIONS.md](docs/OPERATIONS.md).

## Архитектура

WireScope — modular monolith. API и worker работают отдельными процессами, но используют одну локальную модель состояния.

```text
browser / kiosk
      │
      ▼
FastAPI /api/v1
      │
      ├── audits / durable jobs
      ├── inventory / findings / reports
      ├── traffic analysis / topology
      ├── diagnostics / lifecycle
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
      └── findings / reports
```

`backend/app.py` — composition root. SQLite работает в WAL mode; крупные raw artifacts находятся в evidence store и зарегистрированы UUID/size/SHA-256.

Подробнее: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## API

Канонический API — `/api/v1/*`. `/api/*` пока сохранён как compatibility alias.

Topology endpoints:

```text
GET  /api/v1/audits/{audit_id}/topology
GET  /api/v1/topology/global
GET  /api/v1/audits/{audit_id}/topology/compare?against={baseline}
POST /api/v1/audits/{audit_id}/topology/snmp
POST /api/v1/audits/{audit_id}/topology/ssh
```

Подробнее: [docs/API.md](docs/API.md).

## Веб-интерфейс и bind

Обычная appliance-установка слушает `0.0.0.0:8000`, чтобы GUI был доступен через настроенный интерфейс устройства. Локальный kiosk открывает `http://127.0.0.1:8000/`.

Firewall, loopback-only bind, reverse proxy и TLS остаются deployment controls.

## Модель привилегий

`wirescope-api` и `wirescope-worker` не запускаются от root. Packet-capture privileges получает только `/usr/bin/dumpcap`.

Nmap не повышается самим WireScope. SNMP/SSH enrichment также выполняется unprivileged worker-ом.

## Быстрая установка

Репозиторий приватный, поэтому нужен GitHub SSH key/token.

```bash
git clone git@github.com:kmvkos/wirescope.git
cd wirescope

# Для воспроизводимого deployment переключитесь на нужный release/tag/checkpoint.
# Не используйте старые milestone-ветки из исторических инструкций.

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
/opt/wirescope                  code + .venv
/etc/wirescope                  configuration
/var/lib/wirescope              SQLite, runtime, evidence, backups
/etc/systemd/system             systemd units
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

GitHub Actions выполняет compileall, default pytest suite, Chromium regression, wheel build и smoke install wheel вне source tree.

## Текущий этап

**Network Topology v1.2 завершена.** Structural topology прошла live smoke на обновлённой WireScope VM. SNMP/SSH vendor-specific interoperability будет дополнительно проверяться по мере появления подходящих managed devices и не должна подменяться эвристиками.

Следующий этап — **v1.3 Global Correlation Analysis**: детерминированная корреляция persisted inventory/findings/Traffic Analysis/Network Topology без повторного network I/O.

Подробнее: [docs/ROADMAP.md](docs/ROADMAP.md).

## Документация

| Документ | Что внутри |
| --- | --- |
| [API](docs/API.md) | `/api/v1`, jobs, topology, evidence, diagnostics |
| [Установка](docs/INSTALLATION.md) | install, kiosk, bind, TLS, upgrade/rollback |
| [Архитектура](docs/ARCHITECTURE.md) | modules, data flow, jobs, topology, persistence |
| [Network Topology](docs/TOPOLOGY_MODEL.md) | evidence graph, coverage, L2/L3/VLAN, SNMP/SSH, limits |
| [Эксплуатация](docs/OPERATIONS.md) | diagnostics, recovery, retention, backup/restore |
| [Модель сканирования](docs/SCANNING_MODEL.md) | scope, profiles, inventory, protocol audits |
| [Модель безопасности](docs/SECURITY_MODEL.md) | trust boundaries, auth, evidence, privileges |
| [Findings](docs/FINDINGS_MODEL.md) | rules, severity/confidence, state model |
| [Отчёты](docs/REPORTING_MODEL.md) | `audit-report` v1, HTML/JSON/Markdown |
| [GUI](docs/GUI_MODEL.md) | wizard, dashboard, evidence и operator views |
| [Разработка](docs/DEVELOPMENT.md) | local run, migrations, tests |
| [Runbook](docs/RUNBOOK.md) | operational troubleshooting |
| [Roadmap](docs/ROADMAP.md) | текущий статус и следующие milestones |