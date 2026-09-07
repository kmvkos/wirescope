# WireScope

**Русский** · [English](README.en.md)

WireScope — автономный сетевой аудитор для Linux. Его можно установить на отдельный ПК, ноутбук, сервер, виртуальную машину или ARM64-устройство, включая Raspberry Pi, и использовать как переносной appliance для анализа незнакомого сетевого сегмента.

WireScope сначала наблюдает сеть пассивно. Активные проверки запускаются только после явного подтверждения оператором разрешённого scope. Достижимость адреса с хоста сама по себе не считается разрешением на сканирование.

Поддерживаемые платформы:

- Debian / Ubuntu / Raspberry Pi OS;
- Fedora / RHEL / Rocky;
- openSUSE;
- `amd64` и `arm64`.

## Что умеет WireScope

Основной рабочий цикл:

```text
подключение к сети
        ↓
пассивное наблюдение
        ↓
подтверждение active scope
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
```

Дополнительно WireScope умеет работать с PCAP:

```text
сохранённый или импортированный PCAP
        ↓
Traffic Analysis
        ↓
Network Topology
        ↓
Correlated Assessment
```

### Passive discovery

`dumpcap` выполняет ограниченный захват, затем `tshark` декодирует PCAP. WireScope извлекает Ethernet/MAC, VLAN/QinQ, ARP, DHCPv4/v6, LLDP, CDP, STP, IPv6 RA/ND, mDNS, LLMNR, NBNS и SSDP observations.

### Active discovery

Nmap запускается только внутри operator-confirmed scope. Есть профили `discovery`, `standard` и `deep`. Произвольная командная строка Nmap через API не принимается.

### Inventory, protocol audits и findings

Passive и active observations сходятся в нормализованный inventory. После discovery запускаются только подходящие read-only/diagnostic проверки для найденных сервисов: SSH, TLS, HTTP/HTTPS, SMB, DNS, SNMP и LDAP.

Protocol modules сохраняют observations, а отдельный rule engine формирует findings с severity, confidence, rationale, recommendation и evidence references.

### Audit Report

Audit Report является source-of-truth для самого аудита:

- inventory;
- discovered services;
- protocol audit results;
- findings;
- rationale и recommendations;
- audit evidence.

Доступны self-contained HTML, canonical JSON `audit-report` v1 и Markdown.

### Traffic Analysis

Traffic Analysis работает с уже сохранённым PCAP и не обращается к сети. Он показывает факты конкретного capture window: объём и скорость трафика, top talkers, communications graph, TCP health, DNS latency/errors, ARP/DHCP/ICMP diagnostics, broadcast/multicast contributors и protocol metadata.

### Manual PCAP import — v1.4

Внешний `.pcap`, `.pcapng` или gzip-wrapped capture можно загрузить вручную через Web UI/API. Import выполняется offline: WireScope не запускает capture, discovery или protocol probes и не расширяет active scope на основании адресов, найденных в импортированном файле.

Импортированный capture после проверки формата, размера и SHA-256 становится обычным persisted `packet_capture`, после чего оператор явно запускает Traffic Analysis и при необходимости Correlated Assessment.

### Network Topology

Topology строится из persisted evidence: inventory, ARP/ND, routes, DHCP, LLDP/CDP, STP, VLAN/QinQ, active discovery, явно выбранного Traffic Analysis и optional SNMP/SSH enrichment.

Если доказательств недостаточно, WireScope показывает `sufficient / partial / missing`, а не придумывает gateway, physical link или VLAN.

### Correlated Assessment

«Корреляция результатов» сопоставляет уже сохранённый audit с явно выбранным Traffic Analysis и topology. Она показывает межисточниковые связи и evidence gaps, а не дублирует Audit Report или Traffic Analysis.

Для backward compatibility внутренние идентификаторы остаются `global_analysis`, `global-analysis` и `/global-analysis`.

## Архитектура и привилегии

WireScope — modular monolith. API и worker работают отдельными непривилегированными процессами поверх SQLite + evidence store.

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
```

Raw packet-capture privileges получает только `/usr/bin/dumpcap` через `cap_net_admin,cap_net_raw`. API и worker от root не запускаются.

Подробнее: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) и [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md).

## Быстрая установка

Репозиторий публичный. Для обычной system install используйте `/opt/wirescope`.

```bash
git clone https://github.com/kmvkos/wirescope.git
sudo mv wirescope /opt/wirescope
cd /opt/wirescope

sudo ./packaging/install.sh \
  --generate-admin-password \
  --with-kiosk \
  --enable-kiosk
```

> System install из `/home/...` намеренно блокируется installer'ом: systemd units используют `ProtectHome=true`. Сначала переместите checkout в `/opt/wirescope`.

Основные пути:

```text
/opt/wirescope       code + .venv
/etc/wirescope       configuration
/var/lib/wirescope   SQLite, runtime, evidence, backups
```

После установки:

```bash
systemctl is-active wirescope-api wirescope-worker
curl -sS http://127.0.0.1:8000/api/v1/health
curl -sS http://127.0.0.1:8000/api/v1/ready
sudo cat /etc/wirescope/initial-admin.txt
```

Username по умолчанию — `auditor`.

Полная инструкция: [docs/INSTALLATION.md](docs/INSTALLATION.md).

## Kiosk

`--with-kiosk --enable-kiosk` устанавливает минимальный локальный display stack с Chromium и Cage либо Xorg/xinit. Полный desktop environment не требуется.

Kiosk открывает `http://127.0.0.1:8000/` на `tty1`. API и worker не зависят от Chromium и продолжают работать при перезапуске kiosk.

## Разработка и CI

Python 3.11+:

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/alembic upgrade head
.venv/bin/pytest
```

GitHub Actions выполняет compileall, default pytest suite, browser regression, JavaScript syntax checks, wheel build и installed-wheel smoke test.

## Текущий релизный этап

Текущая линия — **v1.4 Manual PCAP Import** поверх завершённых v1.1 Traffic Analysis, v1.2 Network Topology и v1.3 Correlated Assessment.

Ключевые документы:

| Документ | Содержание |
| --- | --- |
| [Установка](docs/INSTALLATION.md) | install, kiosk, bind, TLS, upgrade/rollback |
| [API](docs/API.md) | `/api/v1`, jobs, evidence, topology, correlation |
| [Архитектура](docs/ARCHITECTURE.md) | modules, data flow, jobs, persistence |
| [PCAP management](docs/PCAP_MANAGEMENT.md) | retained/imported capture lifecycle |
| [Topology](docs/TOPOLOGY_MODEL.md) | evidence graph, coverage, L2/L3/VLAN |
| [Correlated Assessment](docs/GLOBAL_ANALYSIS_MODEL.md) | cross-source correlation и evidence gaps |
| [Эксплуатация](docs/OPERATIONS.md) | diagnostics, recovery, retention, backup/restore |
| [Roadmap](docs/ROADMAP.md) | история этапов и следующие задачи |
