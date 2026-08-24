# WireScope

**Русский** · [English](README.en.md)

WireScope — автономный сетевой аудитор для Linux. Его можно поставить на отдельный ПК, ноутбук, сервер, виртуальную машину или ARM64-устройство и использовать как переносной прибор для разбора незнакомого сетевого сегмента.

Рабочая логика простая: WireScope сначала наблюдает сеть пассивно, затем оператор явно подтверждает разрешённый scope для активной проверки. После этого система строит inventory, запускает подходящие проверки сервисов, формирует findings и собирает отчёт. Достижимая с хоста сеть сама по себе не считается разрешённой для сканирования.

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
протокольные проверки
        ↓
findings + evidence
        ↓
HTML / JSON / Markdown отчёт
```

Есть отдельный режим **«Прослушивание»** для записи PCAP: выбирается интерфейс, при необходимости BPF/tcpdump-фильтр, время и максимальный размер файла.

## Что умеет WireScope

### Пассивный анализ

`dumpcap` выполняет ограниченный захват, после чего PCAP один раз разбирается через `tshark -T ek`. Нормализованные packet records дальше обрабатываются сенсорами внутри Python-процесса.

Поддерживаются Ethernet/MAC, 802.1Q/QinQ, ARP, DHCPv4/v6, LLDP, CDP, STP, IPv6 RA/ND, mDNS, LLMNR, NBNS и SSDP.

WireScope отделяет наблюдения от предположений. ARP-адрес не считается доказательством маски сети, а untagged traffic не получает выдуманный VLAN ID.

### Активное обнаружение

Nmap запускается только внутри подтверждённого scope. Произвольные Nmap flags через API не принимаются.

Профили `discovery`, `standard` и `deep` описаны декларативно в `config/active_profiles.json`. Формат ограничен намеренно: можно менять разрешённые параметры профиля, но нельзя подсунуть `-sC`, `--script vuln` или произвольную командную строку.

### Inventory и корреляция

Passive и active observations сходятся в одном inventory. Базовый приоритет идентичности — MAC, затем IP. При конфликте WireScope сохраняет `identity_conflict`, а не молча склеивает два устройства. Hostname сам по себе основанием для merge не является.

Для assets рассчитывается device-class hint с confidence и источниками сигнала:

- `server-like`;
- `workstation-like`;
- `network-device-like`;
- `printer-like`;
- `iot-like`;
- `unknown`.

Это inventory hint, а не security finding.

### Протокольные проверки

После discovery запускаются только модули, подходящие найденным сервисам:

- SSH — `ssh-audit`;
- TLS — `openssl s_client`;
- HTTP/HTTPS — `curl`;
- SMB — `smbclient`;
- DNS — `dig`;
- SNMP — консервативный SNMPv3 noAuth probe;
- LDAP — anonymous base DSE через `ldapsearch`.

Пароли и community strings не перебираются. `testssl.sh`, Nikto и Nuclei остаются `never-default`.

### Findings, evidence и отчёты

Protocol modules сохраняют observations. Отдельный rule engine строит findings поверх нормализованных фактов — scanner output и выводы не смешиваются.

Finding содержит severity, confidence, asset/service, rationale, рекомендацию и ссылки на evidence. Evidence доступно из GUI; текстовые/JSON/XML артефакты можно посмотреть в сыром виде.

Отчёты строятся из сохранённых данных без повторного сканирования:

- self-contained HTML;
- JSON `audit-report` v1;
- Markdown.

PDF не входит в обязательный объём v1.0.

## Обзор и эксплуатация

GUI показывает общий pipeline:

```text
passive → discovery → protocol → findings → report
```

Панель **«Обзор»** позволяет посмотреть:

- количество assets/services;
- findings по severity;
- device classes;
- passive/active correlation;
- самые частые открытые сервисы;
- доступность внешних инструментов;
- фактически загруженные scan profiles;
- diff между двумя аудитами;
- evidence по findings.

Для auditor дополнительно доступна вкладка **«Эксплуатация»**:

- SQLite/migration/worker/core-tool health;
- свободное место и размер evidence store;
- retention policy и preview очистки;
- operational audit log;
- retry failed/interrupted/cancelled stage;
- выгрузка diagnostics JSON.

## Recovery и lifecycle

Если worker перезапустился во время job, текущая job становится `interrupted`, а stale resource locks освобождаются. Оператор может повторить конкретный terminal stage. Retry создаёт **новую** durable job с теми же параметрами; старая история не переписывается.

Retention консервативный. По умолчанию кандидаты:

- temporary artifacts — 24 часа;
- debug — 7 дней;
- PCAP — 30 дней;
- Nmap XML / protocol raw evidence — 90 дней.

Raw evidence не удаляется неожиданно в фоне: auditor сначала видит preview, затем явно подтверждает cleanup. Normalized inventory, findings и reports автоматически не удаляются.

Backup/restore SQLite + evidence уже входит в appliance CLI.

Подробнее: [docs/OPERATIONS.md](docs/OPERATIONS.md).

## Operational audit log

WireScope отдельно хранит журнал значимых действий оператора: login/logout/password change, запуск stages, cancel/retry, network changes, finding changes, report generation и maintenance cleanup.

В журнал не копируются passwords, request body, session token/cookie или provider stdout.

## Архитектура

WireScope — modular monolith. API и worker работают отдельными процессами, но используют одну локальную модель состояния.

```text
browser / kiosk
      │
      ▼
FastAPI
      │
      ├── backend/routers/
      ├── auth / network / scope
      ├── audits / durable jobs
      ├── inventory / correlations
      ├── findings / evidence / reports
      ├── diagnostics / lifecycle / audit log
      │
      ▼
SQLite + evidence store
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

`backend/app.py` — composition root. HTTP routes разнесены по предметным router-модулям.

SQLite работает в WAL mode. Нормализованные данные и metadata артефактов лежат в БД; PCAP, Nmap XML, raw provider evidence и reports хранятся в evidence store с UUID, размером и SHA-256.

Подробнее: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## API

Канонический API — `/api/v1/*`. `/api/*` пока сохранён как скрытый compatibility alias.

Кроме audit/job endpoints есть:

```text
GET  /api/v1/capabilities
GET  /api/v1/scan-profiles
GET  /api/v1/audits/{id}/dashboard
GET  /api/v1/audits/{id}/correlations
GET  /api/v1/audits/{id}/diff?against={old_id}
GET  /api/v1/audits/{id}/findings/{finding_id}/evidence
POST /api/v1/jobs/{job_id}/retry
GET  /api/v1/diagnostics
GET  /api/v1/audit-log
GET  /api/v1/maintenance/status
POST /api/v1/maintenance/cleanup
```

Подробнее: [docs/API.md](docs/API.md).

## Веб-интерфейс и bind

Обычная appliance-установка WireScope **слушает `0.0.0.0:8000`**. Это намеренная модель: GUI должен быть доступен через любой настроенный Ethernet/Wi‑Fi интерфейс устройства.

Локальный kiosk открывает `http://127.0.0.1:8000/`, потому что работает на том же хосте.

Если конкретному deployment нужен другой режим, можно явно использовать firewall, `--bind-host 127.0.0.1`, reverse proxy или TLS.

## Модель привилегий

`wirescope-api` и `wirescope-worker` не запускаются от root. Packet-capture privileges получает только `/usr/bin/dumpcap`.

Nmap дополнительных capabilities от WireScope не получает. При отсутствии raw sockets provider использует доступные непривилегированные fallbacks.

## Быстрая установка

```bash
git clone git@github.com:kmvkos/wirescope.git
cd wirescope
git checkout milestone-8-appliance
cd ..
sudo mv wirescope /opt/wirescope
cd /opt/wirescope

sudo ./packaging/install.sh \
  --generate-admin-password \
  --with-kiosk \
  --enable-kiosk
```

Обычный install/upgrade path использует `0.0.0.0` автоматически.

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

GitHub Actions выполняет `compileall` и default pytest suite. `network` и `live_pi` tests остаются opt-in.

## Где сейчас финиш

Следующий формальный рубеж — **WireScope v1.0 RC1**. Он определяется не количеством новых scanners, а release gate: install/upgrade, persistence, полный audit workflow, recovery, retention, operational log, diagnostics, backup и живой smoke-test на установленном appliance.

Полный checklist: [docs/RELEASE_READINESS.md](docs/RELEASE_READINESS.md).

До прохождения живого smoke-test на установленной VM текущий код остаётся development candidate, даже если CI зелёный. После успешного smoke-test можно ставить tag `v1.0.0-rc1`.

## Документация

| Документ | Что внутри |
| --- | --- |
| [API](docs/API.md) | `/api/v1`, jobs, evidence, diagnostics, maintenance |
| [Установка](docs/INSTALLATION.md) | install, kiosk, bind, TLS, upgrade/rollback |
| [Архитектура](docs/ARCHITECTURE.md) | modules, data flow, jobs, persistence |
| [Эксплуатация](docs/OPERATIONS.md) | diagnostics, recovery, retention, backup/restore |
| [Готовность v1](docs/RELEASE_READINESS.md) | обязательный RC1 release gate |
| [Модель сканирования](docs/SCANNING_MODEL.md) | scope, profiles, inventory, protocol audits |
| [Модель безопасности](docs/SECURITY_MODEL.md) | trust boundaries, auth, evidence, privileges |
| [Findings](docs/FINDINGS_MODEL.md) | rules, severity/confidence, state model |
| [Отчёты](docs/REPORTING_MODEL.md) | `audit-report` v1, HTML/JSON/Markdown |
| [GUI](docs/GUI_MODEL.md) | wizard, dashboard, diff, evidence |
| [Разработка](docs/DEVELOPMENT.md) | local run, migrations, tests |
| [Runbook](docs/RUNBOOK.md) | operational troubleshooting |

## Post-1.0 roadmap

После RC1/1.0 можно развивать функциональность без сдвига финишной черты первой версии: дополнительные protocol modules, PDF, topology graph, CVE enrichment, scheduled audits, deeper historical identity correlation и дальнейшая декомпозиция frontend.
