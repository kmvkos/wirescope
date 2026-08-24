# WireScope

**Русский** · [English](README.en.md)

WireScope — автономный сетевой аудитор для Linux. Его можно поставить на отдельный ПК, ноутбук, сервер, виртуальную машину или ARM64-устройство и использовать как переносной прибор для разбора незнакомого сетевого сегмента.

Рабочая логика простая: WireScope сначала наблюдает сеть пассивно, затем оператор подтверждает разрешённый scope для активной проверки. После этого система строит inventory, запускает подходящие проверки сервисов, формирует findings и собирает отчёт. Достижимая с хоста сеть сама по себе не считается разрешённой для сканирования.

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

## Что уже умеет WireScope

### Пассивный анализ

`dumpcap` выполняет ограниченный захват, после чего PCAP один раз разбирается через `tshark -T ek`. Нормализованные packet records дальше обрабатываются сенсорами внутри Python-процесса.

Поддерживаются Ethernet/MAC, 802.1Q/QinQ, ARP, DHCPv4/v6, LLDP, CDP, STP, IPv6 RA/ND, mDNS, LLMNR, NBNS и SSDP.

WireScope отделяет наблюдения от предположений. Например, ARP-адрес не считается доказательством маски сети, а untagged traffic не получает выдуманный VLAN ID.

### Активное обнаружение

Nmap запускается только внутри подтверждённого scope. Произвольные Nmap flags через API не принимаются.

Профили `discovery`, `standard` и `deep` теперь описаны декларативно в `config/active_profiles.json`. Формат намеренно ограничен: можно менять разрешённые параметры профиля, но нельзя подсунуть `-sC`, `--script vuln` или другую произвольную командную строку.

### Inventory и корреляция

Пассивные и активные данные сходятся в одном inventory. Базовый приоритет идентичности — MAC, затем IP. Если сигналы конфликтуют, WireScope сохраняет `identity_conflict`, а не молча объединяет два устройства. Hostname сам по себе не используется как основание для merge.

Для assets рассчитывается осторожный device-class hint:

- `server-like`;
- `workstation-like`;
- `network-device-like`;
- `printer-like`;
- `iot-like`;
- `unknown`.

Класс хранится вместе с confidence и источниками сигнала. Это подсказка для inventory, а не finding.

### Протокольные проверки

После discovery запускаются только модули, подходящие найденным сервисам:

- SSH — `ssh-audit`;
- TLS — `openssl s_client`;
- HTTP/HTTPS — `curl`;
- SMB — `smbclient`;
- DNS — `dig`;
- SNMP — консервативный SNMPv3 noAuth probe;
- LDAP — anonymous base DSE через `ldapsearch`.

Пароли и community strings не перебираются. `testssl.sh`, Nikto и Nuclei остаются `never-default` и обычным профилем не запускаются.

### Findings, evidence и отчёты

Protocol modules сохраняют observations. Отдельный rule engine уже поверх них строит findings — факт и интерпретация не смешиваются.

Finding содержит severity, confidence, затронутый asset/service, rationale, рекомендацию и ссылки на evidence. Evidence можно открыть непосредственно из GUI; текстовые/JSON/XML артефакты доступны для просмотра в сыром виде.

Отчёты строятся из сохранённых данных без повторного сканирования. Доступны:

- self-contained HTML;
- JSON `audit-report` v1;
- Markdown.

PDF пока не реализован.

## Обзор, pipeline и сравнение аудитов

В GUI добавлен отдельный обзор WireScope. Он показывает:

- количество assets и services;
- findings по severity;
- текущий pipeline `passive → discovery → protocol → findings → report`;
- классы устройств;
- самые частые сервисы;
- доступность внешних инструментов;
- сколько assets подтверждены одновременно пассивными и активными источниками.

Два сохранённых аудита можно сравнить. Diff показывает появившиеся и исчезнувшие assets, открытые сервисы и findings.

## Capabilities

WireScope различает **готовность самого appliance** и наличие дополнительных providers.

Для базовой готовности нужны SQLite/миграции, worker, `dumpcap` и `tshark`. Если, например, отсутствует `ssh-audit` или `smbclient`, `/ready` не падает целиком — соответствующая функция просто отображается как недоступная в `/api/v1/capabilities` и GUI.

## Архитектура

WireScope — modular monolith. API и worker работают отдельными процессами, но общаются через локальное состояние, а не через сетевые микросервисы.

```text
browser / kiosk
      │
      ▼
FastAPI
      │
      ├── backend/routers/
      ├── auth / network / scope
      ├── audits / jobs
      ├── inventory / correlations
      ├── findings / evidence / reports
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

`backend/app.py` — небольшой composition root. HTTP routes разнесены по предметным router-модулям.

SQLite работает в WAL mode. Нормализованные данные и метаданные артефактов лежат в БД; PCAP, Nmap XML, raw stdout/stderr и отчёты хранятся в evidence store и регистрируются по UUID, размеру и SHA-256.

Подробнее: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## API

Канонический API — `/api/v1/*`. Старый `/api/*` пока сохранён как скрытый compatibility alias.

Кроме основных audit/job endpoints есть:

```text
GET /api/v1/capabilities
GET /api/v1/scan-profiles
GET /api/v1/audits/{id}/dashboard
GET /api/v1/audits/{id}/correlations
GET /api/v1/audits/{id}/diff?against={old_id}
GET /api/v1/audits/{id}/findings/{finding_id}/evidence
```

Подробнее: [docs/API.md](docs/API.md).

## Веб-интерфейс и bind

Для обычной appliance-установки WireScope **слушает `0.0.0.0:8000`**. Это сделано намеренно: интерфейс должен быть доступен через любой настроенный интерфейс устройства — Ethernet, Wi‑Fi и т.д.

Локальный kiosk всё равно открывает `http://127.0.0.1:8000/`, потому что он работает на том же хосте.

Если конкретное развёртывание требует ограничить доступ, это можно сделать через firewall, явный `--bind-host 127.0.0.1`, reverse proxy или TLS. Но это дополнительная политика конкретной установки, а не обязательная модель WireScope.

## Модель привилегий

`wirescope-api` и `wirescope-worker` не запускаются от root. Повышенные права для packet capture получает только `/usr/bin/dumpcap`:

```text
/usr/bin/dumpcap
root:wireshark
0750
cap_net_admin,cap_net_raw=eip
```

Nmap сам по себе дополнительных capabilities от WireScope не получает. При отсутствии raw sockets provider использует доступные непривилегированные режимы.

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

Обычный installer/upgrade path задаёт `0.0.0.0` автоматически. При необходимости можно переопределить:

```bash
sudo ./packaging/install.sh --bind-host 127.0.0.1
```

Основные пути:

```text
/opt/wirescope                  код + .venv
/etc/wirescope                  конфигурация
/var/lib/wirescope              SQLite, runtime, evidence, backups
/etc/systemd/system             systemd units
```

Полная инструкция: [docs/INSTALLATION.md](docs/INSTALLATION.md).

## Разработка и тесты

Нужен Python 3.11+.

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/alembic upgrade head
.venv/bin/pytest
```

В репозитории также есть GitHub Actions workflow, который делает `compileall` и запускает default test suite на Python 3.11. Тесты `network` и `live_pi` остаются opt-in.

## Документация

| Документ | Что внутри |
| --- | --- |
| [API](docs/API.md) | `/api/v1`, insights, diff, evidence, auth |
| [Установка](docs/INSTALLATION.md) | system/user install, kiosk, bind, TLS, upgrade/rollback |
| [Архитектура](docs/ARCHITECTURE.md) | модули, data flow, jobs, persistence |
| [Модель сканирования](docs/SCANNING_MODEL.md) | scope, declarative profiles, inventory, protocol audits |
| [Модель безопасности](docs/SECURITY_MODEL.md) | trust boundaries, auth, evidence, privileges |
| [Findings](docs/FINDINGS_MODEL.md) | rules, severity/confidence, state model |
| [Отчёты](docs/REPORTING_MODEL.md) | `audit-report` v1, HTML/JSON/Markdown |
| [GUI](docs/GUI_MODEL.md) | wizard, pipeline, dashboard, diff, evidence |
| [Разработка](docs/DEVELOPMENT.md) | локальный запуск, миграции, тесты |
| [Runbook](docs/RUNBOOK.md) | эксплуатация, диагностика, backup/restore |

## Пока не реализовано

- PDF export;
- отдельная security audit-log таблица;
- policy-driven автоматическая очистка старых audits/evidence;
- автоматический retry interrupted/terminal jobs;
- полный release matrix для версий tshark на всех поддерживаемых дистрибутивах.
