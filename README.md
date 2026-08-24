# WireScope

**Русский** · [English](README.en.md)

WireScope — автономный сетевой аудитор для Linux. Его можно поставить на небольшой ПК, ноутбук, сервер, виртуальную машину или ARM64-устройство и использовать как отдельный прибор для разбора незнакомого сетевого сегмента.

Идея проекта простая: сначала посмотреть на сеть пассивно, затем явно определить, что разрешено проверять активно, собрать инвентаризацию, выполнить проверки найденных сервисов и получить технический отчёт. WireScope не воспринимает всё, что достижимо с хоста, как автоматически разрешённый scope.

Поддерживаемая база — обычный Linux: Debian/Ubuntu, Fedora/RHEL/Rocky и openSUSE на `amd64` и `arm64`. Raspberry Pi подходит как одна из платформ, но не является обязательным условием и Raspberry Pi OS не требуется.

## Как проходит аудит

```text
подключение к сети
        ↓
снимок состояния хоста и интерфейсов
        ↓
пассивный захват трафика
        ↓
ARP / DHCP / VLAN / LLDP / CDP / STP / IPv6 / naming protocols
        ↓
подтверждение оператором разрешённого scope
        ↓
активное обнаружение через Nmap
        ↓
инвентаризация узлов и сервисов
        ↓
протокольные проверки
        ↓
findings
        ↓
HTML / JSON отчёт
```

Отдельно есть режим **«Прослушивание»**: можно выбрать интерфейс, задать BPF/tcpdump-фильтр, время и максимальный размер файла и сохранить PCAP как evidence-артефакт.

### Пассивный анализ

Обычный аудит делает один ограниченный захват через `dumpcap`, после чего PCAP один раз декодируется через `tshark -T ek`. Сенсоры работают уже по нормализованным packet records внутри Python-процесса.

Сейчас разбираются Ethernet/MAC, 802.1Q/QinQ, ARP, DHCPv4/v6, LLDP, CDP, STP, IPv6 RA/ND, mDNS, LLMNR, NBNS и SSDP.

Наблюдения отделены от предположений. Например, ARP может дать полезный hint о группе адресов, но не считается доказательством маски сети. Если access-порт отдаёт кадры без 802.1Q-тега, WireScope не придумывает VLAN ID.

### Активное обнаружение

Nmap запускается только после подтверждения scope. Клиент передаёт цели и профиль, а не произвольные флаги Nmap.

Профили:

- **Discovery** — быстрое обнаружение живых узлов;
- **Standard** — основной профиль: host discovery, TCP top-1000, `-sV`, ограниченный UDP-набор и OS detection, когда нужные privileges уже доступны;
- **Deep** — TCP `1-65535`, более глубокая идентификация сервисов и расширенный UDP-набор.

`0.0.0.0/0`, `::/0`, multicast и неконтролируемое разворачивание больших IPv6-префиксов запрещены. NSE, `-sC`, `vuln`, brute-force, exploit и DoS-скрипты в discovery не используются.

### Протокольные проверки

После инвентаризации запускаются только подходящие найденным сервисам модули:

- SSH — `ssh-audit`;
- TLS — `openssl s_client`;
- HTTP/HTTPS — `curl`;
- SMB — `smbclient`;
- DNS — `dig`;
- SNMP — консервативный SNMPv3 noAuth probe;
- LDAP — anonymous base DSE через `ldapsearch`.

Пароли и community strings не перебираются. `testssl.sh`, Nikto и Nuclei остаются `never-default` и обычным профилем не запускаются.

### Findings и отчёты

Protocol modules сохраняют факты. Отдельный rule engine превращает нормализованные observations в findings. Так факт «сервер предложил такой cipher» не смешивается с выводом «cipher считается слабым».

Finding хранит severity, confidence, затронутый asset/service, объяснение, рекомендацию и ссылки на evidence. Состояния `suppressed` и `accepted_risk` сохраняются вместе с историей изменений.

Отчёт строится из уже сохранённых данных и не запускает сканеры повторно. Сейчас доступны self-contained HTML и JSON по схеме `audit-report` v1. PDF пока не реализован.

## Архитектура

WireScope остаётся modular monolith. API и worker — отдельные процессы, но сетевых микросервисов между ними нет.

```text
frontend (HTML/CSS/JS)
        │
        ▼
FastAPI
        │
        ├── backend/routers/
        ├── auth / network / scope
        ├── audits / jobs
        ├── inventory
        ├── findings / reports
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

`backend/app.py` теперь является composition root: собирает сервисы, подключает router-модули, frontend и static files. HTTP-маршруты разнесены по `backend/routers/` по предметным областям.

SQLite работает в WAL-режиме. Нормализованные данные и метаданные артефактов лежат в БД; PCAP, Nmap XML, raw stdout/stderr и сгенерированные отчёты хранятся в evidence store и регистрируются по UUID, размеру и SHA-256.

Подробнее: [архитектура](docs/ARCHITECTURE.md).

## HTTP API

Канонический API находится под `/api/v1`:

```text
GET  /api/v1/health
GET  /api/v1/environment
POST /api/v1/audits
GET  /api/v1/jobs/{job_id}
```

Старый `/api/*` пока сохранён как compatibility alias, поэтому текущий frontend и существующие клиенты продолжают работать. Legacy routes скрыты из OpenAPI; Swagger/ReDoc показывают только `/api/v1/*`.

Подробнее: [docs/API.md](docs/API.md).

## Модель привилегий

`wirescope-api` и `wirescope-worker` не должны работать от root. Повышенные права для packet capture получает только `/usr/bin/dumpcap`:

```text
wirescope-api / wirescope-worker
        │ unprivileged
        ▼
/usr/bin/dumpcap
root:wireshark, 0750
cap_net_admin,cap_net_raw=eip
```

Nmap не повышается самим WireScope. Если raw sockets недоступны, provider использует TCP connect и пропускает функции, которым нужны соответствующие capabilities.

Внешние команды запускаются массивами аргументов через общий runner; `shell=True` на этом пути не используется.

Подробнее: [модель безопасности](docs/SECURITY_MODEL.md).

## GUI

Оператор работает через браузер. Поддерживаются два основных режима:

1. **локальный kiosk** — Chromium на самом appliance, обычно `http://127.0.0.1:8000/`;
2. **удалённый браузер** — LAN-доступ через TLS/reverse proxy.

Для киоска не нужен GNOME, KDE или XFCE. Системный kiosk-unit занимает `tty1` и запускает Chromium через Cage или Xorg/xinit; на VMware используется Xorg.

Роли:

- `auditor` — запуск/отмена jobs, сетевые настройки, управление findings, генерация отчётов;
- `viewer` — просмотр.

Сессия хранится в HttpOnly cookie; в SQLite сохраняется SHA-256 digest токена, а не сам токен.

## Быстрая установка

Рекомендуемый системный layout — checkout в `/opt/wirescope`.

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

Клон выполняется без `sudo`, чтобы Git использовал SSH-ключи текущего пользователя. Checkout также делается до переноса в `/opt`, чтобы не создавать лишних проблем с ownership и `safe.directory`.

Установщик работает **из checkout** и не копирует код в другой каталог. Не удаляйте и не переименовывайте checkout после установки: systemd units ссылаются на него.

По умолчанию installer и application bind используют **`127.0.0.1:8000`**. Публичный bind требует явного решения:

```bash
sudo ./packaging/install.sh --bind-host 0.0.0.0
```

Для доступа с другой машины предпочтительнее оставить API на loopback и поставить Caddy/nginx перед ним с TLS.

Основные пути system install:

```text
/opt/wirescope                  код и virtualenv
/etc/wirescope                  конфигурация
/var/lib/wirescope              SQLite, runtime, evidence, backups
/etc/systemd/system             system units
```

Полная инструкция: [docs/INSTALLATION.md](docs/INSTALLATION.md).

## Разработка

Нужен Python 3.11+.

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/alembic upgrade head
```

API и worker запускаются отдельно:

```bash
.venv/bin/uvicorn backend.app:app --host 127.0.0.1 --port 8000
.venv/bin/python -m jobs.worker
```

Обычный тестовый прогон не обращается к живой сети:

```bash
.venv/bin/pytest
```

`network` и `live_pi` тесты включаются только явно.

## Документация

| Документ | Что в нём |
| --- | --- |
| [API](docs/API.md) | `/api/v1`, compatibility policy и auth semantics |
| [Установка](docs/INSTALLATION.md) | system/user install, kiosk, TLS, дистрибутивы, upgrade/rollback |
| [Архитектура](docs/ARCHITECTURE.md) | модули, data flow, jobs, persistence, privilege boundaries |
| [Модель сканирования](docs/SCANNING_MODEL.md) | scope, Nmap profiles, inventory, protocol audits |
| [Модель безопасности](docs/SECURITY_MODEL.md) | trust boundaries, auth, TLS, evidence, least privilege |
| [Findings](docs/FINDINGS_MODEL.md) | rules, severity/confidence, deduplication, false-positive boundaries |
| [Отчёты](docs/REPORTING_MODEL.md) | `audit-report` v1, HTML/JSON, evidence references |
| [GUI](docs/GUI_MODEL.md) | роли, wizard, listen/record, kiosk/laptop layout |
| [Разработка](docs/DEVELOPMENT.md) | локальный запуск, миграции, тесты, handler contract |
| [Runbook](docs/RUNBOOK.md) | эксплуатация, диагностика, backup/restore, recovery |
| [План реализации](docs/IMPLEMENTATION_PLAN.md) | история M0–M8 и дальнейшая работа |

## Текущее состояние

Основная appliance-линия включает M0–M7 и текущую M8-обвязку: installer, systemd, kiosk, backup/restore, dependency detection, сетевое управление, TLS/proxy и запись PCAP.

Из известных ограничений:

- PDF export пока отсутствует;
- отдельной security audit-log таблицы ещё нет;
- policy-driven автоматическая очистка завершённых аудитов/evidence не реализована;
- автоматического retry terminal/interrupted jobs нет;
- совместимость tshark требует release-проверки на пакетных версиях поддерживаемых дистрибутивов.
