# WireScope

**Русский** · [English](README.en.md)

WireScope — автономный сетевой аудитор для Linux. Его можно поставить на небольшой ПК, ноутбук, сервер, виртуальную машину или ARM64-устройство и использовать как отдельный прибор для разбора незнакомого сетевого сегмента.

Идея простая: подключить WireScope к сети, сначала посмотреть на неё пассивно, затем явно указать, что разрешено проверять активно, и получить инвентаризацию, технические находки и отчёт. WireScope не начинает сканировать всё, что случайно оказалось достижимо с хоста.

Проект работает на обычном Linux: Debian/Ubuntu, Fedora/RHEL/Rocky и openSUSE; архитектуры `amd64` и `arm64`. Raspberry Pi подходит, но не является обязательной платформой. Raspberry Pi OS тоже не требуется.

## Что умеет WireScope

Текущий рабочий цикл выглядит так:

```text
подключение к сети
        ↓
снимок состояния хоста и интерфейсов
        ↓
пассивный захват трафика
        ↓
наблюдения: ARP, DHCP, VLAN, LLDP/CDP, STP, IPv6, mDNS, LLMNR, NBNS, SSDP
        ↓
подтверждение оператором разрешённого scope
        ↓
активное обнаружение через Nmap
        ↓
инвентаризация узлов и сервисов
        ↓
протокольные проверки по найденным сервисам
        ↓
findings
        ↓
HTML / JSON отчёт
```

Кроме основного аудита есть режим **«Прослушивание»**: оператор выбирает интерфейс, при необходимости задаёт BPF/tcpdump-фильтр, ограничение по времени и размеру, после чего WireScope сохраняет PCAP как evidence-артефакт.

### Пассивный анализ

Обычный аудит делает один ограниченный захват через `dumpcap`, затем один раз декодирует PCAP через `tshark -T ek`. После этого все пассивные сенсоры работают уже внутри Python-процесса.

Сейчас разбираются, среди прочего:

- Ethernet/MAC;
- 802.1Q VLAN и QinQ;
- ARP;
- DHCPv4 и DHCPv6;
- LLDP и CDP;
- STP;
- IPv6 RA и Neighbor Discovery;
- mDNS, LLMNR, NBNS;
- SSDP.

WireScope старается не выдавать предположения за факты. Например, ARP-адреса могут дать полезную группировку, но не считаются доказательством реальной маски подсети. Если access-порт передаёт кадры без 802.1Q-тега, WireScope не придумывает для него VLAN ID.

### Активное обнаружение

Nmap запускается только после подтверждения scope. В API передаются цели и профиль, а не произвольные аргументы Nmap.

Есть три профиля:

- **Discovery** — быстро найти живые узлы;
- **Standard** — основной профиль: discovery, TCP top-1000, `-sV`, ограниченный UDP-набор, OS detection при наличии подходящих привилегий;
- **Deep** — полный TCP `1-65535`, более глубокая идентификация сервисов и расширенный UDP-набор.

`0.0.0.0/0`, `::/0`, multicast и неконтролируемое разворачивание огромных IPv6-сетей запрещены. Для каждого профиля есть лимит числа адресов.

NSE, `-sC`, `vuln`, brute-force, exploit и DoS-скрипты в активном discovery не используются.

### Протокольные проверки

После инвентаризации WireScope запускает только те модули, которые подходят найденному сервису. Сейчас есть проверки для:

- SSH — `ssh-audit`;
- TLS — `openssl s_client`;
- HTTP/HTTPS — `curl`;
- SMB — `smbclient`;
- DNS — `dig`;
- SNMP — безопасный SNMPv3 noAuth probe;
- LDAP — anonymous base DSE через `ldapsearch`.

Модули не перебирают пароли и community strings. `testssl.sh`, Nikto и Nuclei существуют только как отключённые `never-default` заготовки и из обычного профиля не запускаются.

### Findings и отчёты

Протокольные модули сохраняют наблюдения, а не готовые «уязвимости». Findings строятся отдельным rule engine поверх нормализованных данных. Это позволяет не смешивать факт вроде «сервер предложил такой cipher» с интерпретацией «cipher слабый».

Findings содержат severity, confidence, затронутый asset/service, объяснение, рекомендацию и ссылки на исходные evidence. Находку можно подавить (`suppressed`) или принять как риск (`accepted_risk`); смена состояния сохраняется в истории.

Отчёт собирается из уже сохранённых данных и не запускает повторные проверки. Доступны:

- самодостаточный HTML;
- нормализованный JSON по схеме `audit-report` v1.

PDF пока не реализован.

## Как WireScope устроен

Проект остаётся модульным монолитом. API и worker — отдельные процессы, но это не набор микросервисов.

```text
frontend (HTML/CSS/JS)
        │
        ▼
FastAPI
        │
        ├── auth
        ├── environment / interfaces / network / scope
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

SQLite работает в WAL-режиме. В базе лежат нормализованные данные и метаданные артефактов; большие исходные файлы — PCAP, Nmap XML, stdout/stderr провайдеров, JSON/HTML-отчёты — хранятся отдельно в evidence store и регистрируются по UUID, размеру и SHA-256.

Подробнее: [архитектура](docs/ARCHITECTURE.md).

## Модель привилегий

`wirescope-api` и `wirescope-worker` не должны работать от root.

Для захвата пакетов повышенные права получает только `/usr/bin/dumpcap`:

```text
wirescope-api / wirescope-worker
        │ unprivileged
        ▼
/usr/bin/dumpcap
root:wireshark, 0750
cap_net_admin,cap_net_raw=eip
```

Nmap не получает дополнительные права от WireScope. Если raw sockets недоступны, provider переключается на TCP connect и отключает функции, которым нужны соответствующие capabilities.

Внешние команды запускаются массивами аргументов через общий runner. `shell=True` в этой части архитектуры не используется.

Подробнее: [модель безопасности](docs/SECURITY_MODEL.md).

## GUI

Оператор работает через браузер. Интерфейс рассчитан на два варианта:

1. **локальный киоск** — Chromium на том же устройстве, обычно `http://127.0.0.1:8000/`;
2. **удалённый браузер** — доступ по LAN через TLS/reverse proxy.

Для киоска не нужен GNOME, KDE или XFCE. Системный kiosk-unit занимает `tty1` и запускает Chromium через Cage либо Xorg/xinit. На VMware используется Xorg.

Есть две локальные роли:

- `auditor` — может запускать и останавливать задания, менять сетевые настройки, управлять findings и генерировать отчёты;
- `viewer` — только просмотр.

Сессии хранятся в HttpOnly cookie; в SQLite хранится SHA-256 digest токена, а не сам токен.

## Быстрая установка

Рекомендуемый системный layout — checkout в `/opt/wirescope`.

```bash
git clone git@github.com:kmvkos/wirescope.git
sudo mv wirescope /opt/wirescope
cd /opt/wirescope
sudo git checkout milestone-8-appliance

sudo ./packaging/install.sh \
  --generate-admin-password \
  --bind-host 127.0.0.1 \
  --with-kiosk \
  --enable-kiosk
```

Почему клон выше выполняется без `sudo`: `sudo git clone` использует SSH-ключи root, а не текущего пользователя.

Установщик работает **из checkout** и не копирует проект в другое место. Не удаляйте и не переименовывайте каталог после установки: systemd units ссылаются на него.

Данные по умолчанию для system install:

```text
/opt/wirescope                  код и virtualenv
/etc/wirescope                  конфигурация
/var/lib/wirescope              SQLite, runtime, evidence, backups
/etc/systemd/system             system units
```

Полная инструкция, включая Debian/Ubuntu, Fedora/RHEL/Rocky, openSUSE, user-systemd, kiosk, TLS, upgrade и rollback: [docs/INSTALLATION.md](docs/INSTALLATION.md).

> Важно: CLI установщика сам по себе сейчас имеет default `--bind-host 0.0.0.0`. Для автономного киоска и для схемы с reverse proxy в документации везде используется явный `--bind-host 127.0.0.1`. Публиковать обычный HTTP на `0.0.0.0:8000` без осознанной необходимости не стоит.

## Разработка

Нужен Python 3.11+.

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/alembic upgrade head
```

В двух терминалах:

```bash
.venv/bin/uvicorn backend.app:app --host 127.0.0.1 --port 8000
.venv/bin/python -m jobs.worker
```

Обычный тестовый прогон не трогает живую сеть:

```bash
.venv/bin/pytest
```

Тесты с `network` и `live_pi` включаются только явно.

## Документация

| Документ | Что в нём |
| --- | --- |
| [Установка](docs/INSTALLATION.md) | system/user install, kiosk, TLS, дистрибутивы, upgrade/rollback |
| [Архитектура](docs/ARCHITECTURE.md) | модули, потоки данных, jobs, persistence, privilege boundaries |
| [Модель сканирования](docs/SCANNING_MODEL.md) | scope, Nmap profiles, inventory, protocol audits |
| [Модель безопасности](docs/SECURITY_MODEL.md) | trust boundaries, auth, TLS, evidence, least privilege |
| [Findings](docs/FINDINGS_MODEL.md) | rules, severity/confidence, deduplication, false-positive boundaries |
| [Отчёты](docs/REPORTING_MODEL.md) | `audit-report` v1, HTML/JSON, evidence references |
| [GUI](docs/GUI_MODEL.md) | роли, wizard, listen/record, kiosk/laptop layout |
| [Разработка](docs/DEVELOPMENT.md) | локальный запуск, миграции, тесты, handler contract |
| [Runbook](docs/RUNBOOK.md) | эксплуатация, диагностика, backup/restore, recovery |
| [План реализации](docs/IMPLEMENTATION_PLAN.md) | история M0–M8 и то, что ещё осталось закрыть |

## Текущее состояние

Ветка `milestone-8-appliance` содержит реализацию этапов M0–M7 и текущую appliance-обвязку M8: installer, systemd, kiosk, backup/restore, dependency detection, сетевое управление, TLS/proxy guidance и режим записи PCAP.

Из заметных ограничений на текущий момент:

- PDF export отсутствует;
- нет отдельной security audit-log таблицы;
- автоматическая policy-driven очистка завершённых аудитов и зарегистрированных evidence ещё не сделана;
- автоматического retry завершённых/прерванных jobs нет;
- совместимость tshark нужно проверять на версиях пакетов конкретных дистрибутивов перед релизом.
