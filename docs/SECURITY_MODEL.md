# Модель безопасности WireScope

**Русский** · [English](en/SECURITY_MODEL.md)

WireScope сам выполняет сетевые проверки, поэтому его security model строится вокруг конкретных границ: кто принимает ввод, кто запускает внешние процессы, где находятся повышенные привилегии и какие цели разрешено проверять.

## Базовые правила

- API и worker работают без root;
- packet-capture capabilities есть только у `dumpcap`;
- active discovery не запускается без подтверждённого оператором scope;
- пользователь не передаёт произвольные Nmap/tool flags;
- внешние команды запускаются argv-массивами, без shell;
- raw evidence выдаётся по зарегистрированным artifact ID, а не по filesystem path;
- mutating API требует роль `auditor`;
- стандартный appliance слушает `0.0.0.0:8000`, чтобы GUI был доступен через любой настроенный физический или Wi‑Fi интерфейс устройства.

## Trust boundaries

### HTTP/API

FastAPI отвечает за аутентификацию, role checks и валидацию интерфейсов, scope, адресов, портов, фильтров и параметров job. Пользовательская строка не передаётся напрямую в shell или scanner CLI.

### Worker

Worker выполняет только зарегистрированные job types. Network-sensitive jobs:

- `passive_discovery`;
- `packet_capture`;
- `active_discovery`;
- `protocol_audit`.

`findings_evaluation` и `report_generation` работают только с уже сохранёнными данными.

### External tools

`ToolRunner` запускает argument arrays. `shell=True` не используется. Providers сами строят разрешённый argv; unrestricted «extra flags» через HTTP API отсутствуют.

## Least privilege

Нормальная схема system install:

```text
wirescope-api            wirescope-worker
uid=wirescope            uid=wirescope
      │                        │
      └───────────┬────────────┘
                  │
                  ▼
            /usr/bin/dumpcap
        root:wireshark 0750
 cap_net_admin,cap_net_raw=eip
```

Python, Uvicorn и worker не должны иметь `CAP_NET_RAW` или `CAP_NET_ADMIN`.

```bash
getcap /usr/bin/dumpcap
stat -c '%U:%G %a' /usr/bin/dumpcap
sudo -u wirescope /usr/bin/dumpcap -D
getcap /opt/wirescope/.venv/bin/python || true
```

Повышенные права вынесены в узкий capture provider вместо запуска всего backend от root.

## Active discovery

Перед Nmap создаётся immutable confirmed-scope snapshot. Worker повторно проверяет scope и маршрут непосредственно перед запуском scanner.

Запрещены:

- `0.0.0.0/0`;
- `::/0`;
- multicast ranges;
- бесконтрольное разворачивание больших IPv6-префиксов;
- raw user-supplied Nmap flags.

WireScope не повышает привилегии Nmap. Если raw sockets недоступны, provider использует допустимый fallback и фиксирует недоступные возможности. NSE, `-sC`, `vuln`, brute, exploit и DoS scripts в default discovery path не используются.

Подробнее: [SCANNING_MODEL.md](SCANNING_MODEL.md).

## Protocol audits и capabilities

Протокольный модуль запускается только если найден подходящий inventory service и его адрес остаётся внутри authorized scope.

Текущие default modules не перебирают credentials или community strings. Missing optional binary фиксируется как недоступная capability / `tool_unavailable`, а не как «проверка пройдена».

`GET /api/v1/capabilities` показывает оператору реально доступные инструменты. Для readiness обязательны базовые capture/decode dependencies; отсутствие отдельного optional provider, например `ssh-audit` или `smbclient`, не делает весь appliance неготовым.

## Authentication и роли

Локальные роли:

| Действие | `auditor` | `viewer` |
| --- | --- | --- |
| Просмотр audits/jobs/inventory/findings/reports | да | да |
| Dashboard / diff / capabilities / evidence | да | да |
| Смена собственного пароля | да | да |
| Создание audit | да | нет |
| Запуск/отмена jobs | да | нет |
| Listen/Record | да | нет |
| Изменение network config | да | нет |
| Изменение finding state | да | нет |
| Генерация report | да | нет |

Session token случайный. Браузер получает HttpOnly cookie, SQLite хранит SHA-256 digest токена. `SameSite=strict`; `Secure` включается при direct TLS или trusted proxy. Пароли хешируются PBKDF2-HMAC-SHA256. Встроенного постоянного default password нет.

## Web listener, firewall и TLS

### Default appliance policy

WireScope предназначен быть отдельным сетевым прибором, к которому оператор подключается через тот интерфейс, который доступен в текущем сегменте. Поэтому application settings, installer и upgrade path по умолчанию используют:

```text
0.0.0.0:8000
```

Это означает «слушать все локальные IPv4-интерфейсы», а не «открыть WireScope в Интернет». Реальная достижимость определяется адресацией, маршрутизацией, VLAN и firewall хоста/сети.

Локальный kiosk по-прежнему открывает:

```text
http://127.0.0.1:8000/
```

потому что loopback является одним из локальных путей к тому же listener.

### Ограниченный deployment

Если конкретной установке нужен только loopback, это задаётся явно:

```bash
sudo ./packaging/install.sh --bind-host 127.0.0.1
```

При необходимости можно ограничить TCP/8000 firewall'ом, включить direct TLS или поставить reverse proxy. Installer сам firewall не переписывает.

Direct TLS пример:

```bash
sudo ./packaging/install.sh \
  --bind-host 0.0.0.0 \
  --bind-port 8443 \
  --tls-cert /etc/wirescope/tls/cert.pem \
  --tls-key /etc/wirescope/tls/key.pem
```

`GET /api/v1/capabilities` отображает текущие `bind_host`, `bind_port`, TLS и trust-proxy state, чтобы фактический deployment был виден оператору.

## Evidence

PCAP и raw provider output могут содержать чувствительные данные. Клиент не выбирает путь файла; WireScope создаёт UUID-based artifact и хранит metadata в SQLite.

Запись evidence выполняется через temporary file → flush/fsync → atomic rename → SHA-256 → metadata registration.

Обычные permissions:

```text
directories: 0700
files:       0600
```

Artifact download audit-scoped:

```text
GET /api/v1/audits/{audit_id}/artifacts/{artifact_id}
```

Backend проверяет принадлежность artifact указанному audit. Raw PCAP обычного passive audit по умолчанию не сохраняется надолго (`passive_retain_capture=false`); в Listen/Record PCAP является целевым evidence artifact.

## SQLite и durability

SQLite содержит audits, jobs/events, confirmed scopes, inventory, findings, report metadata, local users/sessions и evidence references.

Runtime policy:

- WAL;
- foreign keys;
- busy timeout;
- короткие транзакции;
- `synchronous=FULL` по умолчанию.

Рабочую БД не следует размещать на NFS.

## Resource locking, cancellation и restart

Locks находятся в SQLite. `interface:<name>` не даёт одновременно выполнять конфликтующие capture/active операции на одном интерфейсе; отдельные resource groups ограничивают concurrency.

Cancellation является persistent state. Worker завершает subprocess group и переводит job в `cancelled`.

После restart worker:

- `queued` остаются queued;
- старые `running` становятся `interrupted` с `application_restart`;
- locks освобождаются;
- автоматического resume/retry network scanner jobs нет.

Restart Chromium/kiosk не влияет на durable jobs.

## Network configuration helper

Изменение сетевой конфигурации проходит через отдельный `netctl` privilege boundary. API не становится root и не выполняет произвольный `sudo` command. Потенциально разрывающее management path изменение требует server-side confirmation.

## API docs и логи

Swagger/OpenAPI/ReDoc можно отключить через:

```text
WIRESCOPE_DOCS_ENABLED=false
```

`/api/health` и `/api/ready` остаются публичными для проверки состояния appliance.

HTTP-клиент получает typed safe errors без Python traceback. Worker пишет structured operational logs. Отдельной неизменяемой security audit-log таблицы пока нет.

## Checklist перед эксплуатацией

- API/worker не root;
- Python без network capabilities;
- `dumpcap` не setuid и имеет ожидаемые capabilities;
- `/etc/wirescope` и `/var/lib/wirescope` не world-readable;
- initial admin password сохранён и временный файл удалён;
- выбранная firewall/TLS policy соответствует конкретному сегменту;
- scope caps не увеличены без причины;
- backup защищён так же, как основная БД/evidence.
