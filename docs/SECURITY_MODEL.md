# Модель безопасности WireScope

**Русский** · [English](en/SECURITY_MODEL.md)

WireScope сам выполняет сетевые проверки, поэтому его security model строится вокруг конкретных границ: кто принимает ввод, кто запускает внешние процессы, где находятся повышенные привилегии, какие цели разрешено проверять и как сохраняются действия оператора.

## Базовые правила

- API и worker работают без root;
- packet-capture capabilities есть только у `dumpcap`;
- active discovery не запускается без operator-confirmed scope;
- пользователь не передаёт произвольные Nmap/tool flags;
- внешние команды запускаются argv-массивами без shell;
- raw evidence выдаётся по зарегистрированным artifact ID, а не filesystem path;
- mutating API требует `auditor`;
- normal appliance listener — `0.0.0.0:8000`;
- operational log не хранит password/request body/session token;
- raw-evidence cleanup требует явного confirmation.

## Trust boundaries

### HTTP/API

FastAPI отвечает за authentication, role checks и validation interfaces/scope/addresses/ports/filters/job parameters. Пользовательская строка не передаётся напрямую в shell/scanner CLI.

### Worker

Worker выполняет только зарегистрированные job types. Network-sensitive jobs: `passive_discovery`, `packet_capture`, `active_discovery`, `protocol_audit`. Findings/report jobs работают только с persisted data.

### External tools

`ToolRunner` запускает argument arrays. `shell=True` не используется. Providers сами строят допустимый argv; unrestricted extra flags через HTTP отсутствуют.

## Least privilege

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

Python/Uvicorn/worker не должны иметь `CAP_NET_RAW` или `CAP_NET_ADMIN`. Повышенные права вынесены в узкий packet-capture boundary.

## Active discovery

Перед Nmap сохраняется immutable confirmed-scope snapshot. Worker повторно проверяет scope и route непосредственно перед scanner execution.

Запрещены unspecified/multicast targets, бесконтрольное разворачивание IPv6 и raw user-supplied Nmap flags. WireScope не повышает Nmap. NSE/`-sC`, vuln/brute/exploit/DoS scripts не входят в default discovery path.

## Protocol audits и capabilities

Protocol module запускается только для подходящего inventory service внутри authorized scope. Default modules не перебирают credentials/community strings.

Missing binary фиксируется как unavailable capability / `tool_unavailable`, а не как «проверка пройдена».

```text
GET /api/v1/capabilities
```

Core readiness и optional provider availability разделены.

## Authentication и роли

| Действие | Auditor | Viewer |
| --- | --- | --- |
| Читать audits/inventory/findings/reports | да | да |
| Dashboard/diff/evidence | да | да |
| Сменить свой пароль | да | да |
| Создать audit / запустить job | да | нет |
| Cancel/retry terminal job | да | нет |
| Изменить network config | да | нет |
| Изменить finding state | да | нет |
| Diagnostics/audit log/maintenance | да | нет |

Session token случайный. Browser получает HttpOnly cookie, SQLite хранит SHA-256 token digest. `SameSite=strict`; `Secure` включается для direct TLS/trusted proxy. Password hashes используют PBKDF2-HMAC-SHA256.

## Operational audit log

Значимые mutating requests и login attempts сохраняются в `operational_events`.

Запись содержит:

- UTC timestamp;
- actor/role;
- stable action name;
- normalized API path;
- HTTP status;
- client IP;
- audit id, если его можно получить из path.

**Не сохраняются:** request body, password, session cookie/token, provider stdout/stderr.

Operational log отличается от job events: job events описывают execution history, operational log — действия пользователя с appliance.

Журнал доступен только auditor:

```text
GET /api/v1/audit-log
```

Ошибка записи operational event не должна ломать сам operator request; состояние database/migrations отдельно видно через diagnostics.

## Web listener, firewall и TLS

WireScope — сетевой appliance, GUI которого должен быть доступен через любой настроенный Ethernet/Wi‑Fi interface. Поэтому application settings, argparse, installer и upgrade path по умолчанию используют:

```text
0.0.0.0:8000
```

Это означает listen на локальных IPv4 interfaces, а не автоматическую Internet exposure. Реальная достижимость определяется сетью/firewall.

Local kiosk открывает `127.0.0.1:8000`. Loopback-only deployment можно задать явно через `--bind-host 127.0.0.1`. Direct TLS/reverse proxy/firewall остаются deployment controls.

## Evidence

PCAP/raw provider output могут содержать чувствительные данные. Клиент не выбирает path; WireScope регистрирует UUID artifact metadata в SQLite.

Evidence write: temporary file → flush/fsync → atomic rename → SHA-256 → metadata registration.

Обычные permissions:

```text
directories: 0700
files:       0600
```

Artifact access audit-scoped:

```text
GET /api/v1/audits/{audit_id}/artifacts/{artifact_id}
```

Backend проверяет принадлежность artifact указанному audit.

## Retention и cleanup

Normalized inventory/findings/reports автоматически не удаляются. Aged temporary/debug/raw evidence попадает в cleanup candidates.

Raw cleanup использует двухшаговый contract:

```text
preview: confirm=false
apply:   confirm=true
```

PCAP/Nmap XML/protocol raw output удаляются только после явного auditor confirmation. Cleanup удаляет и file, и metadata row. Это защищает от незаметной потери evidence.

## SQLite и durability

SQLite хранит audits, jobs/events, confirmed scopes, inventory, findings, reports, users/sessions, operational events и artifact references.

Runtime policy: WAL, foreign keys, busy timeout, short transactions, `synchronous=FULL` по умолчанию. Рабочую БД не следует размещать на NFS.

## Resource locking, cancellation и retry

Locks находятся в SQLite. Cancellation persistent: worker завершает subprocess group и переводит job в `cancelled`.

После restart worker:

- queued остаются queued;
- running становятся interrupted;
- stale locks освобождаются.

Automatic network retry отсутствует. Auditor может явно retry `failed/interrupted/cancelled` stage. Retry создаёт новую job и сохраняет terminal source history неизменной.

## Network configuration helper

Network changes идут через отдельный `netctl` privilege boundary. API не становится root и не выполняет произвольный sudo command. Потенциально разрывающее management path изменение требует server-side confirmation.

## Diagnostics

Auditor-only diagnostics собирает safe operational state:

```text
GET /api/v1/diagnostics
GET /api/v1/diagnostics/export
```

В snapshot есть platform/version, listener, capabilities, SQLite quick-check, migration/worker state, disk/evidence usage, retention и recent operational events. Secrets и raw provider contents в export не включаются.

## Backup / restore

Backup содержит SQLite и при необходимости evidence, поэтому защищать его нужно так же, как основную data directory. SQLite snapshot создаётся через backup API. Restore проверяет `PRAGMA integrity_check` перед заменой рабочей database.

## API docs и errors

Swagger/OpenAPI/ReDoc можно отключить через `WIRESCOPE_DOCS_ENABLED=false`. `/health` и `/ready` остаются публичными.

HTTP-клиент получает typed safe errors без Python traceback.

## Checklist перед эксплуатацией

- API/worker не root;
- Python без network capabilities;
- `dumpcap` не setuid и имеет ожидаемые capabilities;
- `/etc/wirescope` и `/var/lib/wirescope` не world-readable;
- initial admin password защищён/временный файл удалён;
- listener/firewall/TLS policy соответствует сегменту;
- scope caps не увеличены без причины;
- diagnostics показывает SQLite `ok`, worker ready и достаточное место;
- backup защищён так же, как database/evidence.

Формальный release checklist: [RELEASE_READINESS.md](RELEASE_READINESS.md).
