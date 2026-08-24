# Модель безопасности WireScope

**Русский** · [English](en/SECURITY_MODEL.md)

WireScope сам выполняет сетевые проверки, поэтому его security model строится не вокруг обещания «всё безопасно», а вокруг конкретных границ: кто принимает ввод, кто может запускать процессы, кто имеет сетевые capabilities и куда вообще разрешено обращаться.

## Коротко

Основные правила:

- API и worker работают без root;
- packet-capture capabilities есть только у `dumpcap`;
- active discovery не запускается без подтверждённого scope;
- пользователь не передаёт произвольные Nmap/tool flags;
- внешние команды запускаются argv-массивами, без shell;
- raw evidence хранится отдельно и недоступно по произвольному filesystem path;
- mutating API требует роль `auditor`;
- plain HTTP наружу не является рекомендуемым production-режимом.

## Trust boundaries

### HTTP/API boundary

FastAPI принимает внешний ввод и отвечает за:

- аутентификацию;
- role checks;
- валидацию интерфейса, scope, адресов, портов, фильтров и параметров;
- создание durable metadata/jobs;
- выдачу данных через контролируемые API.

Backend не передаёт пользовательскую строку напрямую в shell или scanner CLI.

### Job boundary

Worker выполняет только зарегистрированные внутренние job types.

Текущие network-sensitive jobs:

- `passive_discovery`;
- `packet_capture`;
- `active_discovery`;
- `protocol_audit`.

`findings_evaluation` и `report_generation` работают только с уже сохранёнными данными и сами сеть не трогают.

### External tool boundary

Общий `ToolRunner` запускает argument arrays. `shell=True` не используется.

Providers сами строят разрешённый argv. API не принимает «добавь вот эти флаги к Nmap» или аналогичный unrestricted input.

## Least privilege

Нормальный system install выглядит так:

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

Python interpreter, Uvicorn и worker не должны иметь `CAP_NET_RAW` или `CAP_NET_ADMIN`.

Проверка:

```bash
getcap /usr/bin/dumpcap
stat -c '%U:%G %a' /usr/bin/dumpcap
sudo -u wirescope /usr/bin/dumpcap -D
getcap /opt/wirescope/.venv/bin/python || true
```

`python` должен вернуться без capabilities.

`appliance verify` дополнительно проверяет, что `dumpcap` не setuid, permissions имеют ожидаемую форму и backend не получил лишние capabilities.

### Почему `dumpcap`, а не root backend

WireScope не требует root только ради packet capture. `dumpcap` — узкий provider, который умеет захватывать кадры и имеет минимально необходимые file capabilities.

Это ограничивает последствия ошибки в API, parser или frontend: они не превращаются автоматически в root-level packet/process access.

## Nmap и active discovery

Nmap запускается только после server-side подтверждения scope и route validation.

Перед job создаётся immutable confirmed-scope snapshot. Worker повторно проверяет его перед запуском Nmap.

Запрещены:

- `0.0.0.0/0`;
- `::/0`;
- multicast ranges;
- бесконтрольное разворачивание IPv6 `/64`;
- raw user-supplied Nmap flags.

WireScope не повышает привилегии Nmap. Если процесс уже имеет raw-socket capability, provider может использовать соответствующие методы. Если нет — применяется TCP connect fallback, а UDP/OS detection и другие privilege-dependent функции пропускаются и отмечаются в результате.

NSE, `-sC`, `vuln`, brute, exploit и DoS scripts в active discovery не используются.

Подробнее: [SCANNING_MODEL.md](SCANNING_MODEL.md).

## Protocol audits

Протокольный модуль запускается только если:

1. service уже присутствует в inventory;
2. module predicate подходит;
3. asset address остаётся внутри authorized scope;
4. safety class разрешён текущим профилем.

Текущие default modules не перебирают credentials или community strings.

В частности:

- SMB — только conservative null-session probe;
- SNMP — SNMPv3 noAuth probe, без `public/private` guessing и walk;
- LDAP — anonymous base DSE;
- HTTP не следует redirects автоматически;
- `testssl.sh`, Nikto и Nuclei — `never-default` stubs.

Missing tool сохраняется как `tool_unavailable`; это не считается доказательством отсутствия протокола.

## Authentication и роли

Пользователи локальные, хранятся в SQLite.

Роли:

| Действие | `auditor` | `viewer` |
| --- | --- | --- |
| Просмотр audits/jobs/inventory/findings/reports | да | да |
| Смена собственного пароля | да | да |
| Создание audit | да | нет |
| Запуск/отмена jobs | да | нет |
| Listen/record capture | да | только просмотр/download |
| Изменение network config | да | нет |
| Изменение finding state | да | нет |
| Генерация report | да | нет |

Session token генерируется случайно.

- браузер получает HttpOnly cookie;
- cookie имеет `SameSite=strict`;
- в SQLite хранится SHA-256 digest токена;
- при trusted proxy/direct TLS cookie становится `Secure`.

Пароли хешируются через PBKDF2-HMAC-SHA256.

Встроенного default password нет.

## Bind address и TLS

Application-level default — `127.0.0.1:8000`. Installer CLI сейчас имеет собственный default `0.0.0.0`, поэтому в production-командах bind задаётся явно.

### Локальный kiosk

Для автономного устройства:

```text
127.0.0.1:8000
```

Снаружи API вообще не обязан быть доступен.

### LAN-доступ

Рекомендуемая схема:

```text
management browser
      │ HTTPS :443
      ▼
Caddy / nginx
      │ loopback HTTP
      ▼
127.0.0.1:8000
```

Installer:

```bash
sudo ./packaging/install.sh \
  --bind-host 127.0.0.1 \
  --trust-proxy \
  --generate-admin-password
```

В этом режиме:

- API остаётся на loopback;
- session cookie `Secure`;
- forwarded headers доверяются только loopback proxy;
- TCP 8000 не нужно публиковать в LAN.

Примеры: `packaging/proxy/`.

### Direct TLS

Допустим прямой Uvicorn TLS, например на `8443`. Cert/key paths находятся в `wirescope.env`; сам PEM не должен попадать в systemd unit files.

### Plain HTTP на `0.0.0.0`

Технически поддерживается, но не является рекомендуемой LAN-конфигурацией. Если он всё же используется, доступ должен быть ограничен firewall до management network.

Installer сам firewall не меняет.

## API documentation

В development Swagger/OpenAPI/ReDoc могут быть включены.

В appliance environment production docs должны быть отключены:

```text
WIRESCOPE_DOCS_ENABLED=false
```

`/api/health` и `/api/ready` остаются public, чтобы kiosk/proxy мог проверить состояние appliance до login.

## Evidence и чувствительные данные

PCAP может содержать:

- credentials в незашифрованных протоколах;
- внутренние адреса и hostnames;
- cookies/tokens;
- пользовательский трафик;
- идентификаторы устройств.

Поэтому evidence root считается чувствительным audit storage.

Клиент не выбирает путь файла. WireScope генерирует внутренний UUID path.

Запись:

1. temporary file;
2. flush/fsync;
3. atomic rename;
4. SHA-256;
5. регистрация metadata в SQLite.

Обычные режимы:

```text
directories: 0700
files:       0600
```

Raw PCAP для обычного passive audit по умолчанию не сохраняется надолго (`passive_retain_capture=false`). В режиме «Прослушивание» PCAP является целевым результатом и сохраняется в evidence store.

Retention — ответственность операционной политики. Автоматическое policy-driven удаление зарегистрированных audit evidence пока не реализовано.

## SQLite

SQLite содержит:

- audit scope и выбранные interfaces;
- jobs/events/errors;
- inventory;
- findings;
- report metadata;
- local users;
- hashed sessions;
- ссылки на evidence.

Она должна защищаться как часть audit data.

Рабочую БД не следует класть на NFS.

Runtime настройки:

- WAL;
- foreign keys;
- busy timeout;
- короткие транзакции;
- `synchronous=FULL` по умолчанию.

Backup/restore:

```bash
python -m appliance backup
python -m appliance restore <archive>
```

## Resource locking и concurrency

Locks находятся в SQLite.

Это защищает от конфликтов даже при нескольких worker threads:

- `interface:<name>` не даёт одновременно захватывать и активно сканировать один интерфейс;
- packet capture имеет отдельный global group limit;
- active discovery имеет свой group limit;
- protocol audit сериализуется на audit/group;
- findings/report jobs сериализуются отдельно и не держат interface lock.

По умолчанию concurrency консервативна: основные network jobs выполняются по одному.

Только один healthy worker supervisor должен владеть supervisor lease, чтобы случайный второй процесс не умножал настроенную concurrency.

## Cancellation

Running cancellation — persistent state, а не только флаг в памяти.

Worker видит request, выставляет cancellation token, а `ToolRunner` завершает subprocess group.

Отменённый job получает `cancelled`, а не `failed`.

Partial observations, которые уже были корректно сохранены до отмены, могут остаться в inventory/evidence.

## Restart recovery

Если worker перезапущен:

- `queued` jobs остаются queued;
- старые `running` jobs становятся `interrupted`;
- error code — `application_restart`;
- locks освобождаются;
- автоматического resume/retry нет.

Это сделано специально: произвольный network scanner job безопаснее повторно запустить осознанно, чем продолжать после неизвестной точки остановки.

Kiosk/browser restart на job lifecycle не влияет.

## Network configuration helper

WireScope умеет менять сетевую конфигурацию через отдельный `netctl` boundary. API не получает root и не запускает произвольный `sudo` command.

System install использует строго ограниченный helper/sudoers path. Ввод всё равно проходит model validation и confirmation checks, особенно если изменение может отрезать текущий management path.

## Логи

HTTP-клиент получает typed safe errors. Python traceback не возвращается в API response.

Worker пишет structured operational logs с audit/job context. Отдельной неизменяемой security audit-log таблицы пока нет — это текущий technical debt.

## Что проверять перед production

Минимальный checklist:

- API/worker не root;
- Python без capabilities;
- `dumpcap` не setuid и имеет ожидаемые file capabilities;
- `WIRESCOPE_DOCS_ENABLED=false`;
- LAN UI только через HTTPS либо осознанный isolated lab HTTP;
- TCP 8000 не опубликован при reverse proxy;
- `/etc/wirescope` и `/var/lib/wirescope` не world-readable;
- `initial-admin.txt` удалён после сохранения пароля;
- backup хранится с тем же уровнем защиты, что и основная БД/evidence;
- scope caps не увеличены без явной причины.
