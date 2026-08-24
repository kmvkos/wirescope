# Эксплуатация WireScope

**Русский** · [English](en/OPERATIONS.md)

Этот документ про жизнь уже установленного WireScope: как понять, что устройство здорово, что происходит после restart, как повторить упавший этап, когда удаляются сырые артефакты и как сделать backup.

## Diagnostics

Для обычной проверки состояния shell не нужен. Auditor может открыть вкладку **Обзор → Эксплуатация** или запросить:

```text
GET /api/v1/diagnostics
```

Проверяются:

- SQLite accessibility;
- Alembic revision;
- `PRAGMA quick_check`;
- worker heartbeat;
- `dumpcap`/`tshark` core capabilities;
- свободное место;
- evidence-store usage;
- listener/TLS/proxy;
- retention candidates;
- последние operational events.

JSON-снимок можно скачать:

```text
GET /api/v1/diagnostics/export
```

Он специально не содержит password/session cookie/provider raw stdout.

## Что происходит после restart

Jobs durable: их состояние находится в SQLite, а не в памяти браузера.

Если worker/API перезапустился во время выполнения:

```text
running → interrupted
```

Queued jobs остаются queued. Resource locks старого worker освобождаются.

WireScope не пытается восстановить состояние внутреннего процесса Nmap/dumpcap. Оператор может повторить interrupted/failed/cancelled stage:

```text
POST /api/v1/jobs/{job_id}/retry
```

Создаётся **новая** queued job с теми же параметрами. Старая запись не меняется и остаётся частью истории.

## Retention

WireScope разделяет нормализованный результат аудита и тяжёлые raw artifacts.

По умолчанию:

| Тип | Retention |
| --- | ---: |
| temporary | 24 часа |
| debug | 7 дней |
| packet capture | 30 дней |
| Nmap XML | 90 дней |
| protocol raw output | 90 дней |
| inventory/findings/reports | автоматически не удаляются |

Настройки:

```text
WIRESCOPE_TEMP_ARTIFACT_RETENTION_HOURS
WIRESCOPE_DEBUG_RETENTION_DAYS
WIRESCOPE_PCAP_RETENTION_DAYS
WIRESCOPE_RAW_EVIDENCE_RETENTION_DAYS
```

### Почему raw data не удаляется автоматически

Для первой стабильной версии выбран консервативный вариант: policy показывает кандидатов, но aged PCAP/Nmap/protocol evidence удаляются только после явного подтверждения auditor. Это исключает неожиданную потерю доказательств.

Preview:

```json
POST /api/v1/maintenance/cleanup
{"confirm": false, "include_raw": true}
```

Применение:

```json
POST /api/v1/maintenance/cleanup
{"confirm": true, "include_raw": true}
```

Safe housekeeping stale temporary/orphan files может выполняться отдельно и не удаляет нормализованную историю аудита.

## Operational audit log

WireScope ведёт отдельный журнал значимых действий. Это не job events: job events описывают выполнение конкретной job, а operational log отвечает на вопрос «кто что сделал с appliance».

```text
GET /api/v1/audit-log
```

В записи есть:

- UTC time;
- actor;
- role;
- action;
- HTTP method/path;
- status code;
- client IP;
- audit id, если он определяется из URL.

Не сохраняются:

- password;
- request body;
- session cookie/token;
- provider stdout/stderr.

## Backup

Полный локальный backup SQLite + evidence:

```bash
cd /opt/wirescope
sudo ./.venv/bin/python -m appliance backup
```

По умолчанию архив создаётся под data directory в `backups/`.

Без evidence:

```bash
sudo ./.venv/bin/python -m appliance backup --no-evidence
```

SQLite копируется через SQLite backup API, а не обычным `cp` работающей WAL-базы.

## Restore

Restore меняет рабочую базу/evidence. Перед ним API/worker лучше остановить:

```bash
sudo systemctl stop wirescope-api wirescope-worker
sudo /opt/wirescope/.venv/bin/python -m appliance restore /path/to/backup
sudo systemctl start wirescope-worker wirescope-api
```

Перед заменой база из backup проходит `PRAGMA integrity_check`.

После restore:

```bash
curl -sS http://127.0.0.1:8000/api/v1/health
curl -sS http://127.0.0.1:8000/api/v1/ready
```

и в GUI нужно проверить Diagnostics.

## Upgrade

Обычный upgrade выполняется из checkout:

```bash
cd /opt/wirescope
git pull --ff-only
sudo ./packaging/upgrade.sh --project-root /opt/wirescope
```

Upgrade должен:

- обновить venv/dependencies при необходимости;
- применить migrations;
- сохранить `/var/lib/wirescope`;
- сохранить существующую конфигурацию, если явно не запрошено обратное;
- перезапустить services;
- оставить `0.0.0.0:8000` штатным listener, если установка не была специально настроена иначе.

Перед крупным upgrade разумно сделать backup.

## Что проверять при проблеме

Минимальный порядок:

1. открыть **Эксплуатация**;
2. проверить Database / Worker / Core tools / Free space;
3. скачать diagnostics JSON;
4. посмотреть failed/interrupted jobs;
5. при понятной transient-ошибке повторить конкретный stage;
6. только после этого идти в `journalctl`/SSH.

Системные логи:

```bash
journalctl -u wirescope-api -u wirescope-worker --since today
```

## Release readiness

Формальная граница между development build и кандидатом первой стабильной версии описана в [RELEASE_READINESS.md](RELEASE_READINESS.md).
