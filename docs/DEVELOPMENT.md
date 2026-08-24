# Разработка WireScope

**Русский** · [English](en/DEVELOPMENT.md)

Этот документ — короткий рабочий гайд для локальной разработки. Production installation описана отдельно в [INSTALLATION.md](INSTALLATION.md).

## Требования

- Python 3.11+;
- Linux;
- для реального passive capture — `dumpcap` и `tshark`;
- для active discovery — Nmap;
- дополнительные protocol tools нужны только для соответствующих модулей.

Большая часть тестов работает на fixtures и не требует установленных scanners.

## Создание окружения

```bash
python3 -m venv .venv
.venv/bin/pip install --upgrade pip
.venv/bin/pip install -e '.[dev]'
.venv/bin/alembic upgrade head
```

Production tables создаются Alembic migrations. `Base.metadata.create_all()` не является способом инициализации рабочей базы.

## Локальный запуск

API и worker запускаются отдельно.

Терминал 1:

```bash
.venv/bin/uvicorn backend.app:app \
  --host 127.0.0.1 \
  --port 8000
```

Терминал 2:

```bash
.venv/bin/python -m jobs.worker
```

Открыть GUI:

```text
http://127.0.0.1:8000/
```

API создаёт jobs, но сам их не исполняет. Worker отвечает за startup recovery, claiming, handlers, progress и cancellation.

Остановка API не удаляет jobs из SQLite и не останавливает отдельно работающий worker.

## Worker model

Одновременно должен работать один supervisor process. Внутренняя concurrency задаётся bounded thread pool через settings.

Не нужно запускать несколько `python -m jobs.worker`, чтобы «ускорить» обработку: это нарушает предполагаемую appliance process model и supervisor lease.

## Job handler

Новый долгий workflow оформляется как handler и регистрируется в `HandlerRegistry`.

Handler получает контролируемый runtime context, включая:

- immutable audit/job data;
- settings;
- cancellation token;
- evidence store;
- progress callback;
- нужные domain services/providers.

Handler не должен возвращать мегабайты raw data в job row. Большие результаты идут в `EvidenceStore`, а job сохраняет compact result reference/summary.

Progress events создаются по meaningful stages, а не на каждый packet/host/строку stdout.

## External tools

Общие правила:

- argv arrays;
- без `shell=True`;
- timeout;
- process-group cancellation;
- bounded output;
- structured error categories;
- raw output при необходимости сохраняется как evidence.

User input не должен превращаться в произвольные scanner flags.

## Изменение database schema

1. Изменить SQLAlchemy models в `persistence/models.py`.
2. Создать migration:

```bash
.venv/bin/alembic revision \
  --autogenerate \
  -m 'describe change'
```

3. Проверить сгенерированный файл руками.
4. Особое внимание:
   - constraints;
   - indexes;
   - SQLite compatibility;
   - upgrade order;
   - downgrade, если он вообще заявлен как рабочий.
5. Проверить upgrade на новой БД и на БД предыдущей revision.

Scanner/capture/parser никогда не должен выполняться внутри открытой SQLAlchemy transaction/session дольше, чем необходимо для короткой DB-операции.

## Тесты

Обычный прогон:

```bash
.venv/bin/pytest
```

В `pyproject.toml` default marker expression исключает:

```text
network
live_pi
```

То есть стандартные тесты не должны сканировать реальную сеть.

### Основные marker'ы

- `network` — opt-in live network;
- `integration` — более широкий pipeline, но не обязательно live network;
- `browser` — optional Playwright/Chromium;
- `live_pi` — Raspberry Pi hardware-specific проверки.

Для реальных network tests должен быть явно задан scope, например через `WIRESCOPE_LIVE_SCOPE`, и тест запускается с `-m network`.

Findings/reporting tests сеть не используют вообще.

## Проверка import/syntax

```bash
.venv/bin/python -m compileall -q \
  backend config engine inventory jobs parsers persistence \
  protocol_audits findings reports providers sensors storage \
  auth appliance tests
```

Dependency consistency:

```bash
.venv/bin/pip check
```

## Benchmarks

В репозитории есть lightweight benchmarks для persistence/inventory:

```bash
.venv/bin/python -m scripts.benchmark_persistence
.venv/bin/python -m scripts.benchmark_inventory
```

Это regression indicators, а не обещание конкретной производительности на любом железе.

## Bootstrap пользователей в development

Только для development можно создать первых пользователей через environment variables, если таблица `users` ещё пустая:

```bash
export WIRESCOPE_BOOTSTRAP_AUDITOR_USERNAME=auditor
export WIRESCOPE_BOOTSTRAP_AUDITOR_PASSWORD='choose-a-long-password'
export WIRESCOPE_BOOTSTRAP_VIEWER_USERNAME=viewer
export WIRESCOPE_BOOTSTRAP_VIEWER_PASSWORD='choose-a-long-password'
```

После startup accounts создаются один раз.

В production эти секреты не должны попадать в systemd units. Appliance installer использует password file/bootstrap flow из [INSTALLATION.md](INSTALLATION.md).

## Frontend

Отдельной build-системы нет.

Frontend files:

```text
frontend/index.html
frontend/app.js
frontend/i18n.js
frontend/style.css
```

Изменения UI проверяются как минимум на:

- 480×320 kiosk layout;
- desktop width ≥ 900px;
- auditor/viewer role behavior;
- reload во время running job;
- error/partial/cancelled states.

Optional browser tests skip'аются, если Chromium/Playwright не установлен.

## Passive fixtures

Passive parser/sensor tests должны использовать сохранённые PCAP/normalized fixtures, а не требовать live capture.

Новый sensor/provider должен иметь fixtures минимум для:

- normal success;
- отсутствие нужного protocol evidence;
- malformed input;
- provider/parser failure, если применимо.

Ошибка parser не должна тестироваться как `detected=false`; ожидаемый контракт — `partial` или `error`.

## Protocol module

Новый module должен определить:

- predicates;
- tool;
- safety class;
- argv builder;
- parser;
- observation kinds;
- timeout;
- fixtures.

Module parser не должен писать в SQLite напрямую. Persistence выполняется orchestration/store layer.

## Finding rule

Finding rule работает только с normalized data и evidence references.

Нельзя добавлять в finding rule парсинг raw stdout scanner'а. Если rule не хватает поля — сначала поле должно появиться в normalized observation contract.

## Документация при изменениях

Если меняется behavior, обновлять нужно документ того слоя, который реально изменился:

- scope/Nmap/protocol module → `SCANNING_MODEL.md`;
- privilege/auth/evidence → `SECURITY_MODEL.md`;
- persistence/process boundaries → `ARCHITECTURE.md`;
- finding rule semantics → `FINDINGS_MODEL.md`;
- report schema → `REPORTING_MODEL.md`;
- UI workflow → `GUI_MODEL.md`;
- installation/systemd → `INSTALLATION.md` и `RUNBOOK.md`.

Не стоит использовать `IMPLEMENTATION_PLAN.md` как единственное место, где описано уже существующее runtime behavior.
