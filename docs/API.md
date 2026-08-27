# WireScope API

[English](en/API.md)

WireScope публикует канонический HTTP API под префиксом `/api/v1`. Старый `/api/*` пока остаётся скрытым compatibility alias для существующих установок и клиентов.

```text
/api/v1/...   основной контракт
/api/...      переходный compatibility alias
```

В OpenAPI/Swagger показывается только `/api/v1`.

## Системное состояние

```text
GET /api/v1/health
GET /api/v1/status
GET /api/v1/ready
GET /api/v1/environment
GET /api/v1/interfaces
GET /api/v1/capabilities
GET /api/v1/scan-profiles
GET /api/v1/diagnostics
GET /api/v1/diagnostics/export
```

`/health` отвечает только на вопрос «API-процесс жив?». `/ready` проверяет SQLite, актуальность миграций, worker и обязательные для базовой работы `dumpcap`/`tshark`.

Отсутствие optional provider, например `ssh-audit`, `openssh-client` или `smbclient`, не делает весь appliance `not_ready`. Полный список возможностей и обнаруженных бинарников возвращает `/capabilities`.

`/diagnostics` — расширенный снимок для эксплуатации. В нём есть версия/платформа, listener, runtime checks, capabilities, SQLite `quick_check`, disk/evidence usage, retention и последние operational events. `/diagnostics/export` отдаёт тот же безопасный снимок JSON-файлом. Эти endpoints доступны только `auditor`.

`/scan-profiles` возвращает фактически загруженные декларативные профили `discovery`, `standard` и `deep`. API не принимает произвольную строку флагов Nmap.

## Audits и pipeline

```text
POST /api/v1/audits
GET  /api/v1/audits
GET  /api/v1/audits/{audit_id}
POST /api/v1/audits/{audit_id}/passive
POST /api/v1/audits/{audit_id}/discovery
POST /api/v1/audits/{audit_id}/protocol-audits
POST /api/v1/audits/{audit_id}/findings
POST /api/v1/audits/{audit_id}/reports
```

Дополнительные read-only представления:

```text
GET /api/v1/audits/{audit_id}/dashboard
GET /api/v1/audits/{audit_id}/correlations
GET /api/v1/audits/{audit_id}/diff?against={previous_audit_id}
```

`dashboard` собирается из существующих jobs, inventory и findings. Отдельной dashboard database нет.

`correlations` объясняет, за счёт каких сигналов passive и active observations относятся к одному asset. Hostname сам по себе не используется как основание для автоматического merge.

`diff` сравнивает два сохранённых аудита и показывает появившиеся/исчезнувшие assets, открытые services и findings.

## Inventory

```text
GET /api/v1/audits/{audit_id}/assets
GET /api/v1/audits/{audit_id}/assets/{asset_id}
GET /api/v1/audits/{audit_id}/services
GET /api/v1/audits/{audit_id}/inventory
GET /api/v1/audits/{audit_id}/observations
```

Inventory остаётся нормализованным source of truth. Device classification (`server-like`, `workstation-like`, `network-device-like`, `printer-like`, `iot-like`, `unknown`) — это hint с confidence и источниками сигнала, а не finding.

## Network Topology

```text
GET  /api/v1/audits/{audit_id}/topology
GET  /api/v1/topology/global
GET  /api/v1/audits/{audit_id}/topology/compare?against={baseline_audit_id}
POST /api/v1/audits/{audit_id}/topology/snmp
POST /api/v1/audits/{audit_id}/topology/ssh
```

`GET .../topology` строится из persisted normalized evidence и может принимать `traffic_analysis_job_id` для явно выбранного Traffic Analysis overlay. Ответ содержит canonical graph, presentation metadata, `coverage`, warnings и `partial/source_errors`, если часть ожидаемого evidence недоступна.

`topology/compare` использует только сохранённые данные и не запускает scanner, traceroute, SNMP или SSH.

SNMP/SSH enrichment — mutating auditor-only operations. Management target должен находиться внутри operator-confirmed active scope того же audit interface. Credentials передаются worker через ephemeral consume-once spool; plaintext secret material не записывается в topology evidence или обычные job parameters. SSH дополнительно требует strict host-key verification и не принимает произвольную remote-команду.

Полная модель evidence/claimability описана в [TOPOLOGY_MODEL.md](TOPOLOGY_MODEL.md).

## Global Correlation Analysis

Global Analysis объединяет persisted inventory/findings, явно выбранный Traffic Analysis и canonical Network Topology. Он не запускает scanner, не перечитывает PCAP и не выполняет новый network I/O.

Offline preview без сохранения нового artifact:

```text
GET /api/v1/audits/{audit_id}/global-analysis?traffic_analysis_job_id={job_id}
```

Durable запуск:

```text
POST /api/v1/audits/{audit_id}/global-analysis
```

```json
{
  "traffic_analysis_job_id": "completed-traffic-analysis-job-id",
  "priority": 0
}
```

Worker сохраняет `global_analysis_result` (`global-analysis` v1, retention `audit`). Запуск доступен `auditor`; `viewer` может читать сохранённые результаты.

История и чтение:

```text
GET /api/v1/audits/{audit_id}/global-analysis/history
GET /api/v1/jobs/{job_id}/global-analysis
GET /api/v1/jobs/{job_id}/global-analysis/export?format=json
GET /api/v1/jobs/{job_id}/global-analysis/export?format=text
GET /api/v1/jobs/{job_id}/global-analysis/export?format=markdown
```

History сохраняет immutable lifecycle каждого Global Analysis job, включая failed/cancelled/interrupted состояния. Канонический документ доступен только у `completed` job с зарегистрированным `global_analysis_result` правильного audit/job/schema.

Rebuild создаёт новый job и новый artifact:

```json
{
  "traffic_analysis_job_id": "same-traffic-analysis-job-id",
  "rebuild_of_job_id": "previous-completed-global-analysis-job-id"
}
```

Предыдущий result не изменяется. `rebuild_of_job_id` должен ссылаться на завершённый durable Global Analysis того же audit, а выбранный Traffic Analysis должен совпадать с предыдущим source. Это rebuild из текущих persisted normalized inputs, а не resume старого subprocess.

TXT/Markdown exports рендерятся из сохранённого canonical JSON без повторного анализа. Полная correlation/evidence модель описана в [GLOBAL_ANALYSIS_MODEL.md](GLOBAL_ANALYSIS_MODEL.md).

## Jobs и recovery

```text
GET  /api/v1/jobs
GET  /api/v1/jobs/{job_id}
POST /api/v1/jobs/{job_id}/cancel
POST /api/v1/jobs/{job_id}/retry
GET  /api/v1/jobs/{job_id}/events
GET  /api/v1/jobs/{job_id}/result
```

`retry` разрешён только для `failed`, `interrupted` и `cancelled` jobs. Историческая job остаётся неизменной; WireScope создаёт новую queued job с теми же параметрами и связывает обе записи через job events.

Исключение — credentialed management jobs `snmp_topology` и `ssh_topology`: их нельзя повторно поставить в очередь со старым consume-once `credential_ref`. Оператор запускает enrichment заново и предоставляет свежие credentials.

Это stage-level recovery. WireScope не пытается продолжить умерший subprocess с внутренней точки выполнения.

## Evidence

Для finding можно получить зарегистрированные evidence artifacts:

```text
GET /api/v1/audits/{audit_id}/findings/{finding_id}/evidence
```

Контент артефакта читается только через audit-scoped URL:

```text
GET /api/v1/audits/{audit_id}/artifacts/{artifact_id}
```

Перед выдачей проверяется принадлежность artifact к audit. Текстовые/JSON/XML evidence могут открываться inline; бинарные файлы отдаются как attachment. Ответ содержит `X-WireScope-SHA256`.

## Reports

```text
GET /api/v1/audits/{audit_id}/reports
GET /api/v1/audits/{audit_id}/reports/{report_id}
GET /api/v1/audits/{audit_id}/reports/{report_id}/export?format=json
GET /api/v1/audits/{audit_id}/reports/{report_id}/export?format=html
GET /api/v1/audits/{audit_id}/reports/{report_id}/export?format=markdown
```

JSON `audit-report` v1 остаётся каноническим документом. HTML и Markdown строятся из тех же persisted data и не запускают повторное сканирование. `format=md` — alias для Markdown. PDF пока не является частью v1 release gate.

## Operational audit log

```text
GET /api/v1/audit-log
```

Доступно только роли `auditor`. Поддерживаются фильтры `actor`, `action`, `audit_id`, `limit`, `offset`.

В журнал попадают значимые mutating operations: login/logout/password change, создание и запуск audit stages, Global Analysis generation/rebuild, cancel/retry, network changes, finding changes, report generation и maintenance cleanup. Для запуска Global Analysis используется stable action `global_analysis.generate`.

Журнал хранит request metadata, но **не** request body, пароль, session cookie или provider stdout.

## Lifecycle и retention

```text
GET  /api/v1/maintenance/status
POST /api/v1/maintenance/cleanup
```

`maintenance/status` показывает filesystem/evidence usage, SQLite state и текущую retention policy.

Cleanup использует явный двухшаговый контракт:

```json
{"confirm": false, "include_raw": true}
```

возвращает preview и ничего не удаляет.

```json
{"confirm": true, "include_raw": true}
```

разрешает удалить aged raw evidence по policy. Normalized inventory, findings и reports автоматически не удаляются.

Стандартные интервалы:

- temporary: 24 часа;
- debug: 7 дней;
- PCAP: 30 дней;
- Nmap XML / protocol raw output: 90 дней.

## Авторизация

Публичные routes:

- `GET /health`, `/status`, `/ready`;
- `POST /auth/login`, `/auth/logout`.

Остальные routes требуют локальную session. Обычные mutating endpoints требуют роль `auditor`; `viewer` может читать audits, inventory, findings, reports, diff, topology, Global Analysis и evidence. Operational audit log, diagnostics и maintenance доступны только auditor.

Сессия хранится в HttpOnly cookie. Подробнее: [SECURITY_MODEL.md](SECURITY_MODEL.md).

## Правило совместимости v1

В `/api/v1` допустимы совместимые добавления: новые optional fields и новые endpoints. Изменение, которое ломает существующий request/response contract, должно получать новую major API version, а не менять v1 молча.

Критерии, после которых WireScope можно пометить как `v1.0.0-rc1`, описаны в [RELEASE_READINESS.md](RELEASE_READINESS.md).
