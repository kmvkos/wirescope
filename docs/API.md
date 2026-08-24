# WireScope API

[English](en/API.md)

WireScope публикует канонический HTTP API под префиксом `/api/v1`. Старый `/api/*` пока остаётся скрытым compatibility alias, чтобы существующий frontend и внешние клиенты можно было переводить постепенно.

```text
/api/v1/...   основной контракт
/api/...      совместимый переходный alias
```

В OpenAPI/Swagger показывается только `/api/v1`.

## Базовые системные endpoints

```text
GET /api/v1/health
GET /api/v1/status
GET /api/v1/ready
GET /api/v1/environment
GET /api/v1/interfaces
GET /api/v1/capabilities
GET /api/v1/scan-profiles
```

`/health` отвечает на вопрос «API-процесс жив?». `/ready` проверяет SQLite, актуальность миграций, worker и обязательные для базовой работы `dumpcap`/`tshark`.

Отсутствие необязательного provider, например `ssh-audit`, `smbclient` или даже Nmap, больше не делает весь appliance `not_ready`. Полный список доступных функций и обнаруженных бинарников возвращает `/capabilities`.

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

`dashboard` собирается из существующих jobs, inventory и findings. Отдельной «dashboard database» нет.

`correlations` объясняет, за счёт каких сигналов пассивные и активные наблюдения попали в один asset: MAC, IP, источник имени, Nmap и т.д. Hostname сам по себе не используется как основание для автоматического объединения узлов.

`diff` сравнивает два сохранённых аудита и показывает появившиеся/исчезнувшие assets, открытые сервисы и findings. Сравнение строится на стабильной идентичности MAC → IP → имя как последний fallback; findings на разных сервисах одного узла не схлопываются в одну запись.

## Inventory

```text
GET /api/v1/audits/{audit_id}/assets
GET /api/v1/audits/{audit_id}/assets/{asset_id}
GET /api/v1/audits/{audit_id}/services
GET /api/v1/audits/{audit_id}/inventory
GET /api/v1/audits/{audit_id}/observations
```

Inventory остаётся нормализованным source of truth. Классификация (`server-like`, `workstation-like`, `network-device-like`, `printer-like`, `iot-like`, `unknown`) — это hint с confidence и источниками сигнала, а не finding.

## Jobs

```text
GET  /api/v1/jobs
GET  /api/v1/jobs/{job_id}
POST /api/v1/jobs/{job_id}/cancel
GET  /api/v1/jobs/{job_id}/events
GET  /api/v1/jobs/{job_id}/result
```

Job status и большие результаты разделены: список jobs не тянет сырые provider outputs.

## Evidence

Для finding можно получить зарегистрированные evidence-артефакты:

```text
GET /api/v1/audits/{audit_id}/findings/{finding_id}/evidence
```

Контент артефакта читается через audit-scoped URL:

```text
GET /api/v1/audits/{audit_id}/artifacts/{artifact_id}
```

Перед выдачей WireScope проверяет, что artifact действительно относится к этому audit. Текстовые/JSON/XML evidence можно открыть inline; бинарные файлы отдаются как attachment. В ответе также есть `X-WireScope-SHA256`.

## Reports

```text
GET /api/v1/audits/{audit_id}/reports
GET /api/v1/audits/{audit_id}/reports/{report_id}
GET /api/v1/audits/{audit_id}/reports/{report_id}/export?format=json
GET /api/v1/audits/{audit_id}/reports/{report_id}/export?format=html
GET /api/v1/audits/{audit_id}/reports/{report_id}/export?format=markdown
```

JSON `audit-report` v1 остаётся каноническим отчётом. HTML и Markdown — представления над теми же сохранёнными данными. Генерация export не запускает повторное сканирование.

`format=md` является коротким alias для Markdown. PDF пока не реализован.

## Авторизация

Публичные маршруты:

- `GET /health`, `/status`, `/ready`;
- `POST /auth/login`, `/auth/logout`.

Остальные routes требуют локальную сессию. Mutating endpoints требуют роль `auditor`; `viewer` может читать inventory, findings, reports, capabilities, diff и evidence.

Сессия хранится в HttpOnly cookie. Подробнее: [SECURITY_MODEL.md](SECURITY_MODEL.md).

## Правило совместимости v1

Внутри `/api/v1` допустимы совместимые добавления: новые optional поля и новые endpoints. Изменение, которое ломает существующий request/response contract, должно получать новую major-версию API, а не менять v1 молча.
