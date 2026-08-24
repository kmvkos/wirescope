# GUI WireScope

**Русский** · [English](en/GUI_MODEL.md)

GUI — основной интерфейс оператора. Для обычного аудита shell не требуется: создание audit, passive capture, подтверждение scope, active discovery, protocol audits, findings, evidence, reports и базовая диагностика доступны из браузера.

Frontend — клиент durable API. Закрытие вкладки, reload или restart kiosk не отменяют worker job.

## Где запускается GUI

Локальный kiosk открывает:

```text
http://127.0.0.1:8000/
```

Обычная appliance-установка слушает `0.0.0.0:8000`, поэтому удалённый оператор может открыть GUI через IP любого настроенного интерфейса WireScope.

## Frontend

Frontend остаётся без build framework:

```text
frontend/
├── index.html
├── app.js
├── i18n.js
├── style.css
├── enhancements.js
├── enhancements.css
└── operations.js
```

`app.js` содержит основной wizard. `enhancements.js` добавляет dashboard/diff/evidence/Markdown export. `operations.js` отдельно добавляет эксплуатационные функции для auditor.

## Основной audit flow

```text
login
  ↓
home
  ↓
new audit
  ↓
environment / interface
  ↓
network + scope
  ↓
profile
  ↓
confirmation
  ↓
passive → discovery → protocol → findings → report
  ↓
summary / inventory / evidence / report
```

## Pipeline

На progress/summary GUI показывает durable pipeline:

```text
Пассивный анализ
      ↓
Discovery
      ↓
Протоколы
      ↓
Findings
      ↓
Отчёт
```

Состояние вычисляется из jobs в SQLite. Браузер не хранит отдельную state machine.

## Панель «Обзор»

После успешного login панель позволяет выбрать любой сохранённый audit. На login-screen кнопка скрыта.

### «Обзор»

Показывает assets, services, findings, Critical/High counts, passive+active correlation, pipeline, device classes и наиболее частые сервисы.

```text
GET /api/v1/audits/{audit_id}/dashboard
GET /api/v1/audits/{audit_id}/correlations
```

### «Система»

Показывает runtime capabilities, effective listener и загруженные scan profiles:

```text
GET /api/v1/capabilities
GET /api/v1/scan-profiles
```

Отсутствующий optional provider отображается как недоступная capability, а не как успешная проверка.

### «Сравнение»

```text
GET /api/v1/audits/{new_id}/diff?against={old_id}
```

GUI группирует новые/исчезнувшие assets, open services и findings.

### «Evidence»

```text
GET /api/v1/audits/{audit_id}/findings/{finding_id}/evidence
GET /api/v1/audits/{audit_id}/artifacts/{artifact_id}
```

Text/JSON/XML evidence раскрывается inline; binary artifacts открываются отдельно. Artifact access всегда audit-scoped.

### «Эксплуатация»

Эта вкладка показывается только `auditor` и реализована отдельным `operations.js`.

Она использует:

```text
GET  /api/v1/diagnostics
GET  /api/v1/diagnostics/export
GET  /api/v1/audits/{audit_id}/jobs
POST /api/v1/jobs/{job_id}/retry
POST /api/v1/maintenance/cleanup
```

На экране видны:

- runtime ready/not-ready;
- SQLite `quick_check`;
- worker/core tools;
- свободное место;
- размер evidence store;
- retention policy и количество cleanup candidates;
- failed/interrupted/cancelled jobs выбранного audit;
- последние operational events.

Cleanup намеренно двухшаговый. Сначала **«Предпросмотр очистки»** делает запрос с `confirm=false`. Кнопка фактического удаления дополнительно требует browser confirmation и отправляет `confirm=true`.

Retry создаёт новую durable job и не переписывает terminal job.

## Device classification

GUI показывает classification, вычисленную inventory layer:

```text
server-like
workstation-like
network-device-like
printer-like
iot-like
unknown
```

Classification — confidence-rated hint, не finding.

## Роли

| Действие | Auditor | Viewer |
| --- | --- | --- |
| Читать audits/jobs/inventory/findings/reports | да | да |
| Dashboard / diff / capabilities / evidence | да | да |
| Сменить собственный пароль | да | да |
| Создать audit | да | нет |
| Запустить/отменить job | да | нет |
| Retry terminal job | да | нет |
| Listen / Record | да | нет |
| Изменить network settings | да | нет |
| Изменить finding state | да | нет |
| Сгенерировать report | да | нет |
| Diagnostics / audit log / maintenance | да | нет |

Backend проверяет role независимо от видимости кнопки во frontend.

## Session

После login backend выдаёт HttpOnly cookie. Token случайный; в SQLite хранится SHA-256 digest. `SameSite=strict`; `Secure` включается для direct TLS/trusted proxy deployment.

Активный audit id frontend хранит в `sessionStorage` только для восстановления UI после reload. Source of truth — backend/SQLite.

## Summary / observations / assessment / findings

- **Summary** — короткая картина аудита и pipeline;
- **Observations** — нормализованные факты sensors/protocol modules;
- **Assessment** — интерпретации passive evidence с confidence;
- **Findings** — rule-engine conclusions с severity/recommendation/state.

Passive sensor hit сам по себе finding не создаёт.

## VLAN display

VLAN ID показывается как реально увиденный только при наличии 802.1Q tag. Untagged access traffic не получает выдуманный VLAN ID. LLDP/CDP native/voice VLAN остаётся neighbor metadata.

## Listen / Record

Отдельный `packet_capture` job принимает interface, optional BPF/tcpdump filter, duration и max PCAP size. Promiscuous mode записывает всё, что NIC реально принимает, но не превращает switch port в SPAN.

## Network screen

Network settings идут через backend `NetworkService`/`netctl`. Потенциально опасное изменение management path требует server-side confirmation.

## Reports

GUI умеет открывать HTML и экспортировать JSON/Markdown. Markdown-кнопка добавляется `enhancements.js` и использует `/api/v1` export endpoint. PDF пока возвращает `422 pdf_not_available` и не блокирует v1.0.

## Ошибки и recovery

GUI различает validation/provider/timeout/cancellation/authorization/network errors. Terminal failed/interrupted/cancelled job может быть явно повторена auditor через Operations. Автоматического бесконтрольного retry нет.

## Kiosk lifecycle

```text
wirescope-api      переживает restart Chromium
wirescope-worker   переживает restart Chromium
wirescope-kiosk    может рестартовать независимо
```

Экран — клиент, не executor.

## Тестирование

Fixture/API tests проверяют roles и workflow. Static regression tests контролируют подключение enhancement modules, audit-scoped evidence, Markdown и operations lifecycle UI. Optional Playwright tests остаются `browser` marker. Основной CI выполняет compileall и default pytest suite.

Release checklist находится в [RELEASE_READINESS.md](RELEASE_READINESS.md).
