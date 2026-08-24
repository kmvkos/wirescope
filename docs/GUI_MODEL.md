# GUI WireScope

**Русский** · [English](en/GUI_MODEL.md)

GUI — основной интерфейс оператора. Для обычного аудита shell не требуется: создание audit, passive capture, подтверждение scope, active discovery, protocol audits, findings, evidence и reports доступны из браузера.

Frontend остаётся клиентом durable API. Закрытие вкладки, reload или restart kiosk не отменяют worker job.

## Где запускается GUI

### Локальный kiosk

Chromium работает на самом appliance и открывает:

```text
http://127.0.0.1:8000/
```

System kiosk занимает `tty1` без полноценного GNOME/KDE/XFCE. На VMware используется Xorg/xinit, на подходящем железе возможен Cage.

### Удалённый browser

Обычная appliance-установка WireScope слушает `0.0.0.0:8000`, поэтому оператор может открыть GUI через IP любого настроенного интерфейса устройства:

```text
http://<wirescope-ip>:8000/
```

При необходимости deployment можно ужесточить firewall, direct TLS или reverse proxy. Ограничение bind до `127.0.0.1` — явная опция конкретной установки, а не default WireScope.

## Frontend

Frontend намеренно остаётся без build framework:

```text
frontend/
├── index.html
├── app.js
├── i18n.js
├── style.css
├── enhancements.js
└── enhancements.css
```

`app.js` содержит основной wizard и существующие рабочие экраны. `enhancements.js` подключается отдельно и добавляет operator-insights без переписывания основного workflow.

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

На progress/summary GUI показывает общий pipeline:

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

Состояние каждой стадии вычисляется из durable jobs. GUI не хранит отдельную копию pipeline state.

Для стадии отображаются status, progress и связанный job id, если job уже создавался.

## Обзор WireScope

После успешного входа дополнительная панель **«Обзор»** доступна поверх существующего wizard и позволяет выбрать любой сохранённый audit. На login-screen кнопка не показывается.

### Вкладка «Обзор»

Показывает:

- количество assets;
- количество services;
- findings;
- Critical/High counts;
- сколько assets имеют одновременно passive и active evidence;
- pipeline;
- device-class distribution;
- наиболее частые открытые сервисы.

Данные приходят из:

```text
GET /api/v1/audits/{audit_id}/dashboard
GET /api/v1/audits/{audit_id}/correlations
```

Отдельной dashboard database нет.

### Вкладка «Система»

Показывает доступность внешних инструментов и реально загруженные active scan profiles.

```text
GET /api/v1/capabilities
GET /api/v1/scan-profiles
```

Оператор сразу видит, например, что packet capture доступен, но SSH audit недоступен из-за отсутствующего `ssh-audit`.

Также отображается web listener: bind host/port, TLS и trust-proxy state.

### Вкладка «Сравнение»

Позволяет сравнить два сохранённых аудита:

```text
GET /api/v1/audits/{new_id}/diff?against={old_id}
```

GUI группирует:

- новые/исчезнувшие assets;
- новые/исчезнувшие открытые services;
- новые/исчезнувшие findings.

Diff строится backend'ом по persisted state; frontend только отображает результат.

### Вкладка «Evidence»

Для каждого finding GUI запрашивает зарегистрированные evidence artifacts:

```text
GET /api/v1/audits/{audit_id}/findings/{finding_id}/evidence
```

Текстовые/JSON/XML evidence можно раскрыть inline. Бинарные artifacts открываются/download'ятся отдельным запросом.

Канонический artifact URL всегда содержит audit id:

```text
GET /api/v1/audits/{audit_id}/artifacts/{artifact_id}
```

## Device classification

GUI показывает только классификацию, которую уже вычислил inventory layer:

```text
server-like
workstation-like
network-device-like
printer-like
iot-like
unknown
```

Classification hint не превращается в security finding. В API доступны confidence и источники сигнала.

## Роли

Локальные роли:

- `auditor`;
- `viewer`.

| Действие | Auditor | Viewer |
| --- | --- | --- |
| Просмотр audits/jobs/inventory/findings/reports | да | да |
| Dashboard / diff / capabilities / evidence | да | да |
| Смена собственного пароля | да | да |
| Создание audit | да | нет |
| Запуск/отмена jobs | да | нет |
| Listen / Record | да | нет |
| Изменение network settings | да | нет |
| Finding state changes | да | нет |
| Генерация report | да | нет |

Backend проверяет role независимо от того, скрыта ли кнопка во frontend.

## Session

После login backend выдаёт HttpOnly cookie. Token случайный; в SQLite хранится SHA-256 digest. `SameSite=strict`; `Secure` включается для direct TLS/trusted proxy сценария.

Активный audit id frontend хранит в `sessionStorage`, чтобы после reload вернуть пользователя на progress/summary. Это только UI convenience; source of truth — backend/SQLite.

## Summary / observations / assessment / findings

Эти сущности не смешиваются:

- **Summary** — короткая картина аудита и pipeline;
- **Observations** — нормализованные факты protocol modules;
- **Assessment** — интерпретации passive evidence с confidence;
- **Findings** — rule-engine conclusions с severity/recommendation/state.

Passive sensor hit сам по себе finding не создаёт.

## VLAN display

VLAN ID показывается как реально увиденный только при наличии 802.1Q tag в кадре. Untagged access traffic не получает выдуманный VLAN ID. LLDP/CDP native/voice VLAN остаётся neighbor metadata и не смешивается с frame tag.

## «Прослушивание» / Listen & Record

Отдельный `packet_capture` job принимает:

- interface;
- optional BPF/tcpdump filter;
- duration;
- max PCAP size.

`dumpcap` работает promiscuous, но это не заставляет switch отправлять на порт весь traffic сегмента. PCAP сохраняется в evidence store.

## Network screen

Network settings идут через backend `NetworkService`/`netctl`. Потенциально опасное изменение management path требует дополнительного confirmation на backend; JavaScript не может обойти эту проверку.

## Reports

GUI умеет:

- запускать report generation для `auditor`;
- просматривать report history;
- открывать HTML;
- экспортировать JSON;
- экспортировать Markdown.

Markdown-кнопка добавляется модулем `enhancements.js` рядом с существующим JSON export и использует канонический `/api/v1` export endpoint.

PDF пока возвращает `422 pdf_not_available`.

## Ошибки

GUI различает как минимум:

- validation error;
- worker not ready;
- optional provider unavailable;
- timeout;
- cancellation;
- partial result;
- authorization/role error;
- network apply confirmation/error.

Отсутствующий provider не должен отображаться как «проверка пройдена» или «ничего не найдено».

## Kiosk lifecycle

```text
wirescope-api      переживает restart Chromium
wirescope-worker   переживает restart Chromium
wirescope-kiosk    может рестартовать независимо
```

Экран — не executor.

## Тестирование

Backend/API GUI contracts тестируются fixture-based. Static regression tests отдельно проверяют, что `enhancements.js/.css` реально подключены к `index.html`, evidence viewer использует audit-scoped URL, а Markdown export остаётся интегрированным. Optional Playwright tests помечены `browser` и пропускаются, если Playwright/Chromium не установлен. Основной CI также компилирует Python sources и запускает default `pytest` suite.
