# GUI WireScope

**Русский** · [English](en/GUI_MODEL.md)

GUI — основной интерфейс оператора. Для обычного аудита shell не требуется: создание audit, passive capture, подтверждение scope, active discovery, protocol audits, findings, evidence, reports, Traffic Analysis, Network Topology и базовая диагностика доступны из браузера.

Frontend — клиент durable API. Закрытие вкладки, reload или restart kiosk не отменяют worker jobs.

## Где запускается GUI

Локальный kiosk открывает:

```text
http://127.0.0.1:8000/
```

Обычная appliance-установка слушает `0.0.0.0:8000`, поэтому удалённый оператор может открыть GUI через IP любого настроенного интерфейса WireScope.

## Frontend и visual layer

Frontend остаётся без build framework. Основной wizard живёт в `frontend/app.js`, а дополнительные функции вынесены в отдельные modules.

Topology использует отдельные presentation modules поверх canonical API. Browser не является source of truth: topology, jobs, inventory, findings и evidence строятся из backend/SQLite/evidence store.

Root page отдаётся с `Cache-Control: no-store`, а CSS/JS получают version query string. Это важно для topology renderer: после upgrade Chromium не должен продолжать использовать старые JS/CSS.

`packaging/upgrade.sh` перезапускает kiosk browser после успешного upgrade, если kiosk включён; API/worker jobs при этом не отменяются.

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
summary / inventory / evidence / traffic / topology
```

Pipeline state вычисляется из durable jobs в SQLite. Браузер не хранит отдельную state machine аудита.

## Панель «Обзор»

После login можно выбрать сохранённый audit и открыть operator views.

### «Обзор»

Показывает assets, services, findings, Critical/High counts, passive+active correlation, pipeline, device classes и частые сервисы.

```text
GET /api/v1/audits/{audit_id}/dashboard
GET /api/v1/audits/{audit_id}/correlations
```

### «Система»

Показывает runtime capabilities, listener и scan profiles:

```text
GET /api/v1/capabilities
GET /api/v1/scan-profiles
```

Отсутствующий optional provider отображается как unavailable capability, а не как successful check.

### «Сравнение»

```text
GET /api/v1/audits/{new_id}/diff?against={old_id}
```

GUI группирует появившиеся/исчезнувшие assets, open services и findings.

### «Evidence»

```text
GET /api/v1/audits/{audit_id}/findings/{finding_id}/evidence
GET /api/v1/audits/{audit_id}/artifacts/{artifact_id}
```

Text/JSON/XML evidence раскрывается inline; binary artifacts открываются отдельно. Artifact access всегда audit-scoped.

## Network Topology workspace

Topology — отдельный operator workspace, а не декоративное приложение к inventory.

Основной endpoint:

```text
GET /api/v1/audits/{audit_id}/topology
```

Для явно выбранного PCAP overlay передаётся `traffic_analysis_job_id`. WireScope не выбирает «последний capture» автоматически.

### Представления

Доступны:

- **Structural** — основная infrastructure-first схема;
- **L2** — доказанные physical/adjacency/port relationships;
- **L3** — subnet/gateway/router/interface relationships;
- **Traffic** — communication graph выбранного Traffic Analysis;
- **All evidence** — расширенное техническое представление canonical graph;
- **VLAN focus** — evidence-backed VLAN/port context;
- **История topology** — сравнение двух retained audits.

Structural view специально уменьшает шум: directed broadcast, uncorrelated link-local endpoints и PCAP-only external addresses не должны выглядеть как обычные infrastructure hosts.

### Coverage / достаточность данных

GUI показывает `coverage` для:

```text
inventory
l3
l2
traffic
vlan
wifi
hypervisor
```

Статусы:

```text
sufficient
partial
missing
```

Это не процент «изученности сети». `missing` означает, что WireScope не имеет evidence, достаточного для соответствующего класса утверждений. Интерфейс должен показывать оператору, каких данных не хватает, а не скрывать ограничение.

### Topology controls

Поддерживаются:

- zoom;
- pan;
- fit;
- subnet focus;
- confidence filters;
- asset details;
- edge details;
- findings на assets;
- явный Traffic overlay;
- global retained-audit topology.

### Export

Доступны:

- canonical topology JSON;
- полная structural SVG diagram;
- PNG structural diagram;
- SVG текущего viewport;
- VLAN JSON/SVG;
- topology diff JSON.

Полный diagram export не обязан повторять текущий viewport: это отдельный layout для читаемой выгрузки всей структурной схемы.

### Management enrichment

Auditor может запускать optional read-only enrichment:

```text
POST /api/v1/audits/{audit_id}/topology/snmp
POST /api/v1/audits/{audit_id}/topology/ssh
```

Target должен находиться внутри confirmed scope.

SNMP form принимает read-only v2c/v3 credentials.

SSH form предназначена для Linux/OpenWrt-подобных managed devices, требует verified host key и не позволяет вводить arbitrary remote command. Credential material не должен отображаться после отправки и не хранится в persisted topology как plaintext.

Если конкретный MIB/SSH capability недоступен, UI показывает partial/missing evidence вместо фиктивной topology.

Подробнее: [TOPOLOGY_MODEL.md](TOPOLOGY_MODEL.md).

## Traffic Analysis

Отдельный `packet_capture` сохраняет PCAP. После этого оператор может запустить deterministic Traffic Analysis без нового capture.

Traffic Analysis и Network Topology остаются связанными, но разными views: первый отвечает «какой обмен был виден capture point», второй — «какие структурные/сетевые relationships подтверждаются evidence».

## «Эксплуатация»

Вкладка доступна только `auditor` и показывает:

- runtime ready/not-ready;
- SQLite `quick_check`;
- worker/core tools;
- disk/evidence usage;
- retention policy;
- retryable jobs;
- operational events;
- diagnostics export.

Cleanup двухшаговый: preview не удаляет данные; actual cleanup требует отдельного confirmation.

Generic retry создаёт новую durable job. Credentialed SNMP/SSH topology jobs нельзя повторять со старым credential reference — enrichment запускается заново.

## Device classification

GUI показывает inventory classification:

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
| Читать audits/jobs/inventory/findings/reports/topology | да | да |
| Dashboard / diff / capabilities / evidence | да | да |
| Смотреть topology/traffic/history | да | да |
| Сменить собственный пароль | да | да |
| Создать audit | да | нет |
| Запустить/отменить job | да | нет |
| Listen / Record | да | нет |
| SNMP/SSH topology enrichment | да | нет |
| Изменить network settings | да | нет |
| Изменить finding state | да | нет |
| Сгенерировать report | да | нет |
| Diagnostics / audit log / maintenance | да | нет |

Backend проверяет role независимо от видимости кнопки во frontend.

## Session

После login backend выдаёт HttpOnly cookie. Token случайный; в SQLite хранится SHA-256 digest. `SameSite=strict`; `Secure` включается для direct TLS/trusted proxy deployment.

Активный audit id может храниться в `sessionStorage` только как UI convenience. Source of truth — backend.

## VLAN display

Пассивный VLAN ID считается observed только при реальном 802.1Q tag.

В topology VLAN membership может дополнительно подтверждаться FDB/Q-BRIDGE/management evidence. Trunk/hybrid без точного endpoint VLAN не заставляет GUI назначить один произвольный VLAN.

## Network screen

Network settings идут через backend `NetworkService`/`netctl`. Потенциально опасное изменение management path требует server-side confirmation.

## Reports

GUI открывает human-readable HTML и экспортирует canonical JSON/Markdown. Reports строятся из persisted data и не запускают новый network audit.

## Ошибки и recovery

GUI различает validation/provider/timeout/cancellation/authorization/network errors.

Topology дополнительно показывает `partial`, `source_errors` и `coverage`, чтобы потеря одного management artifact не выглядела как полноценная карта.

## Kiosk lifecycle

```text
wirescope-api      переживает restart Chromium
wirescope-worker   переживает restart Chromium
wirescope-kiosk    может рестартовать независимо
```

Экран — клиент, не executor.

## Тестирование

CI проверяет compileall, default pytest, Chromium regression, wheel build и installed-wheel smoke.

Browser regression для topology покрывает structural rendering, filters, zoom/focus, bounded layout, findings, exports и VLAN focus. Live smoke M11.4 выполнен на обновлённой WireScope VM; vendor-specific SNMP/SSH interoperability проверяется дополнительно при наличии подходящих managed devices.