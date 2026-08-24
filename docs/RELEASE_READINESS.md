# Готовность WireScope к v1.0

**Русский** · [English](en/RELEASE_READINESS.md)

У WireScope должен быть момент, когда разработку можно перестать оценивать по принципу «ещё можно что-нибудь добавить» и начать оценивать как продукт. Для первой стабильной версии этим моментом является **WireScope v1.0 RC1**.

RC1 не означает, что в проекте больше никогда не появятся новые protocol modules, форматы отчётов или визуализация топологии. Он означает другое: основной сценарий аудита и эксплуатация самого appliance достаточно предсказуемы, чтобы пользоваться WireScope не как лабораторным прототипом, а как инструментом.

## Что считается финишем

WireScope можно пометить как `1.0.0-rc1`, только если выполнены все обязательные проверки ниже.

### 1. Установка и обновление

- чистая установка проходит на поддерживаемом Linux;
- upgrade существующей установки выполняет Alembic migrations и не теряет audits/evidence;
- API и worker запускаются после установки и после upgrade;
- `0.0.0.0:8000` остаётся штатным listener по умолчанию;
- GUI доступен через IP любого настроенного интерфейса устройства;
- kiosk по-прежнему может открывать локальный `127.0.0.1:8000`;
- `dumpcap` остаётся единственной packet-capture privilege boundary, backend/worker не запускаются от root.

### 2. Состояние данных

- SQLite открывается;
- Alembic revision соответствует текущему head;
- `PRAGMA quick_check` возвращает `ok`;
- backup создаётся штатной командой appliance;
- restore проходит `integrity_check` и возвращает базу/evidence в рабочее состояние;
- перезапуск API/worker не повреждает уже завершённый audit.

### 3. Авторизация и роли

- auditor может выполнять mutating operations;
- viewer может читать результаты, но не запускать/отменять задания и не менять настройки;
- login/logout/password change работают после upgrade;
- session cookie не доступна JavaScript;
- пароли и session tokens не попадают в operational audit log.

### 4. Полный audit workflow

На реальном тестовом сегменте должен пройти путь:

```text
login
  ↓
выбор interface
  ↓
passive capture
  ↓
подтверждение scope
  ↓
active discovery
  ↓
protocol audits
  ↓
findings
  ↓
report
```

При этом:

- passive capture действительно создаёт observations/inventory;
- active discovery никогда не выходит за подтверждённый scope;
- отсутствие optional provider отображается как `unavailable`, а не как «проверка пройдена»;
- failed/timeout/cancelled job не маскируется под успешный результат;
- inventory, findings и report остаются читаемыми после reload браузера.

### 5. Результаты аудита

Проверяются:

- asset inventory;
- services;
- device classification + confidence;
- passive/active correlation;
- findings + evidence;
- HTML report;
- JSON report;
- Markdown report;
- audit-to-audit diff.

VLAN ID считается реально наблюдаемым только при наличии 802.1Q tag. Untagged traffic не получает выдуманный VLAN.

### 6. Recovery

После принудительного restart worker во время job:

- job становится `interrupted`;
- resource lock освобождается;
- audit не остаётся навечно в `running`;
- оператор может явно повторить interrupted/failed/cancelled stage;
- retry создаёт новую durable job и не переписывает историю старой;
- уже завершённые этапы аудита не требуется повторять вручную без необходимости.

WireScope не пытается «продолжить Nmap с того же байта». Recovery работает на уровне durable stage.

### 7. Lifecycle и место на диске

Diagnostics должен показывать:

- состояние SQLite;
- migration state;
- worker readiness;
- core tool readiness;
- свободное место;
- размер evidence store;
- retention policy.

Очистка данных должна быть безопасной:

- preview не удаляет файлы;
- raw evidence удаляется только после явного подтверждения;
- обычная housekeeping-очистка может удалять stale temporary/orphan data;
- normalized inventory/findings/reports автоматически не удаляются;
- удаление aged PCAP/Nmap XML/protocol raw output не должно удалять нормализованный audit history.

Текущая стандартная policy:

| Данные | Значение |
| --- | ---: |
| Temporary artifacts | 24 часа |
| Debug artifacts | 7 дней |
| PCAP | 30 дней |
| Nmap XML / protocol raw evidence | 90 дней |
| Normalized audit history | не удаляется автоматически |

Policy можно изменить environment variables без изменения кода.

### 8. Operational audit log

Для значимых действий сохраняются как минимум:

- login, включая неуспешный;
- logout;
- password change;
- создание audit;
- passive/active/protocol starts;
- cancel/retry job;
- network changes;
- finding state changes;
- report generation;
- maintenance cleanup.

Запись содержит время, actor, role, action, HTTP status и client IP. Request body, пароль, cookie и provider stdout в этот журнал не копируются.

### 9. Diagnostics

`GET /api/v1/diagnostics` должен давать достаточный снимок состояния, чтобы начать troubleshooting без SSH:

- version/platform/Python;
- bind/TLS/proxy;
- runtime checks;
- capabilities;
- database quick-check;
- disk/evidence usage;
- retention candidates;
- последние operational events.

`/api/v1/diagnostics/export` должен отдавать тот же безопасный снимок JSON-файлом.

### 10. CI

Перед RC1 обязательно:

```bash
python -m compileall ...
pytest
```

Оба этапа должны быть зелёными на последнем commit кандидата. Не допускается «зелёный CI» за счёт отключения упавших regression tests.

### 11. Живой smoke-test

CI не заменяет appliance. Последняя обязательная проверка проводится на реально установленной WireScope VM/host после upgrade.

Минимум:

1. обновить checkout;
2. выполнить штатный `packaging/upgrade.sh`;
3. проверить migration head;
4. перезапустить API/worker;
5. открыть GUI с другого хоста по IP WireScope;
6. проверить login;
7. открыть Capabilities/Diagnostics;
8. выполнить passive audit;
9. выполнить Standard audit на разрешённом тестовом scope;
10. проверить assets/services/findings/evidence;
11. открыть HTML report и скачать JSON/Markdown;
12. выполнить второй audit и проверить diff;
13. искусственно прервать одну job рестартом worker и проверить retry;
14. проверить retention preview;
15. создать backup.

Только после этого кандидат получает tag:

```text
v1.0.0-rc1
```

## Когда можно сказать «продукт готов»

После успешного RC1 smoke-test WireScope можно считать **достаточно зрелым для регулярного использования в контролируемом сетевом аудите**.

Перед tag `v1.0.0` желательно провести несколько реальных аудитов на разных сегментах и убедиться, что не возникло release-blocking ошибок установки, persistence, scope control или отчётности. Наличие новых идей само по себе не блокирует 1.0.

## Что не блокирует v1.0

Следующие вещи полезны, но не являются обязательными для первой стабильной версии:

- PDF export;
- React/Vue или другой frontend framework;
- PostgreSQL/Redis/Celery;
- микросервисы;
- topology graph;
- CVE enrichment;
- scheduled audits;
- историческая identity-корреляция между большим количеством аудитов;
- FTP/SMTP/RDP/Redis/DB/MQTT/VNC и другие дополнительные protocol modules;
- полный отказ от совместимого `/api/*` alias;
- автоматическая очистка всей истории аудитов.

Они входят в post-1.0 roadmap и не должны бесконечно сдвигать дату, когда WireScope становится нормальным рабочим инструментом.
