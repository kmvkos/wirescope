# WireScope v1.3 — live validation

[English](en/V1_3_LIVE_VALIDATION.md)

Этот runbook закрывает последний gate v1.3 Global Correlation Analysis на установленной WireScope VM. Он не предназначен для разработки нового функционала: задача — проверить upgrade, durable execution, persisted result, history/rebuild/exports и operator GUI на реальных сохранённых данных.

## Условия перед началом

Нужны:

- установленный WireScope appliance;
- доступ к Git checkout проекта (обычно `/opt/wirescope`, если установка выполнена туда);
- работающие `wirescope-api.service` и `wirescope-worker.service` до обновления;
- хотя бы один Deep audit и один completed Traffic Analysis. Если их нет, их можно создать после upgrade обычным UI workflow;
- auditor account для запуска Global Analysis.

Global Analysis не должен создавать новый network I/O: он работает поверх persisted inventory/findings, выбранного Traffic Analysis и Network Topology.

## 1. Зафиксировать состояние до upgrade

В каталоге проекта:

```bash
cd /opt/wirescope
git status --short
git branch --show-current
git rev-parse HEAD
```

Не продолжать с неожиданными незакоммиченными изменениями, которые могут быть затёрты переключением ветки.

Проверить текущие сервисы:

```bash
systemctl --no-pager --full status wirescope-api.service wirescope-worker.service
```

Если используется kiosk:

```bash
systemctl is-enabled wirescope-kiosk.service
```

## 2. Перейти на v1.3 branch

```bash
cd /opt/wirescope
git fetch origin
git switch v1.3-global-correlation-analysis
git pull --ff-only origin v1.3-global-correlation-analysis
git rev-parse HEAD
```

Записать полученный commit SHA в результаты проверки.

## 3. Выполнить штатный upgrade

```bash
cd /opt/wirescope
sudo ./packaging/upgrade.sh
```

`packaging/upgrade.sh` повторно использует installer, применяет migrations и затем явно перезапускает API/worker. Если kiosk включён, он также перезапускается.

После завершения:

```bash
systemctl --no-pager --full status wirescope-api.service wirescope-worker.service
```

Оба сервиса должны быть `active (running)`.

## 4. Проверить readiness

Default API port — `8000`, если `WIRESCOPE_BIND_PORT` не переопределён.

```bash
curl -fsS http://127.0.0.1:8000/api/v1/ready | python3 -m json.tool
```

Если используется другой port, взять фактическое значение из конфигурации/systemd environment и повторить запрос.

Критерий: endpoint отвечает успешно, database/migrations/worker и обязательные capture tools не переводят appliance в `not_ready`.

Дополнительно:

```bash
curl -fsS http://127.0.0.1:8000/api/v1/health | python3 -m json.tool
```

## 5. Проверить сохранённые входные данные

В web/kiosk UI:

1. убедиться, что существующие audits после upgrade видны;
2. убедиться, что существующие Traffic Analysis results видны;
3. выбрать completed Deep audit с нормальным inventory/findings/topology evidence;
4. выбрать конкретный completed Traffic Analysis. Выбор должен быть явным — Global Analysis не подставляет «последний PCAP» автоматически.

Если подходящих данных нет, создать новый Deep audit и новый Traffic Analysis обычным workflow WireScope, затем вернуться к этому runbook.

## 6. Запустить durable Global Analysis

На домашнем экране открыть **«Глобальный анализ»**.

Проверить:

- workspace открывается без JS/UI ошибки;
- в selector видны retained audits;
- в Traffic Analysis selector видны completed traffic-analysis jobs;
- viewer не получает mutating controls;
- auditor может запустить анализ.

Выбрать Deep audit и Traffic Analysis, затем нажать запуск.

Во время выполнения должны отображаться queued/running state, stage/message и progress. После завершения job должен стать `completed` и появиться в history.

## 7. Проверить canonical result

Открыть завершённый result в workspace.

Обязательные признаки:

- `schema = global-analysis`;
- `schema_version = 1`;
- выбранный `traffic_analysis_job_id` соответствует операторскому выбору;
- durable `execution.job_id` соответствует job из history;
- `network_io = false`;
- присутствуют `summary`, `source_health`, `coverage`, `evidence_references`, `operator_summary`;
- есть `infrastructure_consistency.gateway/dhcp/dns`;
- `partial=true`, если upstream topology/report evidence действительно partial/missing; отсутствие evidence не маскируется как complete;
- hostname-only identity не появляется как основание merge;
- private unknown endpoint не называется Internet/external без global-IP evidence.

Допустимы `consistent`, `divergent` и `insufficient` в infrastructure consistency. `divergent` — самостоятельный аналитический результат, а не crash.

## 8. Проверить exports

Из того же result скачать:

- JSON;
- TXT;
- Markdown.

Проверить:

- JSON остаётся canonical `global-analysis` v1;
- TXT/Markdown читаемы и содержат operator summary/consistency/external communications;
- export не запускает новый Global Analysis job;
- export не вызывает новый scanner/capture;
- evidence lineage не содержит внутренних filesystem paths.

## 9. Проверить immutable rebuild

Сохранить/скачать JSON первого result и его job ID.

Нажать **«Пересобрать»**.

Ожидается:

- создаётся новый Global Analysis job;
- используется тот же selected Traffic Analysis;
- новый job имеет новый ID;
- новый result имеет новый artifact/result reference;
- `execution.rebuild_of_job_id` указывает на первый Global Analysis job;
- старый result остаётся доступен в history и не меняется;
- новый result также проходит canonical checks из раздела 7.

Попытка пересобрать результат с другим Traffic Analysis должна быть отклонена API/UI, а не создавать двусмысленную lineage.

## 10. Проверить history и operational log

History должен показывать как минимум первоначальный completed run и rebuild в правильном порядке, с сохранёнными source/rebuild IDs.

В operational audit log запуск Global Analysis должен фиксироваться stable action:

```text
global_analysis.generate
```

Request body, credentials и provider stdout в operational log попадать не должны.

## 11. Проверить отсутствие regressions appliance

После Global Analysis снова проверить:

```bash
systemctl --no-pager --full status wirescope-api.service wirescope-worker.service
curl -fsS http://127.0.0.1:8000/api/v1/ready | python3 -m json.tool
```

Также открыть обычные экраны WireScope и убедиться, что доступны как минимум:

- audits/inventory/findings;
- Traffic Analysis;
- Network Topology;
- reports.

Global Analysis не должен ломать основной audit pipeline.

## 12. Критерии закрытия v1.3

v1.3 можно закрывать checkpoint/tag только если одновременно выполнено:

- branch CI зелёный;
- upgrade прошёл штатно;
- API и worker healthy/readiness green;
- retained state не потерян;
- durable Global Analysis на реальных данных завершился успешно;
- canonical JSON соответствует `global-analysis` v1;
- partial/evidence quality отображаются честно;
- GUI пригоден для запуска и чтения результата;
- history работает;
- immutable rebuild работает;
- JSON/TXT/Markdown exports работают;
- operational action фиксируется;
- основной WireScope workflow после обновления не сломан.

Если любой пункт не выполнен, v1.3 не тегировать: сохранить job ID/result/error и исправить причину в feature branch.

## Результат проверки

Рекомендуемый короткий протокол:

```text
commit: <sha>
upgrade: PASS/FAIL
ready: PASS/FAIL
deep audit: <audit-id>
traffic analysis: <job-id>
global analysis: <job-id> PASS/FAIL
partial: true/false
rebuild: <job-id> PASS/FAIL
exports: JSON/TXT/MD PASS/FAIL
history: PASS/FAIL
audit log: PASS/FAIL
regression smoke: PASS/FAIL
notes: ...
```
