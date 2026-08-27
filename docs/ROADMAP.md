# WireScope — Roadmap после 1.0

Этот документ описывает развитие WireScope после feature freeze базовой линии v1.0.

Новые возможности не должны ослаблять базовые safety-контракты: пассивное наблюдение не является разрешением на активное сканирование, active scope подтверждается оператором, внешние инструменты запускаются без shell, а выводы должны ссылаться на сохранённые evidence.

## v1.0 — базовый сетевой аудитор

Статус: **feature complete / frozen**.

В базовую линию входят:

- пассивный анализ локального сегмента;
- отдельное прослушивание и сохранение PCAP;
- operator-confirmed active scope;
- профили Discovery / Standard / Deep;
- inventory и консервативная identity correlation;
- protocol audits;
- findings + evidence;
- HTML / JSON / Markdown отчёты;
- audit diff, evidence viewer, diagnostics, retention и recovery;
- web/kiosk UI;
- backup/restore и эксплуатационный контур appliance.

После freeze в v1.0 допускаются исправления дефектов и release engineering, но не новые крупные подсистемы.

---

## v1.1 — PCAP Traffic Analysis

Статус: **implementation complete; основные live-сценарии пройдены**.

Цель v1.1 — превратить сохранённый PCAP в самостоятельный источник сетевой диагностики без нового захвата и без повторного обращения к сети.

Реализовано:

- детерминированный анализ retained PCAP;
- длительность, frames, bytes, packets/s и наблюдаемая полоса;
- top talkers и communications graph;
- TCP health: retransmission, duplicate ACK, out-of-order, reset, zero-window, SYN/handshake visibility;
- DNS errors и latency statistics;
- ARP observations/conflict hints;
- DHCP correlation;
- ICMP/ICMPv6;
- broadcast/multicast contributors;
- TLS/HTTP/QUIC/SMB protocol intelligence без payload decryption;
- ACK RTT с осторожной трактовкой;
- сравнение двух сохранённых traffic-analysis результатов;
- canonical `traffic-analysis` JSON, русский TXT/Markdown и web/kiosk UI.

Communications graph используется как **явно выбираемый** источник для topology. Последний PCAP не подмешивается в карту автоматически.

---

## v1.2 — Network Topology

Статус: **feature complete / closed**.

M11.1–M11.4 реализованы. Полный automated regression зелёный; M11.4 установлен и проверен на рабочей WireScope VM. После обновления appliance сохранил рабочие database/migrations/worker/capture dependencies, `/api/v1/ready` вернул healthy state, а новый Deep audit прошёл live-проверку structural topology. Оператор принял итоговое представление как пригодное для дальнейшего использования.

Цель v1.2 — не просто нарисовать граф обнаруженных IP, а построить объяснимую карту сети и одновременно показать, **какие топологические утверждения реально подтверждаются собранными данными**.

### M11.1 — логическая топология

Статус: **завершено**.

Canonical `network-topology` объединяет persisted evidence из inventory, ARP/ND, route/default-gateway context, DHCP, LLDP/CDP, STP, VLAN/QinQ, active discovery и явно выбранного PCAP Traffic Analysis.

Модель различает WireScope/interface, assets, gateway/router и network-device evidence, subnet segments, DHCP/DNS infrastructure, external traffic endpoints, L2/L3/traffic relationships, confidence и provenance. Факт нахождения двух адресов в одной подсети не считается доказательством прямого L2-соединения.

### M11.2 — операторская визуализация

Статус: **завершено**.

Web/kiosk UI содержит structural/infrastructure-first view, отдельные L2/L3/Traffic/All Evidence представления, subnet regions, global retained-audit topology, confidence filters, asset/edge details и findings, zoom/pan/fit, явный PCAP overlay, topology JSON export, SVG/PNG export structural diagram, viewport SVG export, VLAN focus/export и historical topology compare.

Structural view не выдаёт directed broadcast, link-local шум и PCAP-only external endpoints за обычные инфраструктурные hosts.

### M11.3 — физическое и L3 enrichment

Статус: **завершено**.

Реализованы bounded traceroute/upstream evidence, read-only SNMPv2c/v3, IF-MIB/IP-MIB/BRIDGE-MIB/Q-BRIDGE-MIB/LLDP-MIB, IPv4/IPv6 interface addresses и connected prefixes, ARP/IPv6 ND, FDB/switch-port correlation, VLAN membership и access/trunk/hybrid semantics, LLDP correlation, network-interface nodes, routed-interface relationships, conservative router classification и fail-visible `partial/source_errors`.

SNMP-observed subnet остаётся `active_scope=false`: management evidence может расширить знание о topology, но не разрешение на сканирование.

### M11.4 — topology hardening и достаточность evidence

Статус: **завершено и live-проверено на WireScope VM**.

Основные изменения:

- canonical evidence graph отделён от presentation projection;
- добавлен `coverage` / claimability слой;
- `inventory`, `l3`, `l2`, `traffic`, `vlan`, `wifi`, `hypervisor` получают `sufficient / partial / missing`;
- WireScope показывает, какого evidence не хватает для более сильного вывода;
- multi-homed environment сохраняет per-interface default routes и DHCP router-option evidence;
- gateway audit interface определяется только по точному persisted evidence, без `.1/.254/.11` эвристик;
- optional read-only SSH topology provider для Linux/OpenWrt-подобных устройств;
- fixed allowlist `ip/bridge/iw`, strict host-key verification, no arbitrary command;
- SSH private key/known_hosts передаются через consume-once `0600` spool;
- SNMP/SSH jobs требуют свежих credentials;
- SSH `ip neigh` — IP↔MAC identity evidence, не доказательство кабеля;
- FDB/bridge VLAN/Wi-Fi association усиливают topology только при реальном management evidence;
- source-health охватывает route-trace, SNMP и SSH;
- пропущенный ожидаемый job-backed artifact переводит topology в `partial` с sanitized error.

Принцип v1.2: **если данных недостаточно, WireScope должен показать недостаток evidence, а не дорисовать более смелую схему**.

### Live validation status

На установленной WireScope VM подтверждены штатный upgrade, сохранение appliance state, SQLite/migrations/worker readiness, `dumpcap`/`tshark` readiness, новый Deep audit на реальном LAN interface и structural topology presentation.

SNMP/FDB/Q-BRIDGE/LLDP management enrichment и SSH VLAN/Wi-Fi enrichment пока не объявляются live-validated из-за отсутствия подходящего managed device в текущем стенде. Эти пути покрыты automated regression и не блокируют закрытие v1.2.

Подробная модель: [TOPOLOGY_MODEL.md](TOPOLOGY_MODEL.md).

---

## v1.3 — Global Correlation Analysis

Статус: **implementation complete по коду; automated validation зелёный; требуется live validation на WireScope VM**.

Цель — объединить Deep/active audit, выбранный PCAP Traffic Analysis, findings и Network Topology в один детерминированный аналитический пакет, который показывает не четыре независимых отчёта, а связи между ними.

Обязательные correlation domains:

1. **Asset ↔ traffic identity** — exact IP/MAC, без hostname-only merge.
2. **Service ↔ observed traffic** — какие inventory services/ports наблюдались в выбранном capture.
3. **Finding ↔ traffic relevance** — связь finding с asset/service, участвующим в traffic; отсутствие связи = `uncorrelated`, а не «finding неважен».
4. **Inventory ↔ Traffic coverage** — inventory assets вне visibility capture и traffic endpoints без inventory identity.
5. **Internal ↔ external communications** — global external endpoints, связанные с exact-correlated internal assets.
6. **Infrastructure consistency** — gateway/DHCP/DNS между environment, passive, traffic и topology evidence.
7. **Evidence quality** — partial/missing input наследуется, confidence не усиливается сверх источника.

### Slice 1 — deterministic correlation core ✓

Реализовано:

- пакет `global_analysis`;
- canonical `global-analysis` v1;
- offline preview API;
- exact IP/MAC identity и запрет hostname-only merge;
- deterministic correlation IDs и versioned rule IDs;
- conservative endpoint classes `internal_asset / internal_segment / external_global / private_unknown / special / unknown`;
- pair-level service-use correlation;
- finding↔traffic relevance;
- inventory-vs-capture visibility;
- internal asset ↔ globally routable external endpoint;
- `private_unknown` отдельно от external;
- inheritance topology/report partial state и identity conflicts.

Текущий `traffic-analysis` v1 агрегирует destination ports на communication pair. Поэтому service-use basis остаётся `observed_pair_destination_port`: это подтверждает наблюдение service port в паре с asset, но не заявляет без evidence, какая сторона владела socket.

### Slice 2 — durable result + cross-source consistency ✓

Реализовано:

- durable job type `global_analysis` в worker registry;
- `POST /api/v1/audits/{audit_id}/global-analysis`;
- persisted `global_analysis_result` / `global-analysis` v1 / retention `audit`;
- namespaced `audit.summary.global_analysis`;
- gateway/DHCP/DNS consistency rules;
- safe evidence lineage по audit/assets/services/findings/traffic/topology;
- artifact refs содержат ID/type/hash/schema/timestamp, но не filesystem path;
- deterministic русская `operator_summary`;
- preview и durable stage используют один correlation runtime;
- никакого scanner/PCAP reread/network I/O.

### Slice 3 — history, rebuild, exports и operator GUI ✓

Реализовано:

- история durable Global Analysis jobs для audit;
- чтение только валидного completed `global_analysis_result`;
- immutable rebuild: новый job/artifact с `rebuild_of_job_id`, старый result не изменяется;
- rebuild разрешён только от completed durable result того же audit и с тем же selected Traffic Analysis;
- JSON/TXT/Markdown exports из сохранённого canonical JSON;
- dedicated operational audit action `global_analysis.generate`;
- отдельный operator workspace в web/kiosk UI без вмешательства в основной audit pipeline;
- выбор audit и конкретного completed Traffic Analysis;
- run/progress/cancel для auditor;
- history/read/export для auditor/viewer;
- summary, infrastructure consistency, coverage/source health, finding relevance, external communications, warnings и evidence lineage;
- отдельный `node --check` для нового JS в CI.

### Automated validation

На checkpoint Slice 3 полный CI прошёл:

- Python compile;
- Global Analysis JavaScript syntax check;
- **494 tests passed, 3 deselected**;
- wheel build;
- installed-wheel smoke с импортом `topology` и `global_analysis` вне source tree.

Последующие hardening-правки ограничены rebuild validation и operational audit action; branch CI остаётся обязательным gate перед live installation.

Полная модель: [GLOBAL_ANALYSIS_MODEL.md](GLOBAL_ANALYSIS_MODEL.md). API: [API.md](API.md).

### Что осталось до закрытия v1.3

Только live validation на установленной WireScope VM:

- обновить appliance штатным upgrade path;
- убедиться в `/api/v1/ready`, worker/database/migrations/capture dependencies;
- выбрать существующий/новый Deep audit и сохранённый Traffic Analysis;
- запустить durable Global Analysis;
- проверить canonical result, `partial/source_health`, consistency и evidence lineage на реальных persisted данных;
- проверить operator GUI, history, immutable rebuild и JSON/TXT/Markdown exports;
- после успешной проверки зафиксировать v1.3 checkpoint/tag.

Global Analysis **не перечитывает PCAP и не запускает scanner**: он работает поверх persisted normalized data.

---

## v1.4 — AI-assisted Global Analysis

Цель — опционально добавить AI-аналитику поверх deterministic `global-analysis`.

Базовые ограничения:

- AI не заменяет deterministic correlation;
- raw PCAP по умолчанию не передаётся внешнему provider;
- оператор явно контролирует разрешённый набор передаваемых данных;
- API key хранится backend-side;
- AI output является аналитическим заключением/гипотезой, а не автоматическим WireScope finding;
- вывод должен ссылаться на evidence/correlation IDs.

Возможные providers: внешний API и локальная/offline модель через общую абстракцию `AIProvider`.

---

## Дальнейшие идеи

Не являются текущими обязательствами:

- PDF export;
- дополнительные protocol audit modules;
- CVE enrichment из локальной/контролируемой базы;
- scheduled audits;
- долгосрочная история traffic baselines;
- расширенная cross-site topology history;
- hypervisor-specific topology providers;
- vendor-specific management-plane adapters;
- более широкая distro/architecture/tshark compatibility matrix.

## Текущий следующий шаг

**v1.3 — live validation и закрытие релиза.**

Код Slice 1–3 собран. Следующий этап — штатно обновить WireScope VM и проверить durable Global Analysis, history/rebuild/exports и operator GUI на реальных persisted Deep/Traffic Analysis данных. После успешной live-проверки v1.3 можно закрывать checkpoint/tag и переходить к отдельному v1.4 AI-assisted layer.
