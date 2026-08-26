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

Canonical `network-topology` объединяет persisted evidence из:

- inventory;
- ARP/ND;
- route/default-gateway context;
- DHCP;
- LLDP/CDP;
- STP;
- VLAN/QinQ;
- active discovery;
- явно выбранного PCAP Traffic Analysis.

Модель различает:

- WireScope/interface;
- assets;
- gateway/router и network-device evidence;
- subnet segments;
- DHCP/DNS infrastructure;
- external traffic endpoints;
- L2, L3 и traffic relationships;
- `confirmed / observed / inferred` confidence;
- provenance каждого узла и связи.

Факт нахождения двух адресов в одной подсети не считается доказательством прямого L2-соединения.

### M11.2 — операторская визуализация

Статус: **завершено**.

Web/kiosk UI содержит:

- structural / infrastructure-first view;
- отдельные L2, L3, Traffic и All evidence представления;
- subnet regions;
- global retained-audit topology;
- confidence filters;
- asset/edge details и findings;
- zoom/pan/fit;
- явный PCAP overlay;
- topology JSON export;
- SVG/PNG export полной structural diagram;
- отдельный viewport SVG export;
- VLAN focus и VLAN JSON/SVG export;
- historical topology compare между retained audits.

Structural view не выдаёт directed broadcast, link-local шум и PCAP-only external endpoints за обычные инфраструктурные hosts.

### M11.3 — физическое и L3 enrichment

Статус: **завершено**.

Реализовано:

- bounded traceroute/upstream evidence;
- read-only SNMPv2c/v3 enrichment;
- IF-MIB / IP-MIB / BRIDGE-MIB / Q-BRIDGE-MIB / LLDP-MIB;
- IPv4/IPv6 interface addresses и connected prefixes;
- ARP/IPv6 ND neighbor data;
- FDB/switch-port correlation;
- PVID/tagged/untagged VLAN membership;
- `access / trunk / hybrid / unknown` port semantics;
- LLDP chassis/port/management-address correlation;
- network-interface nodes и L3 routed-interface relationships;
- conservative router classification;
- fail-visible `partial/source_errors` для потерянного persisted management evidence.

SNMP-observed subnet остаётся `active_scope=false`: management evidence может расширить **знание о topology**, но не разрешение на сканирование.

### M11.4 — topology hardening и достаточность evidence

Статус: **завершено и live-проверено на WireScope VM**.

Основные изменения:

- canonical evidence graph отделён от presentation projection;
- добавлен `coverage` / claimability слой;
- домены `inventory`, `l3`, `l2`, `traffic`, `vlan`, `wifi`, `hypervisor` получают `sufficient / partial / missing`;
- WireScope показывает, **чего именно не хватает для более сильного топологического вывода**, вместо фиктивного процента «изученности сети»;
- multi-homed environment сохраняет per-interface default routes и DHCP router-option evidence;
- gateway выбранного audit interface определяется только по точному persisted evidence;
- шаблоны `.1`, `.254`, `.11` и подобные эвристики не используются;
- добавлен optional read-only SSH topology provider для Linux/OpenWrt-подобных managed devices;
- SSH использует fixed allowlist `ip/bridge/iw`, strict host-key verification и не принимает arbitrary remote command;
- SSH private key/known_hosts передаются через consume-once `0600` spool и не сохраняются как plaintext evidence;
- SNMP/SSH management jobs требуют свежих credentials при новом запуске;
- SSH `ip neigh` используется как IP↔MAC identity evidence, но не как доказательство физического кабеля;
- FDB, bridge VLAN и Wi-Fi association могут усиливать L2/VLAN/Wi-Fi topology только при реальных management-plane evidence;
- source-health охватывает route-trace, SNMP и SSH;
- если ожидаемый job-backed artifact не вошёл в карту, topology становится `partial`, а ошибка остаётся sanitized.

Принцип v1.2: **если данных недостаточно, WireScope должен показать недостаток evidence, а не дорисовать более смелую схему**.

### Что было проверено вживую

На установленной WireScope VM подтверждено:

- переход с предыдущего topology checkpoint на M11.4 через штатный `packaging/upgrade.sh`;
- сохранение рабочего состояния appliance;
- SQLite/migrations/worker readiness;
- `dumpcap` и `tshark` readiness;
- новый Deep audit на реальном LAN interface;
- structural topology и новая presentation model;
- отсутствие критических regressions, мешающих пользоваться topology.

### Что не проверялось на живом устройстве

В текущей сети SNMP на роутере не был настроен, поэтому **SNMP/FDB/Q-BRIDGE/LLDP management enrichment не объявляется live-validated**. Эти пути реализованы и покрыты automated regression, но vendor-specific interoperability будет проверяться по мере появления подходящих managed devices.

То же относится к live-проверке SSH VLAN/Wi-Fi enrichment на подходящем Linux/OpenWrt device.

Это больше не блокирует закрытие v1.2: topology корректно сообщает отсутствие соответствующего evidence через `coverage` и не обязана изображать VLAN/FDB/Wi-Fi данные там, где их не удалось получить.

Подробная модель: [TOPOLOGY_MODEL.md](TOPOLOGY_MODEL.md).

---

## v1.3 — Global Correlation Analysis

Статус: **следующий этап**.

Цель — объединить результаты Deep/active audit, PCAP Traffic Analysis, findings и Network Topology в один детерминированный аналитический пакет.

Global Analysis должен отвечать не «что лежит в четырёх разных отчётах», а как эти данные связаны между собой.

Первые обязательные correlation rules:

1. **Asset ↔ traffic identity**
   - exact IP;
   - exact MAC;
   - без hostname-only merge.

2. **Service ↔ observed traffic**
   - какой обнаруженный service/port реально наблюдался в выбранном PCAP;
   - какие inventory services не были видимы с данной capture point.

3. **Finding ↔ traffic relevance**
   - связан ли finding с asset/service, который участвовал в наблюдаемом обмене;
   - отсутствие связи означает `uncorrelated`, а не «finding неважен».

4. **Inventory ↔ Traffic coverage**
   - assets, найденные discovery, но отсутствующие в capture;
   - traffic endpoints, которые не удалось связать с inventory asset.

5. **Internal ↔ external communications**
   - внешние endpoints, связанные с конкретными внутренними assets;
   - ports/protocols/packet-byte context из persisted Traffic Analysis.

6. **Infrastructure consistency**
   - совпадают ли gateway/DHCP/DNS observations между environment, passive evidence и topology;
   - где active/passive/management evidence расходятся.

7. **Evidence quality**
   - partial/missing input должен наследоваться в Global Analysis;
   - correlation не должна усиливать confidence сверх исходных evidence.

Выход v1.3:

- canonical `global-analysis` JSON;
- deterministic rule IDs;
- evidence references на audit/assets/services/findings/traffic/topology;
- русское операторское summary;
- warnings/partial state для неполных источников;
- воспроизводимый offline result без внешнего AI.

Global Analysis **не перечитывает PCAP и не запускает scanner**: он работает поверх persisted normalized data.

---

## v1.4 — AI-assisted Global Analysis

Цель — опционально добавить AI-аналитику поверх уже построенного deterministic `global-analysis`.

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

**v1.3 — Global Correlation Analysis.**

Первый implementation slice: persisted inventory/report source + явно выбранный `traffic-analysis` + canonical `network-topology` → deterministic `global-analysis`, начиная с exact asset identity, observed service use, inventory-vs-traffic coverage и external endpoint correlation.