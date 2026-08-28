# Milestone 12 — Evidence-driven topology and correlation

## Цель

Перестроить цепочку `PCAP -> observations -> identity -> topology/correlation -> presentation`, чтобы WireScope не выдавал граф сетевых коммуникаций за физическую/логическую топологию и не превращал слабые наблюдения (например ARP target из request) в подтверждённые устройства.

Главный принцип milestone: **сначала сохраняем наблюдаемый факт и его provenance/confidence, потом делаем вывод**. Любой topology edge или identity merge должен быть объясним через evidence.

## Проблемы текущей реализации

1. Endpoint выбирается как `IP, иначе MAC`, поэтому IP и MAC не являются равноправными идентификаторами одного asset.
2. Conversation агрегируется как неориентированная пара endpoint'ов. Направление отдельных flow и принадлежность service port теряются.
3. ARP request target может визуально восприниматься как существующее устройство, хотя запрос доказывает только факт обращения к адресу.
4. Communications graph используется как основа topology view, из-за чего большое число внешних peers и сетевых потоков создаёт нечитаемую схему.
5. Capture context (интерфейс, логический VLAN) смешивается с packet evidence (`vlan.id`). Отсутствие 802.1Q tag в кадре не означает отсутствие логического VLAN на точке захвата.
6. Корреляция не проверяет, относятся ли inventory/active discovery и PCAP к совместимым observation domains.
7. Configured DNS и observed DNS usage могут трактоваться как конфликт, хотя это разные типы фактов.

## План работ

### Phase 12.1 — PCAP evidence model

- [x] Зафиксировать milestone и отдельную ветку.
- [ ] Добавить additive evidence model поверх текущего traffic-analysis результата.
- [ ] Разделить ARP request/reply semantics.
- [ ] Ввести состояния endpoint evidence: `confirmed_responder`, `observed_sender`, `observed_peer`, `probed_target`, `external_peer`.
- [ ] Хранить IP<->MAC observations отдельно с source, confidence, count, first_seen/last_seen.
- [ ] Добавить directional transport flows с `src/dst endpoint`, `src/dst port`, transport и protocol stack summary.
- [ ] Разделить capture context и observed VLAN tags.
- [ ] Добавить observation-domain hints без объявления их доказанной subnet topology.
- [ ] Regression tests: ARP probing не создаёт confirmed asset; source IP/MAC создаёт identity evidence; flow сохраняет направление и порты; VLAN context не подменяет packet tag.

### Phase 12.2 — Identity resolver

- [ ] Вынести нормализацию evidence в отдельный identity resolver.
- [ ] Не объединять asset только по слабому совпадению имени/IP.
- [ ] Ввести evidence weights и conflict handling.
- [ ] ARP reply/DHCP/ND/CDP/LLDP — strong identity evidence; Ethernet/IP source mapping — contextual evidence.
- [ ] Сохранять несколько MAC-кандидатов для IP при конфликте/HA вместо немедленного merge.
- [ ] Не использовать L2 destination MAC как MAC удалённого L3 destination за маршрутизатором.

### Phase 12.3 — Discovery protocol extraction

- [ ] CDP: device-id, platform, software, addresses, port-id, capabilities.
- [ ] LLDP: chassis-id, port-id, system-name, capabilities, management address.
- [ ] MikroTik/MNDP при доступных tshark fields.
- [ ] PPPoE discovery как отдельный тип L2 evidence, не как host topology edge.
- [ ] IPv6 ND/RA: router/neighbor evidence и prefixes.
- [ ] DHCP: server/client identity, offered options, advertised DNS/router information.

### Phase 12.4 — Observation-domain compatibility

- [ ] Перед PCAP<->inventory correlation сравнивать адресные пространства, capture interface/context и фактически наблюдаемые inventory identifiers.
- [ ] Результат: `compatible`, `partial`, `different_domain`, `insufficient_evidence`.
- [ ] При `different_domain` не выдавать `0/N correlated` как проблему качества корреляции; объяснять, что источники относятся к разным сегментам/точкам наблюдения.
- [ ] Разделить `configured_dns`, `dhcp_advertised_dns`, `system_resolver`, `observed_dns_usage`.

### Phase 12.5 — Evidence-driven topology builder

Topology edges должны строиться только из topology evidence, а не из любого traffic flow.

Типы связей:

- `l2_adjacency`
- `l3_next_hop`
- `same_segment`
- `routed_via`
- `identity_binding`
- `communicates_with` — только communications layer
- `service_usage` — только communications/service layer

Каждый edge содержит `source`, `confidence`, `evidence_count`, `first_seen`, `last_seen` и при необходимости `limitations`.

### Phase 12.6 — Presentation model / UI

Основной view — **Topology**, а не all-flows graph.

Слои:

1. `Topology` — confirmed routers/gateways/switches/segments/assets.
2. `Communications` — traffic flows, выключены по умолчанию.
3. `Identity` — IP/MAC/name mappings и confidence.
4. `External` — внешние peers, по умолчанию агрегированы в Internet/cloud node.

Правила визуализации:

- `probed_target` скрыт из основной topology.
- external peers агрегируются и раскрываются по запросу.
- broadcast/multicast group не рисуется как обычный host.
- segment/VLAN отображается контейнером/группой, а не сотней пересекающихся связей.
- сильные topology edges визуально отделены от inferred/weak edges.

### Phase 12.7 — Correlation v2

- [ ] Correlation работает asset-to-asset через identity evidence, а не endpoint string-to-string.
- [ ] Для каждого merge/не-merge возвращается reason/evidence.
- [ ] Поддержать partial correlation: MAC совпал, IP изменился; имя совпало, но MAC конфликтует; active discovery видит IP, PCAP видит соседний L2 identity и т.п.
- [ ] Отдельно показывать `unmatched confirmed assets` и `unmatched weak observations`.

### Phase 12.8 — Regression and migration

- [ ] Сохранить совместимость старых traffic-analysis полей на переходный период.
- [ ] Поднять `ANALYZER_VERSION` при изменении persisted semantics.
- [ ] Добавить synthetic fixtures для routed capture, ARP sweep, VLAN subinterface, external traffic, gateway and discovery protocols.
- [ ] Реальный PCAP использовать как локальный/manual regression sample без коммита чувствительного capture в репозиторий.

## Порядок реализации

Работа идёт строго снизу вверх:

`12.1 PCAP evidence -> 12.2 identity -> 12.3 discovery -> 12.4 domain compatibility -> 12.5 topology builder -> 12.6 UI -> 12.7 correlation -> 12.8 regression`.

UI не полируется до исправления evidence/topology model, иначе визуализация будет скрывать ошибки модели данных, а не устранять их.
