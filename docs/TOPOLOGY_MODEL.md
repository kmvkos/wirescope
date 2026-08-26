# Модель Network Topology

[English](en/TOPOLOGY_MODEL.md)

WireScope строит topology как аудитор, а не как генератор красивой схемы. Канонический graph хранит наблюдавшиеся и подтверждённые evidence, а presentation layer отдельно решает, что имеет смысл показывать на структурной карте.

Главное правило: **отсутствующая связь не дорисовывается по догадке**. Одинаковая подсеть, похожий hostname или факт обмена трафиком не доказывают физический L2 hop, конкретный switch port, VLAN membership, Wi‑Fi association или VM→hypervisor placement.

## Статус

Network Topology v1.2 завершена.

M11.4 установлен и проверен на рабочей WireScope VM: штатный upgrade прошёл успешно, `/api/v1/ready` подтвердил database/migrations/worker/dumpcap/tshark, после чего новый Deep audit использовался для live-проверки structural topology. Критических regressions, мешающих использовать карту, не обнаружено.

При этом SNMP на проверочном роутере не был настроен. Поэтому SNMP/FDB/Q-BRIDGE/LLDP management enrichment **не помечается как live-validated**. Он реализован и покрыт automated regression; vendor-specific interoperability остаётся дальнейшей эксплуатационной проверкой, а не условием корректности structural topology.

То же относится к live SSH VLAN/Wi‑Fi enrichment: механизм реализован, но требует подходящего managed Linux/OpenWrt device и dedicated read-only account.

## Слои модели

```text
persisted evidence
      ↓
canonical topology
      ↓
evidence coverage / claimability
      ↓
structural · L2 · L3 · Traffic · all evidence
```

Canonical topology остаётся источником истины. Structural view не удаляет raw/evidence nodes: directed broadcast, link-local endpoints и PCAP-only external endpoints могут быть скрыты или сгруппированы в основном представлении, но остаются доступны в соответствующих evidence/traffic слоях и JSON.

## Достаточность данных

Topology response содержит блок `coverage`. Он отвечает не на вопрос «насколько сеть исследована в процентах», а на более строгий вопрос: **какие типы утверждений поддерживаются сохранёнными evidence сейчас**.

Домены:

- `inventory` — подтверждённые assets;
- `l3` — subnet/gateway/router relationships;
- `l2` — LLDP/CDP/FDB/switch-port/другая физическая adjacency;
- `traffic` — communication edges из явно выбранного persisted Traffic Analysis;
- `vlan` — VLAN membership/PVID/tagged/untagged evidence;
- `wifi` — AP/client association из management plane;
- `hypervisor` — out-of-band guest→host evidence.

Статусы домена:

- `sufficient` — evidence достаточно для соответствующего класса утверждений;
- `partial` — есть полезные observations, но они не описывают класс полностью;
- `missing` — WireScope не располагает evidence для такого утверждения.

`missing` не означает, что объекта или связи в реальной сети нет. Например, отсутствие Wi‑Fi association table означает только, что WireScope не может доказать attachment клиента к AP.

`coverage` не является security score и не оценивает процент реально существующей сети, который «найден» WireScope.

## Structural presentation

Основное представление является infrastructure-first projection, а не прямой отрисовкой всех узлов canonical graph.

В structural view приоритет имеют:

- subnet regions;
- gateway/router evidence;
- network devices;
- assets;
- доказанные инфраструктурные relationships.

Следующие сущности не должны визуально притворяться обычными инфраструктурными hosts:

- directed broadcast конкретной подсети;
- link-local IPv6 noise без достаточной asset correlation;
- multicast/broadcast service endpoints;
- PCAP-only external endpoints.

Traffic и raw evidence остаются доступны отдельными слоями.

## L3 и multi-interface

WireScope сохраняет route context конкретного audit interface. Для multi-homed appliance host-wide default route другого интерфейса не считается gateway выбранной audit-сети.

Допустимые interface-specific gateway sources:

- persisted default route данного interface;
- DHCP lease/router option данного interface;
- read-only SNMP/SSH management evidence;
- bounded route-trace evidence в разрешённом active context.

Адрес gateway не угадывается по шаблону `.1`, `.254`, `.11` и т.п.

Management-discovered connected subnet может быть добавлена в topology как evidence, но получает `active_scope=false`. Новое знание о маршрутизации не является новым разрешением на active scan.

## L2

Физическая линия появляется только из evidence, которое действительно описывает adjacency/port mapping, например:

- LLDP/CDP;
- bridge/FDB + управляемый port context;
- SNMP BRIDGE/Q-BRIDGE/LLDP;
- read-only SSH `bridge` data;
- другой provider с эквивалентным доказательством.

ARP/ND или `ip neigh` сами по себе связывают IP↔MAC identity, но **не доказывают прямой физический кабель** между двумя endpoints.

Unmanaged switch без management/LLDP evidence может остаться невидимым. WireScope не создаёт фиктивный switch-node только потому, что несколько hosts находятся в одной подсети.

## VLAN

VLAN membership назначается консервативно.

Допустимые случаи:

1. FDB entry содержит точный VLAN ID — этот VLAN можно связать с endpoint;
2. FDB entry не содержит VLAN ID, но порт однозначно является single-VLAN access port — PVID/untagged membership можно использовать;
3. trunk/hybrid с несколькими VLAN без точного FDB VLAN — WireScope **не выбирает один VLAN** для endpoint.

Для port evidence сохраняются `port_mode`, `pvid`, `tagged_vlans`, `untagged_vlans`, `vlan_ids` и источник решения.

Пассивно увиденный 802.1Q tag является реальным VLAN evidence, но отсутствие tag на access traffic не доказывает VLAN ID.

## Traffic overlay

PCAP не смешивается с topology автоматически. Оператор явно выбирает persisted Traffic Analysis result.

Traffic layer показывает только коммуникации, реально видимые точке capture. External endpoints из PCAP не превращаются в инфраструктурные устройства structural map только потому, что с ними был трафик.

Отсутствие asset в PCAP также не означает, что asset отсутствовал в сети: capture имеет собственную visibility boundary.

## Read-only management sources

### SNMP

`POST /api/v1/audits/{audit_id}/topology/snmp`

Используется read-only SNMPv2c/v3. Target должен находиться внутри operator-confirmed scope того же audit interface.

Поддерживаемые стандартные источники включают IF-MIB/IP-MIB, BRIDGE-MIB/Q-BRIDGE-MIB и LLDP-MIB там, где устройство их реально предоставляет.

SNMP может дать:

- interface metadata;
- IPv4/IPv6 addresses и prefixes;
- ARP/ND;
- FDB;
- PVID/VLAN membership;
- switch-port mapping;
- LLDP neighbours.

Отсутствующий MIB subtree означает `capability=false/empty`, а не успешную проверку и не ошибку всей topology.

Credentials передаются через ephemeral spool и не записываются в canonical topology/job evidence в открытом виде.

### SSH

`POST /api/v1/audits/{audit_id}/topology/ssh`

SSH provider предназначен для Linux/OpenWrt-подобных managed devices и не является generic remote shell.

Контракт:

- target только внутри confirmed active scope;
- mutating endpoint доступен только `auditor`;
- обязательная strict host-key verification через предоставленный `known_hosts`;
- private key/known_hosts помещаются в `0600` consume-once runtime spool и не сохраняются в SQLite/evidence;
- arbitrary operator command отсутствует;
- `shell=True` не используется;
- remote argv зафиксирован provider-ом.

Текущий allowlist:

```text
ip -j addr show
ip -j route show table main
ip -j neigh show
bridge -j fdb show
bridge -j vlan show
iw dev
iw dev <validated-interface> station dump
```

Недоступная команда превращается в capability/warning и не должна валить остальные доступные источники.

Queued cancel удаляет credential spool сразу. Running handler удаляет его в `finally`. Retry management jobs SNMP/SSH со старым credential reference запрещён: новый запуск требует свежих credentials.

## Wi‑Fi и hypervisor context

Wi‑Fi attachment считается доказанным только при наличии association evidence от managed AP/router, например `iw station dump` или эквивалентного provider.

Обычный LAN scan не способен доказать связь:

```text
physical host → local hypervisor → конкретная VM
```

Для такого утверждения нужен out-of-band hypervisor/API/helper source. VMware OUI или похожий MAC может быть hint, но не доказательством placement.

## Source health

Если job-backed persisted route/SNMP/SSH artifact должен участвовать в topology, но decorator не смог его включить, карта остаётся доступной, однако получает:

```json
{
  "partial": true,
  "source_errors": [
    {
      "component": "ssh-topology",
      "code": "artifact_unavailable"
    }
  ]
}
```

Exception text, filesystem paths и credentials в `source_errors` не помещаются.

Legacy/jobless management artifact не объявляется повреждённым, если WireScope не может надёжно определить, должен ли именно он быть актуальным источником.

## Историческая topology

Topology compare работает только с persisted evidence и не запускает network I/O.

Cross-audit identity остаётся консервативной:

- MAC сильнее IP;
- exact IP может использоваться при отсутствии более сильного конфликта;
- одинаковый hostname сам по себе не доказывает одну identity;
- нестабильный audit-local UUID не должен создавать ложный `removed + added`, если стабильная identity подтверждена.

## Экспорт

Два типа SVG имеют разные задачи:

- **полная structural diagram** — строится для экспорта всей текущей структурной topology;
- **current viewport SVG** — сохраняет текущие filters/zoom/pan для диагностики конкретного представления.

PNG строится из structural diagram. JSON остаётся полным canonical representation и не ограничивается тем, что в данный момент видно на экране.

## API

Основные endpoints:

```text
GET  /api/v1/audits/{audit_id}/topology
GET  /api/v1/topology/global
GET  /api/v1/audits/{audit_id}/topology/compare?against={baseline_audit_id}
POST /api/v1/audits/{audit_id}/topology/snmp
POST /api/v1/audits/{audit_id}/topology/ssh
```

`GET .../topology` может принимать `traffic_analysis_job_id` для явно выбранного PCAP overlay.

Topology compare использует только persisted evidence и не запускает scanner, SNMP, SSH или traceroute.

## Ограничения

Обычный LAN audit не способен достоверно восстановить всё физическое устройство сети. В частности:

- unmanaged switch без LLDP/FDB management evidence может остаться невидимым;
- NAT/route boundaries могут скрывать внутренние endpoints;
- Wi‑Fi attachment требует association data от AP/router;
- VM→hypervisor placement требует hypervisor/API/helper evidence;
- PCAP показывает только видимость конкретной точки capture;
- topology одной подсети не доказывает global multi-site структуру;
- vendor-specific SNMP/CLI может потребовать отдельного adapter после live interoperability проверки.

WireScope показывает эти ограничения через `coverage`, warnings и `partial/source_errors`, а не компенсирует их эвристической дорисовкой.