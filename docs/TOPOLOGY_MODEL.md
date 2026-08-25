# Модель Network Topology

[English](en/TOPOLOGY_MODEL.md)

WireScope строит topology как аудитор, а не как генератор красивой схемы. Канонический graph хранит наблюдавшиеся и подтверждённые evidence, а presentation layer отдельно решает, что имеет смысл показывать на структурной карте.

Главное правило: **отсутствующая связь не дорисовывается по догадке**. Одинаковая подсеть, похожий hostname или факт обмена трафиком не доказывают физический L2 hop, конкретный switch port, VLAN membership, Wi‑Fi association или VM→hypervisor placement.

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

## L3 и multi-interface

WireScope сохраняет route context конкретного audit interface. Для multi-homed appliance host-wide default route другого интерфейса не считается gateway выбранной audit-сети.

Допустимые interface-specific gateway sources:

- persisted default route данного interface;
- DHCP lease/router option данного interface;
- read-only SNMP/SSH management evidence;
- bounded route-trace evidence в разрешённом active context.

Адрес gateway не угадывается по шаблону `.1`, `.254`, `.11` и т.п.

## L2

Физическая линия появляется только из evidence, которое действительно описывает adjacency/port mapping, например:

- LLDP/CDP;
- bridge/FDB + управляемый port context;
- SNMP BRIDGE/Q-BRIDGE/LLDP;
- read-only SSH `bridge` data;
- другой будущий provider с эквивалентным доказательством.

ARP/ND или `ip neigh` сами по себе связывают IP↔MAC identity, но **не доказывают прямой физический кабель** между двумя endpoints.

## VLAN

VLAN membership назначается консервативно.

Допустимые случаи:

1. FDB entry содержит точный VLAN ID — этот VLAN можно связать с endpoint;
2. FDB entry не содержит VLAN ID, но порт однозначно является single-VLAN access port — PVID/untagged membership можно использовать;
3. trunk/hybrid с несколькими VLAN без точного FDB VLAN — WireScope **не выбирает один VLAN** для endpoint.

Для port evidence сохраняются `port_mode`, `pvid`, `tagged_vlans`, `untagged_vlans`, `vlan_ids` и источник решения.

## Traffic overlay

PCAP не смешивается с topology автоматически. Оператор явно выбирает persisted Traffic Analysis result.

Traffic layer показывает только коммуникации, реально видимые точке capture. External endpoints из PCAP не превращаются в инфраструктурные устройства structural map только потому, что с ними был трафик.

## Read-only management sources

### SNMP

`POST /api/v1/audits/{audit_id}/topology/snmp`

Используется read-only SNMPv2c/v3. Target должен находиться внутри operator-confirmed scope того же audit interface. Credentials передаются через ephemeral spool и не записываются в canonical topology/job evidence в открытом виде.

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

Queued cancel удаляет credential spool сразу. Running handler удаляет его в `finally`. Retry management jobs SNMP/SSH запрещён: новый запуск требует свежих credentials.

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

## API

Основные endpoints:

```text
GET  /api/v1/audits/{audit_id}/topology
GET  /api/v1/topology/global
GET  /api/v1/audits/{audit_id}/topology/compare?against={baseline_audit_id}
POST /api/v1/audits/{audit_id}/topology/snmp
POST /api/v1/audits/{audit_id}/topology/ssh
```

Topology compare использует только persisted evidence и не запускает scanner, SNMP, SSH или traceroute.

## Ограничения

Обычный LAN audit не способен достоверно восстановить всё физическое устройство сети. В частности:

- unmanaged switch без LLDP/FDB management evidence может остаться невидимым;
- NAT/route boundaries могут скрывать внутренние endpoints;
- Wi‑Fi attachment требует association data от AP/router;
- VM→hypervisor placement требует hypervisor/API/helper evidence;
- PCAP показывает только видимость конкретной точки capture;
- topology одной подсети не доказывает global multi-site структуру.

WireScope должен показывать эти ограничения через `coverage`, warnings и `partial/source_errors`, а не компенсировать их эвристической дорисовкой.
