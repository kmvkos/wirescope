# Модель сканирования WireScope

**Русский** · [English](en/SCANNING_MODEL.md)

WireScope разделяет сетевой аудит на три слоя: пассивные наблюдения, активную инвентаризацию и протокольные проверки. Findings находятся ещё выше и не являются частью scanner/provider layer.

## Главное правило: увидели ≠ получили разрешение сканировать

Пассивный анализ может показать IP, gateway, VLAN, DHCP server или LLDP/CDP neighbor. Environment discovery может показать connected route. Всё это — **наблюдаемая информация о сети**.

Она не превращается автоматически в active scope.

Перед Nmap оператор подтверждает цели, а backend создаёт immutable snapshot разрешённого scope.

```text
environment + passive evidence
            ↓
      scope proposal
            ↓
   operator confirmation
            ↓
 confirmed scope snapshot
            ↓
       Nmap discovery
            ↓
      asset inventory
            ↓
    protocol audits
```

Frontend не считается trust boundary: worker повторно проверяет scope перед реальным запуском scanner.

## Формат scope

`engine/scope.py` использует стандартный `ipaddress`.

Допустимы:

- одиночный IPv4;
- одиночный IPv6;
- IPv4 CIDR;
- IPv6 CIDR;
- несколько целей одновременно.

Targets canonicalize'ятся: duplicates и адреса, уже покрытые более широкой сетью, убираются.

Запрещены unspecified и multicast ranges, в том числе:

```text
0.0.0.0/0
::/0
224.0.0.0/4
IPv6 multicast equivalents
```

Размер scope считается **до** создания job.

## Лимиты

Default caps рассчитаны на небольшой appliance и обычный LAN-аудит:

| Профиль | IPv4 limit | Примерно соответствует |
| --- | ---: | --- |
| Discovery | 4096 | `/20` |
| Standard | 1024 | `/22` |
| Deep | 256 | `/24` |

IPv6 ограничен отдельно: 256 адресов. WireScope не пытается перебрать `/64`.

При осознанной необходимости администратор может поднять caps через `WIRESCOPE_ALLOW_LARGE_SCOPES=true` и соответствующие `WIRESCOPE_*_MAX_TARGETS`, но запрет unspecified networks остаётся.

## Interface и route validation

Перед active discovery недостаточно, чтобы target формально лежал в CIDR.

WireScope проверяет:

- interface существует;
- interface проходит policy;
- link UP;
- `ip route get` для target реально указывает на выбранный `dev`;
- есть source address нужного address family;
- VLAN subinterface уже существует, если он выбран.

Контекст маршрута сохраняется вместе со scope: source, gateway, interface, family, directly connected/routed.

Если capture NIC не имеет L3-адреса, passive capture всё равно работает. Active discovery требует реального L3 path — например адрес на самом NIC, существующий `eth0.10` или явно подтверждённую и корректно маршрутизируемую сеть.

WireScope сам не создаёт VLAN subinterfaces в active-discovery pipeline.

## Профили Nmap

Пользователь выбирает профиль, а не CLI flags. Timing по умолчанию — **T3**. T5 не используется.

### Discovery

Цель — быстро понять, какие узлы отвечают.

Для directly connected IPv4 при доступных raw privileges используется ARP discovery. Для routed IPv4 — ICMP/TCP discovery probes. Для IPv6 — neighbor discovery при доступных privileges либо TCP probes.

Port scan, `-sV` и OS detection здесь не выполняются.

### Standard

Основной профиль для обычного аудита:

- host discovery;
- TCP top 1000;
- `-sV --version-intensity 5`;
- OS detection, если process уже имеет нужные capabilities;
- ограниченный UDP-набор:
  `53,67,68,69,111,123,137,161,162,500,623,1900,4500,5353,5355`.

### Deep

Более шумный и долгий режим:

- host discovery;
- TCP `1-65535`;
- `--version-intensity 7`;
- OS detection при наличии privilege;
- расширенный UDP-набор.

Deep по-прежнему не включает NSE, `-sC`, `vuln`, brute, exploit, auth или DoS scripts.

## Nmap provider

Единственная точка запуска Nmap — `providers/nmap.py`.

Provider:

- определяет binary/version;
- проверяет доступность raw-socket режима без повышения привилегий;
- строит argv;
- пишет targets в внутренний `0600` target file и передаёт его через `-iL`;
- просит XML через `-oX`;
- сохраняет XML как evidence artifact;
- поддерживает timeout и cooperative cancellation;
- возвращает нормализованные hosts/services/OS hints.

Если raw privileges нет:

```text
SYN / ARP / OS / UDP unavailable
             ↓
        TCP connect -sT
             ↓
 skipped capabilities recorded
```

WireScope не запускает по Nmap process на каждый host. Один audit использует небольшое число scanner processes по стадиям.

Default `WIRESCOPE_MAX_ACTIVE_DISCOVERY_JOBS=1`.

## Host state

Отсутствие ICMP echo не равно «host down».

Inventory различает:

- `observed` — есть только пассивные evidence;
- `responsive` — scanner подтвердил `up`;
- `unresponsive` — одиночный target не ответил;
- `unknown` — состояние определить нельзя.

При сканировании большого CIDR WireScope не создаёт тысячи asset rows для каждого неответившего адреса.

Ошибка Nmap — job error, а не «найдено 0 узлов».

## Inventory

Asset не идентифицируется глобально одним IP.

Хранятся:

- MAC и vendor, если известны;
- addresses с provenance;
- hostnames с provenance;
- services;
- OS hints;
- device-class hints;
- first/last seen.

Service уникален внутри asset по `(protocol, port)`.

### Корреляция passive + active

Порядок:

1. exact MAC;
2. exact IP.

Если MAC говорит, что это asset A, а IP уже принадлежит asset B, WireScope не «угадывает» и не merge'ит их. Конфликт фиксируется отдельно.

Имена из PTR, DHCP, mDNS, LLMNR, NBNS и Nmap сохраняют source/provenance.

### Vendor lookup

OUI lookup локальный:

```text
/usr/share/ieee-data/oui.txt
```

или bundled subset.

На каждый MAC HTTP-запросы наружу не выполняются.

### OS и device class

OS match и device class — hints, а не confirmed facts.

Примеры device class:

- `server-like`;
- `workstation-like`;
- `network-device-like`;
- `printer-like`;
- `iot-like`;
- `unknown`.

## Resource locking

Active discovery берёт:

- `interface:<name>`;
- resource group `active_discovery`.

Поэтому capture и Nmap не работают на одном interface одновременно при стандартной конфигурации.

Default limit — один active-discovery job.

## Network impact

`Standard` + `/24` + T3 — базовый сценарий.

`Deep` заметно тяжелее: полный TCP range и больше UDP probes. Его default scope cap специально ограничен 256 адресами.

Cancellation завершает Nmap process group и переводит job в `cancelled`. Уже корректно сохранённые результаты предыдущих stages могут остаться в inventory.

## Protocol audits

После active inventory включается следующий слой: проверки конкретных сервисов.

```text
inventory service
      ↓
registry predicate match
      ↓
check authorized address
      ↓
provider argv
      ↓
external tool
      ↓
parser
      ↓
normalized protocol observation
      ↓
evidence + SQLite
```

Protocol audit не является vulnerability scanner. Он собирает структурированные факты, которые позже читает findings engine.

## Контракт модуля

Каждый module в `protocol_audits/modules/` задаёт:

- port/transport/service/product/tunnel predicates;
- required tool;
- optional minimum version;
- safety class: `safe`, `gated`, `never-default`;
- argv builder;
- parser без доступа к SQLite;
- timeout budget;
- normalized observation kinds.

Добавление модуля требует registry registration, а не правки orchestration core.

## Текущие protocol modules

| Модуль | Инструмент | Что собирается |
| --- | --- | --- |
| SSH | `ssh-audit` | banner, KEX, host-key, cipher, MAC algorithms |
| TLS | `openssl s_client` | protocol, cipher, certificate metadata, verify code |
| HTTP | `curl` | status, selected headers, HTML title |
| DNS | `dig` | CHAOS identity и DNS flags |
| SMB | `smbclient -N -L` | разрешён/отклонён null session |
| SNMP | `snmpget -v3 -l noAuthNoPriv` | unauthenticated response/timeout |
| LDAP | `ldapsearch -x` | anonymous base DSE / refusal |

## Safety limits protocol audits

- Только confirmed inventory addresses внутри authorized scope.
- Credential store отсутствует.
- Password/community guessing отсутствует.
- SNMP walk не выполняется.
- HTTP redirects не follow'ятся автоматически (`--max-redirs 0`).
- SMB enumeration ограничена null-session list probe.
- Authenticated AD/LDAP audit пока не реализован.
- Внешние Internet callbacks для проверок не нужны.

Default:

```text
WIRESCOPE_MAX_PROTOCOL_AUDIT_JOBS=1
WIRESCOPE_PROTOCOL_AUDIT_CONCURRENCY=1
WIRESCOPE_PROTOCOL_AUDIT_TIMEOUT_SECONDS=20
```

## NSE policy

Protocol-audit path Nmap Scripting Engine не использует.

Нет `-sC` и нет allowlist для `vuln/brute/exploit/dos/auth`, потому что NSE здесь вообще не является provider model.

`testssl.sh`, Nikto и Nuclei зарегистрированы только как `never-default` stubs. Они не строят команды и обычным API request не запускаются.

## Ошибки инструментов

Protocol observation может сообщить:

- `tool_unavailable`;
- timeout;
- cancelled;
- malformed output;
- tool failure;
- protocol-specific negative result.

Эти состояния не должны смешиваться.

Например:

```text
smbclient отсутствует
```

не означает:

```text
SMB null session запрещён
```

и тем более не означает «SMB отсутствует».

## Evidence и повторный запуск

Raw stdout/stderr protocol providers сохраняется как `protocol_tool_output` evidence artifact с SHA-256.

Нормализованные observations upsert'ятся по стабильному dedupe identity, а не дублируются бесконечно при каждом повторном запуске.

Findings engine читает уже эти normalized observations. Raw output ему не нужен.

Подробнее: [FINDINGS_MODEL.md](FINDINGS_MODEL.md).
