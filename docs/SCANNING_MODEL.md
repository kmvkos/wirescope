# Модель сканирования WireScope

**Русский** · [English](en/SCANNING_MODEL.md)

WireScope разделяет аудит на несколько слоёв: пассивные наблюдения, подтверждение scope, активное обнаружение, protocol audits и findings. Это принципиально разные стадии. Данные, увиденные пассивно, не становятся автоматическим разрешением на сканирование.

## Увидели сеть ≠ получили право её сканировать

Пассивный анализ может показать IP, gateway, VLAN, DHCP server, LLDP/CDP neighbor или IPv6 router. Environment discovery может показать connected routes. Всё это считается **наблюдаемой информацией**.

Перед Nmap оператор подтверждает цели. Backend сохраняет snapshot разрешённого scope, и worker повторно проверяет его перед реальным запуском provider.

```text
environment + passive evidence
            ↓
      scope proposal
            ↓
   operator confirmation
            ↓
 confirmed scope snapshot
            ↓
     active discovery
            ↓
       inventory
            ↓
    protocol audits
            ↓
       findings
```

Frontend не является trust boundary.

## Scope

`engine/scope.py` работает со стандартным `ipaddress` и принимает одиночные IPv4/IPv6 адреса, CIDR и несколько целей одновременно.

Targets canonicalize'ятся: duplicates и адреса, уже покрытые более широкой сетью, убираются. Запрещены unspecified и multicast ranges, в том числе:

```text
0.0.0.0/0
::/0
224.0.0.0/4
IPv6 multicast ranges
```

Default caps:

| Профиль | IPv4 limit | Ориентир |
| --- | ---: | --- |
| Discovery | 4096 | `/20` |
| Standard | 1024 | `/22` |
| Deep | 256 | `/24` |

IPv6 ограничен отдельно; WireScope не разворачивает `/64` в огромный список адресов.

## Interface и route validation

До создания active job проверяются:

- interface существует и разрешён policy;
- link находится в подходящем состоянии;
- target действительно маршрутизируется через выбранный interface;
- есть source address нужного family;
- выбранный VLAN subinterface уже существует.

Route context сохраняется вместе со scope: source, gateway, interface, family и признак directly connected/routed.

Пассивный capture может работать на NIC без L3-адреса. Active discovery требует реального L3 path. WireScope не создаёт VLAN subinterfaces автоматически внутри discovery pipeline.

## Декларативные scan profiles

Пользователь выбирает профиль, а не набор CLI flags. Профили описаны в:

```text
config/active_profiles.json
```

Поддерживаются только три имени:

```text
discovery
standard
deep
```

Файл строго валидируется. Неизвестные поля запрещены. UDP ports ограничены 256 значениями, каждый port должен лежать в `1..65535`, а произвольное выражение для TCP range не принимается. Полный диапазон разрешён только как явно поддерживаемое `1-65535` для Deep.

Через `WIRESCOPE_ACTIVE_PROFILES_FILE` можно указать другой declarative profile file. Это даёт возможность менять безопасные параметры без возможности подсунуть произвольную командную строку Nmap.

### Discovery

Цель — быстро определить responsive hosts. Port scan, `-sV` и OS detection не выполняются.

### Standard

Основной профиль:

- host discovery;
- TCP top 1000;
- `-sV --version-intensity 5`;
- OS detection, когда process уже имеет нужные возможности;
- ограниченный UDP-набор.

### Deep

Более шумный режим:

- TCP `1-65535`;
- `--version-intensity 7`;
- OS detection при доступных privileges;
- расширенный UDP-набор.

Ни один профиль не включает NSE, `-sC`, `vuln`, brute-force, exploit, auth или DoS scripts.

Фактически загруженные профили можно посмотреть через:

```text
GET /api/v1/scan-profiles
```

## Nmap provider

Nmap запускается через `providers/nmap.py`. Provider:

- определяет binary/version;
- проверяет доступность raw-socket режима без privilege escalation;
- строит argv из typed profile;
- пишет targets во внутренний `0600` file и передаёт его через `-iL`;
- получает XML через `-oX`;
- сохраняет XML как evidence;
- поддерживает timeout и cooperative cancellation;
- возвращает нормализованные hosts/services/OS hints.

Если raw privileges недоступны, WireScope не повышает Nmap. Используются доступные непривилегированные режимы, а недоступные capabilities фиксируются отдельно.

Ошибка provider — это job error, а не «найдено 0 hosts».

## Inventory и идентичность assets

Inventory хранит:

- MAC и vendor;
- addresses с provenance;
- hostnames с provenance;
- services;
- OS hints;
- device-class hint + confidence;
- first/last seen;
- identity conflicts.

Service уникален внутри asset по `(protocol, port)`.

### Passive + active correlation

Базовый порядок идентичности:

1. exact MAC;
2. exact IP.

Если MAC указывает на asset A, а IP уже принадлежит asset B, WireScope не объединяет их молча. Создаётся `identity_conflict`, а конфликтующие данные сохраняются для разбора.

Hostname намеренно **не используется как самостоятельное merge-доказательство**: DHCP/PTR/mDNS имена могут повторяться, переезжать между адресами и быть устаревшими.

Источник каждого имени сохраняется: Nmap, DHCP, mDNS, LLMNR, NBNS и т.д.

Объяснение текущей корреляции доступно через:

```text
GET /api/v1/audits/{audit_id}/correlations
```

Ответ показывает identity basis, passive/active sources, addresses/names с provenance и факт того, подтверждается ли asset одновременно пассивными и активными источниками.

## Device classification

Классификация — это hint, а не finding. Она использует несколько слабых сигналов вместе:

- OS hint;
- MAC vendor;
- открытые management/server/printer ports;
- naming protocols;
- сетевые признаки вроде SNMP + management ports.

Классы:

```text
server-like
workstation-like
network-device-like
printer-like
iot-like
unknown
```

Confidence повышается только при сочетании независимых сигналов. Например, printer vendor + TCP/9100 сильнее, чем один TCP/9100; MikroTik vendor + RouterOS + SNMP/management ports сильнее, чем один открытый HTTP.

## Host state

Inventory различает:

- `observed` — есть пассивные evidence;
- `responsive` — active provider подтвердил host;
- `unresponsive` — одиночная цель не ответила;
- `unknown` — состояние определить нельзя.

Отсутствие ICMP echo не трактуется автоматически как host down. При CIDR scan WireScope не материализует тысячи rows для каждого неответившего адреса.

## Protocol audits

После inventory запускаются проверки конкретных сервисов:

```text
inventory service
      ↓
module predicate match
      ↓
authorized address check
      ↓
provider argv
      ↓
external tool
      ↓
parser
      ↓
normalized observation
      ↓
SQLite + evidence
```

Текущие modules:

| Модуль | Инструмент | Основные observations |
| --- | --- | --- |
| SSH | `ssh-audit` | banner, KEX, host-key, cipher, MAC algorithms |
| TLS | `openssl s_client` | protocol, cipher, certificate metadata, verify code |
| HTTP | `curl` | status, selected headers, HTML title |
| DNS | `dig` | CHAOS identity и DNS flags |
| SMB | `smbclient -N -L` | null-session list probe |
| SNMP | `snmpget -v3 -l noAuthNoPriv` | unauthenticated response/timeout |
| LDAP | `ldapsearch -x` | anonymous base DSE / refusal |

`testssl.sh`, Nikto и Nuclei зарегистрированы только как `never-default` stubs.

## Safety limits protocol audits

- Только inventory addresses внутри confirmed scope.
- Credential store отсутствует.
- Password/community guessing отсутствует.
- SNMP walk не выполняется.
- HTTP redirects не follow'ятся автоматически.
- SMB ограничен null-session list probe.
- Authenticated AD/LDAP audit пока не реализован.

Ошибки инструментов (`tool_unavailable`, timeout, malformed output, cancellation) не смешиваются с отрицательным результатом проверки. Например, отсутствие `smbclient` не означает, что SMB null session запрещён.

## Evidence

Raw outputs providers сохраняются как evidence artifacts с SHA-256. Findings engine работает с нормализованными observations, а не парсит raw stdout повторно.

Текстовые evidence можно открыть из GUI или через audit-scoped API:

```text
GET /api/v1/audits/{audit_id}/artifacts/{artifact_id}
```

Подробнее: [FINDINGS_MODEL.md](FINDINGS_MODEL.md) и [API.md](API.md).
