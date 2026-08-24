# Findings в WireScope

**Русский** · [English](en/FINDINGS_MODEL.md)

Finding — это не сырое наблюдение scanner'а и не строка из stdout внешнего инструмента. Это уже интерпретация: правило взяло нормализованные данные, проверило условия и сформировало результат с severity, confidence, объяснением и ссылками на evidence.

## Где findings находятся в pipeline

```text
passive_result
inventory services
protocol_observations
        ↓
findings/rules/
        ↓
correlation + deduplication
        ↓
findings
        ↓
report / GUI
```

Findings engine сам сеть не трогает. Он не запускает Nmap, Nuclei, Nikto, NSE, `ssh-audit`, OpenSSL или другие tools.

## Observation и finding — не одно и то же

Пример:

```text
Observation:
TLS session negotiated TLSv1.0
```

Это факт.

```text
Finding:
Legacy TLS protocol is enabled
severity: high
```

Это интерпретация факта по конкретному правилу.

Такое разделение нужно, чтобы scanner/parser не решал за rule engine, что считать проблемой, а повторная оценка могла выполняться без нового сетевого трафика.

## Модель finding

Schema version 1 хранит:

- `rule_id`;
- `rule_version`;
- `severity`;
- `confidence`;
- `status`;
- `asset_id` / `service_id`, если finding относится к конкретному объекту;
- title/description;
- rationale;
- recommendation;
- `observation_ids`;
- `evidence_artifact_ids`;
- `dedupe_key`.

Severity:

```text
critical
high
medium
low
info
```

Confidence использует общую шкалу WireScope:

```text
confirmed
high
medium
low
hint
unknown
```

Status:

```text
open
suppressed
accepted_risk
```

## Источники данных

Rules сейчас читают три основных источника.

### `protocol_observations`

Например:

- `ssh_algorithms`;
- `tls_session`;
- `tls_certificate`;
- `http_response`;
- `dns_flags`;
- `dns_identity`;
- `smb_null_session`;
- `snmp_unauthenticated`;
- `ldap_rootdse`.

### Inventory

Для некоторых вещей достаточно факта открытого сервиса. Например, insecure management protocol может быть определён по inventory даже без отдельного protocol module.

### Passive result

Пассивные findings могут использовать сохранённые sensor summaries/assessment, например LLMNR, NBNS или несколько DHCP servers.

## Rule registry

Rules лежат в:

```text
findings/rules/
```

и регистрируются через findings registry.

Добавление нового правила не требует менять job worker или scanner orchestration.

Правило должно работать с нормализованными объектами. Парсить внутри rule raw `ssh-audit`, OpenSSL, curl, dig, smbclient или другой stdout нельзя.

## Текущие семейства правил

| Rule | Источник | Типичная severity |
| --- | --- | --- |
| `WS-SSH-WEAK-ALGORITHMS` | SSH algorithms | high / medium |
| `WS-TLS-LEGACY-PROTOCOL` | TLS protocol | critical–medium |
| `WS-TLS-WEAK-CIPHER` | TLS cipher | high |
| `WS-TLS-CERT-EXPIRED` | certificate date | high |
| `WS-TLS-CERT-UNTRUSTED` | verify code | medium |
| `WS-HTTP-MISSING-HSTS` | HTTPS response | medium |
| `WS-HTTP-MISSING-SECURITY-HEADERS` | HTTP headers | low |
| `WS-HTTP-SERVER-DISCLOSURE` | response headers | info |
| `WS-SMB-NULL-SESSION` | SMB observation | high |
| `WS-SMB-SIGNING-DISABLED` | SMB signing field | medium |
| `WS-SMB-LEGACY-DIALECT` | SMB dialect field | high |
| `WS-DNS-RECURSION` | DNS flags | medium |
| `WS-DNS-VERSION-DISCLOSED` | CHAOS identity | low |
| `WS-SNMP-UNAUTHENTICATED` | SNMP response | high |
| `WS-LDAP-ANONYMOUS-BIND` | LDAP base DSE | medium |
| `WS-MGMT-INSECURE-PROTOCOL` | inventory service | high / medium |
| `WS-INFRA-LLMNR` / `WS-INFRA-NBNS` | passive sensors | medium |
| `WS-INFRA-MULTIPLE-DHCP` | DHCP summary | medium |

SMB signing/dialect rules срабатывают только когда соответствующие поля действительно присутствуют в normalized observation. Текущий `smbclient -N -L` не всегда даёт эти данные, поэтому отсутствие поля не превращается в finding.

## False-positive boundaries

Findings engine специально не создаёт security finding из технической ошибки provider.

Не являются findings сами по себе:

- `tool_unavailable`;
- timeout;
- `tool_failed`;
- cancellation;
- empty/malformed output;
- `dns_unreachable`;
- `snmp_unauthenticated.responded=false`;
- SMB refusal без дополнительных signing/dialect facts;
- `anonymous_bind=false`;
- `recursion_available=false`;
- нераспарсенная дата сертификата;
- отсутствие HSTS на обычном HTTP.

Особенно важно:

```text
tool missing ≠ protocol absent ≠ secure configuration
```

Это три разных состояния.

## Deduplication

Draft findings объединяются по стабильной паре rule/dedupe identity.

В БД uniqueness строится вокруг `(audit_id, rule_id, dedupe_key)`.

Повторный `findings_evaluation` обновляет тот же finding и evidence links вместо создания копии на каждый запуск.

## Suppress и accepted risk

Оператор может изменить состояние finding:

- `open → suppressed`;
- `open → accepted_risk`;
- вернуть finding в `open`.

Изменение состояния добавляет event с actor, reason и from/to state.

При повторной evaluation существующее `suppressed` или `accepted_risk` состояние не должно исчезать только потому, что правило снова сработало.

## Job

Создание evaluation:

```text
POST /api/audits/{id}/findings
```

создаёт job типа:

```text
findings_evaluation
```

Job использует audit-level lock и findings resource group. Interface lock ему не нужен, потому что сеть он не использует.

## API

Основные endpoints:

```text
POST /api/audits/{id}/findings
GET  /api/audits/{id}/findings
GET  /api/audits/{id}/findings/{finding_id}
POST /api/audits/{id}/findings/{finding_id}/suppress
POST /api/audits/{id}/findings/{finding_id}/accept-risk
POST /api/audits/{id}/findings/{finding_id}/reopen
```

List endpoint paginated и поддерживает фильтрацию.

## Тестирование

Findings evaluation полностью fixture-based и не требует live network.

Обычный:

```bash
pytest
```

не должен запускать сетевые проверки ради findings engine.

Это позволяет отдельно тестировать false-positive boundaries, severity, correlation и deduplication на фиксированных observations.
