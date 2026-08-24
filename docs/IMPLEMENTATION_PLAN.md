# План развития WireScope

**Русский** · [English](en/IMPLEMENTATION_PLAN.md)

Этот файл — история основных архитектурных этапов и актуальный roadmap. Текущее устройство системы описано в [ARCHITECTURE.md](ARCHITECTURE.md), эксплуатация — в [OPERATIONS.md](OPERATIONS.md), а граница первой стабильной версии — в [RELEASE_READINESS.md](RELEASE_READINESS.md).

## Состояние проекта

```text
M0  стабилизация прототипа              ✓
M1  passive foundation                  ✓
M2  durable jobs + persistence          ✓
M3  active discovery                    ✓
M4  service-aware protocol audits       ✓
M5  findings engine                     ✓
M6  reporting                           ✓
M7  operator GUI + local auth           ✓
M8  generic Linux appliance             ✓ implementation
M9  hardening + lifecycle               ✓ implementation / release validation pending

                                  ↓
                         v1.0.0-rc1 release gate
```

Сейчас задача проекта — **не добавлять scanners до бесконечности**, а довести уже существующий appliance до проверяемого RC1.

## Неподвижные правила

Независимо от milestone:

- Python 3.11+;
- generic Linux на `amd64`/`arm64`;
- API/worker не работают от root;
- external tools запускаются argv-массивами без `shell=True`;
- packet-capture privileges принадлежат только `dumpcap`;
- active scan возможен только внутри operator-confirmed scope;
- raw evidence отделено от normalized data;
- failure provider/parser не означает «протокол отсутствует»;
- runtime behavior должен иметь tests и документацию;
- default pytest не должен случайно ходить в живую сеть.

---

# M0 — Stabilize ✓

Прототип был превращён в воспроизводимую Python codebase:

- централизованные settings;
- `pyproject.toml`;
- virtualenv/dependency setup;
- первые API/environment/sensor tests;
- архитектурные границы и roadmap.

---

# M1 — Passive foundation ✓

Появился bounded passive pipeline:

```text
validated interface
      ↓
dumpcap → PCAP
      ↓
tshark -T ek
      ↓
PacketRecord
      ↓
sensors
      ↓
assessment
```

Реализованы Ethernet/MAC, VLAN/QinQ, ARP, DHCPv4/v6, LLDP/CDP, STP, IPv6 RA/ND, mDNS, LLMNR, NBNS, SSDP и confidence-aware assessment.

---

# M2 — Durable jobs + persistence ✓

Process-local state заменён SQLite system of record.

Добавлены:

- SQLAlchemy/Alembic;
- WAL/foreign keys/busy timeout;
- `queued/running/completed/failed/cancelled/interrupted`;
- API/worker split;
- job events;
- worker heartbeat;
- resource locks;
- startup recovery;
- atomic artifact storage.

Перезапуск браузера/API больше не владеет lifetime выполняющейся job.

---

# M3 — Active discovery ✓

WireScope получил подтверждаемый active scope и Nmap provider.

Перед запуском:

- canonical target validation;
- scope caps;
- запрет unspecified/multicast;
- interface/route revalidation;
- immutable confirmed-scope snapshot.

Nmap XML сохраняется как evidence, а assets/services попадают в normalized inventory. Identity correlation использует прежде всего MAC, затем IP и сохраняет conflicts вместо агрессивного merge.

---

# M4 — Service-aware protocol audits ✓

Текущие modules:

| Protocol | Tool |
| --- | --- |
| SSH | `ssh-audit` |
| TLS | `openssl s_client` |
| HTTP/HTTPS | `curl` |
| DNS | `dig` |
| SMB | `smbclient` |
| SNMP | `snmpget` |
| LDAP | `ldapsearch` |

Module запускается только для соответствующего найденного service внутри authorized scope. Credential guessing и aggressive vulnerability scanners не являются default behavior.

---

# M5 — Findings ✓

```text
normalized observations
        ↓
versioned rules
        ↓
findings
```

Findings получили severity, confidence, evidence links, recommendations, deduplication и state trail (`suppressed`, `accepted_risk` и т.д.).

---

# M6 — Reporting ✓

Канонический report contract:

```text
audit-report v1
```

Exports:

- JSON;
- self-contained HTML;
- позднее поверх того же contract добавлен Markdown.

Report generation работает только с persisted state и не запускает сеть повторно.

---

# M7 — GUI + local auth ✓

Появился browser-first workflow без обязательного shell:

```text
login → audit wizard → progress → inventory/findings → report
```

Добавлены `auditor`/`viewer`, local sessions, kiosk-friendly layout, durable polling, network screen, Listen/Record и password change.

---

# M8 — Generic Linux appliance ✓ implementation

M8 сделал проект устанавливаемым appliance, а не только Python checkout.

Реализованы:

- apt/dnf/yum/zypper detection;
- amd64/arm64;
- system и user install;
- service account;
- `/opt/wirescope`, `/etc/wirescope`, `/var/lib/wirescope` layout;
- dumpcap least privilege;
- API/worker/kiosk systemd units;
- tty1 Chromium kiosk без полноценного desktop;
- network helper;
- backup/restore;
- upgrade path;
- direct TLS/reverse-proxy helpers;
- dependency inventory/checksums;
- `0.0.0.0:8000` как штатный appliance listener.

M8 implementation считается закрытым. Cross-distro/hardware smoke остаётся release verification, а не причиной бесконечно держать milestone «незавершённым».

---

# M9 — Hardening & Lifecycle ✓ implementation

M9 — последний обязательный кодовый milestone перед RC1.

## API structure

Большой `backend/app.py` разобран на domain routers. Канонический API — `/api/v1`; `/api` временно остаётся compatibility alias.

## Capabilities / operator insights

Добавлены:

- runtime capabilities;
- declarative active profiles;
- dashboard/pipeline;
- passive/active correlation view;
- device-class improvements;
- audit diff;
- audit-scoped evidence viewer;
- Markdown report export.

## Operational audit log

Новая таблица `operational_events` хранит значимые operator mutations и login attempts без request bodies/secrets.

## Recovery

Manual retry для `failed/interrupted/cancelled` job создаёт новую durable job. Terminal history не переписывается. Recovery работает на уровне stage.

## Lifecycle / retention

Добавлен lifecycle service:

- SQLite quick-check;
- disk/evidence usage;
- retention candidates;
- preview-first cleanup;
- explicit raw-evidence deletion;
- сохранение normalized history.

## Diagnostics

Auditor получает единый diagnostic snapshot и JSON export без необходимости сразу идти в SSH.

## GUI Operations

Отдельный `frontend/operations.js` показывает health, disk, retention, operational events и retry controls, не раздувая основной wizard.

## CI

GitHub Actions выполняет Python compile и default pytest на PR. Regression tests добавлены для API versioning, profiles, insights, evidence, Markdown, bind policy, lifecycle/retry/diagnostics и frontend integration.

---

# v1.0 RC1 — release gate

**RC1 — следующий milestone, но это уже не новый feature milestone.**

Его нельзя закрыть коммитом в GitHub. Нужен живой upgrade/smoke-test на установленном WireScope.

Обязательный путь:

```text
backup
  ↓
git update + packaging/upgrade.sh
  ↓
migrations current
  ↓
API + worker ready
  ↓
remote GUI via appliance IP
  ↓
passive audit
  ↓
Standard audit on authorized test scope
  ↓
assets/services/findings/evidence
  ↓
HTML/JSON/Markdown
  ↓
second audit + diff
  ↓
worker interruption + retry
  ↓
retention preview
  ↓
diagnostics / operational log
```

Полный gate: [RELEASE_READINESS.md](RELEASE_READINESS.md).

После его успешного прохождения:

```text
v1.0.0-rc1
```

После нескольких реальных аудитов без release-blocking defects можно ставить `v1.0.0`.

---

# Post-1.0 roadmap

Эти задачи полезны, но **не блокируют первую стабильную версию**.

## Protocol coverage

Кандидаты: FTP, SMTP, RDP, Redis, PostgreSQL/MySQL/MSSQL, MongoDB, Elasticsearch, MQTT, UPnP, IPMI, NTP, TFTP, Telnet, VNC, Docker API, Kubernetes API.

Для каждого сначала нужен безопасный observation contract, затем findings rules.

## Reports

- PDF renderer поверх `audit-report v1`;
- дополнительные exports при реальной необходимости.

## Network intelligence

- topology graph;
- deeper historical identity tracking;
- CVE enrichment;
- scheduled/baseline audits.

## Engineering

- дальнейшая frontend decomposition;
- eventual removal `/api/*` alias;
- broader distro/architecture CI matrix;
- authenticated audit model, если появятся credentialed checks.

## Definition of done для будущих изменений

Новый runtime behavior считается готовым, когда есть:

- implementation;
- migration при schema change;
- unit/fixture/API tests;
- понятное failure behavior;
- timeout/cancellation для external tools;
- отсутствие secrets в logs/units;
- актуальная документация;
- green default CI.

Главный принцип остаётся прежним: WireScope должен делать ровно то, что показывает оператору, и не превращать недостаток evidence в уверенный вывод.
