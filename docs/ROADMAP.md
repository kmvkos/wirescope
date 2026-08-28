# WireScope — Roadmap после 1.0

Этот документ описывает развитие WireScope после feature freeze базовой линии v1.0.

Главный принцип: WireScope остаётся **переносным автономным сетевым аудитором**, а не развивается незаметно в SIEM/NDR/SOC-платформу. Новые функции не должны ослаблять safety-контракты: passive observation не даёт active authorization, scope подтверждается оператором, внешние инструменты запускаются без shell, а выводы остаются traceable до persisted evidence.

## v1.0 — базовый сетевой аудитор

Статус: **feature complete / frozen**.

Базовая линия включает passive analysis, отдельный PCAP capture, operator-confirmed active scope, Discovery/Standard/Deep, inventory, protocol audits, findings/evidence, HTML/JSON/Markdown reports, audit diff, diagnostics, retention/recovery, web/kiosk UI и appliance backup/restore.

После freeze допускаются bug fixes, compatibility и release engineering, но не скрытое расширение базового scope.

---

## v1.1 — PCAP Traffic Analysis

Статус: **implementation complete; основные live-сценарии пройдены**.

Сохранённый PCAP анализируется offline без нового capture/network I/O.

Реализованы:

- duration/frames/bytes/rates;
- top talkers и communications graph;
- TCP health;
- DNS latency/errors;
- ARP/DHCP/ICMP/ICMPv6 diagnostics;
- broadcast/multicast contributors;
- TLS/HTTP/QUIC/SMB metadata без payload decryption;
- ACK RTT summaries;
- compare persisted Traffic Analysis results;
- canonical `traffic-analysis` JSON, TXT/Markdown и web/kiosk UI.

Traffic Analysis является **source-of-truth для того, что наблюдалось в конкретном capture window**. Он не должен превращаться во второй Audit Report.

---

## v1.2 — Network Topology

Статус: **feature complete / closed**.

M11.1–M11.4 реализованы и основной topology path live-проверен на WireScope VM.

Topology объединяет persisted inventory/ARP/ND/routes/DHCP/LLDP/CDP/STP/VLAN/active evidence и явно выбранный Traffic Analysis. Реализованы structural/L2/L3/Traffic/All Evidence views, subnet regions, historical compare, JSON/SVG/PNG exports, VLAN focus и optional read-only SNMP/SSH enrichment.

`coverage` / claimability показывает `sufficient / partial / missing` для соответствующих evidence domains. WireScope не угадывает gateway, physical links, VLAN или Wi-Fi attachment при недостатке evidence.

Management-discovered topology не расширяет active scope.

Подробности: [TOPOLOGY_MODEL.md](TOPOLOGY_MODEL.md).

---

## v1.3 — Correlated Assessment / Корреляция результатов

Статус: **feature complete / closed**.

Пользовательское название — **«Корреляция результатов»**. Технические identifiers `global_analysis`, `global-analysis` и `/global-analysis` сохранены для backward compatibility.

Цель v1.3 — не создавать «глубокий глобальный анализ», а показать, **что уже сохранённые источники подтверждают или дополняют друг в друге**.

Реализовано:

- exact IP/MAC inventory ↔ traffic identity, без hostname-only merge;
- service ↔ observed traffic correlation;
- finding ↔ observed asset/service relevance без изменения исходной severity;
- inventory ↔ selected-capture visibility;
- exact-correlated internal asset ↔ globally routable endpoint;
- conservative `private_unknown` classification;
- gateway/DHCP/DNS cross-source consistency;
- inherited partial/source-health state;
- deterministic IDs/rule IDs и safe evidence lineage;
- offline preview;
- durable `global_analysis` job + `global_analysis_result` artifact;
- immutable history/rebuild;
- JSON/TXT/Markdown exports;
- operator GUI **«Корреляция результатов»**;
- automated compile/pytest/JS syntax/wheel/installed-wheel validation;
- live validation на установленной WireScope VM.

### Жёсткая граница v1.3

Correlated Assessment **не должен дублировать исходные отчёты**. Он показывает source fact только когда этот факт нужен для объяснения межисточниковой связи.

v1.3 намеренно не включает:

- behavioral/anomaly baselines;
- attack/intent inference;
- threat intelligence/reputation scoring;
- большой traffic pattern engine;
- автоматические новые security findings из correlation result;
- AI-анализ;
- попытку заменить SIEM/NDR.

Текущий `traffic-analysis` v1 агрегирует destination ports по communication pair, поэтому service-use correlation остаётся pair-level `observed_pair_destination_port`. Более точный directional flow contract может появиться позже как отдельное улучшение Traffic Analysis, но не является незакрытой частью v1.3.

Подробности: [GLOBAL_ANALYSIS_MODEL.md](GLOBAL_ANALYSIS_MODEL.md).

---

## v1.3.1 — Product Coherence Review

Статус: **complete / closed**.

Это не новая крупная функция, а системная ревизия уже существующего продукта после v1.3. Цель — убрать повторение одних и тех же данных между Audit Report, Traffic Analysis, Network Topology, Correlated Assessment, dashboard/operator views и human-readable exports.

Зафиксирована единая ownership-модель:

1. **Audit Report** владеет inventory, discovered services, protocol-audit findings, rationale/recommendations и audit evidence.
2. **Traffic Analysis** владеет фактами конкретного capture window: traffic metrics, conversations, protocol observations и network diagnostics.
3. **Network Topology** владеет структурой/relationships/claimability и не пересказывает security/traffic reports целиком.
4. **Correlated Assessment** владеет только cross-source relationships и ссылается на исходные данные вместо их повторения.
5. Dashboard/UI summary показывает compact navigation/status, а не ещё один полный отчёт.

В рамках review завершены:

- дедупликация human-readable Traffic Analysis и унификация операторской терминологии;
- сохранение canonical JSON-контрактов при улучшении TXT/Markdown/HTML/UI presentation;
- очистка Audit Report human exports без изменения persisted canonical report;
- сохранение Correlated Assessment как cross-source view, а не composite vulnerability report;
- приведение topology UI к infrastructure-first модели;
- перенос SNMP/SSH management sources в явный optional/lazy раздел «Дополнительно»;
- изоляция SNMP/SSH topology renderers, чтобы обычная карта после открытия management-модулей не выполняла лишние management API reads;
- regression tests на anti-duplication, presentation safety, kiosk/web layout и lazy management behavior;
- cache-bust/version checks для изменённых frontend assets.

Финальный кодовый checkpoint review прошёл полный GitHub Actions gate: Python compile, JS syntax, default pytest, Chromium kiosk/web smoke, wheel build и installed-wheel smoke.

Подробности: [PRODUCT_COHERENCE.md](PRODUCT_COHERENCE.md) и [REPORTING_MODEL.md](REPORTING_MODEL.md).

---

## v1.4 — Manual PCAP Import

Статус: **implementation complete; требуется установленная VM/live UX-проверка**.

Цель — позволить оператору вручную передать внешний PCAP/PCAPNG в уже существующий offline Traffic Analysis pipeline без создания второго анализатора или отдельного хранилища.

Реализовано:

- ручная загрузка `.pcap` и `.pcapng` из operator UI;
- raw streaming upload без буферизации всего файла в RAM;
- configurable import limit, по умолчанию 256 МиБ;
- confined staging внутри evidence root;
- проверка magic/header, размера и SHA-256 до durable job;
- повторная проверка размера/SHA-256 worker'ом перед регистрацией final artifact;
- reuse существующего `packet_capture` lifecycle с `source_origin=imported`;
- сохранение PCAP/PCAPNG формата и корректного media type при download;
- существующие download/delete/re-analysis операции для импортированного PCAP;
- запуск обычного Traffic Analysis только по явному действию оператора;
- explicit operator selection завершённого Traffic Analysis для последующей корреляции;
- отдельный operational audit event `capture.pcap_import`;
- API, worker и Chromium regression tests.

### Trust boundary v1.4

Внешний PCAP — **исторический недоверенный observation source**.

Импорт:

- не выполняет network I/O;
- не запускает live capture/discovery/probes;
- не создаёт и не расширяет confirmed active scope;
- не означает, что сеть из файла сейчас подключена к WireScope;
- не разрешает active scanning адресов/VLAN, найденных только во внешнем файле;
- не смешивается автоматически с текущим аудитом или корреляцией.

Технический durable result фиксирует `source_origin=imported`, `network_io_performed=false` и `active_scope_authorized=false`.

Подробности: [PCAP_MANAGEMENT.md](PCAP_MANAGEMENT.md).

---

## Идеи после v1.4

Не являются текущими обязательствами и должны проектироваться отдельно:

- PDF export;
- дополнительные protocol audit modules;
- controlled/local CVE enrichment;
- scheduled audits;
- long-term traffic baselines;
- cross-site topology history;
- hypervisor-specific topology providers;
- vendor-specific management-plane adapters;
- расширенная distro/architecture/tshark compatibility matrix.

## Текущий следующий шаг

**Manual PCAP Import реализован. Перед закрытием v1.4 нужен установленный VM-check реального upload → Traffic Analysis → optional Correlated Assessment. Следующее крупное направление после этого пока не выбрано.**
