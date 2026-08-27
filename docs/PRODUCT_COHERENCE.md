# Product Coherence — отчёты и представления WireScope

[English](en/PRODUCT_COHERENCE.md)

Статус: **review complete / closed**.

Этот документ фиксирует, **какая подсистема владеет каким типом информации** и как WireScope избегает повторения одних и тех же данных в разных отчётах и экранах.

## Базовое правило

Для каждого типа данных есть один source-of-truth.

Другой экран или export может показать краткий контекст этого факта только если он нужен для собственной задачи. Полные таблицы, rationale, recommendations и подробная диагностика остаются у владельца.

```text
owner → полная информация
summary/context → короткое представление
cross-source view → связь + ссылка на owner
```

## Ownership matrix

| Подсистема | Владеет | Не должна делать |
|---|---|---|
| Audit Report | inventory, discovered services, protocol-audit results, findings, severity/confidence, rationale, recommendations, audit evidence | пересказывать полный PCAP diagnostic report |
| Traffic Analysis | факты конкретного capture window, rates, conversations, protocol visibility, TCP/DNS/ARP/DHCP/ICMP diagnostics, observed metadata | превращать присутствие протокола в security finding или дублировать рекомендации Audit Report |
| Network Topology | nodes/edges, L2/L3/Traffic relationships, VLAN, infrastructure roles, claimability/coverage | печатать полный findings/traffic report |
| Correlated Assessment | cross-source relationships: audit↔traffic↔topology | копировать source reports целиком или создавать новый vulnerability report |
| Dashboard/operator summary | статус, компактные счётчики, навигация к владельцу | быть ещё одним полноценным отчётом |

## Audit Report

Audit Report остаётся главным документом, если вопрос звучит:

- какие узлы и сервисы обнаружены;
- какие protocol audits выполнены;
- какие security findings сформированы;
- почему finding важен;
- что рекомендуется проверить/исправить;
- на какие audit evidence он опирается.

Security severity, rationale и remediation принадлежат Findings/Audit Report.

## Traffic Analysis

Traffic Analysis отвечает на вопрос:

> Что было видно в этом конкретном PCAP и какие сетевые диагностические признаки присутствовали?

Он может показать:

- Telnet/FTP/HTTP/LLMNR/NBNS **наблюдался**;
- TCP retransmission/zero-window/reset;
- DNS errors/latency;
- ARP conflicts;
- DHCP observations;
- broadcast/multicast;
- TLS/HTTP/QUIC/SMB metadata;
- communications/top talkers/rates.

Но само наличие Telnet/FTP/HTTP не должно превращаться в Traffic Analysis finding с собственной security severity и remediation. Если Audit Report существует, security-контекст принадлежит ему; Correlated Assessment может связать traffic observation с найденным service/finding.

### Внутренняя дедупликация Traffic Analysis

Human-readable Traffic Analysis делится на уровни:

1. **Capture summary / traffic character** — duration, rates, dominant traffic.
2. **Network diagnostics** — TCP health, DNS timing/errors, ARP/ICMP, broadcast/multicast.
3. **Protocol detail** — DNS names/servers, DHCP transaction metadata, TLS/HTTP/QUIC/SMB metadata.
4. **Limitations** — границы capture visibility.

Один подробный список должен иметь одного владельца внутри renderer-а. Например DNS top names принадлежат Protocol Detail и не должны повторяться ещё раз в DNS Diagnostics; DHCP server identifiers принадлежат Protocol Detail и не должны повторяться в общей ARP/ICMP диагностике.

## Network Topology

Topology может показывать badge/count finding или traffic relationship как контекст узла/ребра, но не копирует rationale/recommendation или полный communication report.

Structural view остаётся infrastructure-first. Traffic-only endpoints и связи живут в Traffic view/явном overlay и не превращаются в инфраструктурные факты без дополнительного evidence.

Management sources SNMP/SSH являются явными optional/lazy источниками. Их UI и renderer не должны изменять поведение обычной topology view после закрытия дополнительного режима.

## Correlated Assessment

Correlated Assessment показывает только то, что появляется **на пересечении источников**:

- найденный service наблюдался в выбранном traffic;
- finding относится к asset/service, присутствовавшему в traffic;
- inventory asset не был виден в capture window;
- traffic endpoint не сопоставился с inventory;
- infrastructure observations согласуются/расходятся;
- exact-correlated internal asset общался с global endpoint.

Он может привести минимальный source context, но не копирует полные source sections.

## Dashboard и GUI

Dashboard отвечает на вопрос «куда смотреть дальше».

Допустимы компактные показатели и ссылки:

- findings by severity;
- число assets/services;
- наличие Traffic Analysis;
- partial/failed sources;
- topology availability;
- наличие Correlated Assessment.

Недопустимо встраивать второй полный Audit Report/Traffic Analysis внутрь dashboard.

## Export policy

HTML/Markdown/TXT/JSON одного продукта должны сохранять ту же ownership-модель, что и GUI.

JSON может содержать canonical machine-readable данные своего source-of-truth. Human-readable exports должны быть дедуплицированы и ориентированы на задачу конкретного продукта.

## Compatibility

Coherence changes по возможности выполняются на presentation/interpretation layer без удаления persisted canonical evidence.

Если смысл persisted Traffic Analysis действительно меняется (например observation перестаёт считаться security warning), увеличивается `ANALYZER_VERSION`, чтобы старый retained PCAP можно было пересчитать новым анализатором вместо молчаливого reuse старого результата.

## Acceptance criteria

Product Coherence Review считается завершённым, когда:

- protocol presence в Traffic Analysis не выдаётся за security finding;
- security rationale/recommendations имеют одного owner — Audit Findings;
- DNS/DHCP и другие detailed blocks не повторяются внутри текущего Traffic Analysis renderer;
- Correlated Assessment остаётся cross-source view, а не composite report;
- topology остаётся relationship/claimability view;
- README/reporting/GUI docs описывают одинаковую ownership-модель;
- regression tests фиксируют основные anti-duplication contracts;
- optional SNMP/SSH topology modules не продолжают выполнять management reads после возврата к обычной topology view.

**Все критерии выше выполнены.** Финальный кодовый checkpoint review прошёл полный automated gate: compile, JS syntax, pytest, Chromium kiosk/web smoke, wheel build и installed-wheel smoke.
