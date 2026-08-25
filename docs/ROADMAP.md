# WireScope — Roadmap после 1.0

Этот документ начинается после feature freeze первой стабильной линии WireScope.
Новые возможности не должны менять safety-контракты v1: пассивное наблюдение не является разрешением на активное сканирование, активный scope подтверждается оператором, сетевые инструменты запускаются без shell, evidence остаётся воспроизводимым.

## v1.0 — базовый сетевой аудитор

Статус: **feature complete / frozen**.

Состав релиза:
- пассивный анализ локального сегмента;
- отдельное прослушивание/запись PCAP;
- подтверждённый active scope и профили Discovery / Standard / Deep;
- inventory и корреляция устройств;
- безопасные protocol audits;
- findings;
- HTML / JSON / Markdown отчёты;
- audit diff, evidence viewer, diagnostics, retention, retry;
- web/kiosk UI;
- удаление отдельных отчётов и полное удаление завершённых аудитов.

После freeze допускаются только исправления дефектов и release engineering.

---

## v1.1 — PCAP Traffic Analysis

Цель: превратить «Прослушивание» из простого сохранения PCAP в самостоятельный инструмент диагностики трафика.

### M10.1 — детерминированный анализ сохранённого PCAP

После завершённого или остановленного прослушивания оператор может нажать **«Анализировать PCAP»**.

Анализ выполняется отдельной durable job и не запускает новый сетевой захват.
Источник истины — уже сохранённый PCAP evidence.

Первая версия анализа должна выдавать:
- длительность, количество кадров и объём;
- уникальные MAC / IPv4 / IPv6;
- top talkers по пакетам и байтам;
- распределение основных протоколов;
- список наиболее активных пар узлов;
- TCP health: retransmission, duplicate ACK, out-of-order, reset, zero-window и другие доступные сигналы;
- DNS: запросы, NXDOMAIN/SERVFAIL и наиболее частые имена;
- ARP: IP↔MAC наблюдения, gratuitous/аномальные изменения и возможные конфликты;
- DHCP server hints;
- broadcast / multicast долю и основные источники;
- наблюдение потенциально небезопасных clear-text/legacy протоколов;
- детерминированные пояснения «что наблюдалось → что это может означать → что проверить».

Результаты:
- canonical JSON `traffic-analysis`;
- читаемый русский TXT;
- Markdown export;
- UI-представление в web и kiosk.

### M10.2 — communications graph data

Анализатор сохраняет нормализованные связи между узлами:
- endpoint A / endpoint B;
- пакеты и байты по направлениям;
- наблюдавшиеся протоколы/порты;
- first/last seen;
- provenance=`pcap`;
- confidence=`observed`.

Эти данные являются входом для будущей карты сети, а не отдельной параллельной моделью.

### M10.3 — расширенная диагностика

После стабилизации базового анализатора:
- TCP handshake failures / SYN retransmissions;
- RTT/latency hints там, где их можно корректно вывести из PCAP;
- DNS latency/timeouts;
- DHCP sequence analysis;
- ARP storm / unanswered ARP;
- broadcast/multicast contributors;
- TLS metadata без расшифровки payload;
- SMB/DNS/HTTP/QUIC traffic summaries;
- сравнение двух captures.

Принцип: WireScope не объявляет причину доказанной, если PCAP даёт только симптом. Формулировки должны различать факт, гипотезу и рекомендацию проверки.

---

## v1.2 — Network Topology

Цель: построить понятную карту наблюдаемой сети с указанием происхождения и достоверности каждой связи.

### M11.1 — логическая карта

Источники:
- inventory;
- ARP;
- default gateway / route information;
- DHCP;
- LLDP / CDP;
- STP;
- VLAN/QinQ;
- active discovery;
- PCAP communications graph.

Узлы карты:
- WireScope/interface;
- gateway/router;
- switch/network-device hints;
- DHCP/DNS servers;
- обычные assets;
- VLAN/subnet logical groups.

Связи имеют тип и confidence:
- `confirmed` — LLDP/CDP или другой прямой структурный evidence;
- `observed` — реальный обмен в PCAP;
- `inferred` — осторожный вывод по subnet/VLAN/route/ARP данным.

UI обязан показывать provenance связи, например «LLDP», «наблюдаемый трафик», «default route», а не рисовать предположение как физический факт.

### M11.2 — интерактивная визуализация

Web/kiosk:
- zoom/pan;
- фильтр VLAN/subnet;
- фильтр типа связи;
- клик по asset → адреса, сервисы, vendor, findings;
- толщина communication edge по объёму трафика;
- подсветка gateway/DHCP/DNS/network devices;
- экспорт topology JSON/SVG/PNG, если формат не нарушает appliance/offline требования.

### M11.3 — расширение физической топологии

Не блокирует v1.2:
- безопасный traceroute/upstream view;
- read-only SNMP с явно предоставленными оператором credentials;
- bridge/FDB/ARP tables сетевого оборудования;
- switch-port mapping;
- historical topology diff.

WireScope не должен угадывать невидимый L2-коммутатор. Если физическое соединение не подтверждено LLDP/CDP/SNMP или иным evidence, оно отображается только как логическая/предполагаемая связь.

---

## Дальнейшие идеи после v1.2

Не являются текущими обязательствами:
- PDF export;
- дополнительные protocol audit modules;
- CVE enrichment из локальной/контролируемой базы;
- долгосрочная история traffic baselines;
- topology diff между площадками/периодами;
- расширенная multi-interface/multi-VLAN работа;
- более широкая cross-distro/tshark compatibility matrix.

## Текущий следующий шаг

**M10.1 — PCAP Traffic Analysis.**

Финиш M10.1: завершённый или остановленный capture можно анализировать из GUI; результат воспроизводимо строится только из сохранённого PCAP, доступен как JSON и понятный русский текст, содержит базовую сетевую диагностику и communication edges для M11.
