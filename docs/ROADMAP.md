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

Статус: **implementation complete; smoke-test основных сценариев пройден, дополнительные real-PCAP проверки продолжаются**.

Цель: превратить «Прослушивание» из простого сохранения PCAP в самостоятельный инструмент диагностики трафика.

### M10.1 — детерминированный анализ сохранённого PCAP

Статус: **реализовано**.

После завершённого или остановленного прослушивания оператор может нажать **«Анализировать PCAP»**.

Анализ выполняется отдельной durable job и не запускает новый сетевой захват.
Источник истины — уже сохранённый PCAP evidence.

Анализ выдаёт:
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

Статус: **реализовано как источник данных для M11**.

Анализатор сохраняет нормализованные связи между узлами:
- endpoint A / endpoint B;
- пакеты и байты по направлениям;
- наблюдавшиеся протоколы/порты;
- first/last seen;
- provenance=`pcap`;
- confidence=`observed`.

### M10.3 — расширенная диагностика

Статус: **реализовано**.

Реализовано:
- packets/s и наблюдаемая полоса;
- TCP handshake visibility;
- повторные SYN;
- привязка TCP health сигналов к конкретным парам;
- previous/lost segment hints с осторожным объяснением capture/offload/visibility ограничений;
- DNS latency average / p50 / p95 / max;
- разделение обычного DNS и локального `.local` name-discovery;
- ARP request/reply и repeated unanswered hints;
- ICMP / ICMPv6 диагностика;
- top broadcast/multicast contributors;
- доминирующий обмен и local↔global IP связи;
- операторский «Краткий диагноз»;
- portable tshark compatibility path и graceful fallback.

### M10.4 — Protocol Intelligence

Статус: **реализовано**.

Реализовано:
- динамическое определение поддерживаемых полей `tshark`;
- TLS: SNI/server name, version metadata, ALPN;
- HTTP/1.x: Host, методы, коды ответа, 4xx/5xx;
- QUIC metadata;
- SMB/SMB2 commands и NT status без filenames/payload;
- обычный DNS отдельно от mDNS/LLMNR;
- DHCP message/DORA correlation;
- operator observations для legacy TLS, HTTP 5xx, DNS errors, SMB status и нескольких DHCP servers;
- отдельная секция «Протокольный разбор» в TXT/Markdown.

### M10.5 — TCP RTT и сравнение захватов

Статус: **реализовано**.

RTT:
- `tcp.analysis.ack_rtt` используется только при поддержке установленным `tshark`;
- aggregate average / p50 / p95 / max;
- статистика по конкретным парам;
- отсутствие samples отображается как «RTT не оценён»;
- ACK RTT не трактуется как latency приложения.

Сравнение двух PCAP-анализов:
- persisted normalized `traffic-analysis`, без повторного чтения сети;
- объём, длительность, communications;
- новые/исчезнувшие endpoints и observed edges;
- изменение долей протоколов;
- TCP signals, DNS errors, RTT, broadcast/multicast;
- новые и исчезнувшие warning-сигналы;
- сравнение доступно прямо в web/kiosk UI.

---

## v1.2 — Network Topology

Статус: **разработка начата**.

Цель: построить понятную карту наблюдаемой сети с указанием происхождения и достоверности каждой связи.

### M11.1 — логическая карта

Статус: **первый рабочий срез реализуется в ветке `milestone-11-network-topology`**.

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

Canonical `network-topology` различает:
- узлы WireScope/interface, gateway/router, network-device hints, DHCP/DNS servers, assets и внешние endpoints;
- логические subnet/VLAN groups;
- связи `default_gateway`, `layer2_neighbor`, `stp_observed`, `dhcp_observed`, `communication`;
- `confirmed`, `observed`, `inferred` confidence;
- provenance каждого узла и ребра.

Принцип: WireScope не угадывает физический hop. LLDP/CDP/default route, PCAP traffic и subnet inference остаются разными типами evidence.

PCAP overlay выбирается оператором **явно**. WireScope не подмешивает «последний capture» автоматически, потому что Deep-аудит и прослушивание могут относиться к разным сегментам/моментам времени.

### M11.2 — интерактивная визуализация

Web/kiosk:
- базовый SVG-граф — часть первого M11-среза;
- далее zoom/pan;
- фильтр VLAN/subnet;
- фильтр типа связи/confidence;
- клик по asset → адреса, сервисы, vendor, findings;
- толщина communication edge по объёму трафика;
- подсветка gateway/DHCP/DNS/network devices;
- экспорт topology JSON/SVG/PNG.

### M11.3 — расширение физической топологии

Не блокирует v1.2:
- безопасный traceroute/upstream view;
- read-only SNMP с явно предоставленными оператором credentials;
- bridge/FDB/ARP tables сетевого оборудования;
- switch-port mapping;
- historical topology diff.

WireScope не должен угадывать невидимый L2-коммутатор. Если физическое соединение не подтверждено LLDP/CDP/SNMP или иным evidence, оно отображается только как логическая/предполагаемая связь.

---

## v1.3 — Global Correlation Analysis

Цель: объединить результаты активного/глубокого аудита, PCAP Traffic Analysis и Network Topology в единый детерминированный аналитический пакет.

Global Analysis не просто склеивает отчёты. Он коррелирует persisted normalized данные и отвечает, например:
- какой обнаруженный сервис реально использовался в PCAP;
- относится ли finding к реально наблюдаемому обмену;
- какие assets существуют в inventory, но не наблюдались в выбранном capture;
- какие внешние endpoints связаны с конкретными внутренними assets;
- совпадают ли gateway/DHCP/DNS/topology observations с данными аудита;
- какие network-health симптомы относятся к важным/уязвимым сервисам;
- где active и passive evidence расходятся.

Выход:
- canonical `global-analysis` JSON;
- русское итоговое заключение;
- evidence references на audit/finding/traffic/topology сущности;
- deterministic correlation rules как обязательная offline-база.

Global Analysis должен работать **без внешнего AI**.

---

## v1.4 — AI-assisted Global Analysis

Цель: поверх deterministic `global-analysis` дать опциональное аналитическое заключение внешней или локальной модели.

Архитектура:
- абстракция `AIProvider`;
- первым provider может быть OpenAI API;
- в будущем — локальный/offline provider;
- API key хранится только backend-side;
- raw PCAP по умолчанию внешнему provider не отправляется;
- оператор явно выбирает, какие нормализованные данные разрешено передать;
- передача внешнему provider — отдельная trust boundary и требует явного подтверждения.

AI получает не сырые несвязанные файлы, а подготовленный пакет: audit report JSON + traffic-analysis JSON + topology JSON + deterministic global correlations.

AI-вывод не создаёт WireScope finding автоматически. Он помечается как аналитическое заключение/гипотеза и должен ссылаться на evidence IDs, на которых основан.

---

## Дальнейшие идеи

Не являются текущими обязательствами:
- PDF export;
- дополнительные protocol audit modules;
- CVE enrichment из локальной/контролируемой базы;
- долгосрочная история traffic baselines;
- topology diff между площадками/периодами;
- расширенная multi-interface/multi-VLAN работа;
- более широкая cross-distro/tshark compatibility matrix.

## Текущий следующий шаг

**M11.1 Network Topology:** проверить canonical topology model и первый SVG-view на реальном Deep-аудите; затем подключить один из сохранённых PCAP-анализов как явный overlay и проверить provenance/confidence связей.
