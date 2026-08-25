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

Статус: **M11.1–M11.4 implementation complete; полный automated regression зелёный, остаётся live-network validation нового hardening checkpoint**.

Цель: построить понятную карту наблюдаемой сети с указанием происхождения и достоверности каждой связи и одновременно показывать оператору, **для каких выводов собранных данных действительно хватает**.

### M11.1 — логическая карта

Статус: **реализовано и проверено на реальном Deep-аудите + PCAP overlay**.

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
- отдельные subnet-сегменты;
- связи `default_gateway`, `segment_gateway`, `layer2_neighbor`, `stp_observed`, `dhcp_observed`, `communication`;
- уровни `general`, `l2`, `l3`, `traffic`;
- `confirmed`, `observed`, `inferred` confidence;
- provenance каждого узла и ребра.

Сегменты привязаны к route context конкретного интерфейса аудита. Host-wide default route другого интерфейса не считается шлюзом просканированной сети.

Есть отдельная глобальная карта retained-аудитов: несколько просканированных подсетей сохраняются как разные сегменты, а подтверждённый общий gateway может связывать их на L3-уровне.

Принцип: WireScope не угадывает физический hop. LLDP/CDP/default route, PCAP traffic и subnet inference остаются разными типами evidence.

PCAP overlay выбирается оператором **явно**. WireScope не подмешивает «последний capture» автоматически, потому что Deep-аудит и прослушивание могут относиться к разным сегментам/моментам времени.

### M11.2 — интерактивная визуализация

Статус: **реализовано; Chromium browser smoke и автоматизированная проверка layout/filters/export проходят**.

Реализовано в web/kiosk:
- segment-aware SVG layout: каждая подсеть отображается отдельной визуальной областью;
- общая cross-audit карта сохранённых сетей;
- global topology явно помечается `partial`, если один из retained audits не удалось построить; пропущенные источники возвращаются в `source_errors`, а оператор получает warning;
- выбор конкретной подсети;
- уровни Общая / L2 / L3 / Traffic;
- фильтр confidence: confirmed / observed / inferred;
- отдельное отображение multicast/broadcast;
- возможность скрывать малозначимые несвязанные узлы на больших картах;
- zoom колёсом и кнопками, pan drag, команда «Вписать»;
- двойной клик/Enter по области подсети для фокусировки;
- внешние/global IP визуально вынесены в зону `Internet / внешние адреса`;
- communication edge имеет толщину по объёму и стрелки по наблюдавшимся направлениям PCAP;
- клик по asset → адреса, сервисы, vendor, OS, provenance/confidence и persisted findings, привязанные по `asset_id`;
- клик по edge → layer, provenance, segment context, пакеты, байты, протоколы и направление;
- topology JSON export;
- SVG export текущего отображаемого вида карты с сохранением фильтров и viewport transform;
- PNG export из того же текущего SVG;
- отдельный **VLAN-фокус** по evidence-backed VLAN membership с port mode/PVID/tagged/untagged и VLAN JSON export;
- отдельная VLAN-specific SVG-карта без назначения endpoint в VLAN «по догадке»;
- Chromium regression smoke для фильтров, zoom/focus, bounded rendering, findings, SVG/PNG и VLAN focus/download.

Дополнительная проверка читаемости на очень больших реальных topology остаётся quality-improvement задачей по мере появления таких данных и не блокирует базовую семантику topology.

VLAN принадлежность назначается только при достаточном node↔VLAN evidence. Q-BRIDGE/FDB/PVID различаются: access/trunk/hybrid классифицируется только из наблюдаемых membership bitmaps, а multi-VLAN trunk/hybrid не заставляет WireScope выбрать один VLAN для endpoint.

### M11.3 — расширение физической и L3-топологии

Статус: **реализовано и покрыто automated regression; live management-plane проверка включена в общий M11.4 gate**.

Реализовано:
- безопасный traceroute/upstream view поверх явно ограниченного active context;
- read-only SNMP с явно предоставленными оператором credentials;
- базовые IF-MIB / BRIDGE-MIB / Q-BRIDGE-MIB / LLDP-MIB evidence;
- RFC1213 IPv4 interface address/netmask fallback;
- RFC4293 IP-MIB IPv4/IPv6 interface addresses и connected prefixes;
- современный IPv4 ARP / IPv6 ND neighbor cache через `ipNetToPhysicalTable`;
- `ifType` и `ifPhysAddress` для более точной модели интерфейса;
- LLDP remote management addresses для консервативной корреляции соседей;
- отдельные `network-interface` nodes и L3 `routed_interface` edges;
- SNMP-observed connected subnet создаётся как topology evidence с `active_scope=false`: обнаруженная через SNMP сеть **не становится разрешением на сканирование**;
- корреляция ARP/FDB/bridge evidence сетевого оборудования;
- switch-port mapping без угадывания невидимых L2 hops;
- Q-BRIDGE port membership с отдельными `tagged_vlans`, `untagged_vlans`, PVID и `access/trunk/hybrid/unknown`;
- классический FDB без VLAN ID может получить VLAN только из однозначного access-port membership evidence;
- multi-VLAN trunk/hybrid не назначает endpoint один произвольный VLAN;
- SNMP management IP сам по себе не делает L2 switch роутером; router role требует подтверждённого gateway evidence или нескольких distinct connected L3 prefixes;
- historical topology diff между retained audits;
- conservative cross-audit identity: MAC → IP; одинаковый hostname сам по себе не считается доказательством одного устройства;
- изменение audit-local asset UUID не создаёт ложный `removed + added`, если стабильная identity подтверждена;
- отдельный API comparison и web/kiosk view **«История topology»** с JSON export;
- global topology и historical diff наследуют `partial`/`source_errors`, если часть persisted evidence недоступна;
- source-health проверяет, что сохранённые SNMP/route-trace artifacts действительно вошли в topology; пропуск evidence становится видимым оператору, но один повреждённый исторический artifact не валит всю карту;
- legacy job-less SNMP не объявляется повреждённым без достаточного target/evidence контекста.

WireScope не должен угадывать невидимый L2-коммутатор. Если физическое соединение не подтверждено LLDP/CDP/SNMP/FDB/switch-port или иным evidence, оно отображается только как логическая/предполагаемая связь.

### M11.4 — topology hardening и достаточность evidence

Статус: **implementation complete; automated regression / Chromium / wheel smoke зелёные, требуется live-network validation на WireScope VM**.

Реализовано:
- отдельный `coverage` / claimability слой: `inventory`, `l3`, `l2`, `traffic`, `vlan`, `wifi`, `hypervisor` получают `sufficient / partial / missing` без фиктивного «процента изученности сети»;
- оператору показывается не только схема, но и какие утверждения подтверждены evidence, какие частичны и какие данные нужно получить дополнительно;
- canonical topology остаётся полным evidence graph, а structural presentation отделена от raw/traffic observations;
- infrastructure-first renderer: subnet как структурная область, assets/network devices как основные карточки, Traffic и All evidence вынесены в отдельные представления;
- directed broadcast конкретной подсети, link-local шум и PCAP-only external endpoints больше не выдаются за обычные инфраструктурные hosts structural map;
- экспорт полной structural diagram отделён от экспорта текущего viewport;
- multi-homed environment сохраняет все default routes по interfaces и локальные DHCP lease/router options;
- gateway выбранного audit interface добавляется только по точному persisted evidence, а не по host-wide default route или шаблону адреса;
- добавлен optional **read-only SSH topology provider** для Linux/OpenWrt-подобных managed devices;
- SSH provider имеет фиксированный allowlist `ip/bridge/iw`, strict host-key verification и не принимает произвольную remote command;
- private key и `known_hosts` передаются через consume-once `0600` runtime spool и не сохраняются в SQLite/topology evidence;
- queued cancel сразу удаляет SSH/SNMP credential spool, running handler удаляет credentials в `finally`;
- retry `snmp_topology` / `ssh_topology` со старым `credential_ref` запрещён: новый запуск требует свежих credentials;
- SSH `ip neigh` используется как IP↔MAC identity evidence, но не превращается в выдуманную физическую линию;
- SSH FDB может подтверждать switch-port mapping;
- SSH `iw station dump` может подтверждать AP↔client association;
- SSH interface/prefix и route data участвуют в L3 topology, но management-discovered subnet остаётся `active_scope=false`;
- SSH bridge VLAN semantics различает access/trunk/hybrid: endpoint получает VLAN только из точного FDB VLAN либо из однозначного single-VLAN access port;
- `source_health` охватывает route-trace, SNMP и SSH: job-backed persisted artifact, который должен был войти в topology, не может исчезнуть молча — карта становится `partial` и получает sanitized `source_errors`;
- добавлены regression tests для SSH scope/role/secret lifecycle, credential cleanup/retry, access-vs-trunk VLAN projection и source-health;
- модель подробно зафиксирована в `docs/TOPOLOGY_MODEL.md` / `docs/en/TOPOLOGY_MODEL.md` и API docs.

Принцип M11.4: **если данных недостаточно, WireScope должен показать недостаток evidence, а не компенсировать его более смелой эвристикой**.

### v1.2 live-validation gate

Уже подтверждено на установленной WireScope VM для предыдущего M11 checkpoint:
- upgrade проходит штатным `packaging/upgrade.sh`;
- dependencies, systemd units и SQLite migrations применяются успешно;
- `wirescope-api` и `wirescope-worker` запускаются после upgrade;
- `dumpcap` privilege path остаётся рабочим;
- API health/ready/capabilities после upgrade проверены оператором без критических ошибок.

Для M11.4 нужен **новый Deep audit**, потому что старые audits не содержат нового persisted multi-interface default-route/DHCP lease evidence.

До финального закрытия v1.2 проверить на live VM:
- upgrade до M11.4 checkpoint и сохранность retained audits;
- новый Deep audit на выбранном интерфейсе и confirmed scope;
- structural map: subnet regions, assets/network devices, отсутствие directed-broadcast/link-local/PCAP внешнего шума в основном представлении;
- `coverage`: корректные `sufficient/partial/missing`, рекомендации и отсутствие ложного «данных достаточно»;
- interface-specific gateway: при наличии DHCP/default-route evidence gateway должен относиться именно к выбранному audit interface;
- L2/L3/Traffic/All evidence переключения и явный PCAP overlay;
- findings/details, zoom/pan/fit, JSON/SVG/PNG exports;
- historical topology diff между retained audits;
- read-only SNMP enrichment на доступном router/switch: interface/prefix, ARP/ND, а при поддержке BRIDGE/Q-BRIDGE/LLDP — FDB/VLAN/switch-port/LLDP;
- либо read-only SSH enrichment на подходящем Linux/OpenWrt managed device: route/neigh/FDB/VLAN/Wi-Fi evidence с dedicated read-only account и проверенным host key;
- отсутствие ложной router/VLAN/L2 classification;
- `partial/source_errors` остаются fail-visible при недоступном persisted source.

Если конкретный router/switch не реализует отдельный стандартный MIB subtree или read-only SSH account не имеет доступа к конкретной allow-listed команде, это само по себе не ошибка WireScope: capability должен остаться false/empty, а карта строится из реально доступных источников.

После успешной live-проверки ставится финальный v1.2 topology checkpoint. Только затем начинается v1.3.

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

**M11.4 live-network validation:** обновить WireScope VM до hardening checkpoint, выполнить новый Deep audit и проверить structural map + `coverage` + interface-specific gateway. Затем, если доступен management device, выполнить read-only SNMP или SSH enrichment и проверить реальные L2/L3/VLAN/Wi-Fi evidence. Исправлять только подтверждённые live interoperability/UX проблемы. После зелёной live-проверки закрыть v1.2 и переходить к v1.3 Global Correlation Analysis.
