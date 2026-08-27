(() => {
    "use strict";

    /*
     * Presentation-only terminology cleanup.
     *
     * Important invariant: user/network/evidence values are never generic
     * translation input. We only touch explicitly-known presentation nodes,
     * exact UI labels, and deterministic machine-owned warning/summary text.
     */
    const STATIC_EXACT = new Map([
        ["PCAP TRAFFIC ANALYSIS", "АНАЛИЗ PCAP"],
        ["Traffic Analysis", "Анализ PCAP"],
        ["Нет завершённых Traffic Analysis", "Нет завершённых анализов PCAP"],
        ["Baseline → текущий анализ", "Базовый анализ → текущий анализ"],
        ["CORRELATED ASSESSMENT", "КОРРЕЛЯЦИЯ РЕЗУЛЬТАТОВ"],
        ["Что результаты аудита, PCAP и topology подтверждают или дополняют друг в друге", "Что результаты аудита, анализа PCAP и топологии подтверждают или дополняют друг в друге"],
        ["PCAP выбирается явно. Корреляция использует только сохранённые результаты, не запускает scanner и не перечитывает PCAP.", "PCAP выбирается явно. Корреляция использует только сохранённые результаты, не запускает сканирование и не перечитывает исходный PCAP."],
        ["Читаем сохранённые аудиты и Traffic Analysis.", "Читаем сохранённые аудиты и результаты анализа PCAP."],
        ["Выберите Traffic Analysis и сопоставьте результаты.", "Выберите анализ PCAP и сопоставьте результаты."],
        ["Сначала выберите завершённый Traffic Analysis.", "Сначала выберите завершённый анализ PCAP."],
        ["Viewer может читать результаты корреляции, но не запускать новый job.", "Роль viewer может читать сохранённые результаты, но не запускать новую корреляцию."],
        ["Coverage и качество evidence", "Покрытие и качество данных"],
        ["Findings ↔ наблюдаемый трафик", "Проблемы аудита ↔ наблюдаемый трафик"],
        ["Evidence lineage", "Источники и ссылки на доказательства"],
        ["Findings", "Проблемы аудита"],
        ["External", "Внешние связи"],
        ["Traffic endpoints", "Конечные точки PCAP"],
        ["State", "Состояние"],
        ["Узлы", "Устройства"],
        ["Сервисы", "Службы"],
        ["PARTIAL", "ЧАСТИЧНО"],
        ["COMPLETE", "ПОЛНО"],
        ["offline / no network I/O", "офлайн / без сетевых запросов"],
        ["трафик сервиса наблюдался", "трафик службы наблюдался"],
        ["трафик узла наблюдался", "трафик устройства наблюдался"],
        ["SNMP · физическая топология", "SNMP — данные сетевого оборудования"],
        ["SSH · management topology", "SSH — данные Linux/OpenWrt"],
        ["SNMP enrichment", "SNMP-опрос"],
        ["SSH enrichment", "SSH-сбор данных"],
        ["Запустить read-only SSH", "Собрать данные по SSH"],
        ["Запустить SNMP", "Собрать данные по SNMP"],
        ["Private key", "Закрытый ключ"],
        ["Target", "Адрес"],
        ["Username", "Пользователь"],
        ["Port", "Порт"],
        ["Authentication", "Аутентификация"],
        ["Security", "Уровень безопасности"],
        ["Auth", "Аутентификация"],
        ["Auth password", "Пароль аутентификации"],
        ["Privacy", "Шифрование"],
        ["Privacy password", "Пароль шифрования"],
        ["Management IP", "IP управления"],
        ["partial", "частично"],

        /* Legacy kiosk wording. Real baseline labels carry data-i18n. */
        ["Слабые места", "Проблемы"],
        ["Слабых мест нет", "Проблем безопасности не обнаружено"],
        ["Слабые места появляются после проверки служб.", "Проблемы безопасности появляются после проверки служб."],
        ["Факты с датчиков и проверки служб. Это ещё не слабые места.", "Факты с датчиков и проверки служб. Это ещё не выводы о проблемах безопасности."],
        ["Поиск, проверка служб, слабые места, отчёт.", "Поиск устройств, проверка служб, проблемы безопасности, отчёт."],
        ["Более глубокий Nmap, затем проверка служб, слабые места, отчёт.", "Более глубокий Nmap, затем проверка служб, проблемы безопасности и отчёт."],
        ["Ищем слабые места", "Ищем проблемы безопасности"],
        ["Сначала слушаем сеть, затем ищем хосты в подтверждённой сети.", "Сначала слушаем сеть, затем ищем устройства в подтверждённой сети."],
        ["Проверку служб пропустили: подходящих хостов пока нет.", "Проверку служб пропустили: подходящих устройств пока нет."],
        ["ищем хосты", "ищем устройства"],
        ["Прослушивание не дало MAC/IP, либо поиск хостов ничего не нашёл.", "Прослушивание не дало MAC/IP, либо поиск устройств ничего не нашёл."],
        ["Кадры есть, но в список не попали хосты с MAC/IP. Откройте оценку или соберите отчёт.", "Кадры есть, но в список не попали устройства с MAC/IP. Откройте оценку или соберите отчёт."],
        ["VLAN в кадре виден только при 802.1Q; access-порт коммутатора часто без тега — тогда ID неизвестен, но трафик этой сети всё равно виден", "VLAN в кадре виден только при 802.1Q; порт доступа коммутатора часто передаёт кадры без тега — тогда ID VLAN неизвестен, но трафик сети всё равно виден."],
        ["Тегов 802.1Q не видно. Access-порт часто без тега — ID неизвестен.", "Тегов 802.1Q не видно. Порт доступа часто передаёт кадры без тега, поэтому ID VLAN определить нельзя."],
        ["L3-адрес на NIC захвата", "L3-адрес на интерфейсе захвата"],
    ]);

    const GLOBAL_STATIC_FRAGMENTS = [
        ["Узлы inventory вне visibility выбранного capture:", "Устройства инвентаря, не наблюдавшиеся в выбранном PCAP:"],
        ["Traffic endpoints без exact inventory identity:", "Конечные точки PCAP без точного сопоставления с инвентарём:"],
        ["Не удалось остановить job:", "Не удалось остановить задание:"],
        ["только global IP", "только глобальные IP-адреса"],
    ];

    const MACHINE_FRAGMENTS = [
        ["One or more traffic endpoints matched multiple inventory identities; no automatic merge was performed.", "Одна или несколько конечных точек PCAP соответствуют нескольким записям инвентаря; автоматическое объединение не выполнялось."],
        ["Selected traffic analysis does not contain a usable communications graph.", "Выбранный анализ PCAP не содержит пригодного графа коммуникаций; часть корреляции недоступна."],
        ["Service-use correlation in this schema is pair-level: traffic-analysis v1 stores destination ports aggregated per endpoint pair, so it does not prove which side owned the matched port.", "Сопоставление использования служб выполняется на уровне пары узлов: traffic-analysis v1 хранит порты агрегированно для пары, поэтому по этим данным нельзя доказать, какой стороне принадлежал совпавший порт."],
        ["An inventory asset missing from the selected PCAP is not considered absent from the network; capture-point visibility is limited.", "Если устройство из инвентаря не наблюдалось в выбранном PCAP, это не означает его отсутствие в сети: видимость ограничена точкой и интервалом захвата."],
        ["Asset list exceeded the report input limit", "Список устройств превышает лимит входных данных"],
        ["Service list exceeded the report input limit", "Список служб превышает лимит входных данных"],
        ["Finding list exceeded the report input limit", "Список проблем превышает лимит входных данных"],
        ["Evidence reference list exceeded the report input limit", "Список артефактов доказательств превышает лимит входных данных"],
        ["Environment snapshot artifact was not found", "Снимок окружения не найден"],
        ["Environment snapshot could not be read", "Снимок окружения не удалось прочитать"],
        ["Environment snapshot did not contain an object", "Снимок окружения имеет неожиданный формат"],
        ["Passive result artifact could not be read", "Результат пассивного анализа не удалось прочитать"],
        ["Для exact-correlated assets обмен с global external endpoints", "Для точно сопоставленных устройств обмен с глобальными внешними адресами"],
        ["exact-correlated assets", "точно сопоставленные устройства"],
        ["inventory assets", "устройства инвентаря"],
        ["inventory services", "службы инвентаря"],
        ["infrastructure evidence", "данные об инфраструктуре"],
        ["infrastructure checks", "проверки инфраструктурных данных"],
        ["source_health, coverage и warnings", "состояние источников, покрытие и предупреждения"],
    ];

    const TRAFFIC_STATIC_FRAGMENTS = [
        ["interface —", "интерфейс —"],
        ["Baseline →", "Базовый анализ →"],
    ];

    const SNMP_STATIC_FRAGMENTS = [
        ["Read-only IF-MIB", "Только чтение: IF-MIB"],
        ["router interfaces", "интерфейсы маршрутизатора"],
        ["Credentials используются только для этой job и не сохраняются в SQLite/evidence.", "Учётные данные используются только для текущего опроса и не сохраняются в SQLite или артефактах."],
        ["Viewer может просматривать уже собранную SNMP-топологию, но не запускать новый SNMP read.", "Роль viewer может просматривать уже собранные данные SNMP, но не запускать новый опрос."],
        ["evidence-backed VLAN membership", "подтверждённую принадлежность к VLAN"],
        ["Trunk/hybrid", "Транковый/гибридный порт"],
        ["endpoint к одному VLAN", "конечную точку к одному VLAN"],
        ["SNMP evidence", "данные SNMP"],
        ["membership evidence", "подтверждённую принадлежность"],
        ["node/edge evidence", "данные об узлах и связях"],
        ["port membership", "принадлежность портов"],
        ["Ставим read-only SNMP job…", "Запускаем SNMP-опрос в режиме только чтения…"],
    ];

    const SSH_STATIC_FRAGMENTS = [
        ["Опциональный read-only источник", "Дополнительный источник только для чтения"],
        ["interfaces/routes/ARP-ND/FDB/VLAN и Wi‑Fi associations", "интерфейсы, маршруты, ARP/ND, FDB, VLAN и подключения Wi‑Fi"],
        ["Remote-команды фиксированы в WireScope", "Удалённые команды заранее зафиксированы в WireScope"],
        ["management enrichment", "дополнительный SSH-сбор"],
        ["Private key/known_hosts передаются worker через consume-once 0600 spool и не сохраняются в SQLite/evidence.", "Закрытый ключ и known_hosts передаются рабочему процессу через одноразовый временный файл с правами 0600 и не сохраняются в SQLite или артефактах."],
        ["Host key проверяется строго.", "Ключ хоста проверяется строго."],
        ["Ставим scoped read-only SSH job…", "Запускаем ограниченный SSH-сбор в режиме только чтения…"],
        ["SSH topology panel недоступна", "Панель SSH-сбора недоступна"],
    ];

    const META_EXACT = new Map([
        ["completed", "завершён"],
        ["running", "выполняется"],
        ["queued", "в очереди"],
        ["cancelled", "остановлен"],
        ["interrupted", "прерван"],
        ["failed", "ошибка"],
        ["deep", "глубокий"],
        ["standard", "стандартный"],
        ["discovery", "обнаружение"],
        ["passive", "пассивный"],
        ["partial", "частично"],
    ]);

    function protectedDataNode(parent) {
        return Boolean(parent.closest("pre, code, option, input, textarea, select, [data-ws-raw]"));
    }

    function presentationKind(node) {
        const parent = node.parentElement;
        if (!parent || protectedDataNode(parent)) return null;

        if (parent.closest("#global-analysis-modal")) {
            if (parent.closest(".ga-warnings li, .ga-summary-lines li")) return "machine";
            if (parent.closest("#ga-audit-meta, .ga-history-item, #ga-state, #ga-message")) return "global-meta";
            if (parent.closest(".ga-evidence p")) return "global-evidence";
            if (parent.closest(".ga-table-row")) return "global-row";
            if (
                parent.matches("h2, h3, h4, label, button, .ga-kicker, .ga-subtitle, .ga-note, .ga-empty, .ga-empty-small, .ga-history-partial, .ga-pill") ||
                parent.closest(".ga-metric") ||
                parent.matches(".ga-evidence summary")
            ) return "global-static";
            return null;
        }

        if (parent.closest("#traffic-analysis-modal")) {
            if (parent.matches("h2, label, button, .traffic-analysis-kicker, #traffic-analysis-state, #traffic-analysis-message")) return "traffic-static";
            return null;
        }

        if (parent.closest(".ws-snmp-topology-panel")) {
            if (parent.matches(".ws-snmp-status, .ws-snmp-metric")) return "snmp-meta";
            if (parent.matches("h3, h4, .hint, .muted, .warning, button, .ws-snmp-field > span")) return "snmp-static";
            return null;
        }

        if (parent.closest(".ws-ssh-topology-panel")) {
            if (parent.matches(".ws-ssh-status, .ws-ssh-metric span")) return "ssh-meta";
            if (parent.matches("h3, h4, .hint, .muted, .warning, button, .ws-ssh-field > span")) return "ssh-static";
            return null;
        }

        if (parent.closest("#ws-topology-extras-menu") || parent.closest(".ws-insights-tabs")) return "static";
        if (parent.hasAttribute("data-i18n")) return "static";
        return null;
    }

    function applyFragments(text, fragments) {
        let result = text;
        fragments.forEach(([oldValue, newValue]) => {
            result = result.replaceAll(oldValue, newValue);
        });
        return result;
    }

    function translateMeta(text, { allSegments = true } = {}) {
        const segments = text.split(" · ");
        return segments.map((segment, index) => {
            if (!allSegments && index > 0) return segment;
            if (META_EXACT.has(segment)) return META_EXACT.get(segment);
            if (segment.startsWith("CA ")) return `Корреляция ${segment.slice(3)}`;
            if (segment.startsWith("Traffic ")) return `PCAP ${segment.slice(8)}`;
            if (segment.startsWith("rebuild ")) return `пересборка ${segment.slice(8)}`;
            return segment;
        }).join(" · ");
    }

    function translateEvidence(text) {
        if (text.startsWith("Traffic job:")) return `Задание анализа PCAP:${text.slice("Traffic job:".length)}`;
        if (text.startsWith("Topology:")) return `Топология:${text.slice("Topology:".length)}`;
        if (text.startsWith("Assets refs:")) {
            return text
                .replace(/^Assets refs:/, "Ссылки на устройства:")
                .replace("Service refs:", "Ссылки на службы:")
                .replace("Finding refs:", "Ссылки на проблемы:");
        }
        return text;
    }

    function translateGlobalRow(text) {
        if (/^asset\s+[0-9a-f-]+$/i.test(text)) return text.replace(/^asset\s+/i, "устройство ");
        if (/^\d+\s+pkt\s+·/i.test(text)) return text.replace(/\s+pkt\s+·/i, " пак. ·");
        return text;
    }

    function translateSnmpMeta(text) {
        if (text.includes(" · ") && META_EXACT.has(text.split(" · ", 1)[0])) {
            return translateMeta(text, { allSegments: false });
        }
        return text
            .replace(/\bL3 IF\b/g, "L3-интерфейсов")
            .replace(/\bport links\b/g, "связей портов");
    }

    function normalizeTextNode(node) {
        if (!node || node.nodeType !== Node.TEXT_NODE) return;
        const kind = presentationKind(node);
        if (!kind) return;

        const original = String(node.nodeValue || "");
        const current = original.trim();
        if (!current) return;
        const leading = original.match(/^\s*/)?.[0] || "";
        const trailing = original.match(/\s*$/)?.[0] || "";

        let normalized = current;
        if (["static", "global-static", "traffic-static", "snmp-static", "ssh-static"].includes(kind)) {
            normalized = STATIC_EXACT.get(normalized) || normalized;
        }
        if (kind === "global-static") normalized = applyFragments(normalized, GLOBAL_STATIC_FRAGMENTS);
        if (kind === "machine") normalized = applyFragments(normalized, MACHINE_FRAGMENTS);
        if (kind === "traffic-static") normalized = applyFragments(normalized, TRAFFIC_STATIC_FRAGMENTS);
        if (kind === "snmp-static") normalized = applyFragments(normalized, SNMP_STATIC_FRAGMENTS);
        if (kind === "ssh-static") normalized = applyFragments(normalized, SSH_STATIC_FRAGMENTS);
        if (kind === "global-meta") normalized = translateMeta(normalized);
        if (kind === "global-evidence") normalized = translateEvidence(normalized);
        if (kind === "global-row") normalized = translateGlobalRow(normalized);
        if (kind === "snmp-meta") normalized = translateSnmpMeta(normalized);
        if (kind === "ssh-meta") normalized = translateMeta(normalized, { allSegments: false });

        if (normalized !== current) node.nodeValue = `${leading}${normalized}${trailing}`;
    }

    function normalizeTree(root) {
        if (!root) return;
        if (root.nodeType === Node.TEXT_NODE) {
            normalizeTextNode(root);
            return;
        }
        const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
        let node;
        while ((node = walker.nextNode())) normalizeTextNode(node);
    }

    function boot() {
        normalizeTree(document.body);
        const observer = new MutationObserver((mutations) => {
            mutations.forEach((mutation) => {
                mutation.addedNodes.forEach((node) => normalizeTree(node));
                if (mutation.type === "characterData") normalizeTextNode(mutation.target);
            });
        });
        observer.observe(document.body, {
            childList: true,
            subtree: true,
            characterData: true,
        });
    }

    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot);
    else boot();
})();
