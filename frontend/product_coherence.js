(() => {
    "use strict";

    const EXACT_TEXT = new Map([
        ["PCAP TRAFFIC ANALYSIS", "АНАЛИЗ PCAP"],
        ["Traffic Analysis", "Анализ PCAP"],
        ["Нет завершённых Traffic Analysis", "Нет завершённых анализов PCAP"],
        ["Что результаты аудита, PCAP и topology подтверждают или дополняют друг в друге", "Что результаты аудита, анализа PCAP и топологии подтверждают или дополняют друг в друге"],
        ["PCAP выбирается явно. Корреляция использует только сохранённые результаты, не запускает scanner и не перечитывает PCAP.", "PCAP выбирается явно. Корреляция использует только сохранённые результаты, не запускает сканирование и не перечитывает исходный PCAP."],
        ["Читаем сохранённые аудиты и Traffic Analysis.", "Читаем сохранённые аудиты и результаты анализа PCAP."],
        ["Выберите Traffic Analysis и сопоставьте результаты.", "Выберите анализ PCAP и сопоставьте результаты."],
        ["Сначала выберите завершённый Traffic Analysis.", "Сначала выберите завершённый анализ PCAP."],
        ["Viewer может читать результаты корреляции, но не запускать новый job.", "Роль viewer может читать сохранённые результаты, но не запускать новую корреляцию."],
        ["SNMP · физическая топология", "SNMP — данные сетевого оборудования"],
        ["SSH · management topology", "SSH — данные Linux/OpenWrt"],
        ["SNMP enrichment", "SNMP-опрос"],
        ["SSH enrichment", "SSH-сбор данных"],
        ["Запустить read-only SSH", "Собрать данные по SSH"],
        ["Запустить SNMP", "Собрать данные по SNMP"],
        ["partial", "частично"],
    ]);

    const CORRELATION_FRAGMENTS = [
        ["Узлы inventory вне visibility выбранного capture:", "Устройства инвентаря, не наблюдавшиеся в выбранном PCAP:"],
        ["Traffic endpoints без exact inventory identity:", "Конечные точки PCAP без точного сопоставления с инвентарём:"],
        ["Для exact-correlated assets обмен с global external endpoints в выбранном PCAP не обнаружен.", "Для точно сопоставленных устройств внешние коммуникации в выбранном PCAP не обнаружены."],
        ["exact-correlated assets", "точно сопоставленными устройствами"],
        ["inventory assets", "устройств инвентаря"],
        ["inventory services", "служб инвентаря"],
        ["infrastructure evidence", "данных об инфраструктуре"],
        ["infrastructure checks", "проверок инфраструктурных данных"],
        ["source_health, coverage и warnings", "состояние источников, покрытие и предупреждения"],
        ["Findings ↔", "Проблемы аудита ↔"],
        ["Findings", "Проблемы аудита"],
        ["External endpoint", "Внешний адрес"],
        ["External", "Внешние связи"],
        ["Traffic endpoints", "Конечные точки PCAP"],
        ["Traffic job:", "Задание анализа PCAP:"],
        ["Traffic", "Трафик"],
        ["Protocols / ports", "Протоколы / порты"],
        ["Topology:", "Топология:"],
        ["Assets refs:", "Ссылки на устройства:"],
        ["Service refs:", "Ссылки на службы:"],
        ["Finding refs:", "Ссылки на проблемы:"],
        ["artifacts:", "артефакты:"],
        ["artifact:", "артефакт:"],
        ["Asset", "Устройство"],
        ["asset ", "устройство "],
        ["Сервисы", "Службы"],
        ["Узлы", "Устройства"],
        ["трафик узла", "трафик устройства"],
        ["State", "Состояние"],
        ["PARTIAL", "ЧАСТИЧНО"],
        ["COMPLETE", "ПОЛНО"],
        ["offline / no network I/O", "офлайн / без сетевых запросов"],
        [" pkt ·", " пак. ·"],
        [" · Traffic ", " · PCAP "],
        [" · rebuild ", " · пересборка "],
    ];

    const META_FRAGMENTS = [
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
    ];

    function scopedFragments(node) {
        const parent = node.parentElement;
        if (!parent) return [];
        if (parent.closest("#global-analysis-modal")) {
            const fragments = [...CORRELATION_FRAGMENTS];
            if (parent.closest("#ga-audit-meta")) fragments.push(...META_FRAGMENTS);
            return fragments;
        }
        return [];
    }

    function normalizeTextNode(node) {
        if (!node || node.nodeType !== Node.TEXT_NODE) return;
        const original = String(node.nodeValue || "");
        const current = original.trim();
        if (!current) return;

        const leading = original.match(/^\s*/)?.[0] || "";
        const trailing = original.match(/\s*$/)?.[0] || "";
        let normalized = EXACT_TEXT.get(current) || current;
        scopedFragments(node).forEach(([oldValue, newValue]) => {
            normalized = normalized.replaceAll(oldValue, newValue);
        });
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
