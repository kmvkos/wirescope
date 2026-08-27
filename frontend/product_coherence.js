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
        ["Запустить read-only SSH", "Собрать данные по SSH"],
        ["Запустить SNMP", "Собрать данные по SNMP"],
    ]);

    function normalizeTextNode(node) {
        if (!node || node.nodeType !== Node.TEXT_NODE) return;
        const current = String(node.nodeValue || "").trim();
        if (!current || !EXACT_TEXT.has(current)) return;
        const leading = String(node.nodeValue || "").match(/^\s*/)?.[0] || "";
        const trailing = String(node.nodeValue || "").match(/\s*$/)?.[0] || "";
        node.nodeValue = `${leading}${EXACT_TEXT.get(current)}${trailing}`;
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
