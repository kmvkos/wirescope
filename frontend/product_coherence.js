(() => {
    "use strict";

    const EXACT_TEXT = new Map([
        ["PCAP TRAFFIC ANALYSIS", "АНАЛИЗ PCAP"],
        ["Traffic Analysis", "Анализ PCAP"],
        ["Нет завершённых Traffic Analysis", "Нет завершённых анализов PCAP"],
        ["Baseline → текущий анализ", "Базовый анализ → текущий анализ"],
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

        /* Legacy kiosk wording kept in i18n for compatibility, normalized only in presentation. */
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

    const CORRELATION_FRAGMENTS = [
        ["One or more traffic endpoints matched multiple inventory identities; no automatic merge was performed.", "Одна или несколько конечных точек PCAP соответствуют нескольким записям инвентаря; автоматическое объединение не выполнялось."],
        ["Selected traffic analysis does not contain a usable communications graph.", "Выбранный анализ PCAP не содержит пригодного графа коммуникаций; часть корреляции недоступна."],
        ["Service-use correlation in this schema is pair-level: traffic-analysis v1 stores destination ports aggregated per endpoint pair, so it does not prove which side owned the matched port.", "Сопоставление использования служб выполняется на уровне пары узлов: traffic-analysis v1 хранит порты агрегированно для пары, поэтому по этим данным нельзя доказать, какой стороне принадлежал совпавший порт."],
        ["An inventory asset missing from the selected PCAP is not considered absent from the network; capture-point visibility is limited.", "Если устройство из инвентаря не наблюдалось в выбранном PCAP, это не означает его отсутствие в сети: видимость ограничена точкой и интервалом захвата."],
        ["Asset list exceeded the report input limit", "Список устройств превышает лимит входных данных; корреляция использует только допустимую часть."],
        ["Service list exceeded the report input limit", "Список служб превышает лимит входных данных; корреляция использует только допустимую часть."],
        ["Finding list exceeded the report input limit", "Список проблем превышает лимит входных данных; корреляция использует только допустимую часть."],
        ["Evidence reference list exceeded the report input limit", "Список артефактов доказательств превышает лимит входных данных; используется только допустимая часть."],
        ["Environment snapshot artifact was not found", "Снимок окружения не найден; часть инфраструктурной корреляции может быть недоступна."],
        ["Environment snapshot could not be read", "Снимок окружения не удалось прочитать; часть инфраструктурной корреляции может быть недоступна."],
        ["Environment snapshot did not contain an object", "Снимок окружения имеет неожиданный формат; часть инфраструктурной корреляции может быть недоступна."],
        ["Passive result artifact could not be read", "Результат пассивного анализа не удалось прочитать; часть пассивных данных может быть недоступна."],
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
        [" · Traffic ", " · PCAP "],
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
        [" · rebuild ", " · пересборка "],
        ["CA ", "Корреляция "],
        [" · deep ·", " · Глубокий ·"],
        [" · standard ·", " · Стандартный ·"],
        [" · discovery ·", " · Поиск устройств ·"],
        [" · passive ·", " · Пассивный ·"],
    ];

    const TRAFFIC_FRAGMENTS = [
        ["interface —", "интерфейс —"],
        ["Baseline →", "Базовый анализ →"],
    ];

    const SNMP_FRAGMENTS = [
        ["Read-only IF-MIB", "Только чтение: IF-MIB"],
        ["router interfaces", "интерфейсы маршрутизатора"],
        ["Credentials используются только для этой job и не сохраняются в SQLite/evidence.", "Учётные данные используются только для текущего опроса и не сохраняются в SQLite или артефактах."],
        ["Viewer может просматривать уже собранную SNMP-топологию, но не запускать новый SNMP read.", "Роль viewer может просматривать уже собранные данные SNMP, но не запускать новый опрос."],
        ["evidence-backed VLAN membership", "подтверждённую принадлежность к VLAN"],
        ["Trunk/hybrid", "Транковый/гибридный порт"],
        ["endpoint к одному VLAN", "конечную точку к одному VLAN"],
        ["SNMP evidence", "данных SNMP"],
        ["membership evidence", "подтверждённой принадлежностью"],
        ["node/edge evidence", "данных об узлах и связях"],
        ["port membership", "принадлежности портов"],
        ["tagged ", "тегированные "],
        ["untagged ", "нетегированные "],
        ["port links", "связей портов"],
        ["L3 IF", "L3-интерфейсов"],
        ["Ставим read-only SNMP job…", "Запускаем SNMP-опрос в режиме только чтения…"],
    ];

    const SSH_FRAGMENTS = [
        ["Опциональный read-only источник", "Дополнительный источник только для чтения"],
        ["interfaces/routes/ARP-ND/FDB/VLAN и Wi‑Fi associations", "интерфейсы, маршруты, ARP/ND, FDB, VLAN и подключения Wi‑Fi"],
        ["Remote-команды фиксированы в WireScope", "Удалённые команды заранее зафиксированы в WireScope"],
        ["management enrichment", "дополнительного SSH-сбора"],
        ["Private key/known_hosts передаются worker через consume-once 0600 spool и не сохраняются в SQLite/evidence.", "Закрытый ключ и known_hosts передаются рабочему процессу через одноразовый временный файл с правами 0600 и не сохраняются в SQLite или артефактах."],
        ["Host key проверяется строго.", "Ключ хоста проверяется строго."],
        ["Private key", "Закрытый ключ"],
        ["SSH agent", "SSH-agent"],
        ["port links", "связи портов"],
        ["L3 IF", "L3-интерфейсы"],
        ["Ставим scoped read-only SSH job…", "Запускаем ограниченный SSH-сбор в режиме только чтения…"],
        ["SSH topology job:", "Задание SSH-сбора:"],
        ["management evidence", "данными управления"],
        ["SSH topology panel недоступна", "Панель SSH-сбора недоступна"],
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
        if (parent.closest("#traffic-analysis-modal")) return TRAFFIC_FRAGMENTS;
        if (parent.closest(".ws-snmp-topology-panel")) return [...SNMP_FRAGMENTS, ...META_FRAGMENTS];
        if (parent.closest(".ws-ssh-topology-panel")) return [...SSH_FRAGMENTS, ...META_FRAGMENTS];
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