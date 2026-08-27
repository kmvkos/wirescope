(() => {
    "use strict";

    const API = "/api/v1";

    const PROFILE_LABELS = {
        passive: "Пассивный",
        discovery: "Поиск устройств",
        standard: "Стандартный",
        deep: "Глубокий",
        packet_capture: "Запись трафика",
    };

    const FIELD_LABELS = {
        kind: "Тип",
        label: "Имя",
        roles: "Роли",
        addresses: "Адреса",
        names: "Имена",
        vlan_ids: "VLAN",
        segment_ids: "Сегменты",
        connected_segments: "Подключённые сегменты",
        confidence: "Уверенность",
        provenance: "Источники данных",
        port_name: "Порт",
        port_id: "ID порта",
        local_port: "Локальный порт",
        remote_port: "Удалённый порт",
        ttl: "TTL",
    };

    const RELATION_LABELS = {
        communication: "обмен трафиком",
        default_gateway: "шлюз по умолчанию",
        route_hop: "переход маршрута",
        route_target: "цель маршрута",
        segment_gateway: "шлюз сегмента",
        layer2_neighbor: "L2-сосед",
        stp_observed: "STP-наблюдение",
        dhcp_observed: "DHCP-наблюдение",
    };

    const WARNING_LABELS = new Map([
        [
            "В одном из topology обнаружены повторяющиеся стабильные identity keys; такие узлы не были автоматически склеены.",
            "В одной из топологий обнаружены повторяющиеся стабильные идентификаторы; такие узлы не объединялись автоматически.",
        ],
        [
            "Multicast groups и route-gap placeholders исключены из historical diff как нестабильные визуальные сущности.",
            "Multicast-группы и служебные разрывы маршрута исключены из исторического сравнения как нестабильные визуальные сущности.",
        ],
    ]);

    const el = (tag, text, cls) => {
        const node = document.createElement(tag);
        if (text !== undefined && text !== null) node.textContent = String(text);
        if (cls) node.className = cls;
        return node;
    };

    async function request(path) {
        const response = await fetch(`${API}${path}`, { credentials: "same-origin" });
        const text = await response.text();
        let data = null;
        if (text) {
            try { data = JSON.parse(text); } catch { data = text; }
        }
        if (!response.ok) {
            const detail = data && data.detail;
            throw new Error((detail && detail.message) || response.statusText || `HTTP ${response.status}`);
        }
        return data;
    }

    function profileLabel(value) {
        return PROFILE_LABELS[String(value || "")] || value || "—";
    }

    function fieldLabel(value) {
        return FIELD_LABELS[String(value || "")] || value || "—";
    }

    function relationLabel(value) {
        return RELATION_LABELS[String(value || "")] || value || "связь";
    }

    function warningLabel(value) {
        const text = String(value || "");
        return WARNING_LABELS.get(text) || text;
    }

    function auditLabel(audit) {
        const created = audit.created_at ? new Date(audit.created_at) : null;
        const stamp = created && !Number.isNaN(created.getTime())
            ? created.toLocaleString("ru-RU")
            : "дата неизвестна";
        return `${String(audit.id || "").slice(0, 8)} · ${profileLabel(audit.profile)} · ${audit.interface || "—"} · ${stamp}`;
    }

    function metric(label, value, cls = "") {
        const item = el("div", null, `ws-metric ${cls}`.trim());
        item.append(el("strong", value ?? 0), el("span", label));
        return item;
    }

    function renderSummary(result) {
        const summary = result.summary || {};
        const block = el("div", null, "ws-metric-grid ws-topology-compare-metrics");
        block.append(
            metric("Подсети +", summary.segments_added, "is-added"),
            metric("Подсети −", summary.segments_removed, "is-removed"),
            metric("Узлы +", summary.nodes_added, "is-added"),
            metric("Узлы −", summary.nodes_removed, "is-removed"),
            metric("Узлы Δ", summary.nodes_changed, "is-changed"),
            metric("Связи +", summary.edges_added, "is-added"),
            metric("Связи −", summary.edges_removed, "is-removed"),
            metric("Связи Δ", summary.edges_changed, "is-changed")
        );
        return block;
    }

    function descriptorText(item) {
        const parts = [item.label || item.key || "узел"];
        if (item.mac) parts.push(item.mac);
        if (item.addresses && item.addresses.length) parts.push(item.addresses.join(", "));
        if (item.vlan_ids && item.vlan_ids.length) parts.push(`VLAN ${item.vlan_ids.join(",")}`);
        return parts.join(" · ");
    }

    function simpleSection(title, items, formatter = descriptorText) {
        if (!items || !items.length) return null;
        const section = el("section", null, "ws-topology-compare-section");
        section.append(el("h4", `${title} · ${items.length}`));
        const list = el("ul", null, "ws-topology-compare-list");
        items.slice(0, 100).forEach((item) => list.append(el("li", formatter(item))));
        section.append(list);
        if (items.length > 100) section.append(el("p", `Показаны первые 100 из ${items.length}. Полный результат доступен в JSON.`, "muted"));
        return section;
    }

    function changeText(change) {
        const value = (entry) => {
            if (entry === null || entry === undefined) return "—";
            if (Array.isArray(entry)) return entry.join(", ") || "—";
            if (typeof entry === "object") return JSON.stringify(entry);
            return String(entry);
        };
        return `${value(change.before)} → ${value(change.after)}`;
    }

    function changedSection(title, items) {
        if (!items || !items.length) return null;
        const section = el("section", null, "ws-topology-compare-section");
        section.append(el("h4", `${title} · ${items.length}`));
        const list = el("div", null, "ws-topology-compare-changes");
        items.slice(0, 100).forEach((item) => {
            const card = el("div", null, "ws-topology-compare-change");
            const label = (item.after && item.after.label) || (item.before && item.before.label) || item.key;
            card.append(el("strong", label));
            const fields = el("dl");
            Object.entries(item.changes || {}).forEach(([field, change]) => {
                fields.append(el("dt", fieldLabel(field)), el("dd", changeText(change)));
            });
            card.append(fields);
            list.append(card);
        });
        section.append(list);
        if (items.length > 100) section.append(el("p", `Показаны первые 100 из ${items.length}. Полный результат доступен в JSON.`, "muted"));
        return section;
    }

    function renderResult(host, result) {
        host.replaceChildren();
        const baseline = result.baseline || {};
        const current = result.current || {};
        host.append(
            el("h3", "Изменения топологии"),
            el(
                "p",
                `Базовый аудит: ${String(baseline.audit_id || "").slice(0, 8)} → текущий: ${String(current.audit_id || "").slice(0, 8)}. Устройства сопоставляются консервативно: совпадение подтверждается MAC или IP. Одинаковое имя хоста само по себе не считается идентичностью.`,
                "muted"
            ),
            renderSummary(result)
        );

        const segmentAdded = simpleSection("Новые подсети", (result.segments || {}).added || [], (item) => item);
        const segmentRemoved = simpleSection("Исчезнувшие подсети", (result.segments || {}).removed || [], (item) => item);
        const nodeAdded = simpleSection("Новые узлы", (result.nodes || {}).added || []);
        const nodeRemoved = simpleSection("Исчезнувшие узлы", (result.nodes || {}).removed || []);
        const nodeChanged = changedSection("Изменившиеся узлы", (result.nodes || {}).changed || []);
        const edgeAdded = simpleSection("Новые связи", (result.edges || {}).added || [], (item) => `${relationLabel(item.relation)} · ${item.source || "?"} → ${item.target || "?"}`);
        const edgeRemoved = simpleSection("Исчезнувшие связи", (result.edges || {}).removed || [], (item) => `${relationLabel(item.relation)} · ${item.source || "?"} → ${item.target || "?"}`);
        const edgeChanged = changedSection("Изменившиеся связи", (result.edges || {}).changed || []);
        [segmentAdded, segmentRemoved, nodeAdded, nodeRemoved, nodeChanged, edgeAdded, edgeRemoved, edgeChanged]
            .filter(Boolean)
            .forEach((section) => host.append(section));

        const summary = result.summary || {};
        const totalChanges = [
            summary.segments_added,
            summary.segments_removed,
            summary.nodes_added,
            summary.nodes_removed,
            summary.nodes_changed,
            summary.edges_added,
            summary.edges_removed,
            summary.edges_changed,
        ].reduce((sum, value) => sum + (Number(value) || 0), 0);
        if (!totalChanges) host.append(el("p", "По доступным данным структурных изменений не обнаружено.", "success"));
        (result.warnings || []).forEach((warning) => host.append(el("p", warningLabel(warning), "warning")));

        const download = el("button", "Скачать JSON сравнения", "secondary");
        download.type = "button";
        download.addEventListener("click", () => {
            const blob = new Blob([JSON.stringify(result, null, 2)], { type: "application/json" });
            const url = URL.createObjectURL(blob);
            const link = document.createElement("a");
            link.href = url;
            link.download = `wirescope-topology-diff-${String(baseline.audit_id || "base").slice(0, 8)}-${String(current.audit_id || "current").slice(0, 8)}.json`;
            document.body.append(link);
            link.click();
            link.remove();
            URL.revokeObjectURL(url);
        });
        host.append(download);
    }

    async function render(body, auditId) {
        body.replaceChildren(el("p", "Загружаем сохранённые топологии для сравнения…"));
        const global = await request("/topology/global?limit=100");
        body.replaceChildren();

        const intro = el("div", null, "ws-topology-compare-intro");
        intro.append(
            el("h3", "История топологии"),
            el("p", "Сравнение использует только сохранённые данные двух аудитов и не запускает сканирование, SNMP или трассировку маршрута.", "muted")
        );
        if (global.partial) {
            intro.append(el("p", "Список топологий частичный: некоторые сохранённые аудиты не удалось построить. Они не предлагаются как база сравнения.", "warning"));
        }

        const controls = el("div", null, "ws-topology-compare-controls");
        const select = document.createElement("select");
        const placeholder = el("option", "Выберите предыдущий аудит");
        placeholder.value = "";
        select.append(placeholder);
        const candidates = (global.audits || [])
            .filter((audit) => String(audit.id || "") !== String(auditId))
            .sort((a, b) => String(b.created_at || "").localeCompare(String(a.created_at || "")));
        candidates.forEach((audit) => {
            const option = el("option", auditLabel(audit));
            option.value = audit.id;
            select.append(option);
        });
        const compare = el("button", "Сравнить", "primary");
        compare.type = "button";
        compare.disabled = true;
        controls.append(select, compare);
        const resultHost = el("div", null, "ws-topology-compare-result");

        select.addEventListener("change", () => {
            compare.disabled = !select.value;
        });
        compare.addEventListener("click", async () => {
            if (!select.value) return;
            compare.disabled = true;
            const original = compare.textContent;
            compare.textContent = "Сравниваем…";
            resultHost.replaceChildren(el("p", "Сопоставляем сохранённые узлы и связи…", "muted"));
            try {
                const result = await request(`/audits/${encodeURIComponent(auditId)}/topology/compare?against=${encodeURIComponent(select.value)}`);
                renderResult(resultHost, result);
            } catch (error) {
                resultHost.replaceChildren(el("p", error.message, "error"));
            } finally {
                compare.disabled = !select.value;
                compare.textContent = original;
            }
        });

        body.append(intro);
        if (!candidates.length) {
            body.append(el("p", "Нет другого сохранённого аудита с построенной топологией, который можно использовать как базу сравнения.", "muted"));
            return;
        }
        body.append(controls, resultHost);
    }

    window.WireScopeTopologyCompare = { render };
})();
