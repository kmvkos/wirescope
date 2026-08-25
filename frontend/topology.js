(() => {
    "use strict";

    const API = "/api/v1";
    const SVG_NS = "http://www.w3.org/2000/svg";
    const MAX_VISIBLE_NODES = 90;

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

    function svg(tag, attrs = {}) {
        const node = document.createElementNS(SVG_NS, tag);
        Object.entries(attrs).forEach(([key, value]) => node.setAttribute(key, String(value)));
        return node;
    }

    function short(value, length = 24) {
        const text = String(value || "");
        return text.length > length ? `${text.slice(0, length - 1)}…` : text;
    }

    function bytes(value) {
        let current = Number(value) || 0;
        const units = ["B", "KiB", "MiB", "GiB"];
        let unit = 0;
        while (current >= 1024 && unit < units.length - 1) {
            current /= 1024;
            unit += 1;
        }
        return `${current >= 10 || unit === 0 ? current.toFixed(0) : current.toFixed(1)} ${units[unit]}`;
    }

    function roleScore(node) {
        const roles = new Set(node.roles || []);
        if (node.kind === "wirescope") return 1000;
        if (roles.has("gateway")) return 900;
        if (roles.has("network-neighbor") || roles.has("stp-root")) return 850;
        if (node.kind === "network-device" || roles.has("network-device")) return 800;
        if (roles.has("dhcp-server")) return 700;
        if (node.kind === "asset") return 500;
        if (node.kind === "multicast-group") return 50;
        return 300;
    }

    function nodeKindLabel(node) {
        const roles = new Set(node.roles || []);
        if (node.kind === "wirescope") return "WireScope";
        if (roles.has("gateway")) return "Шлюз";
        if (roles.has("dhcp-server")) return "DHCP";
        if (node.kind === "network-device" || roles.has("network-device") || roles.has("network-neighbor")) return "Сетевое устройство";
        if (node.kind === "multicast-group") return "Multicast/Broadcast";
        if (node.device_class) return node.device_class;
        return "Узел";
    }

    function confidenceLabel(value) {
        return ({ confirmed: "подтверждено", observed: "наблюдалось", inferred: "предположительно" })[value] || value || "—";
    }

    function relationLabel(value) {
        return ({
            default_gateway: "шлюз по умолчанию",
            layer2_neighbor: "L2-сосед",
            stp_observed: "STP-наблюдение",
            dhcp_observed: "DHCP-наблюдение",
            communication: "реальный обмен",
        })[value] || value;
    }

    function degrees(topology) {
        const result = new Map();
        (topology.edges || []).forEach((edge) => {
            result.set(edge.source, (result.get(edge.source) || 0) + 1);
            result.set(edge.target, (result.get(edge.target) || 0) + 1);
        });
        return result;
    }

    function selectVisible(topology, showGroups) {
        const degree = degrees(topology);
        const nodes = (topology.nodes || []).filter((node) => showGroups || node.kind !== "multicast-group");
        nodes.sort((a, b) => {
            const score = (roleScore(b) - roleScore(a));
            if (score) return score;
            return (degree.get(b.id) || 0) - (degree.get(a.id) || 0);
        });
        return nodes.slice(0, MAX_VISIBLE_NODES);
    }

    function layout(nodes) {
        const positions = new Map();
        const width = 1000;
        const height = 680;
        const centerX = width / 2;
        const centerY = height / 2 + 20;
        const core = nodes.filter((node) => roleScore(node) >= 700 && node.kind !== "wirescope");
        const sensor = nodes.find((node) => node.kind === "wirescope");
        const regular = nodes.filter((node) => node !== sensor && !core.includes(node));

        if (sensor) positions.set(sensor.id, { x: centerX, y: 74 });
        core.forEach((node, index) => {
            const angle = -Math.PI * 0.92 + (Math.PI * 1.84 * (index / Math.max(1, core.length)));
            positions.set(node.id, {
                x: centerX + Math.cos(angle) * 155,
                y: centerY + Math.sin(angle) * 120,
            });
        });
        const rings = [250, 315];
        regular.forEach((node, index) => {
            const ringIndex = index % rings.length;
            const inRing = regular.filter((_n, i) => i % rings.length === ringIndex).length;
            const ordinal = Math.floor(index / rings.length);
            const angle = -Math.PI / 2 + (Math.PI * 2 * ordinal / Math.max(1, inRing));
            positions.set(node.id, {
                x: centerX + Math.cos(angle) * rings[ringIndex] * 1.35,
                y: centerY + Math.sin(angle) * rings[ringIndex] * 0.86,
            });
        });
        return positions;
    }

    function detailNode(target, node) {
        target.replaceChildren();
        target.append(el("h4", node.label || node.id));
        const grid = el("div", null, "ws-topology-detail-grid");
        const rows = [
            ["Тип", nodeKindLabel(node)],
            ["Достоверность", confidenceLabel(node.confidence)],
            ["Источник", (node.provenance || []).join(", ") || "—"],
            ["Роли", (node.roles || []).join(", ") || "—"],
            ["Адреса", (node.addresses || []).join(", ") || "—"],
            ["Имена", (node.names || []).join(", ") || "—"],
            ["MAC", node.mac || "—"],
            ["Vendor", node.vendor || "—"],
            ["OS", node.os_name || "—"],
        ];
        rows.forEach(([key, value]) => {
            grid.append(el("strong", key), el("span", value));
        });
        target.append(grid);
        const services = node.services || [];
        if (services.length) {
            target.append(el("h4", "Сервисы"));
            const list = el("div", null, "ws-topology-service-list");
            services.slice(0, 30).forEach((service) => {
                list.append(el("span", `${service.protocol || "?"}/${service.port ?? "?"} ${service.name || service.product || ""}`.trim()));
            });
            target.append(list);
        }
    }

    function detailEdge(target, edge) {
        target.replaceChildren();
        target.append(el("h4", relationLabel(edge.relation)));
        const grid = el("div", null, "ws-topology-detail-grid");
        const rows = [
            ["Достоверность", confidenceLabel(edge.confidence)],
            ["Источник доказательства", (edge.provenance || []).join(", ") || "—"],
            ["Пакеты", edge.packets ?? "—"],
            ["Объём", edge.bytes === undefined ? "—" : bytes(edge.bytes)],
            ["Протоколы", (edge.protocols || []).join(", ") || "—"],
            ["Порты", (edge.ports || []).join(", ") || "—"],
            ["Порт соседа", edge.port_id || "—"],
        ];
        rows.forEach(([key, value]) => grid.append(el("strong", key), el("span", value)));
        target.append(grid);
    }

    function renderGraph(host, topology, showGroups) {
        host.replaceChildren();
        const visible = selectVisible(topology, showGroups);
        const visibleIds = new Set(visible.map((node) => node.id));
        const positions = layout(visible);
        const canvas = svg("svg", {
            viewBox: "0 0 1000 680",
            role: "img",
            "aria-label": "Логическая карта сети WireScope",
        });
        canvas.classList.add("ws-topology-svg");
        const edgesLayer = svg("g", { class: "ws-topology-edges" });
        const nodesLayer = svg("g", { class: "ws-topology-nodes" });
        const details = el("div", "Нажмите на узел или связь, чтобы увидеть источник и достоверность.", "ws-topology-details");

        (topology.edges || []).forEach((edge) => {
            if (!visibleIds.has(edge.source) || !visibleIds.has(edge.target)) return;
            const a = positions.get(edge.source);
            const b = positions.get(edge.target);
            if (!a || !b) return;
            const width = edge.relation === "communication"
                ? Math.min(7, 1.2 + Math.log10(Math.max(1, Number(edge.bytes) || 1)))
                : 2.1;
            const line = svg("line", {
                x1: a.x,
                y1: a.y,
                x2: b.x,
                y2: b.y,
                class: `ws-topology-edge ws-topology-${edge.confidence || "inferred"} ws-topology-rel-${edge.relation}`,
                "stroke-width": width,
                tabindex: "0",
            });
            const title = svg("title");
            title.textContent = `${relationLabel(edge.relation)} · ${confidenceLabel(edge.confidence)} · ${(edge.provenance || []).join(", ")}`;
            line.append(title);
            line.addEventListener("click", () => detailEdge(details, edge));
            line.addEventListener("keydown", (event) => { if (event.key === "Enter") detailEdge(details, edge); });
            edgesLayer.append(line);
        });

        visible.forEach((node) => {
            const point = positions.get(node.id);
            if (!point) return;
            const group = svg("g", {
                class: `ws-topology-node ws-topology-node-${node.kind}`,
                transform: `translate(${point.x} ${point.y})`,
                tabindex: "0",
            });
            const radius = roleScore(node) >= 700 ? 29 : 22;
            const circle = svg("circle", { r: radius });
            const label = svg("text", { y: radius + 18, "text-anchor": "middle" });
            label.textContent = short(node.label, 23);
            const badge = svg("text", { y: 4, "text-anchor": "middle", class: "ws-topology-node-badge" });
            badge.textContent = node.kind === "wirescope" ? "W" : (node.roles || []).includes("gateway") ? "GW" : (node.kind === "network-device" || (node.roles || []).includes("network-device")) ? "SW" : "●";
            const title = svg("title");
            title.textContent = `${node.label} · ${nodeKindLabel(node)} · ${confidenceLabel(node.confidence)}`;
            group.append(circle, badge, label, title);
            group.addEventListener("click", () => detailNode(details, node));
            group.addEventListener("keydown", (event) => { if (event.key === "Enter") detailNode(details, node); });
            nodesLayer.append(group);
        });

        canvas.append(edgesLayer, nodesLayer);
        host.append(canvas, details);
        if ((topology.nodes || []).length > visible.length) {
            host.append(el("p", `На схеме показано ${visible.length} из ${topology.nodes.length} узлов. Остальные сохранены в topology JSON.`, "muted"));
        }
    }

    function summary(topology) {
        const block = el("div", null, "ws-metric-grid");
        const data = topology.summary || {};
        const confidence = data.confidence || {};
        const metric = (label, value) => {
            const item = el("div", null, "ws-metric");
            item.append(el("strong", value ?? 0), el("span", label));
            return item;
        };
        block.append(
            metric("Узлы", data.nodes),
            metric("Связи", data.edges),
            metric("Подтверждено", confidence.confirmed || 0),
            metric("Наблюдалось", confidence.observed || 0),
            metric("Предположительно", confidence.inferred || 0)
        );
        return block;
    }

    async function render(body, auditId) {
        body.replaceChildren(el("p", "Строим логическую карту из сохранённых данных…"));
        const base = await request(`/audits/${encodeURIComponent(auditId)}/topology`);
        const analyses = await request("/traffic-analysis?limit=100");
        body.replaceChildren();

        const controls = el("div", null, "ws-topology-controls");
        const select = el("select");
        const none = el("option", "Без PCAP overlay");
        none.value = "";
        select.append(none);
        const candidates = (analyses.items || []).slice().sort((a, b) => {
            const am = a.interface === base.audit.interface ? 1 : 0;
            const bm = b.interface === base.audit.interface ? 1 : 0;
            return bm - am;
        });
        candidates.forEach((item) => {
            const same = item.interface === base.audit.interface;
            const option = el("option", `${same ? "✓ " : "⚠ "}${item.interface || "—"} · ${String(item.capture_job_id || item.job_id).slice(0, 8)} · analyzer v${item.analyzer_version || "?"}`);
            option.value = item.job_id;
            select.append(option);
        });
        const apply = el("button", "Применить overlay", "secondary");
        const multicastLabel = el("label", null, "ws-topology-check");
        const multicast = document.createElement("input");
        multicast.type = "checkbox";
        multicastLabel.append(multicast, document.createTextNode(" показывать multicast/broadcast группы"));
        controls.append(el("span", "PCAP:"), select, apply, multicastLabel);

        const legend = el("div", null, "ws-topology-legend");
        [["confirmed", "Подтверждено"], ["observed", "Наблюдалось"], ["inferred", "Предположительно"]].forEach(([key, label]) => {
            const item = el("span");
            item.append(el("i", null, `ws-topology-legend-${key}`), document.createTextNode(label));
            legend.append(item);
        });

        const meta = el("div", null, "ws-topology-meta");
        const graph = el("div", null, "ws-topology-canvas");
        let current = base;

        function renderCurrent() {
            meta.replaceChildren(summary(current));
            if (current.overlay) {
                meta.append(el("p", `Overlay: traffic-analysis ${current.overlay.traffic_analysis_job_id.slice(0, 8)} · интерфейс ${current.overlay.interface || "—"} · ${current.overlay.frame_count ?? "—"} кадров.`, "ws-topology-overlay-note"));
            } else {
                meta.append(el("p", "Сейчас показана топология только выбранного аудита. PCAP не подмешивается автоматически.", "muted"));
            }
            (current.warnings || []).forEach((warning) => meta.append(el("p", warning, "warning")));
            renderGraph(graph, current, multicast.checked);
        }

        apply.addEventListener("click", async () => {
            apply.disabled = true;
            apply.textContent = "Строим…";
            try {
                const query = select.value ? `?traffic_analysis_job_id=${encodeURIComponent(select.value)}` : "";
                current = await request(`/audits/${encodeURIComponent(auditId)}/topology${query}`);
                renderCurrent();
            } catch (error) {
                meta.append(el("p", error.message, "error"));
            } finally {
                apply.disabled = false;
                apply.textContent = "Применить overlay";
            }
        });
        multicast.addEventListener("change", () => renderGraph(graph, current, multicast.checked));

        const exportButton = el("button", "Скачать topology JSON", "secondary");
        exportButton.addEventListener("click", () => {
            const blob = new Blob([JSON.stringify(current, null, 2)], { type: "application/json" });
            const url = URL.createObjectURL(blob);
            const link = document.createElement("a");
            link.href = url;
            link.download = `wirescope-topology-${String(auditId).slice(0, 8)}.json`;
            document.body.append(link);
            link.click();
            link.remove();
            URL.revokeObjectURL(url);
        });

        body.append(controls, legend, meta, graph, exportButton);
        renderCurrent();
    }

    window.WireScopeTopology = { render };
})();
