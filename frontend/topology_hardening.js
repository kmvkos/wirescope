(() => {
    "use strict";

    const API = "/api/v1";
    const SVG_NS = "http://www.w3.org/2000/svg";
    const WIDTH = 1400;
    const HEIGHT = 900;
    const CARD_W = 164;
    const CARD_H = 54;
    const legacyRenderer = window.WireScopeTopology;

    const el = (tag, text, cls) => {
        const node = document.createElement(tag);
        if (text !== undefined && text !== null) node.textContent = String(text);
        if (cls) node.className = cls;
        return node;
    };

    const svg = (tag, attrs = {}) => {
        const node = document.createElementNS(SVG_NS, tag);
        Object.entries(attrs).forEach(([key, value]) => node.setAttribute(key, String(value)));
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

    function downloadBlob(blob, filename) {
        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = url;
        link.download = filename;
        document.body.append(link);
        link.click();
        link.remove();
        setTimeout(() => URL.revokeObjectURL(url), 0);
    }

    function safeId(value) {
        return String(value || "").replace(/[^a-zA-Z0-9_-]/g, "-");
    }

    function bareAddress(value) {
        return String(value || "").split("/", 1)[0];
    }

    function firstAddress(node, family = 4) {
        const values = node.addresses || [];
        if (family === 4) return values.map(bareAddress).find((value) => /^\d+\.\d+\.\d+\.\d+$/.test(value)) || "";
        return values.map(bareAddress).find((value) => value.includes(":")) || "";
    }

    function isExternal(node) {
        if ((node.segment_ids || []).length) return false;
        const ip = firstAddress(node, 4);
        if (!ip) return false;
        const parts = ip.split(".").map(Number);
        if (parts.length !== 4) return false;
        if (parts[0] === 10 || parts[0] === 127 || parts[0] === 0) return false;
        if (parts[0] === 169 && parts[1] === 254) return false;
        if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return false;
        if (parts[0] === 192 && parts[1] === 168) return false;
        return parts[0] < 224;
    }

    function labelFor(topology, node) {
        const labels = (topology.presentation || {}).labels || {};
        return labels[node.id] || node.label || firstAddress(node) || String(node.id || "узел");
    }

    function nodeSubtitle(node) {
        const roles = new Set(node.roles || []);
        if (node.kind === "wirescope") return "WireScope sensor";
        if (roles.has("gateway")) return "gateway / router";
        if (node.kind === "network-device" || roles.has("network-device") || roles.has("network-neighbor")) return "network device";
        if (node.kind === "network-interface") return "router interface";
        if (isExternal(node)) return "external endpoint";
        const ip = firstAddress(node);
        if (ip && ip !== node.label) return ip;
        if ((node.services || []).length) return `${node.services.length} services`;
        return node.kind === "asset" ? "asset" : "endpoint";
    }

    function edgeLabel(edge) {
        const relation = ({
            segment_gateway: "gateway",
            default_gateway: "default gateway",
            layer2_neighbor: "LLDP / L2",
            stp_observed: "STP",
            routed_interface: "L3 interface",
            route_hop: "route hop",
            route_target: "route",
            upstream_route: "upstream",
            dhcp_observed: "DHCP",
            communication: "traffic",
        })[edge.relation] || edge.relation || "link";
        if (edge.mapping_type === "switch_port" && edge.port_id) return `${relation} · ${edge.port_id}`;
        return relation;
    }

    function projection(topology, viewName, segmentId, confidence) {
        const presentation = topology.presentation || {};
        const configured = (presentation.views || {})[viewName];
        const nodeMap = new Map((topology.nodes || []).map((node) => [node.id, node]));
        const edgeMap = new Map((topology.edges || []).map((edge) => [edge.id, edge]));

        let nodes = configured
            ? (configured.node_ids || []).map((id) => nodeMap.get(id)).filter(Boolean)
            : (topology.nodes || []).slice();
        let edges = configured
            ? (configured.edge_ids || []).map((id) => edgeMap.get(id)).filter(Boolean)
            : (topology.edges || []).filter((edge) => viewName === "evidence" || (edge.layer || "general") === viewName);

        if (segmentId) {
            edges = edges.filter((edge) =>
                edge.segment_id === segmentId || (edge.segment_ids || []).includes(segmentId)
            );
            const referenced = new Set(edges.flatMap((edge) => [edge.source, edge.target]));
            nodes = nodes.filter((node) =>
                referenced.has(node.id) || (node.segment_ids || []).includes(segmentId) || node.kind === "wirescope"
            );
        }
        if (confidence && confidence !== "all") {
            edges = edges.filter((edge) => edge.confidence === confidence);
            const referenced = new Set(edges.flatMap((edge) => [edge.source, edge.target]));
            nodes = nodes.filter((node) => referenced.has(node.id) || node.kind === "wirescope");
        }
        const visible = new Set(nodes.map((node) => node.id));
        edges = edges.filter((edge) => visible.has(edge.source) && visible.has(edge.target));
        return { ...topology, nodes, edges, view_name: viewName };
    }

    function coveragePanel(topology) {
        const coverage = topology.coverage;
        if (!coverage) return null;
        const section = el("section", null, "ws-topology-coverage");
        const head = el("div", null, "ws-topology-coverage-head");
        const status = coverage.status || "partial";
        head.append(
            el("strong", "Достаточность данных"),
            el("span", status === "sufficient" ? "структурных данных достаточно" : "данные частичные", `ws-coverage-status ws-coverage-${status}`)
        );
        section.append(head);

        const grid = el("div", null, "ws-topology-coverage-grid");
        const order = ["inventory", "l3", "l2", "traffic", "vlan", "wifi", "hypervisor"];
        order.forEach((key) => {
            const domain = (coverage.domains || {})[key];
            if (!domain) return;
            const card = el("button", null, `ws-coverage-card ws-coverage-${domain.status}`);
            card.type = "button";
            card.append(el("strong", domain.title), el("span", ({sufficient: "достаточно", partial: "частично", missing: "нет evidence"})[domain.status] || domain.status));
            card.title = domain.statement || "";
            card.addEventListener("click", () => {
                details.replaceChildren(el("strong", domain.title), el("p", domain.statement || ""));
                if ((domain.evidence || []).length) details.append(el("p", `Есть: ${domain.evidence.join(" · ")}`));
                if ((domain.missing || []).length) details.append(el("p", `Не хватает: ${domain.missing.join(" · ")}`, "warning"));
                (domain.limitations || []).forEach((item) => details.append(el("p", item, "muted")));
            });
            grid.append(card);
        });
        const details = el("div", null, "ws-topology-coverage-details");
        details.append(el("p", "Нажмите на блок, чтобы увидеть, какие утверждения поддержаны evidence."));
        const claims = coverage.claims || {};
        const claimLine = el("p", null, "ws-topology-claim-line");
        const claimNames = {
            logical_segment_membership: "сегмент",
            gateway: "gateway",
            direct_l2_adjacency: "direct L2",
            physical_switch_port: "switch-port",
            vlan_membership: "VLAN",
            observed_traffic: "traffic",
            wifi_association: "Wi‑Fi",
            hypervisor_placement: "VM→host",
        };
        Object.entries(claimNames).forEach(([key, title]) => {
            claimLine.append(el("span", `${claims[key] ? "✓" : "—"} ${title}`, claims[key] ? "ws-claim-yes" : "ws-claim-no"));
        });
        section.append(grid, claimLine, details);
        if ((coverage.recommendations || []).length) {
            const disclosure = el("details", null, "ws-topology-recommendations");
            disclosure.append(el("summary", `Как улучшить карту · ${coverage.recommendations.length}`));
            const list = el("ul");
            coverage.recommendations.forEach((item) => list.append(el("li", item)));
            disclosure.append(list);
            section.append(disclosure);
        }
        return section;
    }

    function createPositionMap(topology, view) {
        const positions = new Map();
        const virtual = [];
        const nodes = view.nodes || [];
        const nodeMap = new Map(nodes.map((node) => [node.id, node]));
        const sensor = nodes.find((node) => node.kind === "wirescope");

        if (view.view_name === "traffic") {
            const internal = nodes.filter((node) => !isExternal(node));
            const external = nodes.filter(isExternal);
            const putColumn = (items, x) => {
                const step = Math.min(112, 690 / Math.max(1, items.length));
                items.forEach((node, index) => positions.set(node.id, { x, y: 135 + step * index }));
            };
            putColumn(internal, 300);
            putColumn(external, 1100);
            return { positions, regions: [], virtual };
        }

        if (view.view_name === "l2") {
            const infra = nodes.filter((node) => node.kind === "wirescope" || node.kind === "network-device" || (node.roles || []).some((role) => ["network-neighbor", "network-device", "stp-root", "stp-bridge"].includes(role)));
            const rest = nodes.filter((node) => !infra.includes(node));
            const stepInfra = Math.min(120, 680 / Math.max(1, infra.length));
            infra.forEach((node, index) => positions.set(node.id, { x: 330 + (index % 2) * 300, y: 140 + Math.floor(index / 2) * stepInfra }));
            const stepRest = Math.min(95, 680 / Math.max(1, rest.length));
            rest.forEach((node, index) => positions.set(node.id, { x: 1050, y: 135 + index * stepRest }));
            return { positions, regions: [], virtual };
        }

        if (view.view_name === "l3") {
            const gateways = nodes.filter((node) => (node.roles || []).includes("gateway") || (node.roles || []).includes("router"));
            const rest = nodes.filter((node) => !gateways.includes(node) && node !== sensor);
            gateways.forEach((node, index) => positions.set(node.id, { x: 700 + (index - (gateways.length - 1) / 2) * 230, y: 170 }));
            if (sensor) positions.set(sensor.id, { x: 700, y: 720 });
            const step = Math.min(190, 900 / Math.max(1, rest.length));
            rest.forEach((node, index) => positions.set(node.id, { x: 250 + index * step, y: 440 }));
            return { positions, regions: [], virtual };
        }

        if (view.view_name === "evidence") {
            const cols = Math.max(1, Math.ceil(Math.sqrt(nodes.length * 1.7)));
            nodes.forEach((node, index) => {
                positions.set(node.id, { x: 110 + (index % cols) * 190, y: 110 + Math.floor(index / cols) * 95 });
            });
            return { positions, regions: [], virtual };
        }

        // Structural map: segment regions are the primary layout primitive.
        const groups = (((topology.presentation || {}).views || {}).structural || {}).segment_groups || [];
        const segments = (topology.segments || []).filter((segment) => groups.some((group) => group.segment_id === segment.id) || (segment.members || []).length);
        const regions = [];
        if (sensor) positions.set(sensor.id, { x: 140, y: 90 });
        const cols = Math.min(2, Math.max(1, Math.ceil(Math.sqrt(Math.max(1, segments.length)))));
        const rows = Math.max(1, Math.ceil(segments.length / cols));
        const gap = 36;
        const left = 90;
        const top = 175;
        const usableW = WIDTH - 180;
        const usableH = HEIGHT - 240;
        const regionW = (usableW - gap * (cols - 1)) / cols;
        const regionH = (usableH - gap * (rows - 1)) / rows;

        segments.forEach((segment, index) => {
            const col = index % cols;
            const row = Math.floor(index / cols);
            const region = {
                id: segment.id,
                label: segment.network || segment.label || segment.id,
                x: left + col * (regionW + gap),
                y: top + row * (regionH + gap),
                width: regionW,
                height: regionH,
            };
            regions.push(region);
            const group = groups.find((item) => item.segment_id === segment.id) || {};
            const ids = [
                ...(group.infrastructure_node_ids || []),
                ...(group.visible_endpoint_node_ids || []),
            ].filter((id, pos, all) => all.indexOf(id) === pos && nodeMap.has(id) && id !== (sensor && sensor.id));
            const gateways = ids.filter((id) => (nodeMap.get(id).roles || []).includes("gateway"));
            const infra = ids.filter((id) => !gateways.includes(id) && (nodeMap.get(id).kind === "network-device" || (nodeMap.get(id).roles || []).some((role) => ["network-device", "network-neighbor", "router"].includes(role))));
            const endpoints = ids.filter((id) => !gateways.includes(id) && !infra.includes(id));

            gateways.forEach((id, i) => positions.set(id, { x: region.x + region.width / 2 + (i - (gateways.length - 1) / 2) * 190, y: region.y + 72 }));
            infra.forEach((id, i) => positions.set(id, { x: region.x + 125 + (i % 3) * 195, y: region.y + 170 + Math.floor(i / 3) * 90 }));
            const endpointTop = region.y + Math.max(270, 190 + Math.ceil(infra.length / 3) * 90);
            const endpointCols = Math.max(1, Math.floor((region.width - 70) / 190));
            endpoints.forEach((id, i) => positions.set(id, { x: region.x + 120 + (i % endpointCols) * 190, y: endpointTop + Math.floor(i / endpointCols) * 82 }));

            if ((group.collapsed_endpoint_count || 0) > 0) {
                const id = `collapsed:${segment.id}`;
                const item = {
                    id,
                    kind: "collapsed-group",
                    label: `+ ${group.collapsed_endpoint_count} устройств`,
                    roles: ["collapsed"],
                    collapsed_node_ids: group.collapsed_endpoint_node_ids || [],
                };
                virtual.push(item);
                const rowIndex = Math.ceil(Math.max(1, endpoints.length) / endpointCols);
                positions.set(id, { x: region.x + region.width - 130, y: Math.min(region.y + region.height - 62, endpointTop + rowIndex * 82) });
            }
        });

        // Infrastructure not assigned to a visible segment stays in a small
        // management strip instead of becoming random floating dots.
        const assigned = new Set(positions.keys());
        const leftovers = nodes.filter((node) => !assigned.has(node.id));
        leftovers.forEach((node, index) => positions.set(node.id, { x: 370 + index * 190, y: 90 }));
        return { positions, regions, virtual };
    }

    function renderDetails(target, topology, item) {
        target.replaceChildren();
        if (!item) return;
        if (item.kind === "collapsed-group") {
            target.append(el("h4", item.label));
            const labels = (item.collapsed_node_ids || []).slice(0, 50).map((id) => ((topology.presentation || {}).labels || {})[id] || id);
            target.append(el("p", labels.join(" · ") || "Скрытые малозначимые endpoints"));
            return;
        }
        target.append(el("h4", labelFor(topology, item)));
        const dl = el("dl", null, "ws-topology-detail-grid");
        const row = (name, value) => { dl.append(el("dt", name), el("dd", value || "—")); };
        row("Тип", nodeSubtitle(item));
        row("Адреса", (item.addresses || []).join(", "));
        row("Имена", (item.names || []).join(", "));
        row("Роли", (item.roles || []).join(", "));
        row("Достоверность", item.confidence);
        row("Источник", (item.provenance || []).join(", "));
        if ((item.services || []).length) row("Сервисы", item.services.map((service) => `${service.protocol}/${service.port}${service.name ? ` ${service.name}` : ""}`).join(" · "));
        if (item.finding_count) row("Findings", item.finding_count);
        target.append(dl);
    }

    function graph(topology, view, onSegmentFocus) {
        const wrap = el("div", null, "ws-topology-v2-canvas ws-topology-canvas");
        const toolbar = el("div", null, "ws-topology-graph-toolbar");
        const zoomOut = el("button", "−", "secondary"); zoomOut.dataset.zoom = "out";
        const zoomValue = el("span", "100%", "ws-topology-zoom-value");
        const zoomIn = el("button", "+", "secondary"); zoomIn.dataset.zoom = "in";
        const fit = el("button", "Вписать", "secondary"); fit.dataset.zoom = "fit";
        toolbar.append(zoomOut, zoomValue, zoomIn, fit, el("span", "Колесо — масштаб · drag — перемещение", "muted"));

        const documentSvg = svg("svg", { class: "ws-topology-svg", viewBox: `0 0 ${WIDTH} ${HEIGHT}`, role: "img" });
        const defs = svg("defs");
        const marker = svg("marker", { id: "ws-v2-arrow", markerWidth: 8, markerHeight: 8, refX: 7, refY: 3, orient: "auto", markerUnits: "strokeWidth" });
        marker.append(svg("path", { d: "M0,0 L0,6 L7,3 z", fill: "#8db8ff" }));
        defs.append(marker);
        documentSvg.append(defs);
        const viewport = svg("g", { class: "ws-topology-viewport", transform: "translate(0 0) scale(1)" });
        documentSvg.append(viewport);

        const { positions, regions, virtual } = createPositionMap(topology, view);
        const allNodes = [...(view.nodes || []), ...virtual];
        const nodeMap = new Map(allNodes.map((node) => [node.id, node]));

        regions.forEach((region) => {
            const group = svg("g", { class: "ws-topology-region", "data-segment-id": region.id, tabindex: 0 });
            group.append(svg("rect", { x: region.x, y: region.y, width: region.width, height: region.height, rx: 22, fill: "#0d2236", stroke: "#2d657b", "stroke-width": 2, "stroke-dasharray": "8 7" }));
            const title = svg("text", { x: region.x + 22, y: region.y + 30, fill: "#89ddeb", "font-size": 17, "font-weight": 700 });
            title.textContent = region.label;
            group.append(title);
            group.addEventListener("dblclick", () => onSegmentFocus && onSegmentFocus(region.id));
            group.addEventListener("keydown", (event) => { if (event.key === "Enter") onSegmentFocus && onSegmentFocus(region.id); });
            viewport.append(group);
        });

        (view.edges || []).forEach((edge) => {
            const a = positions.get(edge.source);
            const b = positions.get(edge.target);
            if (!a || !b) return;
            const width = edge.relation === "communication" ? Math.min(10, 2 + Math.log10(1 + Number(edge.bytes || edge.packets || 1))) : 2.4;
            const line = svg("line", {
                x1: a.x, y1: a.y, x2: b.x, y2: b.y,
                class: `ws-topology-edge ws-topology-${safeId(edge.confidence || "observed")} ws-topology-rel-${safeId(edge.relation)}`,
                stroke: edge.confidence === "confirmed" ? "#59dfd3" : edge.confidence === "inferred" ? "#8290a4" : "#6fa8e8",
                "stroke-width": width,
                "stroke-dasharray": edge.confidence === "inferred" ? "8 7" : "",
                opacity: 0.8,
                "marker-end": edge.relation === "communication" ? "url(#ws-v2-arrow)" : "",
            });
            viewport.append(line);
            if (edge.relation !== "communication") {
                const text = svg("text", { x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 - 8, fill: "#9fb4c9", "font-size": 12, "text-anchor": "middle" });
                text.textContent = edgeLabel(edge);
                viewport.append(text);
            }
        });

        const details = el("div", null, "ws-topology-details");
        allNodes.forEach((node) => {
            const point = positions.get(node.id);
            if (!point) return;
            const group = svg("g", {
                class: `ws-topology-node ws-topology-node-${safeId(node.kind || "endpoint")}`,
                transform: `translate(${point.x - CARD_W / 2} ${point.y - CARD_H / 2})`,
                tabindex: 0,
                "data-node-id": node.id,
            });
            const roles = new Set(node.roles || []);
            const fill = node.kind === "wirescope" ? "#123f46" : roles.has("gateway") ? "#2b334c" : node.kind === "network-device" ? "#263847" : node.kind === "collapsed-group" ? "#162638" : isExternal(node) ? "#33264d" : "#172b3f";
            const stroke = node.confidence === "confirmed" ? "#59dfd3" : node.kind === "collapsed-group" ? "#536b83" : "#77a9d7";
            group.append(svg("rect", { width: CARD_W, height: CARD_H, rx: 13, fill, stroke, "stroke-width": 2 }));
            const title = svg("text", { x: 12, y: 22, fill: "#f1f7fb", "font-size": 14, "font-weight": 700 });
            title.textContent = String(labelFor(topology, node)).slice(0, 25);
            const subtitle = svg("text", { x: 12, y: 41, fill: "#9fb4c9", "font-size": 11 });
            subtitle.textContent = String(nodeSubtitle(node)).slice(0, 27);
            group.append(title, subtitle);
            const activate = () => renderDetails(details, topology, node);
            group.addEventListener("click", activate);
            group.addEventListener("keydown", (event) => { if (event.key === "Enter") activate(); });
            viewport.append(group);
        });

        let scale = 1;
        let panX = 0;
        let panY = 0;
        const applyTransform = () => {
            viewport.setAttribute("transform", `translate(${panX} ${panY}) scale(${scale})`);
            zoomValue.textContent = `${Math.round(scale * 100)}%`;
        };
        zoomIn.addEventListener("click", () => { scale = Math.min(2.4, Number((scale + 0.2).toFixed(2))); applyTransform(); });
        zoomOut.addEventListener("click", () => { scale = Math.max(0.4, Number((scale - 0.2).toFixed(2))); applyTransform(); });
        fit.addEventListener("click", () => { scale = 1; panX = 0; panY = 0; applyTransform(); });
        documentSvg.addEventListener("wheel", (event) => {
            event.preventDefault();
            scale = Math.max(0.4, Math.min(2.4, scale + (event.deltaY < 0 ? 0.1 : -0.1)));
            scale = Number(scale.toFixed(2));
            applyTransform();
        }, { passive: false });
        let drag = null;
        documentSvg.addEventListener("pointerdown", (event) => { drag = { x: event.clientX, y: event.clientY, panX, panY }; documentSvg.setPointerCapture(event.pointerId); });
        documentSvg.addEventListener("pointermove", (event) => {
            if (!drag) return;
            panX = drag.panX + event.clientX - drag.x;
            panY = drag.panY + event.clientY - drag.y;
            applyTransform();
        });
        documentSvg.addEventListener("pointerup", () => { drag = null; });

        wrap.append(toolbar, documentSvg, details);
        wrap.__wsTopologyExport = { svg: documentSvg, viewport, resetTransform: () => viewport.setAttribute("transform", "translate(0 0) scale(1)") };
        return wrap;
    }

    function exportStyle() {
        return `
            .ws-topology-region text,.ws-topology-node text{font-family:Inter,Arial,sans-serif}
            .ws-topology-node{cursor:pointer}.ws-topology-edge{fill:none}
        `;
    }

    function serializeDiagram(canvas, { currentView = false } = {}) {
        const source = canvas.querySelector(".ws-topology-svg");
        if (!source) throw new Error("Topology diagram is not rendered");
        const clone = source.cloneNode(true);
        clone.setAttribute("xmlns", SVG_NS);
        clone.setAttribute("width", "1600");
        clone.setAttribute("height", String(Math.round(1600 * HEIGHT / WIDTH)));
        const viewport = clone.querySelector(".ws-topology-viewport");
        if (viewport && !currentView) viewport.setAttribute("transform", "translate(0 0) scale(1)");
        const style = svg("style");
        style.textContent = exportStyle();
        const defs = clone.querySelector("defs");
        if (defs) defs.prepend(style); else clone.prepend(style);
        const background = svg("rect", { x: 0, y: 0, width: WIDTH, height: HEIGHT, fill: "#071522" });
        if (defs) clone.insertBefore(background, defs.nextSibling); else clone.prepend(background);
        return `<?xml version="1.0" encoding="UTF-8"?>\n${new XMLSerializer().serializeToString(clone)}`;
    }

    async function pngFromSvg(text) {
        const blob = new Blob([text], { type: "image/svg+xml;charset=utf-8" });
        const url = URL.createObjectURL(blob);
        try {
            const image = new Image();
            await new Promise((resolve, reject) => { image.onload = resolve; image.onerror = reject; image.src = url; });
            const canvas = document.createElement("canvas");
            canvas.width = 2800;
            canvas.height = 1800;
            const context = canvas.getContext("2d");
            if (!context) throw new Error("Canvas unavailable");
            context.drawImage(image, 0, 0, canvas.width, canvas.height);
            return await new Promise((resolve, reject) => canvas.toBlob((result) => result ? resolve(result) : reject(new Error("PNG encode failed")), "image/png"));
        } finally {
            URL.revokeObjectURL(url);
        }
    }

    function metricSummary(view) {
        const grid = el("div", null, "ws-metric-grid");
        const metric = (label, value) => {
            const item = el("div", null, "ws-metric");
            item.append(el("strong", value), el("span", label));
            return item;
        };
        const confirmed = (view.edges || []).filter((edge) => edge.confidence === "confirmed").length;
        const observed = (view.edges || []).filter((edge) => edge.confidence === "observed").length;
        grid.append(metric("Подсети", (view.segments || []).length), metric("Показано узлов", (view.nodes || []).length), metric("Связи", (view.edges || []).length), metric("Подтверждено", confirmed), metric("Наблюдалось", observed));
        return grid;
    }

    async function render(body, auditId) {
        body.replaceChildren(el("p", "Строим структурную карту из сохранённого evidence…"));
        const [base, global, analyses] = await Promise.all([
            request(`/audits/${encodeURIComponent(auditId)}/topology`),
            request("/topology/global?limit=100"),
            request("/traffic-analysis?limit=100"),
        ]);
        body.replaceChildren();

        // Old deployments/API fixtures without presentation metadata keep the
        // proven legacy renderer rather than receiving a degraded v2 guess.
        if (!base.presentation || !base.coverage) {
            if (legacyRenderer && legacyRenderer.render) return legacyRenderer.render(body, auditId);
            throw new Error("Topology presentation metadata is unavailable");
        }

        const controls = el("div", null, "ws-topology-controls ws-topology-v2-controls");
        const mode = el("select");
        [["audit", "Текущий аудит"], ["global", "Общая карта сохранённых сетей"]].forEach(([value, title]) => { const option = el("option", title); option.value = value; mode.append(option); });
        const segment = el("select");
        const all = el("option", "Все подсети"); all.value = ""; segment.append(all);
        (base.segments || []).forEach((item) => { const option = el("option", item.network || item.label || item.id); option.value = item.id; segment.append(option); });
        const level = el("select");
        [["structural", "Схема сети"], ["l2", "L2 — физика"], ["l3", "L3 — маршрутизация"], ["traffic", "Traffic — PCAP"], ["evidence", "Все evidence (диагностика)"]].forEach(([value, title]) => { const option = el("option", title); option.value = value; level.append(option); });
        const confidence = el("select");
        [["all", "Все связи"], ["confirmed", "Только подтверждённые"], ["observed", "Только наблюдавшиеся"], ["inferred", "Только предположительные"]].forEach(([value, title]) => { const option = el("option", title); option.value = value; confidence.append(option); });
        const pcap = el("select");
        const none = el("option", "Без PCAP overlay"); none.value = ""; pcap.append(none);
        (analyses.items || []).slice().sort((a, b) => Number(b.interface === base.audit.interface) - Number(a.interface === base.audit.interface)).forEach((item) => {
            const option = el("option", `${item.interface === base.audit.interface ? "✓" : "⚠"} ${item.interface || "—"} · ${String(item.job_id || item.capture_job_id).slice(0, 8)}`);
            option.value = item.job_id;
            pcap.append(option);
        });
        const applyPcap = el("button", "Применить PCAP", "secondary");
        controls.append(el("span", "Вид:"), mode, el("span", "Подсеть:"), segment, el("span", "Карта:"), level, el("span", "Достоверность:"), confidence, el("span", "PCAP:"), pcap, applyPcap);

        const coverageHost = el("div");
        const meta = el("div", null, "ws-topology-meta");
        const graphHost = el("div");
        const actions = el("div", null, "actions ws-topology-export-actions");
        let currentAudit = base;
        let currentCanvas = null;

        const raw = () => mode.value === "global" ? global : currentAudit;
        const focusSegment = (id) => {
            if (mode.value !== "audit") return;
            if (Array.from(segment.options).some((option) => option.value === id)) {
                segment.value = id;
                renderCurrent();
            }
        };

        function renderCurrent() {
            const topology = raw();
            if (mode.value === "global" && !["structural", "l3", "evidence"].includes(level.value)) level.value = "structural";
            segment.disabled = mode.value === "global";
            pcap.disabled = mode.value === "global";
            applyPcap.disabled = mode.value === "global";
            coverageHost.replaceChildren();
            if (mode.value === "audit") {
                const panel = coveragePanel(topology);
                if (panel) coverageHost.append(panel);
            }
            const view = projection(topology, level.value, mode.value === "audit" ? segment.value : "", confidence.value);
            meta.replaceChildren(metricSummary(view));
            if (mode.value === "audit" && topology.overlay) meta.append(el("p", `PCAP подключён: ${String(topology.overlay.traffic_analysis_job_id || "").slice(0, 8)} · ${topology.overlay.interface || "—"}. Он показан отдельно в Traffic и не засоряет структурную схему.`, "ws-topology-overlay-note"));
            if (mode.value === "audit" && level.value === "structural") {
                const hidden = ((topology.presentation || {}).suppressed || {});
                const notes = [];
                if (hidden.unidentified_link_local_count) notes.push(`свёрнуто IPv6 link-local: ${hidden.unidentified_link_local_count}`);
                if ((hidden.broadcast_multicast_node_ids || []).length) notes.push(`скрыто broadcast/multicast: ${hidden.broadcast_multicast_node_ids.length}`);
                if ((hidden.traffic_only_node_ids || []).length) notes.push(`traffic-only endpoints вне схемы: ${hidden.traffic_only_node_ids.length}`);
                if (notes.length) meta.append(el("p", notes.join(" · "), "muted"));
            }
            graphHost.replaceChildren();
            currentCanvas = graph(topology, view, focusSegment);
            graphHost.append(currentCanvas);
        }

        mode.addEventListener("change", () => { segment.value = ""; level.value = "structural"; renderCurrent(); });
        segment.addEventListener("change", renderCurrent);
        level.addEventListener("change", renderCurrent);
        confidence.addEventListener("change", renderCurrent);
        applyPcap.addEventListener("click", async () => {
            applyPcap.disabled = true;
            try {
                const query = pcap.value ? `?traffic_analysis_job_id=${encodeURIComponent(pcap.value)}` : "";
                currentAudit = await request(`/audits/${encodeURIComponent(auditId)}/topology${query}`);
                if (pcap.value) level.value = "traffic";
                renderCurrent();
            } catch (error) {
                meta.append(el("p", error.message, "error"));
            } finally {
                applyPcap.disabled = mode.value === "global";
            }
        });

        const jsonButton = el("button", "Скачать topology JSON", "secondary");
        jsonButton.addEventListener("click", () => downloadBlob(new Blob([JSON.stringify(raw(), null, 2)], {type: "application/json"}), `wirescope-topology-${mode.value}.json`));
        const diagramSvg = el("button", "Скачать схему SVG", "secondary");
        diagramSvg.addEventListener("click", () => {
            try { downloadBlob(new Blob([serializeDiagram(currentCanvas)], {type: "image/svg+xml;charset=utf-8"}), `wirescope-topology-${level.value}.svg`); }
            catch (error) { meta.append(el("p", error.message, "error")); }
        });
        const diagramPng = el("button", "Скачать схему PNG", "secondary");
        diagramPng.addEventListener("click", async () => {
            diagramPng.disabled = true;
            try { downloadBlob(await pngFromSvg(serializeDiagram(currentCanvas)), `wirescope-topology-${level.value}.png`); }
            catch (error) { meta.append(el("p", error.message, "error")); }
            finally { diagramPng.disabled = false; }
        });
        const currentSvg = el("button", "SVG текущего вида", "secondary");
        currentSvg.addEventListener("click", () => downloadBlob(new Blob([serializeDiagram(currentCanvas, {currentView: true})], {type: "image/svg+xml;charset=utf-8"}), `wirescope-topology-current-${level.value}.svg`));
        actions.append(jsonButton, diagramSvg, diagramPng, currentSvg);

        body.append(controls, coverageHost, meta, graphHost, actions);
        renderCurrent();
    }

    window.WireScopeTopologyLegacy = legacyRenderer;
    window.WireScopeTopology = { render, version: "m11.4" };
})();
