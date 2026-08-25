(() => {
    "use strict";

    const API = "/api/v1";
    const SVG_NS = "http://www.w3.org/2000/svg";
    const MAX_VISIBLE_NODES = 120;
    const VIEWBOX = { width: 1200, height: 760 };

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

    function bareAddress(value) {
        return String(value || "").split("/", 1)[0].toLowerCase();
    }

    function isLikelyGlobalAddress(value) {
        const address = bareAddress(value);
        if (!address) return false;
        if (address.includes(".")) {
            const parts = address.split(".").map(Number);
            if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return false;
            if (parts[0] === 10 || parts[0] === 127 || parts[0] === 0) return false;
            if (parts[0] === 169 && parts[1] === 254) return false;
            if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return false;
            if (parts[0] === 192 && parts[1] === 168) return false;
            if (parts[0] >= 224) return false;
            return true;
        }
        if (!address.includes(":")) return false;
        if (address === "::1" || address.startsWith("fe80:") || address.startsWith("fc") || address.startsWith("fd") || address.startsWith("ff")) return false;
        return true;
    }

    function isExternalNode(node) {
        if ((node.segment_ids || []).length) return false;
        if (node.kind === "wirescope" || node.kind === "segment" || node.kind === "multicast-group") return false;
        return (node.addresses || []).some((address) => isLikelyGlobalAddress(address));
    }

    function roleScore(node) {
        const roles = new Set(node.roles || []);
        if (node.kind === "wirescope") return 1000;
        if (roles.has("gateway")) return 950;
        if (node.kind === "segment" || roles.has("subnet")) return 900;
        if (roles.has("network-neighbor") || roles.has("stp-root")) return 850;
        if (node.kind === "network-device" || roles.has("network-device")) return 800;
        if (roles.has("dhcp-server")) return 700;
        if (isExternalNode(node)) return 650;
        if (node.kind === "asset") return 500;
        if (node.kind === "multicast-group") return 50;
        return 300;
    }

    function nodeKindLabel(node) {
        const roles = new Set(node.roles || []);
        if (node.kind === "wirescope") return "WireScope";
        if (node.kind === "segment" || roles.has("subnet")) return "Подсеть";
        if (roles.has("gateway")) return "Шлюз";
        if (roles.has("dhcp-server")) return "DHCP";
        if (node.kind === "network-device" || roles.has("network-device") || roles.has("network-neighbor")) return "Сетевое устройство";
        if (node.kind === "multicast-group") return "Multicast/Broadcast";
        if (isExternalNode(node)) return "Внешний адрес";
        if (node.device_class) return node.device_class;
        return "Узел";
    }

    function confidenceLabel(value) {
        return ({ confirmed: "подтверждено", observed: "наблюдалось", inferred: "предположительно" })[value] || value || "—";
    }

    function relationLabel(value) {
        return ({
            default_gateway: "шлюз по умолчанию",
            segment_gateway: "шлюз сегмента",
            layer2_neighbor: "L2-сосед",
            stp_observed: "STP-наблюдение",
            dhcp_observed: "DHCP-наблюдение",
            communication: "реальный обмен",
        })[value] || value;
    }

    function downloadBlob(blob, filename) {
        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = url;
        link.download = filename;
        document.body.append(link);
        link.click();
        link.remove();
        window.setTimeout(() => URL.revokeObjectURL(url), 0);
    }

    function collectSvgStyles() {
        const rules = [];
        Array.from(document.styleSheets || []).forEach((sheet) => {
            let cssRules;
            try { cssRules = sheet.cssRules; } catch { return; }
            Array.from(cssRules || []).forEach((rule) => {
                const text = String(rule.cssText || "");
                if (text && !text.includes("url(")) rules.push(text);
            });
        });
        return rules.join("\n");
    }

    function serializeCurrentSvg(graph) {
        const source = graph.querySelector(".ws-topology-svg");
        if (!source) throw new Error("Topology SVG is not rendered yet");
        const clone = source.cloneNode(true);
        clone.setAttribute("xmlns", SVG_NS);
        clone.setAttribute("width", String(VIEWBOX.width));
        clone.setAttribute("height", String(VIEWBOX.height));

        const styleText = collectSvgStyles();
        if (styleText) {
            const styleNode = svg("style");
            styleNode.textContent = styleText;
            const defs = clone.querySelector("defs");
            if (defs) defs.prepend(styleNode);
            else clone.prepend(styleNode);
        }

        const computed = window.getComputedStyle(source);
        const background = computed.backgroundColor && computed.backgroundColor !== "rgba(0, 0, 0, 0)" && computed.backgroundColor !== "transparent"
            ? computed.backgroundColor
            : "#ffffff";
        const backgroundNode = svg("rect", {
            x: 0,
            y: 0,
            width: VIEWBOX.width,
            height: VIEWBOX.height,
            fill: background,
        });
        const defs = clone.querySelector("defs");
        clone.insertBefore(backgroundNode, defs ? defs.nextSibling : clone.firstChild);
        const documentText = new XMLSerializer().serializeToString(clone);
        return `<?xml version="1.0" encoding="UTF-8"?>\n${documentText}`;
    }

    async function pngFromSvg(svgText) {
        const svgBlob = new Blob([svgText], { type: "image/svg+xml;charset=utf-8" });
        const url = URL.createObjectURL(svgBlob);
        try {
            const image = new Image();
            const loaded = new Promise((resolve, reject) => {
                image.onload = resolve;
                image.onerror = () => reject(new Error("Could not render topology SVG for PNG export"));
            });
            image.src = url;
            await loaded;
            const canvas = document.createElement("canvas");
            canvas.width = VIEWBOX.width;
            canvas.height = VIEWBOX.height;
            const context = canvas.getContext("2d");
            if (!context) throw new Error("Canvas is unavailable for PNG export");
            context.drawImage(image, 0, 0, VIEWBOX.width, VIEWBOX.height);
            const blob = await new Promise((resolve) => canvas.toBlob(resolve, "image/png"));
            if (!blob) throw new Error("Could not encode topology PNG");
            return blob;
        } finally {
            URL.revokeObjectURL(url);
        }
    }

    function exportBaseName(mode, auditId) {
        return mode === "global"
            ? "wirescope-topology-global"
            : `wirescope-topology-${String(auditId).slice(0, 8)}`;
    }

    function degrees(topology) {
        const result = new Map();
        (topology.edges || []).forEach((edge) => {
            result.set(edge.source, (result.get(edge.source) || 0) + 1);
            result.set(edge.target, (result.get(edge.target) || 0) + 1);
        });
        return result;
    }

    function isLowSignificance(node, degree) {
        if (roleScore(node) >= 650) return false;
        if ((node.services || []).length) return false;
        if ((degree.get(node.id) || 0) > 0) return false;
        return true;
    }

    function selectVisible(topology, { showGroups = false, showMinor = true } = {}) {
        const degree = degrees(topology);
        let nodes = (topology.nodes || []).filter((node) => showGroups || node.kind !== "multicast-group");
        if (!showMinor && nodes.length > 24) nodes = nodes.filter((node) => !isLowSignificance(node, degree));
        nodes.sort((a, b) => {
            const score = roleScore(b) - roleScore(a);
            if (score) return score;
            return (degree.get(b.id) || 0) - (degree.get(a.id) || 0);
        });
        return nodes.slice(0, MAX_VISIBLE_NODES);
    }

    function gridPositions(nodes, bounds, positions) {
        if (!nodes.length) return;
        const cols = Math.max(1, Math.ceil(Math.sqrt(nodes.length * Math.max(1, bounds.width / Math.max(1, bounds.height)))));
        const rows = Math.ceil(nodes.length / cols);
        const xStep = bounds.width / Math.max(1, cols);
        const yStep = bounds.height / Math.max(1, rows);
        nodes.forEach((node, index) => {
            const col = index % cols;
            const row = Math.floor(index / cols);
            positions.set(node.id, {
                x: bounds.x + xStep * (col + 0.5),
                y: bounds.y + yStep * (row + 0.5),
            });
        });
    }

    function segmentLayout(topology, nodes) {
        const positions = new Map();
        const boxes = [];
        const segments = (topology.segments || []).filter((segment) => segment.kind !== "host-scope" || (segment.members || []).length);
        const nodeMap = new Map(nodes.map((node) => [node.id, node]));
        const sensor = nodes.find((node) => node.kind === "wirescope");
        if (sensor) positions.set(sensor.id, { x: 92, y: 70 });

        if (!segments.length) {
            const rest = nodes.filter((node) => node !== sensor);
            gridPositions(rest, { x: 120, y: 90, width: 960, height: 590 }, positions);
            return { positions, boxes };
        }

        const cols = Math.min(3, Math.max(1, Math.ceil(Math.sqrt(segments.length))));
        const rows = Math.ceil(segments.length / cols);
        const marginX = 42;
        const top = 118;
        const gap = 24;
        const usableWidth = VIEWBOX.width - marginX * 2;
        const usableHeight = VIEWBOX.height - top - 45;
        const boxWidth = (usableWidth - gap * (cols - 1)) / cols;
        const boxHeight = (usableHeight - gap * (rows - 1)) / rows;
        const assigned = new Set(sensor ? [sensor.id] : []);

        segments.forEach((segment, index) => {
            const col = index % cols;
            const row = Math.floor(index / cols);
            const box = {
                id: segment.id,
                label: segment.network || segment.label || segment.id,
                x: marginX + col * (boxWidth + gap),
                y: top + row * (boxHeight + gap),
                width: boxWidth,
                height: boxHeight,
                gateways: segment.gateways || [],
                memberCount: (segment.members || []).length,
            };
            boxes.push(box);
            const members = nodes.filter((node) => (node.segment_ids || []).includes(segment.id));
            members.forEach((node) => assigned.add(node.id));
            const gateways = members.filter((node) => (node.roles || []).includes("gateway"));
            const regular = members.filter((node) => !gateways.includes(node) && node.kind !== "wirescope");
            gateways.forEach((node, gatewayIndex) => {
                positions.set(node.id, {
                    x: box.x + box.width * (0.5 + (gatewayIndex - (gateways.length - 1) / 2) * 0.18),
                    y: box.y + 54,
                });
            });
            gridPositions(
                regular,
                { x: box.x + 28, y: box.y + 82, width: box.width - 56, height: box.height - 108 },
                positions
            );
        });

        const external = nodes.filter((node) => !assigned.has(node.id) && isExternalNode(node));
        const other = nodes.filter((node) => !assigned.has(node.id) && node !== sensor && !external.includes(node));
        if (external.length) {
            const width = Math.min(300, Math.max(200, external.length * 70));
            gridPositions(external, { x: VIEWBOX.width - width - 28, y: 22, width, height: 82 }, positions);
        }
        if (other.length) {
            gridPositions(other, { x: 210, y: 20, width: Math.max(260, VIEWBOX.width - 560), height: 82 }, positions);
        }
        return { positions, boxes };
    }

    function globalLayout(topology, nodes) {
        const positions = new Map();
        const segments = nodes.filter((node) => node.kind === "segment" || (node.roles || []).includes("subnet"));
        const gateways = nodes.filter((node) => (node.roles || []).includes("gateway"));
        const rest = nodes.filter((node) => !segments.includes(node) && !gateways.includes(node));
        gridPositions(segments, { x: 80, y: 115, width: 1040, height: 500 }, positions);

        const edgeMap = new Map();
        (topology.edges || []).forEach((edge) => {
            edgeMap.set(`${edge.source}|${edge.target}`, edge);
            edgeMap.set(`${edge.target}|${edge.source}`, edge);
        });
        gateways.forEach((gateway, index) => {
            const linked = segments.filter((segment) => edgeMap.has(`${segment.id}|${gateway.id}`));
            if (linked.length) {
                const points = linked.map((segment) => positions.get(segment.id)).filter(Boolean);
                positions.set(gateway.id, {
                    x: points.reduce((sum, point) => sum + point.x, 0) / points.length,
                    y: Math.max(60, points.reduce((sum, point) => sum + point.y, 0) / points.length - 105),
                });
            } else {
                positions.set(gateway.id, { x: 170 + index * 110, y: 65 });
            }
        });
        gridPositions(rest, { x: 120, y: 640, width: 960, height: 80 }, positions);
        return { positions, boxes: [] };
    }

    function computeLayout(topology, nodes) {
        return topology.schema === "network-topology-global"
            ? globalLayout(topology, nodes)
            : segmentLayout(topology, nodes);
    }

    function detailNode(target, node) {
        target.replaceChildren();
        target.append(el("h4", node.label || node.id));
        const grid = el("div", null, "ws-topology-detail-grid");
        const findingCount = node.finding_count ?? (node.findings || []).length;
        const rows = [
            ["Тип", nodeKindLabel(node)],
            ["Достоверность", confidenceLabel(node.confidence)],
            ["Источник", (node.provenance || []).join(", ") || "—"],
            ["Роли", (node.roles || []).join(", ") || "—"],
            ["Подсети", (node.segment_ids || []).map((id) => String(id).replace(/^segment:/, "")).join(", ") || "—"],
            ["Адреса", (node.addresses || []).join(", ") || node.network || "—"],
            ["Имена", (node.names || []).join(", ") || "—"],
            ["MAC", node.mac || "—"],
            ["Vendor", node.vendor || "—"],
            ["OS", node.os_name || "—"],
            ["Находки", findingCount],
            ["Аудиты", (node.audit_ids || []).map((id) => String(id).slice(0, 8)).join(", ") || "—"],
        ];
        rows.forEach(([key, value]) => grid.append(el("strong", key), el("span", value)));
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
        const findings = node.findings || [];
        if (findingCount || findings.length) {
            target.append(el("h4", "Находки"));
            const list = el("div", null, "ws-topology-service-list");
            findings.forEach((finding) => {
                const severity = String(finding.severity || "unknown").toUpperCase();
                const status = String(finding.status || "unknown");
                const item = el("span", `${severity} · ${finding.title || finding.rule_id || finding.id || "finding"} · ${status}`);
                const context = [finding.description, finding.recommendation].filter(Boolean).join("\n");
                if (context) item.title = context;
                list.append(item);
            });
            if (node.findings_truncated) {
                list.append(el("span", `Показано ${findings.length} из ${findingCount}. Полный список доступен в разделе находок.`, "muted"));
            }
            target.append(list);
        }
    }

    function detailEdge(target, edge) {
        target.replaceChildren();
        target.append(el("h4", relationLabel(edge.relation)));
        const grid = el("div", null, "ws-topology-detail-grid");
        const direction = edge.relation === "communication"
            ? `${edge.packets_a_to_b || 0} → / ${edge.packets_b_to_a || 0} ←`
            : "—";
        const rows = [
            ["Уровень", String(edge.layer || "general").toUpperCase()],
            ["Достоверность", confidenceLabel(edge.confidence)],
            ["Источник доказательства", (edge.provenance || []).join(", ") || "—"],
            ["Сегменты", (edge.segment_ids || []).map((id) => String(id).replace(/^segment:/, "")).join(", ") || "—"],
            ["Пакеты", edge.packets ?? "—"],
            ["Направление", direction],
            ["Объём", edge.bytes === undefined ? "—" : bytes(edge.bytes)],
            ["Протоколы", (edge.protocols || []).join(", ") || "—"],
            ["Порты", (edge.ports || []).join(", ") || "—"],
            ["Порт соседа", edge.port_id || "—"],
        ];
        rows.forEach(([key, value]) => grid.append(el("strong", key), el("span", value)));
        target.append(grid);
    }

    function filterTopology(topology, { segmentId = "", layer = "general", showGroups = false, confidence = "all" } = {}) {
        let nodes = (topology.nodes || []).slice();
        let edges = (topology.edges || []).slice();

        if (segmentId) {
            edges = edges.filter((edge) => (edge.segment_ids || []).includes(segmentId) || edge.segment_id === segmentId);
            const referenced = new Set(edges.flatMap((edge) => [edge.source, edge.target]));
            nodes = nodes.filter((node) => {
                if ((node.segment_ids || []).includes(segmentId)) return true;
                if (node.kind === "wirescope") return true;
                return referenced.has(node.id);
            });
        }

        if (layer !== "general") {
            edges = edges.filter((edge) => (edge.layer || "general") === layer);
            const referenced = new Set(edges.flatMap((edge) => [edge.source, edge.target]));
            nodes = nodes.filter((node) => referenced.has(node.id) || (layer === "l3" && node.kind === "wirescope"));
        }

        if (confidence !== "all") {
            edges = edges.filter((edge) => edge.confidence === confidence);
            const referenced = new Set(edges.flatMap((edge) => [edge.source, edge.target]));
            nodes = nodes.filter((node) => referenced.has(node.id) || node.kind === "wirescope");
        }

        if (!showGroups) {
            const hidden = new Set(nodes.filter((node) => node.kind === "multicast-group").map((node) => node.id));
            nodes = nodes.filter((node) => !hidden.has(node.id));
            edges = edges.filter((edge) => !hidden.has(edge.source) && !hidden.has(edge.target));
        }

        const confidenceCounts = {};
        const layers = {};
        edges.forEach((edge) => {
            confidenceCounts[edge.confidence || "unknown"] = (confidenceCounts[edge.confidence || "unknown"] || 0) + 1;
            layers[edge.layer || "general"] = (layers[edge.layer || "general"] || 0) + 1;
        });
        return {
            ...topology,
            nodes,
            edges,
            summary: {
                ...(topology.summary || {}),
                nodes: nodes.length,
                edges: edges.length,
                confidence: confidenceCounts,
                layers,
            },
        };
    }

    function installViewport(svgNode, viewport, toolbar) {
        const state = { scale: 1, x: 0, y: 0, dragging: false, px: 0, py: 0 };
        const zoomLabel = toolbar.querySelector(".ws-topology-zoom-value");
        const apply = () => {
            viewport.setAttribute("transform", `translate(${state.x} ${state.y}) scale(${state.scale})`);
            if (zoomLabel) zoomLabel.textContent = `${Math.round(state.scale * 100)}%`;
        };
        const fit = () => {
            state.scale = 1;
            state.x = 0;
            state.y = 0;
            apply();
        };
        const zoom = (factor, anchorX = VIEWBOX.width / 2, anchorY = VIEWBOX.height / 2) => {
            const next = Math.max(0.45, Math.min(3.5, state.scale * factor));
            const ratio = next / state.scale;
            state.x = anchorX - (anchorX - state.x) * ratio;
            state.y = anchorY - (anchorY - state.y) * ratio;
            state.scale = next;
            apply();
        };
        toolbar.querySelector("[data-zoom='in']").addEventListener("click", () => zoom(1.2));
        toolbar.querySelector("[data-zoom='out']").addEventListener("click", () => zoom(1 / 1.2));
        toolbar.querySelector("[data-zoom='fit']").addEventListener("click", fit);
        svgNode.addEventListener("wheel", (event) => {
            event.preventDefault();
            const rect = svgNode.getBoundingClientRect();
            const x = ((event.clientX - rect.left) / rect.width) * VIEWBOX.width;
            const y = ((event.clientY - rect.top) / rect.height) * VIEWBOX.height;
            zoom(event.deltaY < 0 ? 1.12 : 1 / 1.12, x, y);
        }, { passive: false });
        svgNode.addEventListener("pointerdown", (event) => {
            if (event.button !== 0 || event.target.closest(".ws-topology-node")) return;
            state.dragging = true;
            state.px = event.clientX;
            state.py = event.clientY;
            svgNode.setPointerCapture(event.pointerId);
            svgNode.classList.add("is-panning");
        });
        svgNode.addEventListener("pointermove", (event) => {
            if (!state.dragging) return;
            const rect = svgNode.getBoundingClientRect();
            state.x += (event.clientX - state.px) * VIEWBOX.width / rect.width;
            state.y += (event.clientY - state.py) * VIEWBOX.height / rect.height;
            state.px = event.clientX;
            state.py = event.clientY;
            apply();
        });
        const stopPan = (event) => {
            if (!state.dragging) return;
            state.dragging = false;
            svgNode.classList.remove("is-panning");
            try { svgNode.releasePointerCapture(event.pointerId); } catch { /* no-op */ }
        };
        svgNode.addEventListener("pointerup", stopPan);
        svgNode.addEventListener("pointercancel", stopPan);
        apply();
    }

    function renderGraph(host, topology, options = {}) {
        host.replaceChildren();
        const visible = selectVisible(topology, { showGroups: options.showGroups, showMinor: options.showMinor });
        const visibleIds = new Set(visible.map((node) => node.id));
        const { positions, boxes } = computeLayout(topology, visible);
        const toolbar = el("div", null, "ws-topology-viewport-tools");
        const zoomOut = el("button", "−", "secondary"); zoomOut.type = "button"; zoomOut.dataset.zoom = "out"; zoomOut.title = "Уменьшить";
        const zoomValue = el("span", "100%", "ws-topology-zoom-value");
        const zoomIn = el("button", "+", "secondary"); zoomIn.type = "button"; zoomIn.dataset.zoom = "in"; zoomIn.title = "Увеличить";
        const fit = el("button", "Вписать", "secondary"); fit.type = "button"; fit.dataset.zoom = "fit";
        toolbar.append(zoomOut, zoomValue, zoomIn, fit, el("span", "Колесо — масштаб · drag — перемещение", "muted"));

        const canvas = svg("svg", {
            viewBox: `0 0 ${VIEWBOX.width} ${VIEWBOX.height}`,
            role: "img",
            "aria-label": "Логическая карта сети WireScope",
        });
        canvas.classList.add("ws-topology-svg");
        const defs = svg("defs");
        const marker = svg("marker", { id: "ws-topology-arrow", viewBox: "0 0 10 10", refX: "8", refY: "5", markerWidth: "6", markerHeight: "6", orient: "auto-start-reverse" });
        marker.append(svg("path", { d: "M 0 0 L 10 5 L 0 10 z", class: "ws-topology-arrow" }));
        defs.append(marker);
        const viewport = svg("g", { class: "ws-topology-viewport" });
        const regionsLayer = svg("g", { class: "ws-topology-regions" });
        const edgesLayer = svg("g", { class: "ws-topology-edges" });
        const nodesLayer = svg("g", { class: "ws-topology-nodes" });
        const details = el("div", "Нажмите на узел или связь, чтобы увидеть источник и достоверность.", "ws-topology-details");

        boxes.forEach((box) => {
            const region = svg("g", { class: "ws-topology-region", tabindex: "0" });
            const rect = svg("rect", { x: box.x, y: box.y, width: box.width, height: box.height, rx: 22, ry: 22 });
            const label = svg("text", { x: box.x + 18, y: box.y + 28, class: "ws-topology-region-label" });
            label.textContent = `${box.label} · ${box.memberCount} узлов${box.gateways.length ? ` · GW ${box.gateways.join(", ")}` : ""}`;
            const title = svg("title"); title.textContent = `Подсеть ${box.label}. Двойной клик — открыть только этот сегмент.`;
            region.append(rect, label, title);
            if (options.onSegmentFocus) {
                region.addEventListener("dblclick", () => options.onSegmentFocus(box.id));
                region.addEventListener("keydown", (event) => { if (event.key === "Enter") options.onSegmentFocus(box.id); });
            }
            regionsLayer.append(region);
        });

        const externalNodes = visible.filter((node) => isExternalNode(node));
        if (externalNodes.length) {
            const externalLabel = svg("text", { x: VIEWBOX.width - 300, y: 22, class: "ws-topology-external-label" });
            externalLabel.textContent = `Internet / внешние адреса · ${externalNodes.length}`;
            regionsLayer.append(externalLabel);
        }

        (topology.edges || []).forEach((edge) => {
            if (!visibleIds.has(edge.source) || !visibleIds.has(edge.target)) return;
            const a = positions.get(edge.source);
            const b = positions.get(edge.target);
            if (!a || !b) return;
            const width = edge.relation === "communication"
                ? Math.min(8, 1.1 + Math.log10(Math.max(1, Number(edge.bytes) || 1)))
                : 2.1;
            const attrs = {
                x1: a.x, y1: a.y, x2: b.x, y2: b.y,
                class: `ws-topology-edge ws-topology-${edge.confidence || "inferred"} ws-topology-rel-${edge.relation}`,
                "stroke-width": width,
                tabindex: "0",
            };
            if (edge.relation === "communication") {
                if (Number(edge.packets_a_to_b || 0) > 0) attrs["marker-end"] = "url(#ws-topology-arrow)";
                if (Number(edge.packets_b_to_a || 0) > 0) attrs["marker-start"] = "url(#ws-topology-arrow)";
            }
            const line = svg("line", attrs);
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
            const external = isExternalNode(node);
            const group = svg("g", {
                class: `ws-topology-node ws-topology-node-${node.kind}${external ? " ws-topology-node-external" : ""}`,
                transform: `translate(${point.x} ${point.y})`,
                tabindex: "0",
            });
            const radius = roleScore(node) >= 700 ? 29 : 22;
            const circle = svg("circle", { r: radius });
            const label = svg("text", { y: radius + 18, "text-anchor": "middle" });
            label.textContent = short(node.label, 23);
            const badge = svg("text", { y: 4, "text-anchor": "middle", class: "ws-topology-node-badge" });
            badge.textContent = node.kind === "wirescope" ? "W"
                : (node.kind === "segment" || (node.roles || []).includes("subnet")) ? "NET"
                : (node.roles || []).includes("gateway") ? "GW"
                : external ? "EXT"
                : (node.kind === "network-device" || (node.roles || []).includes("network-device")) ? "SW" : "●";
            const title = svg("title");
            title.textContent = `${node.label} · ${nodeKindLabel(node)} · ${confidenceLabel(node.confidence)}`;
            group.append(circle, badge, label, title);
            group.addEventListener("click", () => detailNode(details, node));
            group.addEventListener("keydown", (event) => { if (event.key === "Enter") detailNode(details, node); });
            nodesLayer.append(group);
        });

        viewport.append(regionsLayer, edgesLayer, nodesLayer);
        canvas.append(defs, viewport);
        host.append(toolbar, canvas, details);
        installViewport(canvas, viewport, toolbar);
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
            metric("Подсети", data.segments ?? (topology.segments || []).length),
            metric("Узлы", data.nodes ?? (topology.nodes || []).length),
            metric("Связи", data.edges ?? (topology.edges || []).length),
            metric("Подтверждено", confidence.confirmed || 0),
            metric("Наблюдалось", confidence.observed || 0)
        );
        return block;
    }

    function segmentCards(topology) {
        const segments = topology.segments || [];
        if (!segments.length) return null;
        const block = el("div", null, "ws-topology-segments");
        segments.forEach((segment) => {
            const card = el("button", null, "ws-topology-segment-card");
            card.type = "button";
            card.dataset.segmentId = segment.id || "";
            card.append(el("strong", segment.network || segment.label));
            const parts = [];
            if (segment.members) parts.push(`${segment.members.length} узлов`);
            if (segment.member_count !== undefined) parts.push(`${segment.member_count} узлов`);
            if (segment.gateways && segment.gateways.length) parts.push(`GW ${segment.gateways.join(", ")}`);
            if (segment.interfaces && segment.interfaces.length) parts.push(segment.interfaces.join(", "));
            else if (segment.interface) parts.push(segment.interface);
            if (segment.scan_count) parts.push(`сканов ${segment.scan_count}`);
            card.append(el("span", parts.join(" · ") || "сохранённый сегмент", "muted"));
            block.append(card);
        });
        return block;
    }

    async function render(body, auditId) {
        body.replaceChildren(el("p", "Строим интерактивную карту из сохранённых данных…"));
        const [base, global, analyses] = await Promise.all([
            request(`/audits/${encodeURIComponent(auditId)}/topology`),
            request("/topology/global?limit=100"),
            request("/traffic-analysis?limit=100"),
        ]);
        body.replaceChildren();

        const controls = el("div", null, "ws-topology-controls");
        const mode = el("select");
        [["global", "Общая карта всех сохранённых сетей"], ["audit", "Текущий аудит"]].forEach(([value, label]) => {
            const option = el("option", label); option.value = value; mode.append(option);
        });

        const segment = el("select");
        const allSegments = el("option", "Все подсети текущего аудита");
        allSegments.value = "";
        segment.append(allSegments);
        (base.segments || []).forEach((item) => {
            const option = el("option", item.network || item.label || item.id);
            option.value = item.id;
            segment.append(option);
        });

        const layer = el("select");
        [["general", "Общая"], ["l2", "L2 — канальный"], ["l3", "L3 — маршрутизация"], ["traffic", "Traffic — PCAP"]].forEach(([value, label]) => {
            const option = el("option", label); option.value = value; layer.append(option);
        });

        const confidence = el("select");
        [["all", "Все связи"], ["confirmed", "Только подтверждённые"], ["observed", "Только наблюдавшиеся"], ["inferred", "Только предположительные"]].forEach(([value, label]) => {
            const option = el("option", label); option.value = value; confidence.append(option);
        });

        const pcap = el("select");
        const none = el("option", "Без PCAP overlay");
        none.value = "";
        pcap.append(none);
        const candidates = (analyses.items || []).slice().sort((a, b) => {
            const am = a.interface === base.audit.interface ? 1 : 0;
            const bm = b.interface === base.audit.interface ? 1 : 0;
            return bm - am;
        });
        candidates.forEach((item) => {
            const same = item.interface === base.audit.interface;
            const option = el("option", `${same ? "✓ " : "⚠ "}${item.interface || "—"} · ${String(item.capture_job_id || item.job_id).slice(0, 8)} · analyzer v${item.analyzer_version || "?"}`);
            option.value = item.job_id;
            pcap.append(option);
        });

        const apply = el("button", "Применить PCAP", "secondary");
        const multicastLabel = el("label", null, "ws-topology-check");
        const multicast = document.createElement("input");
        multicast.type = "checkbox";
        multicastLabel.append(multicast, document.createTextNode(" multicast/broadcast"));
        const minorLabel = el("label", null, "ws-topology-check");
        const minor = document.createElement("input");
        minor.type = "checkbox";
        minor.checked = true;
        minorLabel.append(minor, document.createTextNode(" малозначимые узлы"));

        controls.append(
            el("span", "Вид:"), mode,
            el("span", "Подсеть:"), segment,
            el("span", "Уровень:"), layer,
            el("span", "Достоверность:"), confidence,
            el("span", "PCAP:"), pcap, apply, multicastLabel, minorLabel
        );

        const legend = el("div", null, "ws-topology-legend");
        [["confirmed", "Подтверждено"], ["observed", "Наблюдалось"], ["inferred", "Предположительно"]].forEach(([key, label]) => {
            const item = el("span");
            item.append(el("i", null, `ws-topology-legend-${key}`), document.createTextNode(label));
            legend.append(item);
        });
        const trafficLegend = el("span");
        trafficLegend.append(el("i", null, "ws-topology-legend-traffic"), document.createTextNode("Traffic: стрелка = направление, толщина = объём"));
        legend.append(trafficLegend);

        const meta = el("div", null, "ws-topology-meta");
        const graph = el("div", null, "ws-topology-canvas");
        let currentAudit = base;

        function selectedRaw() {
            return mode.value === "global" ? global : currentAudit;
        }

        function focusSegment(segmentId) {
            if (mode.value === "global") return;
            const exists = Array.from(segment.options).some((option) => option.value === segmentId);
            if (!exists) return;
            segment.value = segmentId;
            renderCurrent();
        }

        function renderCurrent() {
            const raw = selectedRaw();
            const view = mode.value === "global"
                ? filterTopology(raw, { layer: layer.value, showGroups: multicast.checked, confidence: confidence.value })
                : filterTopology(raw, { segmentId: segment.value, layer: layer.value, showGroups: multicast.checked, confidence: confidence.value });

            segment.disabled = mode.value === "global";
            pcap.disabled = mode.value === "global";
            apply.disabled = mode.value === "global";
            if (mode.value === "global" && !["general", "l3"].includes(layer.value)) {
                layer.value = "general";
                return renderCurrent();
            }

            meta.replaceChildren(summary(view));
            const cards = segmentCards(raw);
            if (cards) {
                cards.querySelectorAll("[data-segment-id]").forEach((card) => {
                    card.addEventListener("click", () => {
                        if (mode.value === "global") return;
                        focusSegment(card.dataset.segmentId);
                    });
                });
                meta.append(cards);
            }

            if (mode.value === "global") {
                meta.append(el("p", "Общая карта объединяет сохранённые подсети разных аудитов и их подтверждённые шлюзы. Один gateway, подтверждённый для нескольких сегментов, визуально связывает эти сети.", "muted"));
            } else if (currentAudit.overlay) {
                meta.append(el("p", `PCAP overlay: ${currentAudit.overlay.traffic_analysis_job_id.slice(0, 8)} · ${currentAudit.overlay.interface || "—"} · ${currentAudit.overlay.frame_count ?? "—"} кадров.`, "ws-topology-overlay-note"));
            } else {
                meta.append(el("p", "Показаны сохранённые данные выбранного аудита. PCAP не подмешивается автоматически.", "muted"));
            }
            (raw.warnings || []).forEach((warning) => meta.append(el("p", warning, "warning")));
            renderGraph(graph, view, {
                showGroups: multicast.checked,
                showMinor: minor.checked,
                onSegmentFocus: focusSegment,
            });
        }

        apply.addEventListener("click", async () => {
            apply.disabled = true;
            apply.textContent = "Строим…";
            try {
                const query = pcap.value ? `?traffic_analysis_job_id=${encodeURIComponent(pcap.value)}` : "";
                currentAudit = await request(`/audits/${encodeURIComponent(auditId)}/topology${query}`);
                if (pcap.value) layer.value = "traffic";
                renderCurrent();
            } catch (error) {
                meta.append(el("p", error.message, "error"));
            } finally {
                apply.disabled = mode.value === "global";
                apply.textContent = "Применить PCAP";
            }
        });

        mode.addEventListener("change", () => {
            layer.value = "general";
            segment.value = "";
            renderCurrent();
        });
        segment.addEventListener("change", renderCurrent);
        layer.addEventListener("change", renderCurrent);
        confidence.addEventListener("change", renderCurrent);
        multicast.addEventListener("change", renderCurrent);
        minor.addEventListener("change", renderCurrent);

        const exportActions = el("div", null, "actions ws-topology-export-actions");
        const exportJson = el("button", "Скачать topology JSON", "secondary");
        exportJson.type = "button";
        exportJson.addEventListener("click", () => {
            const raw = selectedRaw();
            const blob = new Blob([JSON.stringify(raw, null, 2)], { type: "application/json" });
            downloadBlob(blob, `${exportBaseName(mode.value, auditId)}.json`);
        });

        const exportSvg = el("button", "Скачать SVG", "secondary");
        exportSvg.type = "button";
        exportSvg.addEventListener("click", () => {
            try {
                const documentText = serializeCurrentSvg(graph);
                downloadBlob(
                    new Blob([documentText], { type: "image/svg+xml;charset=utf-8" }),
                    `${exportBaseName(mode.value, auditId)}.svg`
                );
            } catch (error) {
                meta.append(el("p", error.message, "error"));
            }
        });

        const exportPng = el("button", "Скачать PNG", "secondary");
        exportPng.type = "button";
        exportPng.addEventListener("click", async () => {
            exportPng.disabled = true;
            const original = exportPng.textContent;
            exportPng.textContent = "Готовим PNG…";
            try {
                const documentText = serializeCurrentSvg(graph);
                const blob = await pngFromSvg(documentText);
                downloadBlob(blob, `${exportBaseName(mode.value, auditId)}.png`);
            } catch (error) {
                meta.append(el("p", error.message, "error"));
            } finally {
                exportPng.disabled = false;
                exportPng.textContent = original;
            }
        });
        exportActions.append(exportJson, exportSvg, exportPng);

        body.append(controls, legend, meta, graph, exportActions);
        renderCurrent();
    }

    window.WireScopeTopology = { render };
})();
