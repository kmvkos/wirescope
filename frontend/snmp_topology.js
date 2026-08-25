(() => {
    "use strict";

    const API = "/api/v1";
    const SVG_NS = "http://www.w3.org/2000/svg";
    const topologyApi = window.WireScopeTopology;
    if (!topologyApi || typeof topologyApi.render !== "function") return;
    const originalRender = topologyApi.render.bind(topologyApi);

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

    async function api(path, options = {}) {
        const response = await fetch(`${API}${path}`, {
            credentials: "same-origin",
            headers: options.body ? { "Content-Type": "application/json" } : undefined,
            ...options,
        });
        const text = await response.text();
        let data = null;
        if (text) {
            try { data = JSON.parse(text); } catch { data = text; }
        }
        if (!response.ok) {
            const detail = data && data.detail;
            const message = detail && (detail.message || detail.code);
            throw new Error(message || response.statusText || `HTTP ${response.status}`);
        }
        return data;
    }

    function candidateAddresses(topology) {
        const result = [];
        const seen = new Set();
        (topology.nodes || []).forEach((node) => {
            const roles = new Set(node.roles || []);
            const relevant = node.kind === "network-device"
                || roles.has("gateway")
                || roles.has("network-device")
                || roles.has("network-neighbor")
                || roles.has("snmp-managed");
            if (!relevant) return;
            (node.addresses || []).forEach((address) => {
                const value = String(address || "").split("/", 1)[0];
                if (!value || seen.has(value)) return;
                seen.add(value);
                result.push({ value, label: node.label || value });
            });
        });
        return result;
    }

    function field(labelText, input) {
        const wrap = el("label", null, "ws-snmp-field");
        wrap.append(el("span", labelText), input);
        return wrap;
    }

    function input(type = "text", placeholder = "") {
        const node = document.createElement("input");
        node.type = type;
        node.placeholder = placeholder;
        node.autocomplete = "off";
        node.spellcheck = false;
        return node;
    }

    function select(options) {
        const node = document.createElement("select");
        options.forEach(([value, label]) => {
            const option = el("option", label);
            option.value = value;
            node.append(option);
        });
        return node;
    }

    function intValues(values) {
        const result = new Set();
        (values || []).forEach((value) => {
            const number = Number(value);
            if (Number.isInteger(number) && number >= 0 && number <= 4095) result.add(number);
        });
        return result;
    }

    function nodeVlans(node) {
        const result = intValues(node.vlan_ids);
        intValues(node.tagged_vlans).forEach((value) => result.add(value));
        intValues(node.untagged_vlans).forEach((value) => result.add(value));
        const pvid = Number(node.pvid);
        if (Number.isInteger(pvid)) result.add(pvid);
        return result;
    }

    function edgeVlans(edge) {
        const result = intValues(edge.vlan_ids);
        intValues(edge.port_vlans).forEach((value) => result.add(value));
        intValues(edge.tagged_vlans).forEach((value) => result.add(value));
        intValues(edge.untagged_vlans).forEach((value) => result.add(value));
        const pvid = Number(edge.port_pvid);
        if (Number.isInteger(pvid)) result.add(pvid);
        return result;
    }

    function availableVlans(topology) {
        const result = new Map();
        (topology.nodes || []).forEach((node) => {
            nodeVlans(node).forEach((value) => {
                if (!result.has(value)) result.set(value, null);
            });
            (node.snmp_vlans || []).forEach((vlan) => {
                const id = Number(vlan && vlan.vlan_id);
                if (!Number.isInteger(id)) return;
                result.set(id, vlan.name || result.get(id) || null);
            });
            (node.snmp_interfaces || []).forEach((iface) => {
                nodeVlans(iface || {}).forEach((value) => {
                    if (!result.has(value)) result.set(value, null);
                });
            });
        });
        (topology.edges || []).forEach((edge) => edgeVlans(edge).forEach((value) => {
            if (!result.has(value)) result.set(value, null);
        }));
        return Array.from(result.entries()).sort((a, b) => a[0] - b[0]);
    }

    function vlanFocus(topology, vlanId) {
        const vlan = Number(vlanId);
        const nodeMap = new Map((topology.nodes || []).map((node) => [node.id, node]));
        const selected = new Set();
        (topology.nodes || []).forEach((node) => {
            if (nodeVlans(node).has(vlan)) selected.add(node.id);
        });
        const edges = (topology.edges || []).filter((edge) => {
            const direct = edgeVlans(edge).has(vlan);
            const endpoint = selected.has(edge.source) || selected.has(edge.target);
            if (direct || endpoint) {
                selected.add(edge.source);
                selected.add(edge.target);
                return true;
            }
            return false;
        });
        // Preserve the parent managed device for an SNMP router-interface node.
        Array.from(selected).forEach((id) => {
            const node = nodeMap.get(id);
            if (node && node.parent_device_id && nodeMap.has(node.parent_device_id)) selected.add(node.parent_device_id);
        });
        const nodes = (topology.nodes || []).filter((node) => selected.has(node.id));
        const ports = [];
        (topology.nodes || []).forEach((device) => {
            (device.snmp_interfaces || []).forEach((iface) => {
                if (!nodeVlans(iface || {}).has(vlan)) return;
                ports.push({
                    device: device.label || device.id,
                    ifindex: iface.ifindex,
                    name: iface.name || iface.description || `ifIndex ${iface.ifindex}`,
                    mode: iface.port_mode || "unknown",
                    pvid: iface.pvid,
                    tagged: Array.from(intValues(iface.tagged_vlans)).sort((a, b) => a - b),
                    untagged: Array.from(intValues(iface.untagged_vlans)).sort((a, b) => a - b),
                });
            });
        });
        return { vlan_id: vlan, nodes, edges, ports };
    }

    function renderVlanGraph(host, focused) {
        host.replaceChildren();
        const nodes = focused.nodes.slice(0, 80);
        if (!nodes.length) {
            host.append(el("p", `Для VLAN ${focused.vlan_id} пока нет node/edge evidence.`, "muted"));
            return;
        }
        const visible = new Set(nodes.map((node) => node.id));
        const canvas = svg("svg", { viewBox: "0 0 1200 520", role: "img", "aria-label": `VLAN ${focused.vlan_id} topology` });
        canvas.classList.add("ws-topology-svg", "ws-snmp-vlan-svg");
        const edgeLayer = svg("g", { class: "ws-topology-edges" });
        const nodeLayer = svg("g", { class: "ws-topology-nodes" });
        const cols = Math.max(1, Math.min(6, Math.ceil(Math.sqrt(nodes.length * 1.8))));
        const rows = Math.ceil(nodes.length / cols);
        const positions = new Map();
        nodes.forEach((node, index) => {
            const col = index % cols;
            const row = Math.floor(index / cols);
            positions.set(node.id, {
                x: 90 + col * (1020 / Math.max(1, cols - 1)),
                y: 80 + row * (350 / Math.max(1, rows - 1)),
            });
        });
        focused.edges.forEach((edge) => {
            if (!visible.has(edge.source) || !visible.has(edge.target)) return;
            const a = positions.get(edge.source);
            const b = positions.get(edge.target);
            if (!a || !b) return;
            const line = svg("line", {
                x1: a.x, y1: a.y, x2: b.x, y2: b.y,
                class: `ws-topology-edge ws-topology-${edge.confidence || "observed"}`,
                "stroke-width": 2.2,
            });
            const title = svg("title");
            title.textContent = `${edge.relation || "link"} · ${(edge.provenance || []).join(", ")} · VLAN ${focused.vlan_id}`;
            line.append(title);
            edgeLayer.append(line);
        });
        nodes.forEach((node) => {
            const point = positions.get(node.id);
            const group = svg("g", { class: `ws-topology-node ws-topology-node-${node.kind || "endpoint"}`, transform: `translate(${point.x} ${point.y})` });
            group.append(svg("circle", { r: 24 }));
            const badge = svg("text", { y: 4, "text-anchor": "middle", class: "ws-topology-node-badge" });
            badge.textContent = (node.roles || []).includes("router-interface") ? "IF"
                : ((node.roles || []).includes("network-device") || node.kind === "network-device") ? "SW" : "●";
            const label = svg("text", { y: 43, "text-anchor": "middle" });
            const text = String(node.label || node.id);
            label.textContent = text.length > 22 ? `${text.slice(0, 21)}…` : text;
            const title = svg("title");
            title.textContent = `${node.label || node.id} · VLAN ${(Array.from(nodeVlans(node))).join(", ") || focused.vlan_id}`;
            group.append(badge, label, title);
            nodeLayer.append(group);
        });
        canvas.append(edgeLayer, nodeLayer);
        host.append(canvas);
        if (focused.nodes.length > nodes.length) host.append(el("p", `Показано ${nodes.length} из ${focused.nodes.length} VLAN-узлов.`, "muted"));
    }

    function installVlanExplorer(panel, topology) {
        const vlans = availableVlans(topology);
        const block = el("section", null, "ws-snmp-vlan-explorer");
        block.append(el("h4", "VLAN-фокус"));
        block.append(el("p", "Показывает только evidence-backed VLAN membership из Q-BRIDGE/FDB/PVID. Trunk/hybrid не привязывает endpoint к одному VLAN без однозначного доказательства.", "hint"));
        if (!vlans.length) {
            block.append(el("p", "В этом аудите VLAN evidence пока нет. Это нормально для обычного L3-роутера без Q-BRIDGE-MIB.", "muted"));
            panel.append(block);
            return;
        }

        const selector = select([["", "Выберите VLAN"], ...vlans.map(([id, name]) => [String(id), `VLAN ${id}${name ? ` · ${name}` : ""}`])]);
        const exportButton = el("button", "Скачать VLAN JSON", "secondary");
        exportButton.type = "button";
        exportButton.disabled = true;
        const controls = el("div", null, "actions wrap ws-snmp-vlan-controls");
        controls.append(selector, exportButton);
        const summary = el("p", "", "ws-snmp-status");
        const ports = el("div", null, "ws-snmp-vlan-ports");
        const graph = el("div", null, "ws-snmp-vlan-graph");
        block.append(controls, summary, ports, graph);
        panel.append(block);

        let current = null;
        function render() {
            ports.replaceChildren();
            graph.replaceChildren();
            exportButton.disabled = !selector.value;
            if (!selector.value) {
                summary.textContent = `${vlans.length} VLAN ID доступны из сохранённого SNMP evidence.`;
                return;
            }
            current = vlanFocus(topology, selector.value);
            summary.textContent = `VLAN ${current.vlan_id}: ${current.nodes.length} узлов · ${current.edges.length} связей · ${current.ports.length} портов с membership evidence.`;
            if (current.ports.length) {
                current.ports.forEach((port) => {
                    const row = el("div", null, "ws-snmp-vlan-port");
                    row.append(
                        el("strong", `${port.device} · ${port.name}`),
                        el("span", `ifIndex ${port.ifindex ?? "—"} · ${port.mode} · PVID ${port.pvid ?? "—"} · tagged ${port.tagged.join(",") || "—"} · untagged ${port.untagged.join(",") || "—"}`)
                    );
                    ports.append(row);
                });
            } else {
                ports.append(el("p", "Для выбранного VLAN есть node/edge evidence, но нет подтверждённой port membership таблицы.", "muted"));
            }
            renderVlanGraph(graph, current);
        }
        selector.addEventListener("change", render);
        exportButton.addEventListener("click", () => {
            if (!current) return;
            const blob = new Blob([JSON.stringify(current, null, 2)], { type: "application/json" });
            const url = URL.createObjectURL(blob);
            const link = document.createElement("a");
            link.href = url;
            link.download = `wirescope-vlan-${current.vlan_id}.json`;
            document.body.append(link);
            link.click();
            link.remove();
            window.setTimeout(() => URL.revokeObjectURL(url), 0);
        });
        render();
    }

    async function waitForJob(jobId, statusNode) {
        for (;;) {
            const job = await api(`/jobs/${encodeURIComponent(jobId)}`);
            const progress = Number(job.progress || 0);
            statusNode.className = "ws-snmp-status";
            statusNode.textContent = `${job.status} · ${progress}% · ${job.message || job.stage || ""}`;
            if (["completed", "failed", "cancelled", "interrupted"].includes(job.status)) return job;
            await new Promise((resolve) => setTimeout(resolve, 1000));
        }
    }

    async function installPanel(body, auditId) {
        const existing = body.querySelector(".ws-snmp-topology-panel");
        if (existing) existing.remove();

        const [me, topology] = await Promise.all([
            api("/auth/me"),
            api(`/audits/${encodeURIComponent(auditId)}/topology`),
        ]);
        const summary = topology.snmp_topology || {};
        const panel = el("section", null, "ws-snmp-topology-panel card");
        const heading = el("div", null, "ws-snmp-heading");
        const title = el("div");
        title.append(el("h3", "SNMP · физическая топология"));
        title.append(el("p", "Read-only IF-MIB / IP-MIB / BRIDGE-MIB / Q-BRIDGE-MIB / LLDP-MIB. Собираются router interfaces, ARP/ND, FDB, VLAN и LLDP. Credentials используются только для этой job и не сохраняются в SQLite/evidence.", "hint"));
        const metric = el(
            "span",
            `${summary.devices || 0} устройств · ${summary.interface_nodes || 0} L3 IF · ${summary.neighbor_links || 0} ARP/ND · ${summary.port_links || 0} port links · ${summary.lldp_links || 0} LLDP`,
            "ws-snmp-metric"
        );
        heading.append(title, metric);
        panel.append(heading);

        installVlanExplorer(panel, topology);

        if (me.role !== "auditor") {
            panel.append(el("p", "Viewer может просматривать уже собранную SNMP-топологию, но не запускать новый SNMP read.", "muted"));
            body.prepend(panel);
            return;
        }

        const form = el("form", null, "ws-snmp-form");
        const target = input("text", "10.11.11.1");
        target.required = true;
        target.maxLength = 64;
        const list = document.createElement("datalist");
        list.id = `ws-snmp-targets-${String(auditId).slice(0, 8)}`;
        candidateAddresses(topology).forEach((candidate) => {
            const option = document.createElement("option");
            option.value = candidate.value;
            option.label = candidate.label;
            list.append(option);
        });
        target.setAttribute("list", list.id);

        const version = select([["3", "SNMPv3"], ["2c", "SNMPv2c"]]);
        const community = input("password", "community");
        community.maxLength = 256;
        const username = input("text", "wirescope-ro");
        username.maxLength = 64;
        const level = select([
            ["authPriv", "authPriv (рекомендуется)"],
            ["authNoPriv", "authNoPriv"],
            ["noAuthNoPriv", "noAuthNoPriv"],
        ]);
        const authProtocol = select([
            ["SHA", "SHA"],
            ["SHA-256", "SHA-256"],
            ["SHA-384", "SHA-384"],
            ["SHA-512", "SHA-512"],
        ]);
        const authPassword = input("password", "auth password");
        authPassword.maxLength = 256;
        const privProtocol = select([["AES", "AES"]]);
        const privPassword = input("password", "privacy password");
        privPassword.maxLength = 256;

        const v2Fields = el("div", null, "ws-snmp-fields");
        v2Fields.append(field("Community", community));
        const v3Fields = el("div", null, "ws-snmp-fields");
        v3Fields.append(
            field("Username", username),
            field("Security", level),
            field("Auth", authProtocol),
            field("Auth password", authPassword),
            field("Privacy", privProtocol),
            field("Privacy password", privPassword)
        );
        const core = el("div", null, "ws-snmp-fields ws-snmp-core");
        core.append(field("Management IP", target), field("Версия", version));

        const warning = el("p", "SNMPv2c community передаётся по сети без шифрования. Для новых устройств используйте SNMPv3 authPriv.", "warning");
        warning.hidden = true;
        const status = el("p", "", "ws-snmp-status");
        const submit = el("button", "Собрать SNMP-топологию", "primary");
        submit.type = "submit";
        const actions = el("div", null, "actions wrap");
        actions.append(submit);
        form.append(core, list, v2Fields, v3Fields, warning, actions, status);
        panel.append(form);

        function syncFields() {
            const isV3 = version.value === "3";
            v3Fields.hidden = !isV3;
            v2Fields.hidden = isV3;
            warning.hidden = isV3;
            const auth = isV3 && level.value !== "noAuthNoPriv";
            const priv = isV3 && level.value === "authPriv";
            authProtocol.disabled = !auth;
            authPassword.disabled = !auth;
            privProtocol.disabled = !priv;
            privPassword.disabled = !priv;
            community.required = !isV3;
            username.required = isV3;
            authPassword.required = auth;
            privPassword.required = priv;
        }
        version.addEventListener("change", syncFields);
        level.addEventListener("change", syncFields);
        syncFields();

        form.addEventListener("submit", async (event) => {
            event.preventDefault();
            submit.disabled = true;
            status.textContent = "Ставим read-only SNMP job…";
            status.className = "ws-snmp-status";
            const payload = {
                target: target.value.trim(),
                version: version.value,
                community: version.value === "2c" ? community.value : null,
                username: version.value === "3" ? username.value.trim() : null,
                security_level: level.value,
                auth_protocol: authProtocol.value,
                auth_password: version.value === "3" && level.value !== "noAuthNoPriv" ? authPassword.value : null,
                priv_protocol: privProtocol.value,
                priv_password: version.value === "3" && level.value === "authPriv" ? privPassword.value : null,
            };
            try {
                const accepted = await api(`/audits/${encodeURIComponent(auditId)}/topology/snmp`, {
                    method: "POST",
                    body: JSON.stringify(payload),
                });
                community.value = "";
                authPassword.value = "";
                privPassword.value = "";
                const job = await waitForJob(accepted.job_id, status);
                if (job.status !== "completed") {
                    throw new Error((job.error && job.error.message) || `SNMP job: ${job.status}`);
                }
                status.textContent = "Готово. Перестраиваем карту с L3/FDB/LLDP/VLAN evidence…";
                await originalRender(body, auditId);
                await installPanel(body, auditId);
            } catch (error) {
                status.className = "ws-snmp-status error";
                status.textContent = error.message;
            } finally {
                submit.disabled = false;
            }
        });

        body.prepend(panel);
    }

    topologyApi.render = async function wrappedRender(body, auditId) {
        await originalRender(body, auditId);
        try {
            await installPanel(body, auditId);
        } catch (error) {
            const note = el("p", `SNMP topology panel недоступна: ${error.message}`, "warning");
            body.prepend(note);
        }
    };
})();
