(() => {
    "use strict";

    const API = "/api/v1";
    const topologyApi = window.WireScopeTopology;
    if (!topologyApi || typeof topologyApi.render !== "function") return;
    const originalRender = topologyApi.render.bind(topologyApi);

    const el = (tag, text, cls) => {
        const node = document.createElement(tag);
        if (text !== undefined && text !== null) node.textContent = String(text);
        if (cls) node.className = cls;
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
        title.append(el("p", "Read-only IF-MIB / BRIDGE-MIB / Q-BRIDGE-MIB / LLDP-MIB / ARP. Credentials используются только для этой job и не сохраняются в SQLite/evidence.", "hint"));
        const metric = el("span", `${summary.devices || 0} устройств · ${summary.port_links || 0} port links · ${summary.lldp_links || 0} LLDP`, "ws-snmp-metric");
        heading.append(title, metric);
        panel.append(heading);

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
                status.textContent = "Готово. Перестраиваем карту с FDB/LLDP/VLAN evidence…";
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
