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
            throw new Error((detail && (detail.message || detail.code)) || response.statusText || `HTTP ${response.status}`);
        }
        return data;
    }

    function input(type = "text", placeholder = "") {
        const node = document.createElement("input");
        node.type = type;
        node.placeholder = placeholder;
        node.autocomplete = "off";
        node.spellcheck = false;
        return node;
    }

    function field(title, control) {
        const label = el("label", null, "ws-ssh-field");
        label.append(el("span", title), control);
        return label;
    }

    function candidateAddresses(topology) {
        const result = [];
        const seen = new Set();
        (topology.nodes || []).forEach((node) => {
            const roles = new Set(node.roles || []);
            if (!(node.kind === "network-device" || roles.has("gateway") || roles.has("router") || roles.has("network-neighbor"))) return;
            (node.addresses || []).forEach((raw) => {
                const value = String(raw || "").split("/", 1)[0];
                if (!value || seen.has(value)) return;
                seen.add(value);
                result.push({ value, label: node.label || value });
            });
        });
        return result;
    }

    async function waitForJob(jobId, statusNode) {
        for (;;) {
            const job = await api(`/jobs/${encodeURIComponent(jobId)}`);
            statusNode.className = "ws-ssh-status";
            statusNode.textContent = `${job.status} · ${Number(job.progress || 0)}% · ${job.message || job.stage || ""}`;
            if (["completed", "failed", "cancelled", "interrupted"].includes(job.status)) return job;
            await new Promise((resolve) => setTimeout(resolve, 1000));
        }
    }

    async function installPanel(body, auditId) {
        body.querySelector(".ws-ssh-topology-panel")?.remove();
        const [me, topology] = await Promise.all([
            api("/auth/me"),
            api(`/audits/${encodeURIComponent(auditId)}/topology`),
        ]);
        const summary = topology.ssh_topology || {};
        const panel = el("section", null, "ws-ssh-topology-panel card");
        const heading = el("div", null, "ws-ssh-heading");
        const title = el("div");
        title.append(
            el("h3", "SSH · management topology"),
            el("p", "Опциональный read-only источник для Linux/OpenWrt-подобных устройств: interfaces/routes/ARP-ND/FDB/VLAN и Wi‑Fi associations. Remote-команды фиксированы в WireScope; произвольная команда от оператора невозможна.", "hint")
        );
        const metrics = el("div", null, "ws-ssh-metrics");
        [
            ["L3 IF", summary.interfaces || 0],
            ["ARP/ND", summary.neighbors || 0],
            ["port links", summary.port_links || 0],
            ["Wi‑Fi", summary.wifi_links || 0],
        ].forEach(([name, value]) => {
            const item = el("div", null, "ws-ssh-metric");
            item.append(el("strong", value), el("span", name));
            metrics.append(item);
        });
        heading.append(title, metrics);
        panel.append(heading);

        if (me.role !== "auditor") {
            panel.append(el("p", "Запуск management enrichment доступен только роли auditor.", "muted"));
            body.prepend(panel);
            return;
        }

        const candidates = candidateAddresses(topology);
        const form = el("form", null, "ws-ssh-form");
        const target = input("text", "10.11.11.11");
        if (candidates.length) target.value = candidates[0].value;
        const datalist = el("datalist");
        datalist.id = `ws-ssh-targets-${String(auditId).slice(0, 8)}`;
        candidates.forEach((item) => {
            const option = el("option");
            option.value = item.value;
            option.label = item.label;
            datalist.append(option);
        });
        target.setAttribute("list", datalist.id);

        const username = input("text", "audit");
        const port = input("number", "22"); port.value = "22"; port.min = "1"; port.max = "65535";
        const auth = el("select");
        [["private_key", "Private key"], ["agent", "SSH agent"]].forEach(([value, label]) => { const option = el("option", label); option.value = value; auth.append(option); });
        const privateKey = el("textarea");
        privateKey.rows = 5;
        privateKey.placeholder = "-----BEGIN OPENSSH PRIVATE KEY-----";
        privateKey.autocomplete = "off";
        privateKey.spellcheck = false;
        const knownHosts = el("textarea");
        knownHosts.rows = 3;
        knownHosts.placeholder = "10.11.11.11 ssh-ed25519 AAAA...";
        knownHosts.autocomplete = "off";
        knownHosts.spellcheck = false;
        const submit = el("button", "Запустить read-only SSH", "secondary");
        submit.type = "submit";
        const status = el("p", "", "ws-ssh-status");
        const trust = el("p", "Host key проверяется строго. Private key/known_hosts передаются worker через consume-once 0600 spool и не сохраняются в SQLite/evidence. На роутере лучше отдельная учётка с разрешением только на команды ip/bridge/iw.", "hint");

        function syncAuth() {
            privateKey.disabled = auth.value === "agent";
            if (privateKey.disabled) privateKey.value = "";
        }
        auth.addEventListener("change", syncAuth);
        syncAuth();

        form.append(
            datalist,
            field("Target", target),
            field("Username", username),
            field("Port", port),
            field("Authentication", auth),
            field("Private key", privateKey),
            field("known_hosts", knownHosts),
            submit,
            trust,
            status,
        );

        form.addEventListener("submit", async (event) => {
            event.preventDefault();
            submit.disabled = true;
            status.className = "ws-ssh-status";
            status.textContent = "Ставим scoped read-only SSH job…";
            const payload = {
                target: target.value.trim(),
                username: username.value.trim(),
                port: Number(port.value || 22),
                authentication: auth.value,
                private_key: auth.value === "private_key" ? privateKey.value : null,
                known_hosts: knownHosts.value,
            };
            try {
                const accepted = await api(`/audits/${encodeURIComponent(auditId)}/topology/ssh`, { method: "POST", body: JSON.stringify(payload) });
                privateKey.value = "";
                const job = await waitForJob(accepted.job_id, status);
                if (job.status !== "completed") throw new Error((job.error && job.error.message) || `SSH topology job: ${job.status}`);
                status.textContent = "Готово. Перестраиваем карту с management evidence…";
                await originalRender(body, auditId);
                await installPanel(body, auditId);
            } catch (error) {
                status.className = "ws-ssh-status error";
                status.textContent = error.message;
            } finally {
                submit.disabled = false;
            }
        });

        panel.append(form);
        body.prepend(panel);
    }

    topologyApi.render = async function wrappedSshTopologyRender(body, auditId) {
        await originalRender(body, auditId);
        try {
            await installPanel(body, auditId);
        } catch (error) {
            body.prepend(el("p", `SSH topology panel недоступна: ${error.message}`, "warning"));
        }
    };
})();
