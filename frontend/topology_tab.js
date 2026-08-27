(() => {
    "use strict";

    let activeView = null;
    let activeExtra = null;
    let extrasOpen = false;

    function insightsBody() {
        return document.getElementById("ws-insights-body");
    }

    function renameEnrichmentPanels(body) {
        const snmp = body && body.querySelector(".ws-snmp-topology-panel");
        const ssh = body && body.querySelector(".ws-ssh-topology-panel");
        const snmpTitle = snmp && snmp.querySelector("h3");
        const sshTitle = ssh && ssh.querySelector("h3");
        if (snmpTitle) snmpTitle.textContent = "SNMP — данные сетевого оборудования";
        if (sshTitle) sshTitle.textContent = "SSH — данные Linux/OpenWrt";
    }

    function syncExtraPanels() {
        const body = insightsBody();
        if (!body) return;
        renameEnrichmentPanels(body);
        body.classList.toggle("ws-extra-snmp-open", activeView === "topology" && activeExtra === "snmp");
        body.classList.toggle("ws-extra-ssh-open", activeView === "topology" && activeExtra === "ssh");
    }

    async function renderSelected() {
        if (!activeView) return;
        const select = document.getElementById("ws-audit-select");
        const body = insightsBody();
        const auditId = select && select.value;
        if (!body || !auditId) return;
        try {
            if (activeView === "topology") {
                if (!window.WireScopeTopology) return;
                await window.WireScopeTopology.render(body, auditId);
                syncExtraPanels();
            } else if (activeView === "compare") {
                activeExtra = null;
                if (!window.WireScopeTopologyCompare) return;
                await window.WireScopeTopologyCompare.render(body, auditId);
                syncExtraPanels();
            }
        } catch (error) {
            body.replaceChildren();
            const message = document.createElement("p");
            message.className = "error";
            message.textContent = error.message || String(error);
            body.append(message);
        }
    }

    function install() {
        const tabs = document.querySelector(".ws-insights-tabs");
        const auditSelect = document.getElementById("ws-audit-select");
        if (!tabs || !auditSelect || document.getElementById("ws-topology-tab")) return false;

        const topologyButton = document.createElement("button");
        topologyButton.id = "ws-topology-tab";
        topologyButton.type = "button";
        topologyButton.className = "secondary";
        topologyButton.textContent = "Топология";

        const compareButton = document.createElement("button");
        compareButton.id = "ws-topology-compare-tab";
        compareButton.type = "button";
        compareButton.className = "secondary";
        compareButton.textContent = "История топологии";

        const extrasButton = document.createElement("button");
        extrasButton.id = "ws-topology-extras-tab";
        extrasButton.type = "button";
        extrasButton.className = "secondary";
        extrasButton.textContent = "Дополнительно";
        extrasButton.setAttribute("aria-expanded", "false");

        tabs.append(topologyButton, compareButton, extrasButton);

        const extrasMenu = document.createElement("div");
        extrasMenu.id = "ws-topology-extras-menu";
        extrasMenu.className = "ws-topology-extras-menu card";
        extrasMenu.hidden = true;

        const copy = document.createElement("div");
        copy.className = "ws-topology-extras-copy";
        const title = document.createElement("strong");
        title.textContent = "Дополнительные источники топологии";
        const hint = document.createElement("span");
        hint.textContent = "Не обязательны для обычного просмотра карты. Используйте их, когда есть доступ к управляемому сетевому оборудованию или Linux/OpenWrt-устройству.";
        copy.append(title, hint);

        const actions = document.createElement("div");
        actions.className = "ws-topology-extras-actions";
        const snmpButton = document.createElement("button");
        snmpButton.type = "button";
        snmpButton.className = "secondary";
        snmpButton.textContent = "SNMP enrichment";
        const sshButton = document.createElement("button");
        sshButton.type = "button";
        sshButton.className = "secondary";
        sshButton.textContent = "SSH enrichment";
        actions.append(snmpButton, sshButton);
        extrasMenu.append(copy, actions);
        tabs.insertAdjacentElement("afterend", extrasMenu);

        const setPrimaryTab = (button) => {
            tabs.querySelectorAll("button").forEach((item) => {
                if (item === extrasButton) return;
                item.className = item === button ? "primary" : "secondary";
            });
        };

        const closeExtrasMenu = () => {
            extrasOpen = false;
            extrasMenu.hidden = true;
            extrasButton.setAttribute("aria-expanded", "false");
        };

        const activate = async (view, button, event) => {
            if (event) {
                event.preventDefault();
                event.stopPropagation();
            }
            activeView = view;
            if (view !== "topology") activeExtra = null;
            setPrimaryTab(button);
            closeExtrasMenu();
            await renderSelected();
        };

        topologyButton.addEventListener("click", (event) => activate("topology", topologyButton, event));
        compareButton.addEventListener("click", (event) => activate("compare", compareButton, event));

        extrasButton.addEventListener("click", async (event) => {
            event.preventDefault();
            event.stopPropagation();
            if (activeView !== "topology") {
                activeView = "topology";
                setPrimaryTab(topologyButton);
                await renderSelected();
            }
            extrasOpen = !extrasOpen;
            extrasMenu.hidden = !extrasOpen;
            extrasButton.setAttribute("aria-expanded", String(extrasOpen));
        });

        const openExtra = async (kind) => {
            activeExtra = kind;
            activeView = "topology";
            setPrimaryTab(topologyButton);
            closeExtrasMenu();
            syncExtraPanels();
            const body = insightsBody();
            const panel = body && body.querySelector(kind === "snmp" ? ".ws-snmp-topology-panel" : ".ws-ssh-topology-panel");
            if (panel) panel.scrollIntoView({ behavior: "smooth", block: "start" });
        };

        snmpButton.addEventListener("click", () => openExtra("snmp"));
        sshButton.addEventListener("click", () => openExtra("ssh"));

        tabs.addEventListener("click", (event) => {
            const target = event.target.closest("button");
            if (!target || target === topologyButton || target === compareButton || target === extrasButton) return;
            activeView = null;
            activeExtra = null;
            closeExtrasMenu();
            syncExtraPanels();
        });

        document.addEventListener("click", (event) => {
            if (!extrasOpen) return;
            if (event.target.closest("#ws-topology-extras-menu") || event.target.closest("#ws-topology-extras-tab")) return;
            closeExtrasMenu();
        });

        auditSelect.addEventListener("change", () => {
            if (!activeView) return;
            setTimeout(renderSelected, 0);
        });
        return true;
    }

    function boot() {
        if (install()) return;
        const observer = new MutationObserver(() => {
            if (install()) observer.disconnect();
        });
        observer.observe(document.body, { childList: true, subtree: true });
    }

    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot);
    else boot();
})();
