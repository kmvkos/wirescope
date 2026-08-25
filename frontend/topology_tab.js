(() => {
    "use strict";

    let activeView = null;

    async function renderSelected() {
        if (!activeView) return;
        const select = document.getElementById("ws-audit-select");
        const body = document.getElementById("ws-insights-body");
        const auditId = select && select.value;
        if (!body || !auditId) return;
        try {
            if (activeView === "topology") {
                if (!window.WireScopeTopology) return;
                await window.WireScopeTopology.render(body, auditId);
            } else if (activeView === "compare") {
                if (!window.WireScopeTopologyCompare) return;
                await window.WireScopeTopologyCompare.render(body, auditId);
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
        compareButton.textContent = "История topology";
        tabs.append(topologyButton, compareButton);

        const activate = async (view, button, event) => {
            event.preventDefault();
            event.stopPropagation();
            activeView = view;
            tabs.querySelectorAll("button").forEach((item) => {
                item.className = item === button ? "primary" : "secondary";
            });
            await renderSelected();
        };

        topologyButton.addEventListener("click", (event) => activate("topology", topologyButton, event));
        compareButton.addEventListener("click", (event) => activate("compare", compareButton, event));

        tabs.addEventListener("click", (event) => {
            const target = event.target.closest("button");
            if (target && target !== topologyButton && target !== compareButton) activeView = null;
        });

        auditSelect.addEventListener("change", () => {
            if (!activeView) return;
            // The legacy insights handler also reacts to this change. Re-render
            // after its synchronous tab bookkeeping so the selected topology
            // view remains active.
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
