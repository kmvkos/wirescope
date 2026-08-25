(() => {
    "use strict";

    let topologyActive = false;

    async function renderSelected() {
        if (!topologyActive || !window.WireScopeTopology) return;
        const select = document.getElementById("ws-audit-select");
        const body = document.getElementById("ws-insights-body");
        const auditId = select && select.value;
        if (!body || !auditId) return;
        try {
            await window.WireScopeTopology.render(body, auditId);
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

        const button = document.createElement("button");
        button.id = "ws-topology-tab";
        button.type = "button";
        button.className = "secondary";
        button.textContent = "Топология";
        tabs.append(button);

        button.addEventListener("click", async (event) => {
            event.preventDefault();
            event.stopPropagation();
            topologyActive = true;
            tabs.querySelectorAll("button").forEach((item) => {
                item.className = item === button ? "primary" : "secondary";
            });
            await renderSelected();
        });

        tabs.addEventListener("click", (event) => {
            const target = event.target.closest("button");
            if (target && target !== button) topologyActive = false;
        });

        auditSelect.addEventListener("change", () => {
            if (!topologyActive) return;
            // The legacy insights handler also reacts to this change. Re-render
            // after its synchronous tab bookkeeping so topology remains active.
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
