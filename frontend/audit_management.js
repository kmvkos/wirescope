(() => {
    "use strict";

    const API = "/api/v1";
    const ACTIVE_KEY = "wirescope.activeAudit";
    const DELETABLE = new Set([
        "created",
        "completed",
        "failed",
        "cancelled",
        "interrupted",
    ]);
    const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

    let canDelete = false;
    let statuses = new Map();
    let refreshTimer = null;

    async function request(method, path) {
        const response = await fetch(`${API}${path}`, {
            method,
            credentials: "same-origin",
            headers: { "Accept": "application/json" },
        });
        const text = await response.text();
        let data = null;
        if (text) {
            try { data = JSON.parse(text); } catch { data = { message: text }; }
        }
        if (!response.ok) {
            const detail = data && data.detail;
            const error = new Error(
                (detail && detail.message) ||
                (data && data.message) ||
                response.statusText ||
                `HTTP ${response.status}`
            );
            error.status = response.status;
            error.code = detail && detail.code;
            throw error;
        }
        return data;
    }

    function auditIdFromCard(card) {
        const spans = card.querySelectorAll("span");
        for (let index = spans.length - 1; index >= 0; index -= 1) {
            const value = String(spans[index].textContent || "").trim();
            if (UUID_RE.test(value)) return value;
        }
        return "";
    }

    function activeAuditId() {
        try {
            const value = JSON.parse(sessionStorage.getItem(ACTIVE_KEY) || "null");
            return value && value.auditId ? String(value.auditId) : "";
        } catch {
            return "";
        }
    }

    function clearActiveIfDeleted(auditId) {
        if (activeAuditId() === auditId) {
            sessionStorage.removeItem(ACTIVE_KEY);
        }
    }

    async function confirmDelete(auditId) {
        const title = "Удалить аудит?";
        const body = (
            `Аудит ${auditId.slice(0, 8)} будет удалён полностью.\n\n` +
            "Удалятся задания, список устройств и служб, findings, отчёты, PCAP, Nmap XML и остальные evidence-файлы. Это действие нельзя отменить."
        );
        if (typeof window.confirmModal === "function") {
            return window.confirmModal(title, body);
        }
        return window.confirm(`${title}\n\n${body}`);
    }

    async function deleteAudit(auditId, button, row) {
        const accepted = await confirmDelete(auditId);
        if (!accepted) return;

        button.disabled = true;
        button.textContent = "Удаляем…";
        try {
            const result = await request(
                "DELETE",
                `/audits/${encodeURIComponent(auditId)}`
            );
            clearActiveIfDeleted(auditId);
            row.remove();

            if (result && result.file_cleanup_pending) {
                window.alert(
                    "Аудит удалён из базы. Часть файлов не удалось удалить сразу; их дочистит обслуживание WireScope."
                );
            }

            const list = document.getElementById("audit-list");
            if (list && !list.querySelector(".audit-manage-row, button.list-item")) {
                if (typeof window.showHome === "function") {
                    await window.showHome();
                }
            }
        } catch (error) {
            button.disabled = false;
            button.textContent = "Удалить";
            if (error.code === "audit_busy" || error.status === 409) {
                window.alert(
                    "Этот аудит ещё выполняется или ждёт выполнения. Сначала нажмите «Стоп» и дождитесь остановки задания."
                );
                return;
            }
            window.alert(`Не удалось удалить аудит: ${error.message}`);
        }
    }

    function decorateCards() {
        if (!canDelete) return;
        const list = document.getElementById("audit-list");
        if (!list) return;

        Array.from(list.children).forEach((child) => {
            if (!(child instanceof HTMLButtonElement)) return;
            if (!child.classList.contains("list-item")) return;

            const auditId = auditIdFromCard(child);
            if (!auditId) return;

            const row = document.createElement("div");
            row.className = "audit-manage-row";
            row.dataset.auditId = auditId;
            child.classList.add("audit-open-card");
            list.insertBefore(row, child);
            row.append(child);

            const remove = document.createElement("button");
            remove.type = "button";
            remove.className = "danger audit-delete-button";
            remove.textContent = "Удалить";
            remove.setAttribute("aria-label", `Удалить аудит ${auditId}`);

            const status = statuses.get(auditId);
            const allowed = !status || DELETABLE.has(status);
            remove.disabled = !allowed;
            if (!allowed) {
                remove.title = "Сначала остановите текущие задания аудита";
            }
            remove.addEventListener("click", (event) => {
                event.preventDefault();
                event.stopPropagation();
                deleteAudit(auditId, remove, row);
            });
            row.append(remove);
        });
    }

    async function refreshState() {
        const home = document.getElementById("screen-home");
        if (!home || home.hidden) return;
        try {
            const [me, page] = await Promise.all([
                request("GET", "/auth/me"),
                request("GET", "/audits?limit=100"),
            ]);
            canDelete = Boolean(me && me.role === "auditor");
            statuses = new Map(
                ((page && page.items) || []).map((audit) => [
                    String(audit.id),
                    String(audit.status || ""),
                ])
            );
            decorateCards();
        } catch {
            // The base UI owns connectivity/session errors. This enhancement
            // must never make the audit list unusable.
        }
    }

    function scheduleRefresh() {
        clearTimeout(refreshTimer);
        refreshTimer = setTimeout(refreshState, 40);
    }

    function boot() {
        const home = document.getElementById("screen-home");
        const list = document.getElementById("audit-list");
        if (!home || !list) return;

        new MutationObserver(scheduleRefresh).observe(home, {
            attributes: true,
            attributeFilter: ["hidden"],
        });
        new MutationObserver(scheduleRefresh).observe(list, {
            childList: true,
        });
        scheduleRefresh();
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", boot);
    } else {
        boot();
    }
})();
