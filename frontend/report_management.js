(() => {
    "use strict";

    const API = "/api/v1";
    const ACTIVE_KEY = "wirescope.activeAudit";

    function activeAuditId() {
        try {
            const parsed = JSON.parse(sessionStorage.getItem(ACTIVE_KEY) || "null");
            return parsed && parsed.auditId ? String(parsed.auditId) : "";
        } catch {
            return "";
        }
    }

    async function request(method, path) {
        const response = await fetch(`${API}${path}`, {
            method,
            credentials: "same-origin",
            headers: { "Accept": "application/json" },
        });
        const text = await response.text();
        let data = null;
        if (text) {
            try { data = JSON.parse(text); } catch { data = text; }
        }
        if (!response.ok) {
            const detail = data && data.detail;
            throw new Error(
                (detail && detail.message) ||
                (data && data.message) ||
                response.statusText ||
                `HTTP ${response.status}`
            );
        }
        return data;
    }

    function formatDate(value) {
        if (!value) return "—";
        const date = new Date(value);
        if (Number.isNaN(date.getTime())) return String(value);
        return date.toLocaleString("ru-RU");
    }

    function exportUrl(auditId, reportId, format) {
        return `${API}/audits/${encodeURIComponent(auditId)}/reports/${encodeURIComponent(reportId)}/export?format=${format}`;
    }

    function ensurePanel() {
        const screen = document.getElementById("screen-report");
        if (!screen) return null;
        let panel = document.getElementById("report-history-panel");
        if (panel) return panel;

        panel = document.createElement("section");
        panel.id = "report-history-panel";
        panel.className = "ws-section report-history-panel";

        const title = document.createElement("h3");
        title.textContent = "История отчётов";
        const hint = document.createElement("p");
        hint.className = "hint";
        hint.textContent = "Удаление отчёта не удаляет аудит, устройства, сервисы, findings и исходные evidence.";
        const list = document.createElement("div");
        list.id = "report-history-list";
        list.className = "report-history-list";
        panel.append(title, hint, list);

        const frame = document.getElementById("report-frame");
        if (frame) screen.insertBefore(panel, frame);
        else screen.append(panel);
        return panel;
    }

    function actionButton(text, className, handler) {
        const button = document.createElement("button");
        button.type = "button";
        button.className = className;
        button.textContent = text;
        button.addEventListener("click", handler);
        return button;
    }

    async function refreshHistory() {
        const panel = ensurePanel();
        if (!panel) return;
        const list = document.getElementById("report-history-list");
        if (!list) return;

        const auditId = activeAuditId();
        if (!auditId) {
            list.replaceChildren();
            return;
        }

        list.replaceChildren();
        const loading = document.createElement("p");
        loading.className = "hint";
        loading.textContent = "Загружаем историю отчётов…";
        list.append(loading);

        try {
            const [page, me] = await Promise.all([
                request("GET", `/audits/${encodeURIComponent(auditId)}/reports?limit=100`),
                request("GET", "/auth/me"),
            ]);
            list.replaceChildren();
            const reports = (page && page.items) || [];
            if (!reports.length) {
                const empty = document.createElement("p");
                empty.className = "hint";
                empty.textContent = "Сформированных отчётов пока нет.";
                list.append(empty);
                return;
            }

            const canDelete = me && me.role === "auditor";
            reports.forEach((report, index) => {
                const item = document.createElement("article");
                item.className = "report-history-item";

                const head = document.createElement("div");
                head.className = "report-history-head";
                const title = document.createElement("strong");
                title.textContent = `${index === 0 ? "Последний отчёт" : "Отчёт"} · ${formatDate(report.generated_at)}`;
                const meta = document.createElement("span");
                meta.className = "hint";
                meta.textContent = `hash ${String(report.source_hash || "—").slice(0, 12)} · ${String(report.id || "").slice(0, 8)}`;
                head.append(title, meta);

                const actions = document.createElement("div");
                actions.className = "actions wrap report-history-actions";
                actions.append(
                    actionButton("HTML", "secondary", () => {
                        window.open(exportUrl(auditId, report.id, "html"), "_blank", "noopener");
                    }),
                    actionButton("JSON", "secondary", () => {
                        window.location.assign(exportUrl(auditId, report.id, "json"));
                    }),
                    actionButton("Markdown", "secondary", () => {
                        window.location.assign(exportUrl(auditId, report.id, "markdown"));
                    })
                );

                if (canDelete) {
                    actions.append(actionButton("Удалить", "danger", async (event) => {
                        const button = event.currentTarget;
                        const accepted = window.confirm(
                            "Удалить этот сформированный отчёт?\n\nСам аудит, найденные устройства, сервисы, findings и evidence останутся."
                        );
                        if (!accepted) return;
                        button.disabled = true;
                        button.textContent = "Удаляем…";
                        try {
                            await request(
                                "DELETE",
                                `/audits/${encodeURIComponent(auditId)}/reports/${encodeURIComponent(report.id)}`
                            );
                            if (typeof window.showReport === "function") {
                                await window.showReport();
                            }
                            await refreshHistory();
                        } catch (error) {
                            button.disabled = false;
                            button.textContent = "Удалить";
                            window.alert(`Не удалось удалить отчёт: ${error.message}`);
                        }
                    }));
                }

                item.append(head, actions);
                list.append(item);
            });
        } catch (error) {
            list.replaceChildren();
            const failed = document.createElement("p");
            failed.className = "error";
            failed.textContent = `Не удалось загрузить историю отчётов: ${error.message}`;
            list.append(failed);
        }
    }

    function boot() {
        const screen = document.getElementById("screen-report");
        if (!screen) return;
        ensurePanel();

        const observer = new MutationObserver(() => {
            if (!screen.hidden) refreshHistory();
        });
        observer.observe(screen, { attributes: true, attributeFilter: ["hidden"] });

        const status = document.getElementById("report-status");
        if (status) {
            new MutationObserver(() => {
                if (!screen.hidden) refreshHistory();
            }).observe(status, { childList: true, characterData: true, subtree: true });
        }

        if (!screen.hidden) refreshHistory();
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", boot);
    } else {
        boot();
    }
})();
