(() => {
    "use strict";

    const API = "/api/v1";

    const el = (tag, text, cls) => {
        const node = document.createElement(tag);
        if (text !== undefined && text !== null) node.textContent = String(text);
        if (cls) node.className = cls;
        return node;
    };

    async function request(path, options = {}) {
        const response = await fetch(`${API}${path}`, {
            credentials: "same-origin",
            ...options,
            headers: {
                ...(options.body ? { "Content-Type": "application/json" } : {}),
                ...(options.headers || {}),
            },
        });
        const text = await response.text();
        let data = null;
        if (text) {
            try { data = JSON.parse(text); } catch { data = text; }
        }
        if (!response.ok) {
            const detail = data && data.detail;
            const error = new Error(
                (detail && detail.message) ||
                (typeof detail === "string" ? detail : null) ||
                response.statusText ||
                `HTTP ${response.status}`
            );
            error.status = response.status;
            error.code = detail && detail.code;
            throw error;
        }
        return data;
    }

    function metric(label, value) {
        const box = el("div", null, "ws-metric");
        box.append(el("strong", value ?? "—"), el("span", label));
        return box;
    }

    function sectionTitle(text) { return el("h3", text); }

    function bytes(value) {
        let size = Number(value) || 0;
        const units = ["B", "KiB", "MiB", "GiB", "TiB"];
        let index = 0;
        while (size >= 1024 && index < units.length - 1) {
            size /= 1024;
            index += 1;
        }
        return `${index === 0 ? Math.round(size) : size.toFixed(1)} ${units[index]}`;
    }

    function selectedAuditId() {
        const select = document.getElementById("ws-audit-select");
        return select && select.value ? select.value : "";
    }

    function table(headers) {
        const node = el("table", null, "ws-table");
        const head = el("tr");
        headers.forEach((label) => head.append(el("th", label)));
        node.append(head);
        return node;
    }

    function appendStatusGrid(body, diagnostics) {
        const checks = (diagnostics.runtime && diagnostics.runtime.checks) || {};
        const storage = (diagnostics.lifecycle && diagnostics.lifecycle.storage) || {};
        const database = (diagnostics.lifecycle && diagnostics.lifecycle.database) || {};
        const grid = el("div", null, "ws-metric-grid");
        grid.append(
            metric("Runtime", diagnostics.runtime && diagnostics.runtime.ready ? "готов" : "есть проблемы"),
            metric("SQLite", database.quick_check === "ok" ? "ok" : (database.quick_check || "ошибка")),
            metric("Worker", checks.worker ? "готов" : "нет"),
            metric("Core tools", checks.core_tools ? "готовы" : "неполный набор"),
            metric("Свободно", bytes(storage.filesystem_free_bytes)),
            metric("Evidence", bytes(storage.evidence_bytes))
        );
        body.append(sectionTitle("Состояние устройства"), grid);
    }

    function appendRetention(body, diagnostics) {
        const retention = diagnostics.lifecycle.retention || {};
        const policy = retention.policy || {};
        const candidates = retention.candidates || {};
        body.append(sectionTitle("Хранилище и retention"));
        const grid = el("div", null, "ws-metric-grid");
        grid.append(
            metric("К удалению", candidates.count || 0),
            metric("Объём", bytes(candidates.bytes)),
            metric("PCAP", `${policy.packet_capture_days || "—"} дн.`),
            metric("Raw evidence", `${policy.raw_provider_days || "—"} дн.`),
            metric("Debug", `${policy.debug_days || "—"} дн.`)
        );
        body.append(grid);

        const actions = el("div", null, "actions wrap ws-section");
        const preview = el("button", "Предпросмотр очистки", "secondary");
        const cleanup = el("button", "Удалить старые raw-артефакты", "danger");
        const result = el("div", null, "ws-section");
        actions.append(preview, cleanup);
        body.append(actions, result);

        preview.addEventListener("click", async () => {
            result.replaceChildren(el("p", "Проверяем…"));
            try {
                const data = await request("/maintenance/cleanup", {
                    method: "POST",
                    body: JSON.stringify({ confirm: false, include_raw: true }),
                });
                const item = data.would_delete || {};
                result.replaceChildren(
                    el("p", `Будет удалено: ${item.count || 0} артефактов, ${bytes(item.bytes)}. Нормализованные данные аудитов и отчёты не удаляются.`)
                );
            } catch (error) {
                result.replaceChildren(el("p", error.message, "error"));
            }
        });

        cleanup.addEventListener("click", async () => {
            const ok = window.confirm(
                "Удалить устаревшие PCAP и raw provider evidence по текущей retention policy? Нормализованный inventory, findings и reports останутся."
            );
            if (!ok) return;
            result.replaceChildren(el("p", "Очистка…"));
            try {
                const data = await request("/maintenance/cleanup", {
                    method: "POST",
                    body: JSON.stringify({ confirm: true, include_raw: true }),
                });
                const removed = data.deleted || {};
                result.replaceChildren(
                    el("p", `Удалено: ${removed.artifact_rows || 0} записей / ${removed.files || 0} файлов / ${bytes(removed.bytes)}.`)
                );
            } catch (error) {
                result.replaceChildren(el("p", error.message, "error"));
            }
        });
    }

    async function appendRecovery(body) {
        const auditId = selectedAuditId();
        if (!auditId) return;
        body.append(sectionTitle("Восстановление заданий"));
        const section = el("div", null, "ws-section");
        body.append(section);
        try {
            const page = await request(`/audits/${encodeURIComponent(auditId)}/jobs?limit=100`);
            const retryable = (page.items || []).filter((job) =>
                ["failed", "interrupted", "cancelled"].includes(job.status)
            );
            if (!retryable.length) {
                section.append(el("p", "Нет заданий, требующих повторного запуска."));
                return;
            }
            for (const job of retryable) {
                const row = el("div", null, "ws-recovery-row");
                const copy = el("div");
                copy.append(
                    el("strong", `${job.type} · ${job.status}`),
                    el("div", job.message || job.error?.message || job.id)
                );
                const retry = el("button", "Повторить этап", "secondary");
                retry.addEventListener("click", async () => {
                    retry.disabled = true;
                    try {
                        const accepted = await request(`/jobs/${encodeURIComponent(job.id)}/retry`, { method: "POST" });
                        retry.textContent = `Поставлено: ${accepted.job_id.slice(0, 8)}`;
                    } catch (error) {
                        retry.disabled = false;
                        retry.textContent = `Ошибка: ${error.message}`;
                    }
                });
                row.append(copy, retry);
                section.append(row);
            }
        } catch (error) {
            section.append(el("p", error.message, "error"));
        }
    }

    function appendAuditLog(body, diagnostics) {
        body.append(sectionTitle("Последние действия"));
        const recent = ((diagnostics.audit_log || {}).recent || []).slice(0, 20);
        if (!recent.length) {
            body.append(el("p", "Журнал пока пуст."));
            return;
        }
        const node = table(["Время", "Кто", "Действие", "HTTP", "IP"]);
        recent.forEach((item) => {
            const row = el("tr");
            row.append(
                el("td", item.created_at || "—"),
                el("td", item.actor || "—"),
                el("td", item.action),
                el("td", `${item.method} ${item.status_code}`),
                el("td", item.client_ip || "—")
            );
            node.append(row);
        });
        body.append(node);
    }

    function appendDiagnosticsExport(body) {
        const actions = el("div", null, "actions wrap ws-section");
        const download = el("button", "Скачать диагностику JSON", "secondary");
        download.addEventListener("click", () => {
            window.location.href = `${API}/diagnostics/export`;
        });
        actions.append(download);
        body.append(actions);
    }

    async function renderOperations() {
        const body = document.getElementById("ws-insights-body");
        if (!body) return;
        body.replaceChildren(el("p", "Проверяем состояние WireScope…"));
        try {
            const diagnostics = await request("/diagnostics");
            body.replaceChildren();
            appendStatusGrid(body, diagnostics);
            appendRetention(body, diagnostics);
            await appendRecovery(body);
            appendAuditLog(body, diagnostics);
            appendDiagnosticsExport(body);
        } catch (error) {
            body.replaceChildren(el("p", error.message, "error"));
        }
    }

    async function boot() {
        try {
            const me = await request("/auth/me");
            if (me.role !== "auditor") return;
        } catch {
            return;
        }

        const tabs = document.querySelector(".ws-insights-tabs");
        if (!tabs || tabs.querySelector('[data-ws-tab="operations"]')) return;
        const button = el("button", "Эксплуатация", "secondary");
        button.dataset.wsTab = "operations";
        tabs.append(button);
        tabs.addEventListener("click", (event) => {
            const target = event.target.closest('button[data-ws-tab="operations"]');
            if (!target) return;
            renderOperations();
        });
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", boot);
    } else {
        boot();
    }
})();
