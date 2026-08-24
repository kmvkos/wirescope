(() => {
    "use strict";

    const API = "/api/v1";
    const ACTIVE_KEY = "wirescope.activeAudit";
    let selectedAudit = "";
    let audits = [];
    let refreshTimer = null;

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
            throw new Error((detail && detail.message) || response.statusText || "API error");
        }
        return data;
    }

    function activeAuditId() {
        try {
            const parsed = JSON.parse(sessionStorage.getItem(ACTIVE_KEY) || "null");
            if (parsed && parsed.auditId) return parsed.auditId;
        } catch {}
        return selectedAudit;
    }

    function clear(node) { node.replaceChildren(); }

    function metric(label, value) {
        const box = el("div", null, "ws-metric");
        box.append(el("strong", value ?? "—"), el("span", label));
        return box;
    }

    function sectionTitle(text) { return el("h3", text); }

    function stageLabel(value) {
        return ({
            passive: "Пассивный анализ",
            discovery: "Discovery",
            protocol: "Протоколы",
            findings: "Findings",
            report: "Отчёт",
        })[value] || value;
    }

    function pipeline(data) {
        const wrap = el("div", null, "ws-inline-pipeline");
        (data || []).forEach((item) => {
            const stage = el("div", null, "ws-pipeline-stage");
            stage.dataset.status = item.status || "pending";
            stage.append(
                el("strong", stageLabel(item.stage)),
                el("span", item.status || "не запускался"),
                el("span", item.progress === null || item.progress === undefined ? "" : `${item.progress}%`)
            );
            wrap.append(stage);
        });
        return wrap;
    }

    async function loadAudits() {
        const page = await request("/audits?limit=100");
        audits = (page.items || []).filter((item) => item.profile !== "packet_capture");
        if (!selectedAudit) selectedAudit = activeAuditId() || (audits[0] && audits[0].id) || "";
        const select = document.getElementById("ws-audit-select");
        if (!select) return;
        clear(select);
        audits.forEach((audit) => {
            const option = el("option", `${audit.profile} · ${audit.interface || "—"} · ${audit.status}`);
            option.value = audit.id;
            option.selected = audit.id === selectedAudit;
            select.append(option);
        });
    }

    async function renderOverview(body) {
        clear(body);
        if (!selectedAudit) {
            body.append(el("p", "Нет выбранного аудита."));
            return;
        }
        const [data, correlations] = await Promise.all([
            request(`/audits/${encodeURIComponent(selectedAudit)}/dashboard`),
            request(`/audits/${encodeURIComponent(selectedAudit)}/correlations`),
        ]);
        const inv = data.inventory || {};
        const findings = data.findings || {};
        const severity = findings.by_severity || {};
        const grid = el("div", null, "ws-metric-grid");
        grid.append(
            metric("Узлы", inv.assets),
            metric("Сервисы", inv.services),
            metric("Findings", findings.total),
            metric("Critical", severity.critical || 0),
            metric("High", severity.high || 0),
            metric("Passive + active", `${correlations.correlated_assets || 0}/${correlations.total_assets || 0}`)
        );
        body.append(grid, sectionTitle("Pipeline"), pipeline(data.pipeline));

        body.append(sectionTitle("Классы устройств"));
        const classesGrid = el("div", null, "ws-metric-grid");
        Object.entries(inv.device_classes || {}).forEach(([name, count]) => classesGrid.append(metric(name, count)));
        if (!classesGrid.children.length) classesGrid.append(el("p", "Пока нет классифицированных устройств."));
        body.append(classesGrid);

        body.append(sectionTitle("Частые сервисы"));
        const table = el("table", null, "ws-table");
        const head = el("tr");
        head.append(el("th", "Сервис"), el("th", "Количество"));
        table.append(head);
        (data.common_services || []).forEach((item) => {
            const row = el("tr");
            row.append(el("td", item.name), el("td", item.count));
            table.append(row);
        });
        body.append(table);
    }

    async function renderCapabilities(body) {
        clear(body);
        const [caps, profiles] = await Promise.all([
            request("/capabilities"),
            request("/scan-profiles"),
        ]);

        body.append(sectionTitle("Web-интерфейс"));
        const web = caps.web || {};
        const webGrid = el("div", null, "ws-metric-grid");
        webGrid.append(
            metric("Bind", `${web.bind_host || "—"}:${web.bind_port || "—"}`),
            metric("Все интерфейсы", web.all_interfaces ? "да" : "нет"),
            metric("TLS", web.tls ? "включён" : "нет"),
            metric("Trust proxy", web.trust_proxy ? "да" : "нет")
        );
        body.append(webGrid);

        body.append(sectionTitle("Возможности хоста"));
        const table = el("table", null, "ws-table");
        const h = el("tr");
        h.append(el("th", "Функция"), el("th", "Инструмент"), el("th", "Статус"), el("th", "Путь"));
        table.append(h);
        (caps.tools || []).forEach((item) => {
            const row = el("tr");
            const status = el("td", item.available ? "доступно" : "нет", item.available ? "ws-ok" : "ws-missing");
            row.append(el("td", item.capability), el("td", item.tool), status, el("td", item.path || item.configured_binary));
            table.append(row);
        });
        body.append(table);

        body.append(sectionTitle("Профили активного обнаружения"));
        Object.entries((profiles && profiles.profiles) || {}).forEach(([name, profile]) => {
            const block = el("div", null, "ws-section");
            block.append(el("strong", name));
            const details = [
                `timing ${profile.timing}`,
                profile.tcp_top_ports ? `TCP top ${profile.tcp_top_ports}` : (profile.tcp_ports ? `TCP ${profile.tcp_ports}` : "без TCP scan"),
                profile.udp_ports && profile.udp_ports.length ? `UDP ${profile.udp_ports.length} ports` : "без UDP scan",
                profile.service_detection ? "service detection" : "без service detection",
                `timeout ${profile.timeout_seconds}s`,
            ];
            block.append(el("p", details.join(" · ")));
            body.append(block);
        });
    }

    function diffGroup(title, items) {
        const box = el("div", null, "ws-section");
        box.append(sectionTitle(`${title} (${(items || []).length})`));
        if (!(items || []).length) {
            box.append(el("p", "Нет изменений."));
            return box;
        }
        (items || []).slice(0, 100).forEach((item) => {
            const text = item.label || item.title || [
                item.asset,
                item.protocol && `${item.protocol}/${item.port}`,
                item.service,
            ].filter(Boolean).join(" · ") || JSON.stringify(item);
            box.append(el("div", text));
        });
        return box;
    }

    async function renderDiff(body) {
        clear(body);
        if (!selectedAudit) return body.append(el("p", "Нет выбранного аудита."));
        const candidates = audits.filter((item) => item.id !== selectedAudit);
        if (!candidates.length) return body.append(el("p", "Для сравнения нужен как минимум ещё один аудит."));
        const label = el("label", "Сравнить с: ");
        const select = el("select");
        candidates.forEach((audit) => {
            const option = el("option", `${audit.profile} · ${audit.interface || "—"} · ${audit.id.slice(0, 8)}`);
            option.value = audit.id;
            select.append(option);
        });
        const button = el("button", "Сравнить", "secondary");
        const result = el("div", null, "ws-section");
        label.append(select);
        body.append(label, button, result);
        button.addEventListener("click", async () => {
            clear(result);
            try {
                const data = await request(`/audits/${encodeURIComponent(selectedAudit)}/diff?against=${encodeURIComponent(select.value)}`);
                result.append(
                    diffGroup("Новые узлы", data.assets.added),
                    diffGroup("Исчезнувшие узлы", data.assets.removed),
                    diffGroup("Новые сервисы", data.services.added),
                    diffGroup("Исчезнувшие сервисы", data.services.removed),
                    diffGroup("Новые findings", data.findings.added),
                    diffGroup("Исчезнувшие findings", data.findings.removed)
                );
            } catch (error) {
                result.append(el("p", error.message, "error"));
            }
        });
    }

    async function renderEvidence(body) {
        clear(body);
        if (!selectedAudit) return body.append(el("p", "Нет выбранного аудита."));
        const auditId = encodeURIComponent(selectedAudit);
        const page = await request(`/audits/${auditId}/findings?limit=100`);
        if (!(page.items || []).length) return body.append(el("p", "Findings отсутствуют."));

        for (const finding of page.items) {
            const block = el("div", null, "ws-section");
            const button = el("button", `[${finding.severity}] ${finding.title}`, "secondary");
            const details = el("div");
            block.append(button, details);
            button.addEventListener("click", async () => {
                clear(details);
                try {
                    const evidence = await request(`/audits/${auditId}/findings/${encodeURIComponent(finding.id)}/evidence`);
                    if (!(evidence.items || []).length) {
                        details.append(el("p", "Для этого finding evidence не зарегистрирован."));
                        return;
                    }
                    for (const item of evidence.items) {
                        if (!item.available) {
                            details.append(el("p", `${item.id}: artifact отсутствует`, "ws-missing"));
                            continue;
                        }
                        const line = el("div", null, "ws-section");
                        const open = el("button", `${item.artifact_type} · ${item.size} B`, "secondary");
                        const raw = el("pre", null, "ws-pre");
                        raw.hidden = true;
                        line.append(open, raw);
                        details.append(line);

                        open.addEventListener("click", async () => {
                            const artifactUrl = item.url || `/api/v1/audits/${auditId}/artifacts/${encodeURIComponent(item.id)}`;
                            try {
                                const response = await fetch(artifactUrl, { credentials: "same-origin" });
                                if (!response.ok) throw new Error(response.statusText || `HTTP ${response.status}`);
                                const contentType = response.headers.get("content-type") || "";
                                if (/text|json|xml|ndjson/.test(contentType)) {
                                    raw.textContent = await response.text();
                                    raw.hidden = !raw.hidden;
                                } else {
                                    window.open(artifactUrl, "_blank", "noopener");
                                }
                            } catch (error) {
                                raw.textContent = error.message;
                                raw.hidden = false;
                            }
                        });
                    }
                } catch (error) {
                    details.append(el("p", error.message, "error"));
                }
            });
            body.append(block);
        }
    }

    async function renderTab(name) {
        const body = document.getElementById("ws-insights-body");
        if (!body) return;
        body.replaceChildren(el("p", "Загрузка…"));
        try {
            if (name === "overview") await renderOverview(body);
            else if (name === "capabilities") await renderCapabilities(body);
            else if (name === "diff") await renderDiff(body);
            else if (name === "evidence") await renderEvidence(body);
        } catch (error) {
            clear(body);
            body.append(el("p", error.message, "error"));
        }
    }

    function buildPanel() {
        if (document.getElementById("ws-insights")) return;
        const backdrop = el("div", null, "ws-insights-backdrop");
        backdrop.id = "ws-insights-backdrop";
        backdrop.hidden = true;
        const panel = el("section", null, "ws-insights");
        panel.id = "ws-insights";
        panel.hidden = true;
        const head = el("div", null, "ws-insights-head");
        head.append(el("h2", "Обзор WireScope"));
        const close = el("button", "Закрыть", "secondary");
        head.append(close);
        const controls = el("div", null, "ws-insights-controls");
        const auditSelect = el("select");
        auditSelect.id = "ws-audit-select";
        controls.append(el("span", "Аудит:"), auditSelect);
        const tabs = el("div", null, "ws-insights-tabs");
        const tabNames = [
            ["overview", "Обзор"],
            ["capabilities", "Система"],
            ["diff", "Сравнение"],
            ["evidence", "Evidence"],
        ];
        tabNames.forEach(([key, label]) => {
            const button = el("button", label, key === "overview" ? "primary" : "secondary");
            button.dataset.wsTab = key;
            tabs.append(button);
        });
        const body = el("div");
        body.id = "ws-insights-body";
        panel.append(head, controls, tabs, body);
        const toggle = el("button", "Обзор", "primary ws-insights-toggle");
        toggle.id = "ws-insights-toggle";
        document.body.append(backdrop, panel, toggle);

        let currentTab = "overview";
        const open = async () => {
            backdrop.hidden = false;
            panel.hidden = false;
            await loadAudits();
            await renderTab(currentTab);
        };
        const hide = () => {
            backdrop.hidden = true;
            panel.hidden = true;
        };
        toggle.addEventListener("click", open);
        close.addEventListener("click", hide);
        backdrop.addEventListener("click", hide);
        auditSelect.addEventListener("change", async () => {
            selectedAudit = auditSelect.value;
            await renderTab(currentTab);
        });
        tabs.addEventListener("click", async (event) => {
            const button = event.target.closest("button[data-ws-tab]");
            if (!button) return;
            currentTab = button.dataset.wsTab;
            tabs.querySelectorAll("button").forEach((item) => {
                item.className = item === button ? "primary" : "secondary";
            });
            await renderTab(currentTab);
        });

        const sessionChip = document.getElementById("session-chip");
        const syncVisibility = () => {
            const signedIn = Boolean(sessionChip && !sessionChip.hidden);
            toggle.hidden = !signedIn;
            if (!signedIn) hide();
        };
        if (sessionChip) {
            new MutationObserver(syncVisibility).observe(sessionChip, {
                attributes: true,
                attributeFilter: ["hidden"],
            });
        }
        syncVisibility();
    }

    function setupMarkdownExport() {
        const jsonButton = document.getElementById("download-json-report");
        if (!jsonButton || document.getElementById("download-markdown-report")) return;

        const markdownButton = el("button", "Экспорт Markdown", "secondary");
        markdownButton.type = "button";
        markdownButton.id = "download-markdown-report";
        markdownButton.hidden = jsonButton.hidden;
        jsonButton.insertAdjacentElement("afterend", markdownButton);

        const syncVisibility = () => {
            markdownButton.hidden = jsonButton.hidden;
        };
        new MutationObserver(syncVisibility).observe(jsonButton, {
            attributes: true,
            attributeFilter: ["hidden"],
        });

        markdownButton.addEventListener("click", async () => {
            const auditId = activeAuditId();
            if (!auditId) return;
            try {
                const page = await request(`/audits/${encodeURIComponent(auditId)}/reports?limit=1`);
                const latest = page && page.items && page.items[0];
                if (!latest) return;
                const url = `${API}/audits/${encodeURIComponent(auditId)}/reports/${encodeURIComponent(latest.id)}/export?format=markdown`;
                window.location.assign(url);
            } catch (error) {
                console.error("WireScope Markdown export failed", error);
            }
        });
    }

    async function renderInlineDashboard() {
        const auditId = activeAuditId();
        if (!auditId) return;
        const target = [
            document.getElementById("screen-progress"),
            document.getElementById("screen-summary"),
        ].find((node) => node && !node.hidden);
        if (!target) return;
        let box = target.querySelector(".ws-inline-dashboard");
        if (!box) {
            box = el("div", null, "ws-inline-dashboard");
            const heading = target.querySelector("h2");
            if (heading && heading.nextSibling) target.insertBefore(box, heading.nextSibling);
            else target.prepend(box);
        }
        try {
            const data = await request(`/audits/${encodeURIComponent(auditId)}/dashboard`);
            clear(box);
            const inv = data.inventory || {};
            const f = data.findings || {};
            const metrics = el("div", null, "ws-metric-grid");
            metrics.append(
                metric("Узлы", inv.assets),
                metric("Сервисы", inv.services),
                metric("Findings", f.total)
            );
            box.append(metrics, pipeline(data.pipeline));
        } catch {}
    }

    function startInlineRefresh() {
        if (refreshTimer) clearInterval(refreshTimer);
        renderInlineDashboard();
        refreshTimer = setInterval(renderInlineDashboard, 2500);
    }

    function boot() {
        buildPanel();
        setupMarkdownExport();
        startInlineRefresh();
    }

    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot);
    else boot();
})();
