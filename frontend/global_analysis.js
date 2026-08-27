(() => {
    "use strict";

    const API = "/api/v1";
    const TERMINAL = new Set(["completed", "failed", "cancelled", "interrupted"]);
    let activeAuditId = "";
    let activeJobId = "";
    let currentDocument = null;
    let currentUser = null;
    let pollToken = 0;

    async function request(method, path, body) {
        const options = {
            method,
            credentials: "same-origin",
            headers: { "Accept": "application/json" },
        };
        if (body !== undefined) {
            options.headers["Content-Type"] = "application/json";
            options.body = JSON.stringify(body);
        }
        const response = await fetch(`${API}${path}`, options);
        const text = await response.text();
        let data = null;
        if (text) {
            try { data = JSON.parse(text); } catch { data = text; }
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

    function el(tag, className, text) {
        const node = document.createElement(tag);
        if (className) node.className = className;
        if (text !== undefined && text !== null) node.textContent = String(text);
        return node;
    }

    function shortId(value) {
        const text = String(value || "");
        return text ? text.slice(0, 8) : "—";
    }

    function formatDate(value) {
        if (!value) return "—";
        try { return new Date(value).toLocaleString("ru-RU"); } catch { return String(value); }
    }

    function formatBytes(value) {
        const bytes = Number(value) || 0;
        if (bytes < 1024) return `${bytes} B`;
        if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
        if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
        return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GiB`;
    }

    function statusLabel(value) {
        const labels = {
            completed: "готов",
            running: "выполняется",
            queued: "в очереди",
            failed: "ошибка",
            cancelled: "остановлен",
            interrupted: "прерван",
            consistent: "согласовано",
            divergent: "расхождение",
            insufficient: "недостаточно данных",
            sufficient: "достаточно",
            partial: "частично",
            missing: "нет данных",
            unknown: "неизвестно",
            service_traffic_observed: "трафик сервиса наблюдался",
            asset_traffic_observed: "трафик asset наблюдался",
            uncorrelated: "не сопоставлено с PCAP",
        };
        const raw = String(value || "unknown");
        return labels[raw] || raw;
    }

    function statusClass(value) {
        const raw = String(value || "unknown");
        if (["completed", "consistent", "sufficient"].includes(raw)) return "ok";
        if (["failed", "divergent", "missing"].includes(raw)) return "bad";
        if (["partial", "insufficient", "cancelled", "interrupted"].includes(raw)) return "warn";
        if (["queued", "running"].includes(raw)) return "active";
        return "neutral";
    }

    function ensureModal() {
        let modal = document.getElementById("global-analysis-modal");
        if (modal) return modal;
        modal = document.createElement("div");
        modal.id = "global-analysis-modal";
        modal.className = "global-analysis-modal";
        modal.hidden = true;
        modal.innerHTML = `
            <section class="global-analysis-card" role="dialog" aria-modal="true" aria-labelledby="global-analysis-title">
                <header class="ga-head">
                    <div>
                        <span class="ga-kicker">GLOBAL CORRELATION ANALYSIS</span>
                        <h2 id="global-analysis-title">Глобальный анализ</h2>
                        <p class="ga-subtitle">Inventory + Findings + выбранный PCAP Traffic Analysis + Network Topology</p>
                    </div>
                    <button type="button" class="secondary ga-close">Закрыть</button>
                </header>
                <div id="ga-error" class="error" hidden></div>
                <div class="ga-layout">
                    <aside class="ga-sidebar">
                        <label for="ga-audit-select">Аудит</label>
                        <select id="ga-audit-select"></select>
                        <div id="ga-audit-meta" class="ga-meta"></div>
                        <label for="ga-traffic-select">Traffic Analysis</label>
                        <select id="ga-traffic-select"></select>
                        <p class="ga-note">PCAP выбирается явно. Global Analysis не запускает scanner и не перечитывает PCAP.</p>
                        <button id="ga-run" type="button" class="primary">Запустить анализ</button>
                        <div class="ga-history-head">
                            <h3>История</h3>
                            <button id="ga-refresh-history" type="button" class="secondary compact">Обновить</button>
                        </div>
                        <div id="ga-history" class="ga-history"></div>
                    </aside>
                    <main class="ga-main">
                        <section class="ga-status-panel">
                            <div>
                                <strong id="ga-state">Выберите аудит</strong>
                                <span id="ga-message">Здесь появится сохранённый результат или можно запустить новый.</span>
                            </div>
                            <div class="ga-progress"><span id="ga-progress-fill"></span></div>
                        </section>
                        <div id="ga-actions" class="actions wrap" hidden>
                            <a id="ga-export-json" class="button secondary" href="#">JSON</a>
                            <a id="ga-export-text" class="button secondary" href="#">TXT</a>
                            <a id="ga-export-md" class="button secondary" href="#">Markdown</a>
                            <button id="ga-rebuild" type="button" class="secondary">Пересобрать</button>
                            <button id="ga-cancel" type="button" class="danger" hidden>Стоп</button>
                        </div>
                        <section id="ga-content" class="ga-content">
                            <div class="ga-empty">Выберите аудит слева.</div>
                        </section>
                    </main>
                </div>
            </section>
        `;
        document.body.append(modal);
        modal.querySelector(".ga-close").addEventListener("click", closeModal);
        modal.addEventListener("click", (event) => {
            if (event.target === modal) closeModal();
        });
        document.getElementById("ga-audit-select").addEventListener("change", async (event) => {
            activeAuditId = String(event.target.value || "");
            currentDocument = null;
            activeJobId = "";
            await loadAuditWorkspace();
        });
        document.getElementById("ga-run").addEventListener("click", () => startAnalysis(null));
        document.getElementById("ga-rebuild").addEventListener("click", () => {
            if (activeJobId) startAnalysis(activeJobId);
        });
        document.getElementById("ga-cancel").addEventListener("click", cancelActive);
        document.getElementById("ga-refresh-history").addEventListener("click", loadHistory);
        return modal;
    }

    function setError(message) {
        const node = document.getElementById("ga-error");
        if (!node) return;
        node.hidden = !message;
        node.textContent = message || "";
    }

    function openModal() {
        const modal = ensureModal();
        modal.hidden = false;
        document.body.classList.add("global-analysis-open");
        setError("");
    }

    function closeModal() {
        pollToken += 1;
        const modal = ensureModal();
        modal.hidden = true;
        document.body.classList.remove("global-analysis-open");
    }

    async function bootUser() {
        try { currentUser = await request("GET", "/auth/me"); } catch { currentUser = null; }
        const run = document.getElementById("ga-run");
        const rebuild = document.getElementById("ga-rebuild");
        if (run) run.hidden = !(currentUser && currentUser.role === "auditor");
        if (rebuild) rebuild.hidden = !(currentUser && currentUser.role === "auditor");
    }

    function auditLabel(audit) {
        return `${formatDate(audit.created_at)} · ${audit.profile || "—"} · ${audit.interface || "—"} · ${shortId(audit.id)}`;
    }

    function trafficLabel(item) {
        return `${formatDate(item.created_at)} · ${item.interface || "—"} · ${shortId(item.job_id)}`;
    }

    async function populateAudits() {
        const select = document.getElementById("ga-audit-select");
        select.replaceChildren();
        const page = await request("GET", "/audits?limit=100");
        const audits = (page.items || []).filter((audit) => audit.profile !== "packet_capture");
        if (!audits.length) {
            const option = el("option", "", "Нет сохранённых аудитов");
            option.value = "";
            select.append(option);
            activeAuditId = "";
            return [];
        }
        audits.forEach((audit) => {
            const option = el("option", "", auditLabel(audit));
            option.value = String(audit.id);
            select.append(option);
        });
        const preferred = audits.find((audit) => audit.profile === "deep" && audit.status === "completed")
            || audits.find((audit) => audit.status === "completed")
            || audits[0];
        if (!activeAuditId || !audits.some((audit) => audit.id === activeAuditId)) {
            activeAuditId = String(preferred.id);
        }
        select.value = activeAuditId;
        return audits;
    }

    async function populateTraffic() {
        const select = document.getElementById("ga-traffic-select");
        select.replaceChildren();
        const page = await request("GET", "/traffic-analysis?limit=100");
        const items = (page && page.items) || [];
        if (!items.length) {
            const option = el("option", "", "Нет завершённых Traffic Analysis");
            option.value = "";
            select.append(option);
            return [];
        }
        items.forEach((item) => {
            const option = el("option", "", trafficLabel(item));
            option.value = String(item.job_id);
            select.append(option);
        });
        return items;
    }

    async function openWorkspace() {
        openModal();
        document.getElementById("ga-state").textContent = "Загрузка…";
        document.getElementById("ga-message").textContent = "Читаем сохранённые audits и Traffic Analysis.";
        try {
            await bootUser();
            await Promise.all([populateAudits(), populateTraffic()]);
            await loadAuditWorkspace();
        } catch (error) {
            setError(`Не удалось открыть Global Analysis: ${error.message}`);
            document.getElementById("ga-state").textContent = "Ошибка";
        }
    }

    async function loadAuditWorkspace() {
        pollToken += 1;
        if (!activeAuditId) return;
        setError("");
        try {
            const audit = await request("GET", `/audits/${encodeURIComponent(activeAuditId)}`);
            document.getElementById("ga-audit-meta").textContent = [
                audit.status,
                audit.profile,
                audit.interface || "без интерфейса",
                `ID ${shortId(audit.id)}`,
            ].join(" · ");
            await loadHistory();
        } catch (error) {
            setError(`Не удалось загрузить аудит: ${error.message}`);
        }
    }

    function historyButton(item) {
        const button = el("button", `ga-history-item ${statusClass(item.status)}`);
        button.type = "button";
        const title = el("strong", "", `${statusLabel(item.status)} · ${formatDate(item.created_at)}`);
        const meta = el(
            "span",
            "",
            `GA ${shortId(item.job_id)} · Traffic ${shortId(item.traffic_analysis_job_id)}${item.rebuild_of_job_id ? ` · rebuild ${shortId(item.rebuild_of_job_id)}` : ""}`
        );
        button.append(title, meta);
        if (item.partial === true) button.append(el("em", "ga-history-partial", "partial"));
        button.addEventListener("click", async () => {
            activeJobId = String(item.job_id || "");
            if (item.result_available) {
                await loadResult(activeJobId);
            } else if (!TERMINAL.has(String(item.status))) {
                await pollJob(activeJobId);
            } else {
                showJobFailure(item);
            }
        });
        return button;
    }

    async function loadHistory() {
        const container = document.getElementById("ga-history");
        container.replaceChildren();
        if (!activeAuditId) return;
        try {
            const page = await request("GET", `/audits/${encodeURIComponent(activeAuditId)}/global-analysis/history?limit=50`);
            const items = (page && page.items) || [];
            if (!items.length) {
                container.append(el("div", "ga-empty-small", "Сохранённых Global Analysis пока нет."));
                resetResult("Выберите Traffic Analysis и запустите первый анализ.");
                return;
            }
            items.forEach((item) => container.append(historyButton(item)));
            const latest = items.find((item) => item.result_available);
            const active = items.find((item) => !TERMINAL.has(String(item.status)));
            if (active) {
                activeJobId = String(active.job_id);
                await pollJob(activeJobId);
            } else if (latest && (!activeJobId || !items.some((item) => item.job_id === activeJobId))) {
                activeJobId = String(latest.job_id);
                await loadResult(activeJobId);
            }
        } catch (error) {
            container.append(el("div", "ga-empty-small", `История недоступна: ${error.message}`));
        }
    }

    function resetResult(message) {
        currentDocument = null;
        activeJobId = "";
        document.getElementById("ga-actions").hidden = true;
        document.getElementById("ga-cancel").hidden = true;
        document.getElementById("ga-progress-fill").style.width = "0%";
        document.getElementById("ga-state").textContent = "Global Analysis не запускался";
        document.getElementById("ga-message").textContent = message || "";
        const content = document.getElementById("ga-content");
        content.replaceChildren(el("div", "ga-empty", message || "Нет результата"));
    }

    async function startAnalysis(rebuildOfJobId) {
        if (!activeAuditId) return;
        if (!currentUser || currentUser.role !== "auditor") {
            setError("Viewer может читать Global Analysis, но не запускать новый job.");
            return;
        }
        const trafficJobId = String(document.getElementById("ga-traffic-select").value || "");
        if (!trafficJobId) {
            setError("Сначала выберите завершённый Traffic Analysis.");
            return;
        }
        if (rebuildOfJobId && currentDocument) {
            const previousTraffic = String((currentDocument.inputs || {}).traffic_analysis_job_id || "");
            if (previousTraffic && previousTraffic !== trafficJobId) {
                document.getElementById("ga-traffic-select").value = previousTraffic;
            }
        }
        const sourceTraffic = rebuildOfJobId && currentDocument
            ? String((currentDocument.inputs || {}).traffic_analysis_job_id || trafficJobId)
            : trafficJobId;
        const body = { traffic_analysis_job_id: sourceTraffic };
        if (rebuildOfJobId) body.rebuild_of_job_id = rebuildOfJobId;
        setError("");
        try {
            const accepted = await request(
                "POST",
                `/audits/${encodeURIComponent(activeAuditId)}/global-analysis`,
                body
            );
            activeJobId = String(accepted.job_id);
            await loadHistory();
            await pollJob(activeJobId);
        } catch (error) {
            setError(`Не удалось запустить Global Analysis: ${error.message}`);
        }
    }

    async function cancelActive() {
        if (!activeJobId) return;
        try {
            await request("POST", `/jobs/${encodeURIComponent(activeJobId)}/cancel`);
        } catch (error) {
            setError(`Не удалось остановить job: ${error.message}`);
        }
    }

    function updateJob(job) {
        const percent = Math.max(0, Math.min(100, Number(job.progress) || 0));
        document.getElementById("ga-state").textContent = `Global Analysis · ${statusLabel(job.status)}`;
        document.getElementById("ga-message").textContent = job.message || job.stage || "";
        document.getElementById("ga-progress-fill").style.width = `${job.status === "completed" ? 100 : percent}%`;
        const cancel = document.getElementById("ga-cancel");
        cancel.hidden = TERMINAL.has(job.status) || !(currentUser && currentUser.role === "auditor");
    }

    async function pollJob(jobId) {
        const token = ++pollToken;
        activeJobId = jobId;
        while (token === pollToken) {
            let job;
            try {
                job = await request("GET", `/jobs/${encodeURIComponent(jobId)}`);
            } catch (error) {
                setError(`Не удалось получить состояние Global Analysis: ${error.message}`);
                return;
            }
            if (token !== pollToken) return;
            updateJob(job);
            if (job.status === "completed") {
                await loadResult(jobId);
                await loadHistoryWithoutAutoload();
                return;
            }
            if (TERMINAL.has(job.status)) {
                showJobFailure(job);
                await loadHistoryWithoutAutoload();
                return;
            }
            await new Promise((resolve) => setTimeout(resolve, 1000));
        }
    }

    function showJobFailure(job) {
        currentDocument = null;
        document.getElementById("ga-actions").hidden = true;
        document.getElementById("ga-cancel").hidden = true;
        document.getElementById("ga-state").textContent = `Global Analysis · ${statusLabel(job.status)}`;
        const detail = job.error && job.error.message ? job.error.message : (job.message || "Результат не создан");
        document.getElementById("ga-message").textContent = detail;
        const content = document.getElementById("ga-content");
        content.replaceChildren(el("div", "ga-empty", detail));
    }

    async function loadHistoryWithoutAutoload() {
        const container = document.getElementById("ga-history");
        container.replaceChildren();
        try {
            const page = await request("GET", `/audits/${encodeURIComponent(activeAuditId)}/global-analysis/history?limit=50`);
            ((page && page.items) || []).forEach((item) => container.append(historyButton(item)));
        } catch (error) {
            container.append(el("div", "ga-empty-small", `История недоступна: ${error.message}`));
        }
    }

    async function loadResult(jobId) {
        setError("");
        try {
            const documentData = await request("GET", `/jobs/${encodeURIComponent(jobId)}/global-analysis`);
            activeJobId = jobId;
            currentDocument = documentData;
            renderDocument(documentData);
        } catch (error) {
            setError(`Не удалось прочитать Global Analysis: ${error.message}`);
        }
    }

    function metric(label, value, detail) {
        const card = el("div", "ga-metric");
        card.append(el("span", "", label), el("strong", "", value));
        if (detail) card.append(el("small", "", detail));
        return card;
    }

    function section(title) {
        const node = el("section", "ga-section");
        node.append(el("h3", "", title));
        return node;
    }

    function renderSummary(documentData, content) {
        const summary = documentData.summary || {};
        const box = section("Сводка");
        const grid = el("div", "ga-metrics");
        grid.append(
            metric("Assets", Number(summary.inventory_assets) || 0, `${Number(summary.inventory_assets_observed_in_traffic) || 0} видны в PCAP`),
            metric("Services", Number(summary.services) || 0, `${Number(summary.services_observed_in_traffic) || 0} наблюдались`),
            metric("Findings", Number(summary.findings) || 0, "сопоставление с traffic ниже"),
            metric("External", Number(summary.external_communications) || 0, "только global IP"),
            metric("Traffic endpoints", Number(summary.traffic_endpoints) || 0, `${Number(summary.unmatched_traffic_endpoints) || 0} не сопоставлены`),
            metric("State", documentData.partial ? "PARTIAL" : "COMPLETE", documentData.network_io === false ? "offline / no network I/O" : "")
        );
        box.append(grid);
        content.append(box);
    }

    function renderOperatorSummary(documentData, content) {
        const operator = documentData.operator_summary || {};
        const box = section(operator.headline || "Операторская сводка");
        const list = el("ul", "ga-summary-lines");
        (operator.lines || []).forEach((line) => list.append(el("li", "", line)));
        if (!list.children.length) list.append(el("li", "", "Сводка отсутствует."));
        box.append(list);
        content.append(box);
    }

    function renderConsistency(documentData, content) {
        const box = section("Infrastructure consistency");
        const grid = el("div", "ga-consistency-grid");
        const consistency = documentData.infrastructure_consistency || {};
        ["gateway", "dhcp", "dns"].forEach((name) => {
            const row = consistency[name] || {};
            const card = el("article", `ga-consistency ${statusClass(row.status)}`);
            const head = el("div", "ga-consistency-head");
            head.append(el("strong", "", name.toUpperCase()), el("span", "ga-pill", statusLabel(row.status)));
            card.append(head);
            const sources = row.sources || {};
            Object.keys(sources).forEach((source) => {
                const values = (sources[source] || []).join(", ") || "—";
                const line = el("p", "ga-source-line");
                line.append(el("b", "", `${source}: `), document.createTextNode(values));
                card.append(line);
            });
            if ((row.common_values || []).length) {
                card.append(el("p", "ga-common", `Общее: ${(row.common_values || []).join(", ")}`));
            }
            grid.append(card);
        });
        box.append(grid);
        content.append(box);
    }

    function countBy(rows, key) {
        const result = {};
        (rows || []).forEach((row) => {
            const value = String((row && row[key]) || "unknown");
            result[value] = (result[value] || 0) + 1;
        });
        return result;
    }

    function renderCoverage(documentData, content) {
        const box = section("Coverage и качество evidence");
        const health = documentData.source_health || {};
        const healthRow = el("div", "ga-health-row");
        Object.keys(health).sort().forEach((name) => {
            const value = health[name];
            healthRow.append(el("span", `ga-health ${statusClass(value)}`, `${name}: ${statusLabel(value)}`));
        });
        box.append(healthRow);
        const coverage = documentData.coverage || {};
        const inventoryMissing = (coverage.inventory_assets_not_observed || []).length;
        const trafficUnknown = (coverage.unmatched_traffic_endpoints || []).length;
        const note = el("p", "ga-note", `Inventory assets вне visibility выбранного capture: ${inventoryMissing}. Traffic endpoints без exact inventory identity: ${trafficUnknown}.`);
        box.append(note);
        content.append(box);
    }

    function renderFindingRelevance(documentData, content) {
        const box = section("Findings ↔ Traffic relevance");
        const counts = countBy(documentData.finding_traffic_relevance || [], "traffic_relevance");
        const grid = el("div", "ga-relevance-grid");
        ["service_traffic_observed", "asset_traffic_observed", "uncorrelated"].forEach((key) => {
            grid.append(metric(statusLabel(key), counts[key] || 0));
        });
        box.append(grid);
        const correlated = (documentData.finding_traffic_relevance || []).filter((row) => row.traffic_relevance !== "uncorrelated");
        if (correlated.length) {
            const table = el("div", "ga-table");
            correlated.slice(0, 30).forEach((row) => {
                const line = el("div", "ga-table-row");
                line.append(
                    el("strong", "", shortId(row.finding_id)),
                    el("span", "", row.severity || "—"),
                    el("span", "", statusLabel(row.traffic_relevance)),
                    el("span", "", row.asset_id ? `asset ${shortId(row.asset_id)}` : "—")
                );
                table.append(line);
            });
            box.append(table);
        }
        content.append(box);
    }

    function protocolList(rows) {
        const values = [];
        (rows || []).forEach((row) => {
            const value = row && typeof row === "object" ? (row.name || row.protocol) : row;
            if (value && !values.includes(String(value))) values.push(String(value));
        });
        return values.join(", ") || "—";
    }

    function portList(rows) {
        const values = [];
        (rows || []).forEach((row) => {
            const value = row && typeof row === "object" ? row.port : row;
            if (value && !values.includes(String(value))) values.push(String(value));
        });
        return values.join(", ") || "—";
    }

    function renderExternal(documentData, content) {
        const box = section("Internal ↔ External communications");
        const rows = [...(documentData.external_communications || [])].sort(
            (a, b) => (Number(b.bytes) || 0) - (Number(a.bytes) || 0)
        );
        if (!rows.length) {
            box.append(el("p", "ga-note", "Exact-correlated assets с global external endpoints в выбранном PCAP не обнаружены."));
            content.append(box);
            return;
        }
        const table = el("div", "ga-table ga-external-table");
        const header = el("div", "ga-table-row ga-table-header");
        ["Asset", "External endpoint", "Traffic", "Protocols / ports"].forEach((name) => header.append(el("strong", "", name)));
        table.append(header);
        rows.slice(0, 50).forEach((row) => {
            const line = el("div", "ga-table-row");
            line.append(
                el("span", "", shortId(row.asset_id)),
                el("code", "", row.external_endpoint || "—"),
                el("span", "", `${Number(row.packets) || 0} pkt · ${formatBytes(row.bytes)}`),
                el("span", "", `${protocolList(row.protocols)} · ${portList(row.ports)}`)
            );
            table.append(line);
        });
        box.append(table);
        content.append(box);
    }

    function renderWarnings(documentData, content) {
        const warnings = (documentData.warnings || []).filter(Boolean);
        if (!warnings.length) return;
        const box = section("Warnings и ограничения");
        const list = el("ul", "ga-warnings");
        warnings.forEach((warning) => list.append(el("li", "", warning)));
        box.append(list);
        content.append(box);
    }

    function renderEvidence(documentData, content) {
        const lineage = documentData.evidence_references || {};
        const details = el("details", "ga-evidence");
        details.append(el("summary", "", "Evidence lineage"));
        const traffic = lineage.traffic_analysis || {};
        details.append(el("p", "", `Traffic job: ${traffic.job_id || "—"} · artifact: ${traffic.artifact_id || "—"}`));
        const topology = lineage.topology || {};
        details.append(el("p", "", `Topology: ${topology.schema || "—"} v${topology.schema_version || "—"} · artifacts: ${(topology.artifact_ids || []).length}`));
        const inventory = lineage.inventory || {};
        const findings = lineage.findings || {};
        details.append(el("p", "", `Assets refs: ${(inventory.asset_ids || []).length} · Service refs: ${(inventory.service_ids || []).length} · Finding refs: ${(findings.finding_ids || []).length}`));
        content.append(details);
    }

    function renderDocument(documentData) {
        const content = document.getElementById("ga-content");
        content.replaceChildren();
        const inputs = documentData.inputs || {};
        document.getElementById("ga-state").textContent = documentData.partial ? "Global Analysis · PARTIAL" : "Global Analysis · COMPLETE";
        document.getElementById("ga-message").textContent = `Generated ${formatDate(documentData.generated_at)} · Traffic ${shortId(inputs.traffic_analysis_job_id)}`;
        document.getElementById("ga-progress-fill").style.width = "100%";
        const actions = document.getElementById("ga-actions");
        actions.hidden = false;
        document.getElementById("ga-cancel").hidden = true;
        document.getElementById("ga-export-json").href = `${API}/jobs/${encodeURIComponent(activeJobId)}/global-analysis/export?format=json`;
        document.getElementById("ga-export-text").href = `${API}/jobs/${encodeURIComponent(activeJobId)}/global-analysis/export?format=text`;
        document.getElementById("ga-export-md").href = `${API}/jobs/${encodeURIComponent(activeJobId)}/global-analysis/export?format=markdown`;
        const rebuild = document.getElementById("ga-rebuild");
        rebuild.hidden = !(currentUser && currentUser.role === "auditor");
        if (inputs.traffic_analysis_job_id) {
            const select = document.getElementById("ga-traffic-select");
            if ([...select.options].some((option) => option.value === String(inputs.traffic_analysis_job_id))) {
                select.value = String(inputs.traffic_analysis_job_id);
            }
        }
        renderSummary(documentData, content);
        renderOperatorSummary(documentData, content);
        renderConsistency(documentData, content);
        renderCoverage(documentData, content);
        renderFindingRelevance(documentData, content);
        renderExternal(documentData, content);
        renderWarnings(documentData, content);
        renderEvidence(documentData, content);
    }

    function installHomeButton() {
        const actions = document.querySelector("#screen-home .actions");
        if (!actions || document.getElementById("global-analysis-button")) return;
        const button = el("button", "secondary", "Глобальный анализ");
        button.id = "global-analysis-button";
        button.type = "button";
        button.addEventListener("click", openWorkspace);
        const listen = document.getElementById("listen-button");
        if (listen && listen.nextSibling) actions.insertBefore(button, listen.nextSibling);
        else actions.append(button);
    }

    function boot() {
        ensureModal();
        installHomeButton();
        const home = document.getElementById("screen-home");
        if (home) {
            new MutationObserver(installHomeButton).observe(home, {
                attributes: true,
                childList: true,
                subtree: true,
                attributeFilter: ["hidden"],
            });
        }
    }

    window.WireScopeGlobalAnalysis = { open: openWorkspace };
    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", boot);
    } else {
        boot();
    }
})();
