(() => {
    "use strict";

    const API = "/api/v1";
    const TERMINAL = new Set(["completed", "failed", "cancelled", "interrupted"]);
    let rowRefreshTimer = null;
    let activeAnalysisJobId = "";
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

    async function currentUser() {
        try { return await request("GET", "/auth/me"); } catch { return null; }
    }

    function activeCaptureId() {
        try {
            const parsed = JSON.parse(sessionStorage.getItem("wirescope.activeCapture") || "null");
            return parsed && parsed.jobId ? String(parsed.jobId) : "";
        } catch {
            return "";
        }
    }

    function ensureModal() {
        let modal = document.getElementById("traffic-analysis-modal");
        if (modal) return modal;

        modal = document.createElement("div");
        modal.id = "traffic-analysis-modal";
        modal.className = "traffic-analysis-modal";
        modal.hidden = true;
        modal.innerHTML = `
            <section class="traffic-analysis-card" role="dialog" aria-modal="true" aria-labelledby="traffic-analysis-title">
                <div class="traffic-analysis-head">
                    <div>
                        <span class="traffic-analysis-kicker">PCAP TRAFFIC ANALYSIS</span>
                        <h2 id="traffic-analysis-title">Анализ сетевого трафика</h2>
                    </div>
                    <button type="button" class="secondary traffic-analysis-close">Закрыть</button>
                </div>
                <div class="traffic-analysis-status">
                    <strong id="traffic-analysis-state">Подготовка…</strong>
                    <span id="traffic-analysis-message">Проверяем сохранённый PCAP</span>
                    <div class="traffic-analysis-progress"><span id="traffic-analysis-progress-fill"></span></div>
                </div>
                <div id="traffic-analysis-error" class="error" hidden></div>
                <div id="traffic-analysis-actions" class="actions wrap" hidden>
                    <a id="traffic-analysis-txt" class="button secondary" href="#">TXT</a>
                    <a id="traffic-analysis-md" class="button secondary" href="#">Markdown</a>
                    <a id="traffic-analysis-json" class="button secondary" href="#">JSON</a>
                    <button id="traffic-analysis-stop" type="button" class="danger" hidden>Стоп</button>
                </div>
                <pre id="traffic-analysis-report" class="traffic-analysis-report">Запускаем анализ…</pre>
            </section>
        `;
        document.body.append(modal);
        modal.querySelector(".traffic-analysis-close").addEventListener("click", closeModal);
        modal.addEventListener("click", (event) => {
            if (event.target === modal) closeModal();
        });
        document.getElementById("traffic-analysis-stop").addEventListener("click", async () => {
            if (!activeAnalysisJobId) return;
            const button = document.getElementById("traffic-analysis-stop");
            button.disabled = true;
            button.textContent = "Останавливаем…";
            try {
                await request("POST", `/jobs/${encodeURIComponent(activeAnalysisJobId)}/cancel`);
            } catch (error) {
                showError(`Не удалось остановить анализ: ${error.message}`);
            }
        });
        return modal;
    }

    function closeModal() {
        pollToken += 1;
        const modal = ensureModal();
        modal.hidden = true;
        document.body.classList.remove("traffic-analysis-open");
    }

    function showError(message) {
        const error = document.getElementById("traffic-analysis-error");
        if (!error) return;
        error.hidden = !message;
        error.textContent = message || "";
    }

    function openModal() {
        const modal = ensureModal();
        modal.hidden = false;
        document.body.classList.add("traffic-analysis-open");
        showError("");
        document.getElementById("traffic-analysis-actions").hidden = true;
        document.getElementById("traffic-analysis-report").textContent = "Запускаем анализ сохранённого PCAP…";
        document.getElementById("traffic-analysis-progress-fill").style.width = "0%";
    }

    function exportUrl(jobId, format) {
        return `${API}/jobs/${encodeURIComponent(jobId)}/traffic-analysis/export?format=${format}`;
    }

    function updateJobUi(job) {
        const percent = Math.max(0, Math.min(100, Number(job.progress) || 0));
        const state = document.getElementById("traffic-analysis-state");
        const message = document.getElementById("traffic-analysis-message");
        const fill = document.getElementById("traffic-analysis-progress-fill");
        state.textContent = job.status === "completed"
            ? "Анализ готов"
            : job.status === "failed"
                ? "Анализ завершился ошибкой"
                : job.status === "cancelled"
                    ? "Анализ остановлен"
                    : `Анализируем PCAP · ${percent}%`;
        message.textContent = job.message || job.stage || "Выполняется анализ";
        fill.style.width = `${job.status === "completed" ? 100 : percent}%`;
        const stop = document.getElementById("traffic-analysis-stop");
        stop.hidden = TERMINAL.has(job.status);
        stop.disabled = false;
        stop.textContent = "Стоп";
    }

    async function showCompleted(jobId) {
        const report = document.getElementById("traffic-analysis-report");
        const actions = document.getElementById("traffic-analysis-actions");
        const txt = document.getElementById("traffic-analysis-txt");
        const md = document.getElementById("traffic-analysis-md");
        const json = document.getElementById("traffic-analysis-json");
        txt.href = exportUrl(jobId, "text");
        md.href = exportUrl(jobId, "markdown");
        json.href = exportUrl(jobId, "json");
        actions.hidden = false;
        try {
            const response = await fetch(exportUrl(jobId, "text"), {
                credentials: "same-origin",
                headers: { "Accept": "text/plain" },
            });
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            report.textContent = await response.text();
        } catch (error) {
            report.textContent = `Анализ завершён, но текстовое представление не загрузилось: ${error.message}`;
        }
    }

    async function pollAnalysis(jobId) {
        activeAnalysisJobId = jobId;
        const myToken = ++pollToken;
        while (myToken === pollToken) {
            let job;
            try {
                job = await request("GET", `/jobs/${encodeURIComponent(jobId)}`);
            } catch (error) {
                showError(`Не удалось получить состояние анализа: ${error.message}`);
                return;
            }
            if (myToken !== pollToken) return;
            updateJobUi(job);
            if (job.status === "completed") {
                await showCompleted(jobId);
                return;
            }
            if (TERMINAL.has(job.status)) {
                const detail = job.error && job.error.message ? `: ${job.error.message}` : "";
                showError(`Анализ не завершён${detail}`);
                document.getElementById("traffic-analysis-report").textContent =
                    "Можно закрыть окно и запустить анализ повторно.";
                return;
            }
            await new Promise((resolve) => setTimeout(resolve, 1000));
        }
    }

    async function analyzeCapture(captureJobId) {
        openModal();
        try {
            const accepted = await request(
                "POST",
                `/captures/${encodeURIComponent(captureJobId)}/analyze`
            );
            await pollAnalysis(accepted.job_id);
        } catch (error) {
            showError(`Не удалось запустить анализ PCAP: ${error.message}`);
            document.getElementById("traffic-analysis-report").textContent = "Анализ не запущен.";
        }
    }

    function analysisButton(captureJobId) {
        const button = document.createElement("button");
        button.type = "button";
        button.className = "secondary traffic-analysis-button";
        button.textContent = "Анализировать";
        button.addEventListener("click", (event) => {
            event.stopPropagation();
            analyzeCapture(captureJobId);
        });
        return button;
    }

    async function enhanceCaptureRows() {
        const list = document.getElementById("listen-session-list");
        if (!list || list.hidden) return;
        let page;
        let me;
        try {
            [page, me] = await Promise.all([
                request("GET", "/captures?limit=20"),
                currentUser(),
            ]);
        } catch {
            return;
        }
        if (!me || me.role !== "auditor") return;
        const rows = Array.from(list.querySelectorAll(".session-row"));
        const sessions = (page && page.items) || [];
        rows.forEach((row, index) => {
            const session = sessions[index];
            if (!session || row.querySelector(".traffic-analysis-button")) return;
            if (!session.pcap_url || !TERMINAL.has(session.status)) return;
            row.append(analysisButton(session.job_id));
        });
    }

    function scheduleRowEnhancement() {
        clearTimeout(rowRefreshTimer);
        rowRefreshTimer = setTimeout(enhanceCaptureRows, 80);
    }

    async function updateProgressAnalyzeButton() {
        const screen = document.getElementById("screen-listen-progress");
        const done = document.getElementById("listen-done-button");
        if (!screen || screen.hidden || !done || done.hidden) return;
        const captureJobId = activeCaptureId();
        if (!captureJobId) return;
        const me = await currentUser();
        if (!me || me.role !== "auditor") return;
        let session;
        try { session = await request("GET", `/captures/${encodeURIComponent(captureJobId)}`); } catch { return; }
        let button = document.getElementById("listen-analyze-button");
        if (!session.pcap_url || !TERMINAL.has(session.status)) {
            if (button) button.hidden = true;
            return;
        }
        if (!button) {
            button = analysisButton(captureJobId);
            button.id = "listen-analyze-button";
            const parent = done.parentElement || screen;
            parent.append(button);
        }
        button.hidden = false;
        button.onclick = (event) => {
            event.stopPropagation();
            analyzeCapture(captureJobId);
        };
    }

    function boot() {
        ensureModal();
        const list = document.getElementById("listen-session-list");
        if (list) {
            new MutationObserver(scheduleRowEnhancement).observe(list, {
                childList: true,
                subtree: true,
            });
            scheduleRowEnhancement();
        }
        const listenScreen = document.getElementById("screen-listen");
        if (listenScreen) {
            new MutationObserver(() => {
                if (!listenScreen.hidden) scheduleRowEnhancement();
            }).observe(listenScreen, { attributes: true, attributeFilter: ["hidden"] });
        }
        const progressScreen = document.getElementById("screen-listen-progress");
        const done = document.getElementById("listen-done-button");
        if (progressScreen) {
            new MutationObserver(updateProgressAnalyzeButton).observe(progressScreen, {
                attributes: true,
                attributeFilter: ["hidden"],
            });
        }
        if (done) {
            new MutationObserver(updateProgressAnalyzeButton).observe(done, {
                attributes: true,
                attributeFilter: ["hidden"],
            });
        }
    }

    window.WireScopeTrafficAnalysis = { analyzeCapture };
    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", boot);
    } else {
        boot();
    }
})();
