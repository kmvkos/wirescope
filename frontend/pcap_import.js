(() => {
    "use strict";

    const API = "/api/v1";
    const TERMINAL = new Set(["completed", "failed", "cancelled", "interrupted"]);
    let role = null;
    let refreshTimer = null;
    let pollToken = 0;

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
            const error = new Error(
                (detail && detail.message) ||
                (data && data.message) ||
                response.statusText ||
                `HTTP ${response.status}`
            );
            error.code = detail && detail.code;
            error.status = response.status;
            throw error;
        }
        return data;
    }

    async function isAuditor() {
        if (role !== null) return role === "auditor";
        try {
            const me = await request("GET", "/auth/me");
            role = me && me.role ? String(me.role) : "";
        } catch {
            role = "";
        }
        return role === "auditor";
    }

    function ensureImportCard() {
        let card = document.getElementById("pcap-import-card");
        if (card) return card;
        const list = document.getElementById("listen-session-list");
        if (!list) return null;
        card = document.createElement("div");
        card.id = "pcap-import-card";
        card.className = "card compact";
        card.innerHTML = `
            <h3>Импорт PCAP</h3>
            <p class="hint">Добавьте внешний PCAP/PCAPNG для офлайн-анализа. Импорт не выполняет сетевых запросов и не создаёт активный scope.</p>
            <label for="pcap-import-file">Файл PCAP или PCAPNG</label>
            <input id="pcap-import-file" type="file" accept=".pcap,.pcapng,application/vnd.tcpdump.pcap,application/x-pcapng">
            <p id="pcap-import-file-meta" class="hint">Лимит по умолчанию: 256 МиБ. Его можно изменить политикой устройства.</p>
            <div class="actions wrap">
                <button id="pcap-import-submit" type="button" class="secondary">Импортировать PCAP</button>
            </div>
            <p id="pcap-import-status" class="callout" hidden></p>
            <p id="pcap-import-error" class="error" role="alert" hidden></p>
        `;
        const sessionsHeading = list.previousElementSibling;
        if (sessionsHeading && sessionsHeading.tagName === "H3") {
            sessionsHeading.before(card);
        } else {
            list.before(card);
        }
        const input = card.querySelector("#pcap-import-file");
        const submit = card.querySelector("#pcap-import-submit");
        input.addEventListener("change", updateFileMeta);
        submit.addEventListener("click", uploadSelected);
        return card;
    }

    function formatBytes(bytes) {
        const value = Number(bytes) || 0;
        if (value < 1024) return `${value} B`;
        if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KiB`;
        return `${(value / (1024 * 1024)).toFixed(1)} MiB`;
    }

    function updateFileMeta() {
        const input = document.getElementById("pcap-import-file");
        const meta = document.getElementById("pcap-import-file-meta");
        const file = input && input.files && input.files[0];
        if (!meta) return;
        meta.textContent = file
            ? `${file.name} · ${formatBytes(file.size)}`
            : "Лимит по умолчанию: 256 МиБ. Его можно изменить политикой устройства.";
    }

    function setMessage(id, message) {
        const node = document.getElementById(id);
        if (!node) return;
        node.hidden = !message;
        node.textContent = message || "";
    }

    async function uploadSelected() {
        if (!(await isAuditor())) return;
        const input = document.getElementById("pcap-import-file");
        const button = document.getElementById("pcap-import-submit");
        const file = input && input.files && input.files[0];
        setMessage("pcap-import-error", "");
        if (!file) {
            setMessage("pcap-import-error", "Выберите файл .pcap или .pcapng.");
            return;
        }
        button.disabled = true;
        button.textContent = "Загружаем…";
        setMessage("pcap-import-status", `Загрузка ${file.name}…`);
        try {
            const response = await fetch(`${API}/captures/import`, {
                method: "POST",
                credentials: "same-origin",
                headers: {
                    "Accept": "application/json",
                    "Content-Type": "application/octet-stream",
                    "X-WireScope-Filename": encodeURIComponent(file.name),
                },
                body: file,
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
                    response.statusText ||
                    `HTTP ${response.status}`
                );
                error.code = detail && detail.code;
                throw error;
            }
            setMessage("pcap-import-status", "Файл принят. WireScope проверяет и сохраняет PCAP…");
            refreshListenScreen();
            await pollImport(String(data.job_id || ""), file.name);
        } catch (error) {
            const prefix = error.code === "pcap_import_too_large"
                ? "Файл превышает разрешённый размер"
                : error.code === "pcap_import_unsupported"
                    ? "Это не поддерживаемый PCAP/PCAPNG"
                    : "Не удалось импортировать PCAP";
            setMessage("pcap-import-error", `${prefix}: ${error.message}`);
            setMessage("pcap-import-status", "");
        } finally {
            button.disabled = false;
            button.textContent = "Импортировать PCAP";
        }
    }

    async function pollImport(jobId, filename) {
        if (!jobId) return;
        const token = ++pollToken;
        while (token === pollToken) {
            let job;
            try {
                job = await request("GET", `/jobs/${encodeURIComponent(jobId)}`);
            } catch (error) {
                setMessage("pcap-import-error", `Не удалось получить состояние импорта: ${error.message}`);
                return;
            }
            if (token !== pollToken) return;
            if (job.status === "completed") {
                setMessage("pcap-import-status", `${filename} импортирован. Теперь его можно анализировать как обычный сохранённый PCAP.`);
                const input = document.getElementById("pcap-import-file");
                if (input) input.value = "";
                updateFileMeta();
                refreshListenScreen();
                return;
            }
            if (TERMINAL.has(job.status)) {
                const detail = job.error && job.error.message ? job.error.message : (job.message || job.status);
                setMessage("pcap-import-error", `Импорт не завершён: ${detail}`);
                setMessage("pcap-import-status", "");
                refreshListenScreen();
                return;
            }
            const percent = Math.max(0, Math.min(100, Number(job.progress) || 0));
            setMessage("pcap-import-status", `Импортируем ${filename} · ${percent}% · ${job.message || job.stage || "обработка"}`);
            await new Promise((resolve) => setTimeout(resolve, 700));
        }
    }

    function refreshListenScreen() {
        const button = document.getElementById("listen-button");
        if (button) button.click();
        scheduleDecorate();
    }

    async function decorateImportedRows() {
        const list = document.getElementById("listen-session-list");
        if (!list || list.hidden) return;
        let page;
        try {
            page = await request("GET", "/captures?limit=20");
        } catch {
            return;
        }
        const sessions = (page && page.items) || [];
        const rows = Array.from(list.querySelectorAll(".session-row"));
        rows.forEach((row, index) => {
            const session = sessions[index];
            if (!session || session.source_origin !== "imported") return;
            const button = row.querySelector(".list-item");
            const title = button && button.querySelector("strong");
            const meta = button && button.querySelector("span");
            if (title) {
                const status = String(title.textContent || "").split(" · ")[0] || "PCAP";
                title.textContent = `${status} · Импорт PCAP · ${session.original_filename || "внешний файл"}`;
            }
            if (meta) {
                const format = String(session.capture_format || "pcap").toUpperCase();
                meta.textContent = [format, session.pcap_bytes != null ? formatBytes(session.pcap_bytes) : ""].filter(Boolean).join(" · ");
            }
            row.dataset.pcapOrigin = "imported";
        });
    }

    function scheduleDecorate() {
        clearTimeout(refreshTimer);
        refreshTimer = setTimeout(decorateImportedRows, 100);
    }

    async function syncVisibility() {
        const card = ensureImportCard();
        if (!card) return;
        card.hidden = !(await isAuditor());
        if (!card.hidden) scheduleDecorate();
    }

    function boot() {
        ensureImportCard();
        const list = document.getElementById("listen-session-list");
        if (list) {
            new MutationObserver(scheduleDecorate).observe(list, { childList: true, subtree: true });
        }
        const screen = document.getElementById("screen-listen");
        if (screen) {
            new MutationObserver(() => {
                if (!screen.hidden) {
                    syncVisibility();
                    scheduleDecorate();
                }
            }).observe(screen, { attributes: true, attributeFilter: ["hidden"] });
        }
        syncVisibility();
        scheduleDecorate();
    }

    window.WireScopePcapImport = { uploadSelected };
    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", boot);
    } else {
        boot();
    }
})();
