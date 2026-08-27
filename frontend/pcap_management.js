(() => {
    "use strict";

    const API = "/api/v1";
    const TERMINAL = new Set(["completed", "failed", "cancelled", "interrupted"]);
    let currentRole = null;
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
        if (currentRole !== null) return currentRole === "auditor";
        try {
            const me = await request("GET", "/auth/me");
            currentRole = me && me.role ? String(me.role) : "";
        } catch {
            currentRole = "";
        }
        return currentRole === "auditor";
    }

    function activeCaptureId() {
        try {
            const parsed = JSON.parse(sessionStorage.getItem("wirescope.activeCapture") || "null");
            return parsed && parsed.jobId ? String(parsed.jobId) : "";
        } catch {
            return "";
        }
    }

    function ensureDialog() {
        let modal = document.getElementById("pcap-delete-modal");
        if (modal) return modal;
        modal = document.createElement("div");
        modal.id = "pcap-delete-modal";
        modal.className = "modal";
        modal.hidden = true;
        modal.innerHTML = `
            <div class="dialog" role="alertdialog" aria-modal="true" aria-labelledby="pcap-delete-title" aria-describedby="pcap-delete-body">
                <h2 id="pcap-delete-title">Удалить файл PCAP?</h2>
                <p id="pcap-delete-body">Сырой PCAP будет удалён с устройства. Запись исчезнет из списка сохранённых PCAP. История захвата и уже рассчитанные анализы останутся. Повторно анализировать этот захват без файла PCAP будет нельзя.</p>
                <div class="actions">
                    <button type="button" class="secondary" data-pcap-delete-cancel>Отмена</button>
                    <button type="button" class="danger" data-pcap-delete-confirm>Удалить PCAP</button>
                </div>
            </div>
        `;
        document.body.append(modal);
        return modal;
    }

    function confirmDelete() {
        const modal = ensureDialog();
        const cancel = modal.querySelector("[data-pcap-delete-cancel]");
        const confirm = modal.querySelector("[data-pcap-delete-confirm]");
        modal.hidden = false;
        document.body.classList.add("modal-open");
        confirm.focus();
        return new Promise((resolve) => {
            const finish = (value) => {
                modal.hidden = true;
                document.body.classList.remove("modal-open");
                cancel.removeEventListener("click", onCancel);
                confirm.removeEventListener("click", onConfirm);
                modal.removeEventListener("click", onBackdrop);
                resolve(value);
            };
            const onCancel = () => finish(false);
            const onConfirm = () => finish(true);
            const onBackdrop = (event) => {
                if (event.target === modal) finish(false);
            };
            cancel.addEventListener("click", onCancel);
            confirm.addEventListener("click", onConfirm);
            modal.addEventListener("click", onBackdrop);
        });
    }

    function markRowUnavailable(row) {
        row.querySelectorAll(".pcap-delete-button, .traffic-analysis-button").forEach((node) => node.remove());
        row.querySelectorAll("a, button").forEach((node) => {
            if (/скачать\s+pcap/i.test(node.textContent || "")) node.remove();
        });
        let note = row.querySelector(".pcap-unavailable-note");
        if (!note) {
            note = document.createElement("span");
            note.className = "muted pcap-unavailable-note";
            row.append(note);
        }
        note.textContent = "PCAP недоступен";
    }

    function showEmptyState(list) {
        if (!list || list.querySelector(".session-row") || list.querySelector(".pcap-empty-state")) return;
        const empty = document.createElement("div");
        empty.className = "list-item pcap-empty-state";
        const title = document.createElement("strong");
        title.textContent = "Сохранённых PCAP нет";
        const detail = document.createElement("span");
        detail.textContent = "Создайте новую запись трафика, чтобы она появилась здесь.";
        empty.append(title, detail);
        list.append(empty);
    }

    async function deletePcap(jobId, { row = null, button = null } = {}) {
        if (!jobId || !(await isAuditor())) return false;
        if (!(await confirmDelete())) return false;
        if (button) {
            button.disabled = true;
            button.textContent = "Удаляем…";
        }
        try {
            const result = await request("DELETE", `/captures/${encodeURIComponent(jobId)}/pcap`);
            if (row) {
                const list = row.parentElement;
                row.remove();
                showEmptyState(list);
            }
            const download = document.getElementById("listen-download-button");
            const analyze = document.getElementById("listen-analyze-button");
            const progressDelete = document.getElementById("listen-delete-pcap-button");
            if (activeCaptureId() === jobId) {
                if (download) download.hidden = true;
                if (analyze) analyze.hidden = true;
                if (progressDelete) progressDelete.hidden = true;
                const warning = document.getElementById("listen-progress-warning");
                if (warning) {
                    warning.hidden = false;
                    warning.textContent = result.file_cleanup_pending
                        ? "PCAP исключён из WireScope, но файл не удалось удалить с диска. Проверьте диагностику хранилища."
                        : "PCAP удалён. История записи и уже готовые анализы сохранены.";
                }
            } else if (result.file_cleanup_pending) {
                window.alert("PCAP исключён из WireScope, но файл не удалось удалить с диска. Проверьте диагностику хранилища.");
            }
            scheduleRefresh();
            return true;
        } catch (error) {
            if (button) {
                button.disabled = false;
                button.textContent = "Удалить PCAP";
            }
            const warning = document.getElementById("listen-progress-warning");
            if (warning && activeCaptureId() === jobId) {
                warning.hidden = false;
                warning.textContent = error.code === "pcap_delete_busy"
                    ? "Сначала остановите или дождитесь завершения захвата/анализа, затем удалите PCAP."
                    : `Не удалось удалить PCAP: ${error.message}`;
            } else {
                window.alert(`Не удалось удалить PCAP: ${error.message}`);
            }
            return false;
        }
    }

    function makeDeleteButton(session, row = null) {
        const button = document.createElement("button");
        button.type = "button";
        button.className = "danger pcap-delete-button";
        button.dataset.captureJobId = String(session.job_id);
        button.textContent = "Удалить PCAP";
        button.addEventListener("click", (event) => {
            event.preventDefault();
            event.stopPropagation();
            deletePcap(String(session.job_id), { row, button });
        });
        return button;
    }

    function syncDeleteButton(row, session) {
        const jobId = String(session.job_id);
        let button = row.querySelector(".pcap-delete-button");
        if (button && button.dataset.captureJobId !== jobId) {
            button.remove();
            button = null;
        }
        if (!button) {
            row.append(makeDeleteButton(session, row));
        }
    }

    async function enhanceCaptureRows() {
        const list = document.getElementById("listen-session-list");
        if (!list || list.hidden || !(await isAuditor())) return;
        let page;
        try {
            page = await request("GET", "/captures?limit=20");
        } catch {
            return;
        }
        const rows = Array.from(list.querySelectorAll(".session-row"));
        const sessions = (page && page.items) || [];
        rows.forEach((row, index) => {
            const session = sessions[index];
            if (!session || !TERMINAL.has(session.status)) return;
            if (session.pcap_url) {
                row.querySelector(".pcap-unavailable-note")?.remove();
                syncDeleteButton(row, session);
            } else if (session.result_available) {
                // This is not a manual deletion: manually-deleted rows are
                // filtered from /captures. Keep the warning only for an
                // unexpectedly missing/expired raw file.
                markRowUnavailable(row);
            } else {
                row.querySelector(".pcap-delete-button")?.remove();
            }
        });
    }

    async function updateProgressControls() {
        const screen = document.getElementById("screen-listen-progress");
        const done = document.getElementById("listen-done-button");
        if (!screen || screen.hidden || !done || done.hidden) return;
        const jobId = activeCaptureId();
        if (!jobId) return;
        let session;
        try {
            session = await request("GET", `/captures/${encodeURIComponent(jobId)}`);
        } catch {
            return;
        }
        const download = document.getElementById("listen-download-button");
        const analyze = document.getElementById("listen-analyze-button");
        if (download) download.hidden = !session.pcap_url;
        if (analyze && !session.pcap_url) analyze.hidden = true;

        let button = document.getElementById("listen-delete-pcap-button");
        const allowed = await isAuditor();
        if (!allowed || !session.pcap_url || !TERMINAL.has(session.status)) {
            if (button) button.hidden = true;
            return;
        }
        if (!button) {
            button = makeDeleteButton(session);
            button.id = "listen-delete-pcap-button";
            const parent = download && download.parentElement
                ? download.parentElement
                : (done.parentElement || screen);
            parent.insertBefore(button, done);
        }
        button.hidden = false;
        button.disabled = false;
        button.textContent = "Удалить PCAP";
    }

    function scheduleRefresh() {
        clearTimeout(refreshTimer);
        refreshTimer = setTimeout(() => {
            enhanceCaptureRows();
            updateProgressControls();
        }, 80);
    }

    function boot() {
        ensureDialog();
        const list = document.getElementById("listen-session-list");
        if (list) {
            new MutationObserver(scheduleRefresh).observe(list, {
                childList: true,
                subtree: true,
            });
        }
        const listen = document.getElementById("screen-listen");
        const progress = document.getElementById("screen-listen-progress");
        const done = document.getElementById("listen-done-button");
        [listen, progress, done].filter(Boolean).forEach((node) => {
            new MutationObserver(scheduleRefresh).observe(node, {
                attributes: true,
                attributeFilter: ["hidden"],
            });
        });
        scheduleRefresh();
    }

    window.WireScopePcapManagement = { deletePcap };
    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", boot);
    } else {
        boot();
    }
})();