(() => {
    "use strict";

    // Active discovery reports coarse stage boundaries (15/35/82%) while an
    // external Nmap process is running. Those values are not Nmap completion
    // percentages, so presenting them as exact progress is misleading.
    const EXTERNAL_NMAP_STAGES = new Set([
        "discovering_hosts",
        "scanning_tcp",
        "udp_discovery",
    ]);

    const STAGE_COPY = {
        discovering_hosts: "Nmap ищет доступные узлы",
        scanning_tcp: "Nmap проверяет TCP-порты",
        udp_discovery: "Nmap проверяет выбранные UDP-порты",
    };

    const PHASE_COPY = {
        discovering_hosts: "ищем хосты",
        scanning_tcp: "проверяем TCP-порты",
        udp_discovery: "проверяем UDP-порты",
    };

    function isExternalNmap(job) {
        return Boolean(
            job &&
            job.status === "running" &&
            EXTERNAL_NMAP_STAGES.has(String(job.stage || ""))
        );
    }

    function stageElapsed(job) {
        if (!job || typeof window.parseTime !== "function") return "";
        const started = window.parseTime(job.updated_at) || window.parseTime(job.started_at);
        if (!Number.isFinite(started)) return "";
        const ms = Math.max(0, Date.now() - started);
        if (typeof window.formatElapsed === "function") return window.formatElapsed(ms);
        return `${Math.floor(ms / 1000)} с`;
    }

    const originalTiming = window.renderProgressTiming;
    if (typeof originalTiming === "function") {
        window.renderProgressTiming = function renderProgressTimingWithNmapState(job, jobs) {
            originalTiming(job, jobs);
            if (!isExternalNmap(job)) return;
            const activity = document.getElementById("progress-activity");
            if (!activity) return;
            const elapsed = stageElapsed(job);
            const copy = STAGE_COPY[job.stage] || "Nmap выполняет внешний этап";
            activity.textContent = elapsed ? `${copy} · этап ${elapsed}` : copy;
        };
    }

    const originalProgress = window.renderProgress;
    if (typeof originalProgress === "function") {
        window.renderProgress = function renderProgressWithNmapState(job, jobs) {
            originalProgress(job, jobs);
            if (!isExternalNmap(job)) return;

            const phase = document.getElementById("progress-stage");
            const ring = document.getElementById("progress-ring");
            const arc = document.getElementById("progress-ring-value");
            const label = document.getElementById("progress-ring-label");
            if (phase) phase.textContent = PHASE_COPY[job.stage] || "активное сканирование";
            if (ring) {
                ring.classList.add("indeterminate");
                ring.setAttribute("aria-busy", "true");
            }
            if (arc) arc.style.strokeDashoffset = "0";
            if (label) label.textContent = "…";

            // Keep the horizontal pipeline position, but do not repeat a fake
            // precise percentage in the current job row.
            const current = document.querySelector('#progress-jobs [aria-current="true"]');
            const meta = current && current.querySelector(".job-meta");
            if (meta) meta.textContent = "идёт";
        };
    }
})();
