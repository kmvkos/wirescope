(() => {
    "use strict";

    // Compatibility/runtime fixes kept separate from the large legacy app.js.
    // They are loaded after app.js and before enhancement panels.

    const EXTERNAL_NMAP_STAGES = new Set([
        "discovering_hosts",
        "scanning_tcp",
        "udp_discovery",
    ]);

    const PHASE_COPY = {
        discovering_hosts: "ищем хосты",
        scanning_tcp: "проверяем TCP-порты",
        udp_discovery: "проверяем UDP-порты",
    };

    function normalizeUtcText(value) {
        if (typeof value !== "string") return value;
        const text = value.trim();
        // SQLite can return timezone columns as naive UTC. Treat ISO timestamps
        // without an explicit zone as UTC instead of browser-local time.
        if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?$/.test(text)) {
            return `${text}Z`;
        }
        return text;
    }

    const originalParseTime = window.parseTime;
    if (typeof originalParseTime === "function") {
        window.parseTime = function parseWireScopeTime(value) {
            const normalized = normalizeUtcText(value);
            const ms = Date.parse(normalized);
            return Number.isNaN(ms) ? NaN : ms;
        };
    }

    // A manually entered target is an explicit operator scope. Do not silently
    // append the whole automatically-derived interface prefix to it. If the
    // manual field is empty, keep the derived proposal as the convenient default.
    if (typeof window.combinedTargets === "function") {
        window.combinedTargets = function combinedTargetsOperatorScope() {
            const manual = parseTargets(state.draft.extras || "");
            const source = manual.length ? manual : (state.draft.proposed || []);
            const seen = new Set();
            const result = [];
            source.forEach((item) => {
                const value = String(item || "").trim();
                if (value && !seen.has(value)) {
                    seen.add(value);
                    result.push(value);
                }
            });
            return result;
        };
    }

    function isExternalNmap(job) {
        return Boolean(
            job &&
            job.status === "running" &&
            EXTERNAL_NMAP_STAGES.has(String(job.stage || ""))
        );
    }

    function elapsedFrom(value) {
        const started = window.parseTime ? window.parseTime(value) : NaN;
        if (!Number.isFinite(started)) return "";
        const ms = Math.max(0, Date.now() - started);
        if (typeof window.formatElapsed === "function") return window.formatElapsed(ms);
        return `${Math.floor(ms / 1000)} с`;
    }

    function scopeText(job) {
        const params = (job && job.parameters) || {};
        const scope = Array.isArray(params.scope) ? params.scope : [];
        if (!scope.length) return "";
        return scope.join(", ");
    }

    function profileName(job) {
        return String((((job || {}).parameters || {}).profile) || "").toLowerCase();
    }

    function detailLine(job) {
        if (!job) return "";
        const stage = String(job.stage || "");
        const params = job.parameters || {};
        const iface = params.interface || "";
        const scope = scopeText(job);
        const profile = profileName(job);

        if (job.cancel_requested && !TERMINAL.has(job.status)) {
            if (job.type === "packet_capture") return "Останавливаем dumpcap и сохраняем уже принятые кадры…";
            if (job.type === "active_discovery") return "Останавливаем Nmap и ждём завершения процесса…";
            return "Останавливаем текущее задание…";
        }

        const fixed = {
            queued: "Задание поставлено в очередь и ждёт исполнителя",
            resource_wait: "Ждём освобождения сетевого ресурса",
            starting: "Исполнитель запускает задание",
            preparing_interface: iface ? `Готовим интерфейс ${iface}` : "Готовим сетевой интерфейс",
            starting_capture: iface ? `dumpcap слушает трафик на ${iface}` : "dumpcap слушает трафик",
            saving_capture: "Останавливаем захват и сохраняем PCAP",
            parsing_capture: "tshark разбирает сохранённые пакеты",
            running_sensors: "Пассивные датчики анализируют протоколы и объявления",
            building_assessment: "Собираем пассивную оценку сегмента",
            validating_scope: scope ? `Проверяем подтверждённую область: ${scope}` : "Проверяем подтверждённую область сканирования",
            resolving_route: iface ? `Проверяем маршрут к цели через ${iface}` : "Проверяем маршрут к цели",
            hosts_discovered: I18N.jobMessage(job.message),
            fingerprinting_services: "Разбираем результаты TCP-сканирования и сохраняем службы",
            correlating_observations: "Сопоставляем пассивные и активные наблюдения",
            persisting_inventory: "Сохраняем итоговый список устройств и служб",
            loading_inventory: "Загружаем найденные устройства и службы",
            matching_services: "Выбираем службы для безопасных протокольных проверок",
            summarizing: "Собираем результаты протокольных проверок",
            loading_inputs: "Загружаем наблюдения для анализа слабых мест",
            evaluating_rules: "Применяем правила findings к сохранённым наблюдениям",
            persisting_findings: "Сохраняем найденные проблемы и рекомендации",
            building_report: "Формируем понятный отчёт из сохранённых результатов",
            persisting_report: "Сохраняем HTML, JSON и Markdown отчёта",
        };
        if (fixed[stage]) return fixed[stage];

        if (stage === "discovering_hosts") {
            return scope
                ? `Nmap определяет доступные узлы в ${scope}`
                : "Nmap определяет доступные узлы";
        }
        if (stage === "scanning_tcp") {
            if (profile === "deep") {
                return "Nmap: полный TCP 1–65535 по найденным хостам, версии служб и определение ОС (T3)";
            }
            if (profile === "standard") {
                return "Nmap: TCP top-1000 по найденным хостам, версии служб и определение ОС (T3)";
            }
            return "Nmap проверяет TCP-порты найденных хостов";
        }
        if (stage === "udp_discovery") {
            return profile === "deep"
                ? "Nmap: расширенный набор UDP-портов с определением версий (T3)"
                : "Nmap: выборочная проверка инфраструктурных UDP-портов (T3)";
        }
        if (stage.startsWith("auditing_")) {
            return I18N.jobMessage(job.message);
        }
        return I18N.jobMessage(job.message);
    }

    const originalTiming = window.renderProgressTiming;
    if (typeof originalTiming === "function") {
        window.renderProgressTiming = function renderProgressTimingWithStage(job, jobs) {
            originalTiming(job, jobs);
            if (!job || TERMINAL.has(job.status)) return;
            const activity = document.getElementById("progress-activity");
            if (!activity) return;
            const stageTime = elapsedFrom(job.updated_at || job.started_at || job.created_at);
            const prefix = job.cancel_requested
                ? "запрошена остановка"
                : (isExternalNmap(job) ? "внешний процесс Nmap работает" : "этап выполняется");
            activity.textContent = stageTime ? `${prefix} · этап ${stageTime}` : prefix;
        };
    }

    const originalProgress = window.renderProgress;
    if (typeof originalProgress === "function") {
        window.renderProgress = function renderProgressWithRuntimeState(job, jobs) {
            originalProgress(job, jobs);

            const message = document.getElementById("progress-message");
            if (message) message.textContent = detailLine(job);

            const stop = document.getElementById("stop-audit-button");
            if (stop && job) {
                stop.disabled = Boolean(job.cancel_requested && !TERMINAL.has(job.status));
                stop.textContent = job.cancel_requested && !TERMINAL.has(job.status)
                    ? "Останавливаем…"
                    : t("action.stop");
            }

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
            const current = document.querySelector('#progress-jobs [aria-current="true"]');
            const meta = current && current.querySelector(".job-meta");
            if (meta) meta.textContent = "идёт";
        };
    }

    const originalListenProgress = window.renderListenProgress;
    if (typeof originalListenProgress === "function") {
        window.renderListenProgress = function renderListenProgressWithCancel(job) {
            originalListenProgress(job);
            const stop = document.getElementById("listen-stop-button");
            if (stop) {
                stop.disabled = Boolean(job && job.cancel_requested && !TERMINAL.has(job.status));
                stop.textContent = job && job.cancel_requested && !TERMINAL.has(job.status)
                    ? "Останавливаем…"
                    : t("action.stop");
            }
            const message = document.getElementById("listen-progress-message");
            if (message && job && job.cancel_requested && !TERMINAL.has(job.status)) {
                message.textContent = "Останавливаем dumpcap и сохраняем уже принятые кадры…";
            }
        };
    }

    // app.js accidentally calls showConfirm() here, which navigates to the
    // audit confirmation screen. Intercept the click before the legacy handler
    // and use the modal confirmation instead.
    const listenStop = document.getElementById("listen-stop-button");
    if (listenStop) {
        listenStop.addEventListener("click", async (event) => {
            event.preventDefault();
            event.stopImmediatePropagation();
            if (!state.captureJobId || !canMutate() || listenStop.disabled) return;
            const confirmed = await confirmModal(t("listen.stopTitle"), t("listen.stopBody"));
            if (!confirmed) return;
            listenStop.disabled = true;
            listenStop.textContent = "Останавливаем…";
            const message = document.getElementById("listen-progress-message");
            if (message) message.textContent = "Останавливаем dumpcap и сохраняем уже принятые кадры…";
            try {
                await api("POST", `/api/jobs/${state.captureJobId}/cancel`);
            } catch (error) {
                listenStop.disabled = false;
                listenStop.textContent = t("action.stop");
                if (message) message.textContent = displayError(error);
            }
        }, true);
    }

    // Do not leave the progress screen before the worker has actually stopped
    // Nmap/current tool. Existing pollJob() will observe the terminal state and
    // then route to the summary normally.
    const auditStop = document.getElementById("stop-audit-button");
    if (auditStop) {
        auditStop.addEventListener("click", async (event) => {
            event.preventDefault();
            event.stopImmediatePropagation();
            if (!canMutate() || !state.jobId || auditStop.disabled) return;
            const confirmed = await confirmModal(t("progress.stopTitle"), t("progress.stopBody"));
            if (!confirmed) return;
            auditStop.disabled = true;
            auditStop.textContent = "Останавливаем…";
            const message = document.getElementById("progress-message");
            if (message) message.textContent = "Останавливаем текущее задание и ждём завершения процесса…";
            try {
                await api("POST", `/api/jobs/${state.jobId}/cancel`);
            } catch (error) {
                auditStop.disabled = false;
                auditStop.textContent = t("action.stop");
                if (message) message.textContent = displayError(error);
            }
        }, true);
    }
})();
