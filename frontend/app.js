const ACTIVE_KEY = "wirescope.activeAudit";
const DRAFT_KEY = "wirescope.draft";
const TERMINAL = new Set(["completed", "failed", "cancelled", "interrupted"]);
const PIPELINES = {
    passive: ["passive"],
    discovery: ["passive", "discovery"],
    standard: ["passive", "discovery", "protocol", "findings", "report"],
    deep: ["passive", "discovery", "protocol", "findings", "report"],
};

const state = {
    user: null,
    draft: defaultDraft(),
    auditId: null,
    jobId: null,
    pipeline: [],
    pipelineIndex: 0,
    pollDelay: 1000,
    pollTimer: null,
    stopping: false,
};

function defaultDraft() {
    return {
        interface: "",
        vlan: "",
        targets: "",
        profile: "passive",
        duration: 30,
        authorized: false,
    };
}

function $(id) {
    return document.getElementById(id);
}

function showScreen(name) {
    document.querySelectorAll(".screen").forEach((section) => {
        section.hidden = section.dataset.screen !== name;
    });
    $("header-subtitle").textContent =
        name === "login" ? "Network audit appliance" : screenTitle(name);
}

function screenTitle(name) {
    return {
        home: "Audits",
        environment: "New audit · environment",
        interface: "New audit · interface",
        scope: "New audit · scope",
        profile: "New audit · profile",
        confirm: "New audit · confirm",
        progress: "Audit progress",
        summary: "Audit summary",
        assets: "Assets and services",
        observations: "Observations",
        assessment: "Assessment",
        findings: "Findings",
        report: "Report",
    }[name] || "WireScope";
}

async function api(method, path, body) {
    const options = {
        method,
        credentials: "same-origin",
        headers: {},
    };
    if (body !== undefined) {
        options.headers["Content-Type"] = "application/json";
        options.body = JSON.stringify(body);
    }
    const response = await fetch(path, options);
    if (response.status === 204) {
        return null;
    }
    const text = await response.text();
    let data = null;
    if (text) {
        try {
            data = JSON.parse(text);
        } catch {
            data = { message: text };
        }
    }
    if (!response.ok) {
        const detail = data && data.detail;
        const error = new Error(
            (detail && detail.message) ||
            (typeof detail === "string" ? detail : null) ||
            response.statusText
        );
        error.status = response.status;
        error.code = detail && detail.code;
        error.detail = detail;
        throw error;
    }
    return data;
}

function setStatus(kind, label) {
    const element = $("system-status");
    element.textContent = label;
    element.className = `status ${kind}`;
}

function setSessionChip() {
    const chip = $("session-chip");
    if (!state.user) {
        chip.hidden = true;
        return;
    }
    chip.hidden = false;
    $("session-label").textContent =
        `${state.user.username} · ${state.user.role}`;
}

function canMutate() {
    return Boolean(state.user && state.user.role === "auditor");
}

function saveDraft() {
    sessionStorage.setItem(DRAFT_KEY, JSON.stringify(state.draft));
}

function loadDraft() {
    try {
        const raw = sessionStorage.getItem(DRAFT_KEY);
        if (raw) {
            state.draft = { ...defaultDraft(), ...JSON.parse(raw) };
        }
    } catch {
        state.draft = defaultDraft();
    }
}

function saveActive() {
    if (!state.auditId) {
        sessionStorage.removeItem(ACTIVE_KEY);
        return;
    }
    sessionStorage.setItem(
        ACTIVE_KEY,
        JSON.stringify({
            auditId: state.auditId,
            jobId: state.jobId,
            pipeline: state.pipeline,
            pipelineIndex: state.pipelineIndex,
            draft: state.draft,
        })
    );
}

function loadActive() {
    try {
        const raw = sessionStorage.getItem(ACTIVE_KEY);
        return raw ? JSON.parse(raw) : null;
    } catch {
        return null;
    }
}

function clearActive() {
    sessionStorage.removeItem(ACTIVE_KEY);
}

function setError(id, message) {
    const element = $(id);
    if (!element) {
        return;
    }
    element.hidden = !message;
    element.textContent = message || "";
}

function parseTargets(text) {
    return text
        .split(/[\s,]+/)
        .map((item) => item.trim())
        .filter(Boolean);
}

async function refreshHealth() {
    try {
        await api("GET", "/api/status");
        setStatus("online", "READY");
    } catch {
        setStatus("offline", "ERROR");
    }
}

async function restoreSession() {
    try {
        state.user = await api("GET", "/api/auth/me");
        applyPolicy(state.user.policy);
        setSessionChip();
        return true;
    } catch {
        state.user = null;
        setSessionChip();
        return false;
    }
}

function applyPolicy(policy) {
    if (!policy) {
        return;
    }
    const duration = $("scope-duration");
    duration.min = policy.passive_duration_min;
    duration.max = policy.passive_duration_max;
    if (!state.draft.duration) {
        state.draft.duration = policy.passive_duration_default;
    }
}

async function showLogin(message) {
    stopPolling();
    showScreen("login");
    setError("login-error", message || "");
    $("login-username").focus();
}

async function showHome() {
    showScreen("home");
    $("new-audit-button").hidden = !canMutate();
    $("home-role-hint").textContent = canMutate()
        ? "Start a new audit or resume a running one. Jobs survive display restart."
        : "Viewer session: you can inspect audits but cannot start or cancel them.";
    const page = await api("GET", "/api/audits?limit=20");
    const list = $("audit-list");
    list.replaceChildren();
    if (!page.items.length) {
        list.append(listItem("No audits yet", "Create one to begin."));
        return;
    }
    page.items.forEach((audit) => {
        const button = document.createElement("button");
        button.type = "button";
        button.className = "list-item";
        const title = document.createElement("strong");
        title.textContent = `${audit.status} · ${audit.profile} · ${audit.interface || "no iface"}`;
        const meta = document.createElement("span");
        meta.textContent = audit.id;
        button.append(title, meta);
        button.addEventListener("click", () => openAudit(audit.id));
        list.append(button);
    });
}

function listItem(title, detail) {
    const item = document.createElement("div");
    item.className = "list-item";
    const strong = document.createElement("strong");
    strong.textContent = title;
    const span = document.createElement("span");
    span.textContent = detail;
    item.append(strong, span);
    return item;
}

async function showEnvironment() {
    showScreen("environment");
    const data = await api("GET", "/api/environment");
    const grid = $("environment-grid");
    grid.replaceChildren();
    const iface = (data.interfaces || []).find((item) => !item.is_loopback)
        || (data.interfaces || [])[0]
        || {};
    const fields = [
        ["Hostname", data.hostname],
        ["Interface", iface.name],
        ["Link", iface.state],
        ["Speed", iface.speed_mbps ? `${iface.speed_mbps} Mbps` : "Unknown"],
        ["IPv4", (iface.ipv4 || []).join(", ") || "None"],
        ["Gateway", data.default_route && data.default_route.gateway],
        ["MAC", iface.mac],
        ["MTU", iface.mtu],
    ];
    fields.forEach(([label, value]) => {
        const item = document.createElement("div");
        item.className = "item";
        const span = document.createElement("span");
        span.textContent = label;
        const strong = document.createElement("strong");
        strong.textContent = value || "—";
        item.append(span, strong);
        grid.append(item);
    });
    $("environment-dns").textContent =
        (data.dns || []).join(", ") || "Not detected";
}

async function showInterfaces() {
    showScreen("interface");
    setError("interface-error", "");
    const data = await api("GET", "/api/interfaces");
    const list = $("interface-list");
    list.replaceChildren();
    (data.interfaces || []).forEach((iface) => {
        const button = document.createElement("button");
        button.type = "button";
        button.className = "choice";
        button.disabled = !iface.allowed;
        if (!iface.allowed) {
            button.classList.add("denied");
        }
        if (iface.name === state.draft.interface) {
            button.classList.add("selected");
        }
        const title = document.createElement("strong");
        title.textContent = iface.name;
        const meta = document.createElement("span");
        meta.textContent = iface.allowed
            ? `${iface.state || "unknown"} · ${(iface.ipv4 || []).join(", ") || "no IPv4"}`
            : iface.denial_reason || "Not allowed";
        button.append(title, meta);
        button.addEventListener("click", () => {
            if (!iface.allowed) {
                return;
            }
            state.draft.interface = iface.name;
            saveDraft();
            list.querySelectorAll(".choice").forEach((node) => {
                node.classList.toggle("selected", node === button);
            });
        });
        list.append(button);
    });
}

function showScope() {
    showScreen("scope");
    $("scope-vlan").value = state.draft.vlan;
    $("scope-targets").value = state.draft.targets;
    setError("scope-error", "");
}

function showProfile() {
    showScreen("profile");
    $("scope-duration").value = state.draft.duration;
    document.querySelectorAll("#profile-list .choice").forEach((button) => {
        button.classList.toggle(
            "selected",
            button.dataset.profile === state.draft.profile
        );
    });
    setError("profile-error", "");
}

function showConfirm() {
    showScreen("confirm");
    const targets = parseTargets(state.draft.targets);
    const rows = [
        ["Interface", state.draft.interface || "—"],
        ["VLAN", state.draft.vlan || "None"],
        ["Scope", targets.join(", ") || "Passive / not authorized"],
        ["Profile", state.draft.profile],
        ["Duration", `${state.draft.duration}s`],
        ["Stages", (PIPELINES[state.draft.profile] || []).join(" → ")],
    ];
    const list = $("confirm-summary");
    list.replaceChildren();
    rows.forEach(([key, value]) => {
        const dt = document.createElement("dt");
        dt.textContent = key;
        const dd = document.createElement("dd");
        dd.textContent = value;
        list.append(dt, dd);
    });
    $("confirm-authorize").checked = Boolean(state.draft.authorized);
    setError("confirm-error", "");
}

async function startAudit() {
    if (!canMutate()) {
        setError("confirm-error", "Viewer cannot start audits");
        return;
    }
    if (!state.draft.interface) {
        setError("confirm-error", "Select an interface");
        return;
    }
    const targets = parseTargets(state.draft.targets);
    if (state.draft.profile !== "passive" && !targets.length) {
        setError("confirm-error", "Active profiles require authorized CIDR or host targets");
        return;
    }
    if (!$("confirm-authorize").checked) {
        setError("confirm-error", "Confirm the authorized scope before starting");
        return;
    }
    state.draft.authorized = true;
    saveDraft();
    const audit = await api("POST", "/api/audits", {
        profile: state.draft.profile,
        interface: state.draft.interface,
        scope: {
            vlan: state.draft.vlan || null,
            targets,
            confirmed: true,
        },
    });
    state.auditId = audit.id;
    state.pipeline = PIPELINES[state.draft.profile] || ["passive"];
    state.pipelineIndex = 0;
    state.jobId = null;
    saveActive();
    showScreen("progress");
    await runPipeline();
}

async function runPipeline() {
    $("stop-audit-button").hidden = !canMutate();
    while (state.pipelineIndex < state.pipeline.length) {
        if (state.stopping) {
            return;
        }
        const stage = state.pipeline[state.pipelineIndex];
        try {
            const accepted = await enqueueStage(stage);
            state.jobId = accepted.job_id;
            saveActive();
            const job = await pollJob(accepted.job_id);
            if (job.status !== "completed") {
                $("progress-message").textContent =
                    `Stage ${stage} ended as ${job.status}`;
                await showSummary();
                return;
            }
        } catch (error) {
            if (
                stage === "protocol" &&
                (error.code === "inventory_empty" || error.code === "scope_not_confirmed")
            ) {
                $("progress-warning").hidden = false;
                $("progress-warning").textContent =
                    "Protocol audits skipped: no matching inventory yet.";
                state.pipelineIndex += 1;
                saveActive();
                continue;
            }
            $("progress-message").textContent = error.message;
            await showSummary();
            return;
        }
        state.pipelineIndex += 1;
        saveActive();
    }
    await showSummary();
}

async function enqueueStage(stage) {
    const auditId = state.auditId;
    if (stage === "passive") {
        return api("POST", `/api/audits/${auditId}/passive`, {
            duration_seconds: Number(state.draft.duration),
        });
    }
    if (stage === "discovery") {
        return api("POST", `/api/audits/${auditId}/discovery`, {
            interface: state.draft.interface,
            scope: parseTargets(state.draft.targets),
            profile: state.draft.profile === "passive"
                ? "discovery"
                : state.draft.profile,
        });
    }
    if (stage === "protocol") {
        return api("POST", `/api/audits/${auditId}/protocol-audits`, {});
    }
    if (stage === "findings") {
        return api("POST", `/api/audits/${auditId}/findings`, {});
    }
    if (stage === "report") {
        return api("POST", `/api/audits/${auditId}/reports`, {});
    }
    throw new Error(`Unknown stage: ${stage}`);
}

function stopPolling() {
    if (state.pollTimer) {
        clearTimeout(state.pollTimer);
        state.pollTimer = null;
    }
}

function sleep(ms) {
    return new Promise((resolve) => {
        state.pollTimer = setTimeout(resolve, ms);
    });
}

async function pollJob(jobId) {
    state.pollDelay = 1000;
    $("progress-warning").hidden = true;
    while (true) {
        try {
            const job = await api("GET", `/api/jobs/${jobId}`);
            renderProgress(job);
            state.pollDelay = 1000;
            if (TERMINAL.has(job.status)) {
                return job;
            }
            const events = await api("GET", `/api/jobs/${jobId}/events?limit=8`);
            renderEvents(events.items || []);
        } catch (error) {
            state.pollDelay = Math.min(state.pollDelay * 2, 5000);
            $("progress-warning").hidden = false;
            $("progress-warning").textContent =
                "Progress poll failed; retrying without stopping the job.";
        }
        await sleep(state.pollDelay);
    }
}

function renderProgress(job) {
    $("progress-stage").textContent =
        `${job.type} · ${job.stage} · ${job.status}`;
    $("progress-message").textContent = job.message || "Running";
    $("progress-fill").style.width = `${job.progress || 0}%`;
    $("progress-bar").setAttribute("aria-valuenow", String(job.progress || 0));
}

function renderEvents(events) {
    const list = $("progress-events");
    list.replaceChildren();
    events.slice().reverse().forEach((event) => {
        const item = document.createElement("li");
        item.textContent = `${event.stage || event.event_type}: ${event.message}`;
        list.append(item);
    });
}

async function requestStop() {
    if (!canMutate() || !state.jobId) {
        return;
    }
    const confirmed = await confirmModal(
        "Stop audit?",
        "This cancels the current job. Already finished stages stay stored."
    );
    if (!confirmed) {
        return;
    }
    state.stopping = true;
    try {
        await api("POST", `/api/jobs/${state.jobId}/cancel`);
    } finally {
        state.stopping = false;
        await showSummary();
    }
}

function confirmModal(title, body) {
    return new Promise((resolve) => {
        const modal = $("modal");
        $("modal-title").textContent = title;
        $("modal-body").textContent = body;
        modal.hidden = false;
        const finish = (result) => {
            modal.hidden = true;
            $("modal-confirm").onclick = null;
            $("modal-cancel").onclick = null;
            resolve(result);
        };
        $("modal-confirm").focus();
        $("modal-confirm").onclick = () => finish(true);
        $("modal-cancel").onclick = () => finish(false);
    });
}

async function openAudit(auditId) {
    state.auditId = auditId;
    const jobs = await api("GET", `/api/audits/${auditId}/jobs?limit=20`);
    const running = (jobs.items || []).find(
        (job) => job.status === "queued" || job.status === "running"
    );
    if (running) {
        state.jobId = running.id;
        state.pipeline = [running.type];
        state.pipelineIndex = 0;
        saveActive();
        showScreen("progress");
        const job = await pollJob(running.id);
        if (job.status === "completed") {
            await showSummary();
        } else {
            await showSummary();
        }
        return;
    }
    saveActive();
    await showSummary();
}

async function showSummary() {
    stopPolling();
    showScreen("summary");
    const audit = await api("GET", `/api/audits/${state.auditId}`);
    const inventory = await api("GET", `/api/audits/${state.auditId}/inventory`);
    const findings = await api("GET", `/api/audits/${state.auditId}/findings?limit=1`);
    const jobs = await api("GET", `/api/audits/${state.auditId}/jobs?limit=20`);
    const rows = [
        ["Audit", audit.id],
        ["Status", audit.status],
        ["Profile", audit.profile],
        ["Interface", audit.interface || "—"],
        ["Assets", String(inventory.assets)],
        ["Services", String(inventory.services)],
        ["Findings", String(findings.total)],
        ["Jobs", (jobs.items || []).map((job) => `${job.type}:${job.status}`).join(", ")],
    ];
    const list = $("summary-list");
    list.replaceChildren();
    rows.forEach(([key, value]) => {
        const dt = document.createElement("dt");
        dt.textContent = key;
        const dd = document.createElement("dd");
        dd.textContent = value;
        list.append(dt, dd);
    });
}

async function showAssets() {
    showScreen("assets");
    const assets = await api("GET", `/api/audits/${state.auditId}/assets?limit=50`);
    const services = await api("GET", `/api/audits/${state.auditId}/services?limit=50`);
    const assetList = $("asset-list");
    const serviceList = $("service-list");
    assetList.replaceChildren();
    serviceList.replaceChildren();
    if (!assets.items.length) {
        assetList.append(listItem("No assets", "Run discovery after confirming scope."));
    }
    assets.items.forEach((asset) => {
        const address = (asset.addresses || []).map((item) => item.address).join(", ");
        const name = (asset.names || []).map((item) => item.name).join(", ");
        assetList.append(
            listItem(
                name || address || asset.id,
                `${asset.state} · ${asset.mac || "no MAC"} · ${asset.vendor || "vendor unknown"}`
            )
        );
    });
    services.items.forEach((service) => {
        serviceList.append(
            listItem(
                `${service.protocol}/${service.port} ${service.service_name || ""}`.trim(),
                `${service.state} · ${service.product || "unknown product"}`
            )
        );
    });
}

async function showObservations() {
    showScreen("observations");
    const page = await api(
        "GET",
        `/api/audits/${state.auditId}/observations?limit=50`
    );
    const list = $("observation-list");
    list.replaceChildren();
    if (!page.items.length) {
        list.append(listItem(
            "No protocol observations",
            "Passive sensor facts stay in the capture result; this list is service-audit evidence."
        ));
        return;
    }
    page.items.forEach((item) => {
        list.append(
            listItem(
                `${item.protocol} · ${item.kind}`,
                `${item.confidence} · module ${item.module}`
            )
        );
    });
}

async function showAssessment() {
    showScreen("assessment");
    const list = $("assessment-list");
    list.replaceChildren();
    const jobs = await api("GET", `/api/audits/${state.auditId}/jobs?limit=50`);
    const passive = (jobs.items || []).find(
        (job) => job.type === "passive_discovery" && job.result_available
    );
    if (!passive) {
        list.append(listItem(
            "No assessment yet",
            "Assessment appears after a completed passive job."
        ));
        return;
    }
    const result = await api("GET", `/api/jobs/${passive.id}/result`);
    const assessment = (result.result && result.result.assessment)
        || result.assessment
        || {};
    const visibility = assessment.visibility || {};
    list.append(listItem(
        `Visibility · ${visibility.confidence || "unknown"}`,
        String(visibility.value || visibility.rationale || "No visibility statement")
    ));
    (assessment.infrastructure || []).forEach((item) => {
        list.append(listItem(
            `${item.confidence || "unknown"}`,
            item.rationale || JSON.stringify(item.value || {})
        ));
    });
}

async function showFindings() {
    showScreen("findings");
    const page = await api("GET", `/api/audits/${state.auditId}/findings?limit=50`);
    const list = $("finding-list");
    list.replaceChildren();
    if (!page.items.length) {
        list.append(listItem("No findings", "Evaluate findings after protocol audits."));
        return;
    }
    page.items.forEach((item) => {
        list.append(
            listItem(
                `${item.severity} · ${item.title}`,
                `${item.status} · ${item.rule_id} · ${item.confidence}`
            )
        );
    });
}

async function showReport() {
    showScreen("report");
    $("generate-report-button").hidden = !canMutate();
    const page = await api("GET", `/api/audits/${state.auditId}/reports?limit=5`);
    const latest = page.items[0];
    const openHtml = $("open-html-report");
    const downloadJson = $("download-json-report");
    const frame = $("report-frame");
    if (!latest) {
        $("report-status").textContent = "No report generated yet.";
        openHtml.hidden = true;
        downloadJson.hidden = true;
        frame.hidden = true;
        return;
    }
    $("report-status").textContent =
        `Generated ${latest.generated_at} · hash ${latest.source_hash.slice(0, 12)}`;
    openHtml.hidden = false;
    downloadJson.hidden = false;
    openHtml.onclick = () => window.open(latest.html_url, "_blank");
    downloadJson.onclick = () => window.open(latest.json_url, "_blank");
    frame.hidden = false;
    frame.src = latest.html_url;
}

async function generateReport() {
    if (!canMutate()) {
        return;
    }
    const accepted = await api("POST", `/api/audits/${state.auditId}/reports`, {});
    showScreen("progress");
    await pollJob(accepted.job_id);
    await showReport();
}

function bindUi() {
    $("login-form").addEventListener("submit", async (event) => {
        event.preventDefault();
        setError("login-error", "");
        try {
            state.user = await api("POST", "/api/auth/login", {
                username: $("login-username").value,
                password: $("login-password").value,
            });
            applyPolicy(state.user.policy);
            setSessionChip();
            const active = loadActive();
            if (active && active.auditId) {
                await openAudit(active.auditId);
                return;
            }
            await showHome();
        } catch (error) {
            setError("login-error", error.message);
        }
    });

    $("logout-button").addEventListener("click", async () => {
        stopPolling();
        await api("POST", "/api/auth/logout");
        state.user = null;
        setSessionChip();
        await showLogin();
    });

    $("new-audit-button").addEventListener("click", async () => {
        state.draft = defaultDraft();
        saveDraft();
        await showEnvironment();
    });

    document.querySelectorAll("[data-nav]").forEach((button) => {
        button.addEventListener("click", async () => {
            const target = button.dataset.nav;
            if (target === "home") {
                clearActive();
                await showHome();
                return;
            }
            if (target === "interface") {
                await showInterfaces();
                return;
            }
            if (target === "environment") {
                await showEnvironment();
                return;
            }
            if (target === "scope") {
                if (!state.draft.interface) {
                    setError("interface-error", "Select an allowed interface");
                    return;
                }
                showScope();
                return;
            }
            if (target === "profile") {
                state.draft.vlan = $("scope-vlan").value.trim();
                state.draft.targets = $("scope-targets").value;
                saveDraft();
                showProfile();
                return;
            }
            if (target === "confirm") {
                state.draft.duration = Number($("scope-duration").value);
                if (!state.draft.profile) {
                    setError("profile-error", "Select a profile");
                    return;
                }
                saveDraft();
                showConfirm();
                return;
            }
            if (target === "summary") {
                await showSummary();
            }
        });
    });

    document.querySelectorAll("[data-open]").forEach((button) => {
        button.addEventListener("click", async () => {
            const target = button.dataset.open;
            if (target === "assets") {
                await showAssets();
            } else if (target === "observations") {
                await showObservations();
            } else if (target === "assessment") {
                await showAssessment();
            } else if (target === "findings") {
                await showFindings();
            } else if (target === "report") {
                await showReport();
            }
        });
    });

    document.querySelectorAll("#profile-list .choice").forEach((button) => {
        button.addEventListener("click", () => {
            state.draft.profile = button.dataset.profile;
            saveDraft();
            showProfile();
        });
    });

    $("interface-next").addEventListener("click", () => {
        if (!state.draft.interface) {
            setError("interface-error", "Select an allowed interface");
            return;
        }
        showScope();
    });

    $("start-audit-button").addEventListener("click", async () => {
        try {
            await startAudit();
        } catch (error) {
            setError("confirm-error", error.message);
        }
    });

    $("stop-audit-button").addEventListener("click", () => {
        requestStop().catch((error) => {
            $("progress-message").textContent = error.message;
        });
    });

    $("generate-report-button").addEventListener("click", () => {
        generateReport().catch((error) => {
            $("report-status").textContent = error.message;
        });
    });

    $("scope-duration").addEventListener("change", () => {
        state.draft.duration = Number($("scope-duration").value);
        saveDraft();
    });
}

async function boot() {
    bindUi();
    loadDraft();
    await refreshHealth();
    const signedIn = await restoreSession();
    if (!signedIn) {
        await showLogin();
        return;
    }
    const active = loadActive();
    if (active && active.auditId) {
        state.draft = { ...state.draft, ...(active.draft || {}) };
        await openAudit(active.auditId);
        return;
    }
    await showHome();
}

boot().catch((error) => {
    setStatus("offline", "ERROR");
    showLogin(error.message);
});
