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
    network: null,
    networkIface: "",
};

function defaultDraft() {
    return {
        interface: "",
        vlan: "",
        targets: "",
        extras: "",
        proposed: [],
        proposal: null,
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
    $("header-subtitle").textContent = t(`screen.${name}`);
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
        `${state.user.username} · ${I18N.role(state.user.role)}`;
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

function combinedTargets() {
    const extras = parseTargets(state.draft.extras || "");
    const seen = new Set();
    const result = [];
    (state.draft.proposed || []).concat(extras).forEach((item) => {
        if (!seen.has(item)) {
            seen.add(item);
            result.push(item);
        }
    });
    return result;
}

async function loadScopeProposal() {
    const proposal = await api(
        "GET",
        `/api/scope/proposal?interface=${encodeURIComponent(state.draft.interface)}`
    );
    state.draft.proposed = proposal.canonical_targets || [];
    state.draft.proposal = proposal;
    if (!state.draft.vlan && (proposal.vlan_ids || []).length) {
        state.draft.vlan = proposal.vlan_ids
            .map((id) => `VLAN ${id}`)
            .join(", ");
    }
    applyVlanScanInterface(proposal);
    saveDraft();
    return proposal;
}

function applyVlanScanInterface(proposal) {
    if (!proposal || proposal.source !== "vlan_hints" || !proposal.interface) {
        return;
    }
    state.draft.interface = proposal.interface;
}

function isNetworkError(error) {
    return Boolean(
        error &&
        !(error.status) &&
        (error.name === "TypeError" || /failed to fetch|network|load failed/i.test(String(error.message || "")))
    );
}

function isSecureCookieOverHttp(health) {
    return Boolean(health && health.cookie_secure && !window.isSecureContext);
}

function displayError(error) {
    if (isNetworkError(error)) {
        if (location.protocol === "https:") {
            return t("error.tlsOrNetwork");
        }
        return t("error.apiUnreachable", {
            detail: String(error.message || "connection refused"),
        });
    }
    return I18N.apiError(error);
}

async function refreshHealth() {
    try {
        const health = await api("GET", "/api/status");
        if (isSecureCookieOverHttp(health)) {
            setStatus("offline", t("status.error"));
            setError("login-error", t("error.secureCookieOverHttp"));
            return;
        }
        setStatus("online", t("status.ready"));
    } catch (error) {
        setStatus("offline", t("status.error"));
        setError("login-error", displayError(error));
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
    $("network-button").hidden = !canMutate();
    $("password-button").hidden = !state.user;
    $("home-role-hint").textContent = canMutate()
        ? t("home.auditorHint")
        : t("home.viewerHint");
    const page = await api("GET", "/api/audits?limit=20");
    const list = $("audit-list");
    list.replaceChildren();
    if (!page.items.length) {
        list.append(listItem(t("home.emptyTitle"), t("home.emptyDetail")));
        return;
    }
    page.items.forEach((audit) => {
        const button = document.createElement("button");
        button.type = "button";
        button.className = "list-item";
        const title = document.createElement("strong");
        title.textContent = [
            I18N.status(audit.status),
            I18N.profile(audit.profile),
            audit.interface || t("common.noInterface"),
        ].join(" · ");
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
    const ifaces = (data.interfaces || []).filter((item) => !item.is_loopback);
    const fields = [
        [t("environment.hostname"), data.hostname],
        [t("environment.gateway"), data.default_route && data.default_route.gateway],
    ];
    ifaces.forEach((iface) => {
        fields.push([
            iface.name,
            [
                I18N.link(iface.state),
                (iface.ipv4 || []).join(", ") || t("common.noIpv4"),
                iface.mac || t("common.noMac"),
            ].filter(Boolean).join(" · "),
        ]);
    });
    fields.forEach(([label, value]) => {
        const item = document.createElement("div");
        item.className = "item";
        const span = document.createElement("span");
        span.textContent = label;
        const strong = document.createElement("strong");
        strong.textContent = value || t("common.dash");
        item.append(span, strong);
        grid.append(item);
    });
    $("environment-dns").textContent =
        (data.dns || []).join(", ") || t("common.notDetected");
}

async function showInterfaces() {
    showScreen("interface");
    setError("interface-error", "");
    const data = await api("GET", "/api/interfaces");
    const list = $("interface-list");
    list.replaceChildren();
    const ifaces = data.interfaces || [];
    if (!state.draft.interface) {
        state.draft.interface = preferredAuditInterface(ifaces);
        saveDraft();
    }
    ifaces.forEach((iface) => {
        const button = document.createElement("button");
        button.type = "button";
        button.className = "choice";
        const selectable = iface.selectable !== false && !iface.is_loopback
            && iface.denial_reason !== "loopback_denied"
            && iface.denial_reason !== "not_allowed";
        button.disabled = !selectable;
        if (!selectable) {
            button.classList.add("denied");
        }
        if (iface.name === state.draft.interface) {
            button.classList.add("selected");
        }
        const title = document.createElement("strong");
        title.textContent = iface.name;
        const meta = document.createElement("span");
        const addressing = iface.addressing === "none"
            ? t("common.noIpv4")
            : (iface.ipv4 || []).join(", ") || t("common.noIpv4");
        if (!selectable) {
            meta.textContent = I18N.denial(iface.denial_reason);
        } else {
            meta.textContent = [
                I18N.link(iface.state),
                addressing,
                iface.has_default_route ? t("network.defaultRoute") : "",
                ifaceHostsGui(iface) ? t("interface.guiHint") : "",
            ].filter(Boolean).join(" · ");
        }
        button.append(title, meta);
        button.addEventListener("click", () => {
            if (!selectable) {
                return;
            }
            state.draft.interface = iface.name;
            saveDraft();
            list.querySelectorAll(".choice").forEach((node) => {
                node.classList.toggle("selected", node === button);
            });
            if (iface.denial_reason === "link_not_up") {
                setError("interface-error", t("interface.downHint"));
            } else {
                setError("interface-error", "");
            }
        });
        list.append(button);
    });
}

function preferredAuditInterface(interfaces) {
    const usable = (interfaces || []).filter((item) => {
        if (item.is_loopback) {
            return false;
        }
        if (item.denial_reason === "loopback_denied" || item.denial_reason === "not_allowed") {
            return false;
        }
        return item.selectable !== false;
    });
    const up = usable.find((item) => String(item.state || "").toUpperCase() === "UP");
    return (up || usable[0] || {}).name || "";
}

function ifaceHostsGui(iface) {
    const host = String(location.hostname || "").replace(/^\[|\]$/g, "");
    if (!host || host === "localhost" || host === "127.0.0.1" || host === "::1") {
        return false;
    }
    const addresses = [...(iface.ipv4 || []), ...(iface.ipv6 || [])].map((value) => (
        String(value).split("/")[0]
    ));
    return addresses.includes(host);
}

async function showScope() {
    showScreen("scope");
    $("scope-vlan").value = state.draft.vlan;
    $("scope-targets").value = state.draft.extras || "";
    setError("scope-error", "");
    $("scope-reason").textContent = t("scope.loading");
    $("scope-proposal").replaceChildren();
    try {
        const proposal = await loadScopeProposal();
        $("scope-vlan").value = state.draft.vlan;
        renderScopeProposal(proposal);
    } catch (error) {
        state.draft.proposed = [];
        state.draft.proposal = null;
        $("scope-reason").textContent = "";
        setError("scope-error", displayError(error));
    }
}

function renderScopeProposal(proposal) {
    const reason = $("scope-reason");
    const list = $("scope-proposal");
    list.replaceChildren();
    const networks = (proposal.canonical_targets || []).join(", ");
    if (proposal.source === "interface_prefix") {
        reason.textContent = t("scope.derivedFromAddress", {
            iface: proposal.interface,
            addresses: (proposal.assigned_addresses || []).join(", ") || t("common.dash"),
            networks,
        });
    } else if (proposal.source === "vlan_hints") {
        reason.textContent = t("scope.derivedFromVlan", {
            vlans: (proposal.vlan_ids || []).join(", ") || t("common.dash"),
            networks,
        });
    } else if (proposal.source === "route_hints") {
        reason.textContent = t("scope.derivedFromRoute", { networks });
    } else {
        reason.textContent = t("scope.emptyProposal");
    }
    (proposal.networks || []).forEach((item) => {
        list.append(listItem(item.cidr, scopeOriginLabel(item)));
    });
    (proposal.rejected || []).forEach((item) => {
        list.append(
            listItem(
                t("scope.rejectedTitle", { value: item.value }),
                I18N.token("error", item.code)
            )
        );
    });
}

function scopeOriginLabel(item) {
    if (item.origin === "vlan") {
        return t("scope.originVlan", {
            id: item.vlan_id || t("common.dash"),
            iface: item.interface || t("common.dash"),
        });
    }
    if (item.origin === "route") {
        return t("scope.originRoute");
    }
    return t("scope.originAssigned");
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

async function showConfirm() {
    if (state.draft.interface) {
        try {
            await loadScopeProposal();
        } catch {
            // Keep any previously saved proposal; startAudit still validates.
        }
    }
    showScreen("confirm");
    const targets = combinedTargets();
    const rows = [
        [t("confirm.interface"), state.draft.interface || t("common.dash")],
        [t("confirm.vlan"), state.draft.vlan || t("common.none")],
        [
            t("confirm.scope"),
            targets.join(", ") || t("confirm.passiveScope"),
        ],
        [t("confirm.profile"), I18N.profile(state.draft.profile)],
        [t("confirm.duration"), t("common.seconds", { value: state.draft.duration })],
        [
            t("confirm.stages"),
            (PIPELINES[state.draft.profile] || [])
                .map((stage) => I18N.jobType(stage))
                .join(" → "),
        ],
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
        setError("confirm-error", t("error.viewerCannotStart"));
        return;
    }
    if (!state.draft.interface) {
        setError("confirm-error", t("error.selectInterface"));
        return;
    }
    const targets = combinedTargets();
    if (state.draft.profile !== "passive" && !targets.length) {
        setError("confirm-error", t("error.activeScopeRequired"));
        return;
    }
    if (!$("confirm-authorize").checked) {
        setError("confirm-error", t("error.confirmScope"));
        return;
    }
    state.draft.authorized = true;
    state.draft.targets = targets.join("\n");
    saveDraft();
    const audit = await api("POST", "/api/audits", {
        profile: state.draft.profile,
        interface: state.draft.interface,
        scope: {
            vlan: state.draft.vlan || null,
            targets,
            proposed: state.draft.proposed,
            derived_from: (
                state.draft.proposal && state.draft.proposal.source
            ) || "manual",
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
                $("progress-message").textContent = t("progress.stageEnded", {
                    stage: I18N.jobType(stage),
                    status: I18N.status(job.status),
                });
                await showSummary();
                return;
            }
        } catch (error) {
            const skippable = new Set(["discovery", "protocol", "findings"]);
            if (skippable.has(stage) && state.pipeline.includes("report")) {
                $("progress-warning").hidden = false;
                $("progress-warning").textContent = t("progress.stageSkipped", {
                    stage: I18N.jobType(stage),
                    error: displayError(error),
                });
                if (stage === "discovery") {
                    const skip = new Set(["discovery", "protocol"]);
                    while (
                        state.pipelineIndex < state.pipeline.length
                        && skip.has(state.pipeline[state.pipelineIndex])
                    ) {
                        state.pipelineIndex += 1;
                    }
                } else {
                    state.pipelineIndex += 1;
                }
                saveActive();
                continue;
            }
            $("progress-message").textContent = displayError(error);
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
            scope: combinedTargets(),
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
    throw new Error(t("error.unknownStage", { stage }));
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
            $("progress-warning").textContent = t("progress.pollFailed");
        }
        await sleep(state.pollDelay);
    }
}

function renderProgress(job) {
    $("progress-stage").textContent = t("progress.stageLine", {
        type: I18N.jobType(job.type),
        stage: I18N.stage(job.stage),
        status: I18N.status(job.status),
    });
    $("progress-message").textContent = I18N.jobMessage(job.message);
    $("progress-fill").style.width = `${job.progress || 0}%`;
    $("progress-bar").setAttribute("aria-valuenow", String(job.progress || 0));
}

function renderEvents(events) {
    const list = $("progress-events");
    list.replaceChildren();
    events.slice().reverse().forEach((event) => {
        const item = document.createElement("li");
        const stage = event.stage || event.event_type;
        item.textContent = `${I18N.stage(stage)}: ${I18N.jobMessage(event.message)}`;
        list.append(item);
    });
}

async function requestStop() {
    if (!canMutate() || !state.jobId) {
        return;
    }
    const confirmed = await confirmModal(
        t("progress.stopTitle"),
        t("progress.stopBody")
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

function networkRoleLabel(role) {
    return t(`network.role.${role || "unknown"}`);
}

function renderNetworkUrls(payload) {
    const urls = (payload && payload.gui_urls) || [];
    const box = $("network-urls");
    if (!urls.length) {
        box.textContent = t("network.noUrls");
        return;
    }
    box.textContent = t("network.openGui", { urls: urls.join(", ") });
}

function fillNetworkForm(iface) {
    $("network-form").hidden = false;
    $("network-form-title").textContent = iface.name;
    const role = iface.role === "management" || iface.role === "capture"
        ? iface.role
        : (iface.has_default_route ? "management" : "capture");
    $("network-role").value = role;
    const method = iface.addressing === "dhcp" || iface.addressing === "static"
        ? iface.addressing
        : (role === "capture" ? "none" : "dhcp");
    $("network-method").value = method;
    $("network-address").value = (iface.ipv4 || [])[0] || "";
    $("network-gateway").value = "";
    $("network-dns").value = ((state.network && state.network.dns) || []).join(" ");
    syncNetworkForm();
}

function syncNetworkForm() {
    const role = $("network-role").value;
    const method = $("network-method").value;
    $("network-role-hint").textContent = role === "capture"
        ? t("network.captureHint")
        : t("network.managementHint");
    if (role === "management" && method === "none") {
        $("network-method").value = "dhcp";
    }
    $("network-static-fields").hidden = $("network-method").value !== "static";
}

async function showNetwork() {
    if (!canMutate()) {
        await showHome();
        return;
    }
    showScreen("network");
    setError("network-error", "");
    $("network-result").hidden = true;
    const payload = await api("GET", "/api/network/interfaces");
    state.network = payload;
    renderNetworkUrls(payload);
    const list = $("network-list");
    list.replaceChildren();
    (payload.interfaces || []).forEach((iface) => {
        if (iface.is_loopback) {
            return;
        }
        const button = document.createElement("button");
        button.type = "button";
        button.className = "choice";
        if (iface.name === state.networkIface) {
            button.classList.add("selected");
        }
        const title = document.createElement("strong");
        title.textContent = iface.name;
        const meta = document.createElement("span");
        meta.textContent = [
            networkRoleLabel(iface.role),
            I18N.link(iface.state),
            (iface.ipv4 || []).join(", ") || t("common.noIpv4"),
            iface.has_default_route ? t("network.defaultRoute") : t("network.noDefault"),
            t(`network.addressing.${iface.addressing || "none"}`),
            ifaceHostsGui(iface) ? t("interface.guiHint") : "",
        ].filter(Boolean).join(" · ");
        button.append(title, meta);
        button.addEventListener("click", () => {
            state.networkIface = iface.name;
            list.querySelectorAll(".choice").forEach((node) => {
                node.classList.toggle("selected", node === button);
            });
            fillNetworkForm(iface);
        });
        list.append(button);
    });
    if (state.networkIface) {
        const selected = (payload.interfaces || []).find((item) => item.name === state.networkIface);
        if (selected) {
            fillNetworkForm(selected);
        }
    } else {
        $("network-form").hidden = true;
    }
}

async function applyNetwork(confirm) {
    if (!canMutate()) {
        setError("network-error", t("error.forbidden_role"));
        return;
    }
    if (!state.networkIface) {
        setError("network-error", t("error.selectInterface"));
        return;
    }
    setError("network-error", "");
    $("network-result").hidden = true;
    const method = $("network-method").value;
    const body = {
        role: $("network-role").value,
        method,
        confirm: Boolean(confirm),
    };
    if (method === "static") {
        body.address = $("network-address").value.trim();
        body.gateway = $("network-gateway").value.trim() || null;
        body.dns = parseTargets($("network-dns").value);
    }
    try {
        const result = await api(
            "POST",
            `/api/network/interfaces/${encodeURIComponent(state.networkIface)}`,
            body
        );
        state.network = result;
        renderNetworkUrls(result);
        const urls = (result.gui_urls || []).join(", ");
        $("network-result").hidden = false;
        $("network-result").textContent = t("network.result", { urls });
        await showNetwork();
        $("network-result").hidden = false;
        $("network-result").textContent = t("network.result", { urls });
    } catch (error) {
        if (error.status === 409 && error.code === "confirm_required") {
            const confirmed = await confirmModal(
                t("network.confirmTitle"),
                t("network.confirmBody")
            );
            if (confirmed) {
                await applyNetwork(true);
                return;
            }
        }
        throw error;
    }
}

function clearPasswordForm() {
    $("password-current").value = "";
    $("password-new").value = "";
    $("password-confirm").value = "";
}

function showPassword() {
    showScreen("password");
    setError("password-error", "");
    $("password-result").hidden = true;
    $("password-result").textContent = "";
    clearPasswordForm();
    $("password-current").focus();
}

async function submitPasswordChange() {
    const currentPassword = $("password-current").value;
    const newPassword = $("password-new").value;
    const confirmPassword = $("password-confirm").value;
    setError("password-error", "");
    $("password-result").hidden = true;
    if (newPassword !== confirmPassword) {
        setError("password-error", t("password.mismatch"));
        return;
    }
    try {
        await api("POST", "/api/auth/password", {
            current_password: currentPassword,
            new_password: newPassword,
        });
        clearPasswordForm();
        $("password-result").hidden = false;
        $("password-result").textContent = t("password.success");
    } catch (error) {
        if (error.status === 401 && error.code === "invalid_credentials") {
            setError("password-error", t("password.wrongCurrent"));
            return;
        }
        setError("password-error", displayError(error));
    }
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
    const reports = await api("GET", `/api/audits/${state.auditId}/reports?limit=1`);
    const sensors = Array.isArray(audit.summary && audit.summary.detected_sensors)
        ? audit.summary.detected_sensors
        : [];
    const frames = audit.summary && audit.summary.frame_count;
    const tagged = Array.isArray(audit.summary && audit.summary.tagged_vlan_ids)
        ? audit.summary.tagged_vlan_ids
        : [];
    const neighbors = Array.isArray(audit.summary && audit.summary.neighbors)
        ? audit.summary.neighbors
        : [];
    const hadL3 = audit.summary && audit.summary.had_l3_address;
    const visibility = audit.summary && audit.summary.visibility;
    const duration = audit.summary && audit.summary.duration_seconds;
    const arpHosts = audit.summary && audit.summary.arp_hosts;
    const neighborText = neighbors.length
        ? neighbors.map((item) => {
            const name = item.name || t("common.unknown");
            const port = item.port_id ? ` ${item.port_id}` : "";
            const native = item.native_vlan != null ? ` native ${item.native_vlan}` : "";
            const voice = item.voice_vlan != null ? ` voice ${item.voice_vlan}` : "";
            const pvid = item.pvid != null ? ` PVID ${item.pvid}` : "";
            return `${item.protocol || "L2"} ${name}${port}${native}${voice}${pvid}`.trim();
        }).join("; ")
        : t("common.dash");
    const l3Text = hadL3 === true
        ? t("summary.hasL3")
        : hadL3 === false
            ? t("summary.noL3")
            : t("common.dash");
    const rows = [
        [t("summary.audit"), audit.id],
        [t("summary.status"), I18N.status(audit.status)],
        [t("summary.profile"), I18N.profile(audit.profile)],
        [t("summary.interface"), audit.interface || t("common.dash")],
        [t("summary.l3"), l3Text],
        [t("summary.frames"), frames === undefined || frames === null ? t("common.dash") : String(frames)],
        [t("summary.duration"), duration === undefined || duration === null ? t("common.dash") : t("common.seconds", { value: duration })],
        [t("summary.vlans"), tagged.length ? tagged.join(", ") : t("summary.noTaggedVlans")],
        [t("summary.visibility"), visibility || t("common.dash")],
        [t("summary.neighbors"), neighborText],
        [t("summary.arp"), arpHosts === undefined || arpHosts === null ? t("common.dash") : String(arpHosts)],
        [t("summary.sensors"), sensors.length ? sensors.join(", ") : t("common.dash")],
        [t("summary.assets"), String(inventory.assets)],
        [t("summary.services"), String(inventory.services)],
        [t("summary.findings"), String(findings.total)],
        [
            t("summary.jobs"),
            (jobs.items || [])
                .map((job) => `${I18N.jobType(job.type)}:${I18N.status(job.status)}`)
                .join(", "),
        ],
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
    const conclusionEl = $("summary-conclusion");
    const conclusionTitle = $("summary-conclusion-title");
    const fromReport = reports.items && reports.items[0] && reports.items[0].summary
        ? reports.items[0].summary.summary
        : "";
    const fromAudit = audit.summary && audit.summary.executive_conclusion
        ? audit.summary.executive_conclusion.summary
        : "";
    const conclusionText = fromReport || fromAudit || "";
    if (conclusionEl) {
        if (conclusionText) {
            conclusionEl.hidden = false;
            conclusionEl.textContent = conclusionText;
            if (conclusionTitle) {
                conclusionTitle.hidden = false;
            }
        } else {
            conclusionEl.hidden = true;
            conclusionEl.textContent = "";
            if (conclusionTitle) {
                conclusionTitle.hidden = true;
            }
        }
    }
    const note = $("summary-note");
    if (note) {
        const status = audit.summary && audit.summary.segment_status;
        if (frames === 0 || status === "quiet") {
            note.hidden = false;
            note.textContent = t("summary.emptyCapture");
        } else if (status === "tagged_vlans" && tagged.length) {
            note.hidden = false;
            note.textContent = t("summary.segmentTagged", { vlans: tagged.join(", ") });
        } else if (status === "untagged_traffic") {
            note.hidden = false;
            note.textContent = t("summary.segmentUntagged");
        } else if (Number(frames) > 0 && inventory.assets === 0) {
            note.hidden = false;
            note.textContent = t("summary.framesWithoutAssets");
        } else {
            note.hidden = true;
            note.textContent = "";
        }
    }
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
        assetList.append(listItem(t("assets.emptyTitle"), t("assets.emptyDetail")));
    }
    assets.items.forEach((asset) => {
        const address = (asset.addresses || []).map((item) => item.address).join(", ");
        const name = (asset.names || []).map((item) => item.name).join(", ");
        assetList.append(
            listItem(
                name || address || asset.mac || asset.id,
                t("assets.meta", {
                    state: I18N.assetState(asset.state),
                    mac: asset.mac || t("common.noMac"),
                    vendor: asset.vendor || t("common.vendorUnknown"),
                })
            )
        );
    });
    services.items.forEach((service) => {
        serviceList.append(
            listItem(
                `${service.protocol}/${service.port} ${service.service_name || ""}`.trim(),
                t("assets.serviceMeta", {
                    state: I18N.serviceState(service.state),
                    product: service.product || t("common.unknownProduct"),
                })
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
            t("observations.emptyTitle"),
            t("observations.emptyDetail")
        ));
        return;
    }
    page.items.forEach((item) => {
        list.append(
            listItem(
                t("observations.item", {
                    protocol: item.protocol,
                    kind: item.kind,
                }),
                t("observations.meta", {
                    confidence: I18N.confidence(item.confidence),
                    module: item.module,
                })
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
            t("assessment.emptyTitle"),
            t("assessment.emptyDetail")
        ));
        return;
    }
    const result = await api("GET", `/api/jobs/${passive.id}/result`);
    const assessment = (result.result && result.result.assessment)
        || result.assessment
        || {};
    const visibility = assessment.visibility || {};
    list.append(listItem(
        t("assessment.visibility", {
            confidence: I18N.confidence(visibility.confidence || "unknown"),
        }),
        String(visibility.value || visibility.rationale || t("assessment.noVisibility"))
    ));
    const layer2 = assessment.layer2 || {};
    const vlans = Array.isArray(layer2.tagged_vlans_observed)
        ? layer2.tagged_vlans_observed
        : [];
    list.append(listItem(
        t("assessment.vlans"),
        vlans.length ? vlans.join(", ") : t("assessment.noVlans")
    ));
    const portHint = layer2.port_type_hint || {};
    if (portHint.value) {
        list.append(listItem(
            t("assessment.portHint", {
                confidence: I18N.confidence(portHint.confidence || "unknown"),
            }),
            String(portHint.value)
        ));
    }
    const neighbors = Array.isArray(layer2.neighbors) ? layer2.neighbors : [];
    if (!neighbors.length) {
        list.append(listItem(t("assessment.noNeighbors"), t("summary.vlanTagNote")));
    }
    neighbors.forEach((item) => {
        list.append(listItem(
            t("assessment.neighbors", { protocol: item.protocol || "L2" }),
            t("assessment.neighborMeta", {
                port: item.port_id || item.system_name || item.device_id || t("common.dash"),
                native: item.native_vlan == null ? t("common.dash") : item.native_vlan,
                voice: item.voice_vlan == null ? t("common.dash") : item.voice_vlan,
                pvid: item.pvid == null ? t("common.dash") : item.pvid,
            })
        ));
    });
    const stp = layer2.stp || {};
    if (stp.bpdus_observed) {
        const roots = (stp.root_bridge_ids || []).join(", ") || t("common.dash");
        list.append(listItem(
            t("assessment.stp"),
            t("assessment.stpMeta", { bpdus: stp.bpdus_observed, root: roots })
        ));
    }
    const ipv4 = assessment.ipv4 || {};
    if (ipv4.observed_hosts && ipv4.observed_hosts.length) {
        list.append(listItem(
            t("assessment.arp"),
            ipv4.observed_hosts.map((item) => item.ipv4).filter(Boolean).join(", ")
        ));
    }
    (assessment.infrastructure || []).forEach((item) => {
        list.append(listItem(
            I18N.confidence(item.confidence || "unknown"),
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
        list.append(listItem(t("findings.emptyTitle"), t("findings.emptyDetail")));
        return;
    }
    page.items.forEach((item) => {
        list.append(
            listItem(
                t("findings.item", {
                    severity: I18N.severity(item.severity),
                    title: item.title,
                }),
                t("findings.meta", {
                    status: I18N.findingStatus(item.status),
                    rule: item.rule_id,
                    confidence: I18N.confidence(item.confidence),
                })
                + (item.description ? ` · ${item.description}` : "")
                + (item.recommendation
                    ? ` · ${t("findings.recommendation", { text: item.recommendation })}`
                    : "")
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
        $("report-status").textContent = t("report.empty");
        openHtml.hidden = true;
        downloadJson.hidden = true;
        frame.hidden = true;
        return;
    }
    $("report-status").textContent = t("report.generated", {
        when: latest.generated_at,
        hash: latest.source_hash.slice(0, 12),
    });
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
            setError("login-error", displayError(error));
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

    $("network-button").addEventListener("click", async () => {
        await showNetwork();
    });

    $("password-button").addEventListener("click", () => {
        showPassword();
    });

    $("password-form").addEventListener("submit", async (event) => {
        event.preventDefault();
        await submitPasswordChange();
    });

    document.querySelectorAll("[data-nav]").forEach((button) => {
        button.addEventListener("click", async () => {
            const target = button.dataset.nav;
            if (target === "home") {
                clearActive();
                await showHome();
                return;
            }
            if (target === "network") {
                await showNetwork();
                return;
            }
            if (target === "password") {
                showPassword();
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
                    setError("interface-error", t("error.selectAllowedInterface"));
                    return;
                }
                await showScope();
                return;
            }
            if (target === "profile") {
                state.draft.vlan = $("scope-vlan").value.trim();
                state.draft.extras = $("scope-targets").value;
                applyVlanScanInterface(state.draft.proposal);
                state.draft.targets = combinedTargets().join("\n");
                saveDraft();
                showProfile();
                return;
            }
            if (target === "confirm") {
                state.draft.duration = Number($("scope-duration").value);
                if (!state.draft.profile) {
                    setError("profile-error", t("error.selectProfile"));
                    return;
                }
                saveDraft();
                await showConfirm();
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

    $("interface-next").addEventListener("click", async () => {
        if (!state.draft.interface) {
            setError("interface-error", t("error.selectAllowedInterface"));
            return;
        }
        await showScope();
    });

    $("start-audit-button").addEventListener("click", async () => {
        try {
            await startAudit();
        } catch (error) {
            setError("confirm-error", displayError(error));
        }
    });

    $("stop-audit-button").addEventListener("click", () => {
        requestStop().catch((error) => {
            $("progress-message").textContent = displayError(error);
        });
    });

    $("generate-report-button").addEventListener("click", () => {
        generateReport().catch((error) => {
            $("report-status").textContent = displayError(error);
        });
    });

    $("network-apply").addEventListener("click", () => {
        applyNetwork().catch((error) => {
            setError("network-error", displayError(error));
        });
    });
    $("network-role").addEventListener("change", syncNetworkForm);
    $("network-method").addEventListener("change", syncNetworkForm);

    $("scope-duration").addEventListener("change", () => {
        state.draft.duration = Number($("scope-duration").value);
        saveDraft();
    });
}

async function boot() {
    I18N.apply();
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
    setStatus("offline", t("status.error"));
    showLogin(displayError(error));
});
