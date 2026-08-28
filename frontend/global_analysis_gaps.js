(() => {
    "use strict";

    const API = "/api/v1";
    let observer = null;
    let inFlightJob = "";
    let renderedJob = "";
    let timer = null;

    function el(tag, className, text) {
        const node = document.createElement(tag);
        if (className) node.className = className;
        if (text !== undefined && text !== null) node.textContent = String(text);
        return node;
    }

    function priorityLabel(value) {
        return {
            high: "высокий приоритет",
            medium: "средний приоритет",
            low: "низкий приоритет",
        }[String(value || "")] || "нужны данные";
    }

    function priorityClass(value) {
        const raw = String(value || "low");
        return ["high", "medium", "low"].includes(raw) ? raw : "low";
    }

    function currentJobId() {
        const link = document.getElementById("ga-export-json");
        if (!link) return "";
        const href = String(link.getAttribute("href") || "");
        const match = href.match(/\/jobs\/([^/]+)\/global-analysis\/export/);
        return match ? decodeURIComponent(match[1]) : "";
    }

    async function requestDocument(jobId) {
        const response = await fetch(`${API}/jobs/${encodeURIComponent(jobId)}/global-analysis`, {
            credentials: "same-origin",
            headers: { "Accept": "application/json" },
        });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return response.json();
    }

    function listBlock(title, items, className) {
        const block = el("div", `ga-gap-block ${className || ""}`.trim());
        block.append(el("strong", "ga-gap-block-title", title));
        const list = el("ul", "ga-gap-list");
        (items || []).filter(Boolean).forEach((item) => list.append(el("li", "", item)));
        if (!list.children.length) list.append(el("li", "ga-gap-empty", "Нет дополнительных сведений."));
        block.append(list);
        return block;
    }

    function renderGap(gap) {
        const priority = priorityClass(gap.priority);
        const card = el("article", `ga-gap-card ${priority}`);
        const head = el("div", "ga-gap-head");
        const title = el("div", "ga-gap-title");
        title.append(
            el("strong", "", gap.title || "Нужны дополнительные данные"),
            el("span", "ga-gap-category", String(gap.category || "").replaceAll("_", " "))
        );
        head.append(title, el("span", `ga-gap-priority ${priority}`, priorityLabel(gap.priority)));
        card.append(head);

        if (gap.safe_conclusion) {
            const conclusion = el("div", "ga-gap-conclusion");
            conclusion.append(el("strong", "", "Пока корректно утверждать"), el("p", "", gap.safe_conclusion));
            card.append(conclusion);
        }

        const evidence = el("div", "ga-gap-evidence-grid");
        evidence.append(
            listBlock("Что уже есть", gap.known_evidence || [], "known"),
            listBlock("Чего не хватает", gap.missing_evidence || [], "missing")
        );
        card.append(evidence);

        const collect = listBlock("Как добрать данные", gap.collection_options || [], "collect");
        const collectList = collect.querySelector("ul");
        if (collectList) collectList.classList.add("ga-gap-steps");
        card.append(collect);

        const affected = gap.affected || {};
        if (Number(affected.count) > 1) {
            card.append(el("small", "ga-gap-affected", `Затронуто объектов/проверок: ${Number(affected.count)}`));
        }
        return card;
    }

    function renderSection(documentData, jobId) {
        const content = document.getElementById("ga-content");
        if (!content || currentJobId() !== jobId) return;
        content.querySelector(".ga-evidence-gaps")?.remove();

        const gaps = (documentData.evidence_gaps || []).filter((row) => row && typeof row === "object");
        if (!gaps.length) {
            renderedJob = jobId;
            content.dataset.evidenceGapsJob = jobId;
            return;
        }

        const section = el("section", "ga-section ga-evidence-gaps");
        const heading = el("div", "ga-gaps-heading");
        const titleBox = el("div", "");
        titleBox.append(
            el("h3", "", "Что ещё нужно подтвердить"),
            el("p", "ga-note", "WireScope не додумывает недостающие факты. Ниже показано, какие выводы пока ограничены текущими данными и что можно собрать для их подтверждения.")
        );
        const high = gaps.filter((row) => row.priority === "high").length;
        const counter = el("div", "ga-gap-counter");
        counter.append(el("strong", "", String(gaps.length)), el("span", "", "пробелов в доказательствах"));
        if (high) counter.append(el("em", "", `${high} приоритетных`));
        heading.append(titleBox, counter);
        section.append(heading);

        const cards = el("div", "ga-gap-cards");
        gaps.forEach((gap) => cards.append(renderGap(gap)));
        section.append(cards);

        const sections = Array.from(content.children).filter((node) => node.classList && node.classList.contains("ga-section"));
        const operatorSummary = sections.length > 1 ? sections[1] : sections[0];
        if (operatorSummary && operatorSummary.nextSibling) {
            content.insertBefore(section, operatorSummary.nextSibling);
        } else {
            content.append(section);
        }
        renderedJob = jobId;
        content.dataset.evidenceGapsJob = jobId;
    }

    async function sync() {
        timer = null;
        const content = document.getElementById("ga-content");
        const jobId = currentJobId();
        if (!content || !jobId || inFlightJob === jobId) return;
        if (renderedJob === jobId && content.querySelector(".ga-evidence-gaps")) return;
        inFlightJob = jobId;
        try {
            const documentData = await requestDocument(jobId);
            if (currentJobId() === jobId) renderSection(documentData, jobId);
        } catch {
            // The base correlation UI already owns request-error presentation.
        } finally {
            if (inFlightJob === jobId) inFlightJob = "";
        }
    }

    function schedule() {
        clearTimeout(timer);
        timer = setTimeout(sync, 30);
    }

    function boot() {
        const content = document.getElementById("ga-content");
        if (!content || observer) return;
        observer = new MutationObserver((records) => {
            const ownOnly = records.every((record) => {
                const target = record.target;
                return target instanceof Element && target.closest(".ga-evidence-gaps");
            });
            if (!ownOnly) schedule();
        });
        observer.observe(content, { childList: true, subtree: true });
        schedule();
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", boot);
    } else {
        boot();
    }
})();
