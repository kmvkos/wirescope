(() => {
    "use strict";

    const API = "/api/v1";
    const baseRenderer = window.WireScopeTopology;
    if (!baseRenderer || typeof baseRenderer.render !== "function") return;

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
            throw new Error((detail && detail.message) || response.statusText || `HTTP ${response.status}`);
        }
        return data;
    }

    function findControlSelect(controls, values) {
        const required = new Set(values);
        return Array.from(controls.querySelectorAll("select")).find((select) => {
            const options = new Set(Array.from(select.options).map((option) => option.value));
            return Array.from(required).every((value) => options.has(value));
        }) || null;
    }

    function findApplyButton(controls) {
        return Array.from(controls.querySelectorAll("button")).find((button) =>
            /применить\s+pcap/i.test(button.textContent || "")
        ) || null;
    }

    function metric(label, value) {
        const node = el("div", null, "ws-metric");
        node.append(el("strong", value ?? "—"), el("span", label));
        return node;
    }

    function statusLabel(status) {
        return ({
            compatible: "тот же observation domain",
            partial: "частичное совпадение domain",
            different_domain: "другой observation domain",
            insufficient_evidence: "недостаточно evidence",
        })[status] || status || "не определено";
    }

    function correlationLabel(status) {
        return ({
            matched: "есть совпадения",
            conflict: "identity-конфликт",
            no_exact_match: "точных совпадений нет",
            partial: "частичная корреляция",
            skipped_different_domain: "корреляция не выполнялась",
            insufficient_evidence: "недостаточно evidence",
            compatible_without_exact_identity: "domain совпал, identity — нет",
        })[status] || status || "не определено";
    }

    function normalizeRelationLabels(body) {
        const replacements = {
            l3_next_hop: "next hop",
        };
        body.querySelectorAll(".ws-topology-svg text").forEach((node) => {
            const current = String(node.textContent || "").trim();
            if (replacements[current]) node.textContent = replacements[current];
        });
    }

    function ensurePanel(body, controls) {
        let panel = body.querySelector(".ws-topology-pcap-evidence");
        if (panel) return panel;
        panel = el("section", null, "ws-topology-pcap-evidence");
        controls.insertAdjacentElement("afterend", panel);
        panel.hidden = true;
        return panel;
    }

    function renderReasons(host, items, cls = "") {
        if (!(items || []).length) return;
        const details = el("details", null, "ws-topology-pcap-details");
        details.append(el("summary", "Почему WireScope сделал такой вывод"));
        const list = el("ul", null, cls);
        items.forEach((item) => list.append(el("li", item)));
        details.append(list);
        host.append(details);
    }

    function renderPanel(panel, topology) {
        panel.replaceChildren();
        const overlay = topology && topology.overlay;
        if (!overlay) {
            panel.hidden = true;
            return;
        }
        panel.hidden = false;

        const presentation = topology.presentation || {};
        const compatibility = overlay.compatibility || {};
        const correlation = overlay.correlation || {};
        const topologyEnrichment = overlay.topology_enrichment || {};
        const discovery = overlay.discovery || {};
        const nextHop = overlay.next_hop || {};
        const labelConflicts = presentation.identity_label_conflicts || [];
        const trafficView = ((presentation.views || {}).traffic || {});
        const status = compatibility.status || "insufficient_evidence";

        const head = el("div", null, "ws-topology-pcap-evidence-head");
        const title = el("div");
        title.append(
            el("strong", `PCAP ${String(overlay.traffic_analysis_job_id || "").slice(0, 8)}`),
            el("span", ` · ${overlay.interface || "интерфейс неизвестен"}`)
        );
        const badge = el(
            "span",
            statusLabel(status),
            `ws-topology-pcap-domain ws-topology-pcap-domain-${status}`
        );
        head.append(title, badge);
        panel.append(head);

        if (status === "different_domain") {
            panel.append(el(
                "p",
                "Этот PCAP и выбранный аудит относятся к разным точкам/сегментам наблюдения. WireScope не будет трактовать 0 совпадений как плохую корреляцию и не должен склеивать их устройства напрямую.",
                "warning"
            ));
        } else if (status === "compatible") {
            panel.append(el(
                "p",
                "PCAP совместим с observation domain аудита. Strong identity evidence можно использовать для корреляции и структурной карты.",
                "ws-ok"
            ));
        } else if (status === "partial") {
            panel.append(el(
                "p",
                "Есть пересечение observation domains, но данных недостаточно для агрессивного merge. Совпадения остаются консервативными.",
                "warning"
            ));
        } else {
            panel.append(el(
                "p",
                "PCAP подключён, но пока недостаточно evidence, чтобы доказать совпадение или различие сетевых доменов.",
                "muted"
            ));
        }

        if (topologyEnrichment.allowed === false) {
            panel.append(el(
                "p",
                "Структурное обогащение отключено для этого PCAP: endpoint state, identity, discovery devices и next-hop не переносятся в текущую схему. Raw Traffic/Evidence при этом остаются доступны отдельно.",
                "ws-topology-enrichment-blocked"
            ));
        }

        const grid = el("div", null, "ws-metric-grid ws-topology-pcap-metrics");
        grid.append(
            metric("Domain", statusLabel(status)),
            metric("Correlation", correlationLabel(correlation.status)),
            metric("Совпало assets", correlation.matched_asset_count ?? (correlation.matches || []).length ?? 0),
            metric("Identity conflicts", (correlation.conflicts || []).length),
            metric("Discovery devices", discovery.device_count ?? 0),
            metric("L3 next-hop", nextHop.topology_edges_added ?? nextHop.candidate_count ?? 0),
            metric("Next-hop отброшено", nextHop.identity_collision_count ?? 0),
            metric("Разделено подписей", labelConflicts.length)
        );
        panel.append(grid);

        if (correlation.headline) panel.append(el("p", correlation.headline));
        if (nextHop.topology_edges_added) {
            panel.append(el(
                "p",
                `В структурную/L3-карту добавлено ${nextHop.topology_edges_added} подтверждённых наблюдением next-hop связей. Это immediate next hop в точке захвата, а не дорисованный полный маршрут до Internet.`,
                "ws-ok"
            ));
        }
        if (nextHop.identity_collision_count) {
            panel.append(el(
                "p",
                `Отброшено next-hop кандидатов из-за identity collision: ${nextHop.identity_collision_count}. Source и next hop разрешились в одно устройство, поэтому self-loop намеренно не рисуется.`,
                "warning"
            ));
        }

        const cleanup = [];
        if (trafficView.external_peers_aggregated) {
            cleanup.push(`внешние peers свёрнуты в Internet: ${trafficView.external_peer_count || 0}`);
        } else if (trafficView.external_peer_count) {
            cleanup.push(`внешних peers: ${trafficView.external_peer_count}`);
        }
        if (trafficView.arp_edges_hidden) cleanup.push(`ARP communication edges скрыто: ${trafficView.arp_edges_hidden}`);
        if (trafficView.hidden_endpoint_edges) cleanup.push(`служебных/broadcast edges скрыто: ${trafficView.hidden_endpoint_edges}`);
        if (trafficView.raw_node_count !== undefined && trafficView.visible_node_count !== undefined) {
            cleanup.push(`Traffic view: ${trafficView.raw_node_count} → ${trafficView.visible_node_count} узлов`);
        }
        if (cleanup.length) panel.append(el("p", cleanup.join(" · "), "muted"));

        const discoveryParts = [];
        if (discovery.cdp_devices) discoveryParts.push(`CDP ${discovery.cdp_devices}`);
        if (discovery.lldp_devices) discoveryParts.push(`LLDP ${discovery.lldp_devices}`);
        if (discovery.mndp_devices) discoveryParts.push(`MNDP ${discovery.mndp_devices}`);
        if (discoveryParts.length) {
            const discoverySuffix = discovery.topology_enrichment_skipped
                ? " Объявления сохранены как evidence, но не добавлены в structural map из-за observation-domain guard."
                : " Эти объявления используются как identity/topology evidence, а не как обычный traffic edge.";
            panel.append(el("p", `Discovery: ${discoveryParts.join(" · ")}.${discoverySuffix}`));
        }

        renderReasons(panel, compatibility.reasons || []);

        if ((correlation.conflicts || []).length) {
            const details = el("details", null, "ws-topology-pcap-details");
            details.append(el("summary", `Identity-конфликты · ${correlation.conflicts.length}`));
            const list = el("ul");
            correlation.conflicts.slice(0, 20).forEach((item) => {
                list.append(el("li", item.reason || item.type || JSON.stringify(item)));
            });
            details.append(list);
            panel.append(details);
        }

        if (labelConflicts.length) {
            const details = el("details", null, "ws-topology-pcap-details");
            details.append(el("summary", `Одинаковые подписи, разные identity · ${labelConflicts.length}`));
            const list = el("ul");
            labelConflicts.slice(0, 20).forEach((item) => {
                const macs = (item.macs || []).join(" ↔ ");
                list.append(el("li", `${item.label || "одинаковая подпись"}: ${macs || item.reason || "разные identity"}`));
            });
            details.append(list);
            panel.append(details);
        }
    }

    function waitForApply(button, timeoutMs = 12000) {
        return new Promise((resolve) => {
            const started = Date.now();
            const poll = () => {
                if (!button.isConnected || !button.disabled || Date.now() - started >= timeoutMs) {
                    resolve();
                    return;
                }
                setTimeout(poll, 60);
            };
            setTimeout(poll, 0);
        });
    }

    async function attach(body, auditId) {
        const controls = body.querySelector(".ws-topology-v2-controls");
        if (!controls || controls.dataset.m12EvidenceUi === "1") return;
        controls.dataset.m12EvidenceUi = "1";

        const mode = findControlSelect(controls, ["audit", "global"]);
        const level = findControlSelect(controls, ["structural", "l2", "l3", "traffic", "evidence"]);
        const pcap = Array.from(controls.querySelectorAll("select")).find((select) =>
            Array.from(select.options).some((option) => option.textContent.includes("Без PCAP overlay"))
        );
        const apply = findApplyButton(controls);
        if (!level || !pcap || !apply) return;

        const panel = ensurePanel(body, controls);
        normalizeRelationLabels(body);

        // Capture phase runs before topology_hardening's target listener. Keep
        // the operator's chosen map instead of its legacy forced switch to
        // `traffic` after a PCAP is applied.
        controls.addEventListener("click", async (event) => {
            const target = event.target.closest && event.target.closest("button");
            if (target !== apply) return;
            const preferredView = level.value || "structural";
            const selectedAnalysis = pcap.value;

            await waitForApply(apply);
            if (!apply.isConnected) return;

            if (level.value !== preferredView) {
                level.value = preferredView;
                level.dispatchEvent(new Event("change", { bubbles: true }));
            }
            normalizeRelationLabels(body);

            if (!selectedAnalysis) {
                panel.hidden = true;
                panel.replaceChildren();
                return;
            }

            try {
                const topology = await request(
                    `/audits/${encodeURIComponent(auditId)}/topology?traffic_analysis_job_id=${encodeURIComponent(selectedAnalysis)}`
                );
                renderPanel(panel, topology);
                normalizeRelationLabels(body);
            } catch (error) {
                panel.hidden = false;
                panel.replaceChildren(el("p", error.message, "error"));
            }
        }, true);

        level.addEventListener("change", () => {
            setTimeout(() => normalizeRelationLabels(body), 0);
        });

        if (mode) {
            mode.addEventListener("change", () => {
                panel.hidden = mode.value === "global" || !pcap.value;
                setTimeout(() => normalizeRelationLabels(body), 0);
            });
        }
    }

    async function render(body, auditId) {
        const result = await baseRenderer.render(body, auditId);
        await attach(body, auditId);
        normalizeRelationLabels(body);
        return result;
    }

    window.WireScopeTopologyEvidenceBase = baseRenderer;
    window.WireScopeTopology = {
        ...baseRenderer,
        render,
        version: "m12-evidence-ui",
    };
})();
