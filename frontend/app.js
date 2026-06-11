const api = {
  async get(path) {
    const res = await fetch(path);
    if (!res.ok) throw new Error(await res.text());
    return res.json();
  },
  async send(path, method, body, extraHeaders = {}) {
    const res = await fetch(path, {
      method,
      headers: {"Content-Type": "application/json", ...extraHeaders},
      body: JSON.stringify(body),
    });
    if (!res.ok) throw new Error(await res.text());
    return res.json();
  },
};

const impactStatuses = [
  "open",
  "acknowledged",
  "in_progress",
  "fixed",
  "accepted_risk",
  "false_positive",
  "not_affected",
];

let selectedImpactId = null;
let selectedServiceId = null;
let selectedAdvisoryId = null;
let currentSession = defaultSession();

function defaultSession() {
  return {
    auth_mode: "disabled",
    authenticated: false,
    principal: "web-console",
    roles: ["admin", "security-approver", "service-owner"],
    owner_teams: [],
    capabilities: {
      manage_services: true,
      manage_credentials: true,
      manage_alert_channels: true,
      update_impacts: true,
      bulk_update_impacts: true,
      accept_risk: true,
    },
  };
}

function can(capability) {
  return currentSession?.capabilities?.[capability] === true;
}

function hasRole(role) {
  return Array.isArray(currentSession?.roles) && currentSession.roles.includes(role);
}

function canBulkImpactTarget(status) {
  if (!can("bulk_update_impacts")) return false;
  if (hasRole("admin") || hasRole("security-approver") || currentSession.auth_mode === "disabled") return true;
  if (!hasRole("service-owner") || !["acknowledged", "in_progress"].includes(status)) return false;
  const ownerTeam = document.querySelector('#impact-filter-form input[name="owner_team"]')?.value?.trim();
  return Boolean(ownerTeam && currentSession.owner_teams?.includes(ownerTeam));
}

function setDisabled(selector, disabled) {
  document.querySelectorAll(selector).forEach((element) => {
    element.disabled = disabled;
  });
}

async function loadSession() {
  currentSession = await api.get("/api/v1/session");
  renderSessionSummary();
  applyRoleControls();
}

function renderSessionSummary() {
  const target = document.querySelector("#session-summary");
  if (!target) return;
  const roles = currentSession.roles?.length ? currentSession.roles.join(", ") : "no role";
  target.textContent = currentSession.auth_mode === "disabled"
    ? "auth disabled"
    : `${currentSession.principal || "unknown"} · ${roles}`;
}

function applyRoleControls() {
  setDisabled("#service-form button[type='submit'], #endpoint-test", !can("manage_services"));
  setDisabled("#credential-form button[type='submit']", !can("manage_credentials"));
  setDisabled("#alert-channel-form button[type='submit']", !can("manage_alert_channels"));
  setDisabled("#dispatcher-preflight-form button[type='submit']", !can("manage_alert_channels"));
  setDisabled("#dispatcher-activation-form button[type='submit']", !can("manage_alert_channels"));
  setDisabled("#daily-digest-preview-form button[type='submit']", !can("manage_alert_channels"));
  setDisabled("#canonicalization-apply", !can("manage_alert_channels"));
  setDisabled("#impact-bulk-action-form button[type='submit']", !can("bulk_update_impacts"));
  document.querySelectorAll("#impact-bulk-action-form select[name='target_status'] option").forEach((option) => {
    option.disabled = !canBulkImpactTarget(option.value);
  });
  const statusButton = document.querySelector("#impact-status-form button[type='submit']");
  if (statusButton) {
    statusButton.disabled = !can("update_impacts");
  }
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function metric(label, value) {
  return `<div class="metric"><strong>${escapeHtml(value)}</strong><span>${escapeHtml(label)}</span></div>`;
}

function alertReadinessMetric(readiness) {
  const status = readiness?.status || "unknown";
  const channel = readiness?.default_channel_target_masked || "no default channel";
  return `<div class="metric ${status === "ready" ? "" : "warning"}"><strong>${escapeHtml(status)}</strong><span>${escapeHtml(channel)}</span></div>`;
}

function advisorySyncReadinessMetric(readiness) {
  const status = readiness?.status || "unknown";
  const count = `${readiness?.initialized_count ?? 0}/${readiness?.required_count ?? 0}`;
  return `<div class="metric ${status === "ready" ? "" : "warning"}"><strong>${escapeHtml(status)}</strong><span>Advisory Sync ${escapeHtml(count)}</span></div>`;
}

function readinessClass(status) {
  if (["ready", "ok", "sqlite_fallback"].includes(status)) return "ok";
  if (["blocked", "not_ready", "failed"].includes(status)) return "danger";
  return "warning";
}

function renderReadinessBadge(status) {
  return `<span class="badge ${readinessClass(status)}">${escapeHtml(status || "unknown")}</span>`;
}

async function loadOverview() {
  const [overview, databaseReadiness, canonicalization] = await Promise.all([
    api.get("/api/v1/overview"),
    api.get("/api/v1/operations/database-readiness"),
    api.get("/api/v1/operations/canonicalization?limit=20"),
  ]);
  const alertReadiness = overview.alert_readiness || {};
  const advisorySyncReadiness = overview.advisory_sync_readiness || {};
  document.querySelector("#metrics").innerHTML = [
    metric("Services", overview.service_count),
    metric("Open Impacts", overview.open_impacts),
    metric("Critical", overview.critical_impacts),
    metric("High", overview.high_impacts),
    metric("SLA Overdue", overview.sla_overdue_impacts || 0),
    metric("Alert Pending", alertReadiness.pending_count || 0),
    metric("System Alerts", alertReadiness.system_pending_count || 0),
    metric("Dead Letters", alertReadiness.dead_letter_count || 0),
    alertReadinessMetric(alertReadiness),
    advisorySyncReadinessMetric(advisorySyncReadiness),
    metric("Endpoint Unhealthy", overview.endpoint_unhealthy),
  ].join("");
  renderDatabaseReadiness(databaseReadiness);
  renderCanonicalizationStatus(canonicalization);
}

function renderDatabaseReadiness(readiness) {
  const migration = readiness.migration || {};
  const cutover = readiness.cutover || {};
  const required = readiness.cutover_required || {};
  const preflight = readiness.postgres_preflight || {};
  document.querySelector("#database-readiness").innerHTML = `
    <div class="section-header">
      <h3>Database Readiness</h3>
      ${renderReadinessBadge(readiness.status)}
    </div>
    ${renderPostgresPreflightSummary(preflight)}
    <div class="detail-grid readiness-grid">
      ${detailRow("Backend", readiness.database_backend)}
      ${detailRow("URL Source", readiness.database_url_source || "unknown")}
      ${detailRow("Migration", `${migration.current ?? 0}/${migration.required ?? 0}`)}
      ${detailRow("Cutover Mode", cutover.mode || "unknown")}
      ${detailRow("Current Cutover", cutover.status || "unknown")}
      ${detailRow("PostgreSQL Required", required.status || "unknown")}
      ${detailRow("Split Required", required.require_split ? "yes" : "no")}
      ${detailRow("Required Mode", preflight.required_mode || required.mode || "unknown")}
      ${detailRow("PostgreSQL Configured", cutover.postgres_configured ? "yes" : "no")}
      ${detailRow("Split Ready", preflight.split_ready ? "yes" : "no")}
      ${detailRow("Preflight Checks", `${preflight.blockers ?? 0} blockers / ${preflight.warnings ?? 0} warnings / ${preflight.ok ?? 0} ok`)}
      ${detailRow("Next Action", preflight.next_action || "unknown")}
    </div>
    <div class="history readiness-checks">
      <h3>PostgreSQL Cutover Checks</h3>
      ${renderPostgresCutoverCheckGroups(required.checks || [])}
    </div>
  `;
}

function renderPostgresPreflightSummary(preflight) {
  const blockers = Number(preflight.blockers || 0);
  const warnings = Number(preflight.warnings || 0);
  const ok = Number(preflight.ok || 0);
  let status = "ok";
  let title = "Cutover ready";
  if (blockers > 0) {
    status = "danger";
    title = "Cutover blocked";
  } else if (warnings > 0) {
    status = "warning";
    title = "Cutover needs attention";
  }
  return `
    <div class="postgres-preflight-summary ${status}">
      <strong>${escapeHtml(title)}</strong>
      <span>${escapeHtml(`${blockers} blockers / ${warnings} warnings / ${ok} ok`)}</span>
      <p>${escapeHtml(preflight.next_action || "No next action reported.")}</p>
    </div>
  `;
}

function renderPostgresCutoverCheckGroups(checks) {
  if (!checks.length) {
    return '<ul><li><span>No checks reported.</span></li></ul>';
  }
  const groups = [
    ["blocker", "Blocking checks"],
    ["warning", "Warning checks"],
    ["ok", "Passing checks"],
  ];
  return groups.map(([status, title]) => {
    const items = checks.filter((check) => check.status === status);
    if (!items.length) return "";
    return `
      <div class="cutover-check-group ${status}">
        <h4>${escapeHtml(title)}</h4>
        <ul>${items.map((check) => `
          <li>
            ${renderReadinessBadge(check.status)}
            <span>${escapeHtml(check.id)}</span>
            <strong>${escapeHtml(check.detail)}</strong>
          </li>
        `).join("")}</ul>
      </div>
    `;
  }).join("");
}

function renderCanonicalizationStatus(status) {
  const advisoryMerge = status.advisory_merge || {};
  const impactBackfill = status.impact_backfill || {};
  const advisoryItems = (advisoryMerge.items || []).slice(0, 5).map((item) => `
    <li>
      ${renderReadinessBadge("action_required")}
      <span>${escapeHtml(item.alias_value)} · ${escapeHtml(item.ecosystem)} / ${escapeHtml(item.canonical_package_name)}</span>
      <strong>${escapeHtml(item.target_advisory_id)} ← ${escapeHtml((item.source_advisory_ids || []).join(", "))}</strong>
    </li>
  `).join("");
  const impactItems = (impactBackfill.items || []).slice(0, 5).map((item) => `
    <li>
      ${renderReadinessBadge(item.action || "update")}
      <span>${escapeHtml(item.impact_id)}</span>
      <strong>${escapeHtml(item.from_identity)} → ${escapeHtml(item.to_identity)}</strong>
    </li>
  `).join("");
  document.querySelector("#canonicalization-status").innerHTML = `
    <div class="section-header">
      <h3>Canonicalization</h3>
      ${renderReadinessBadge(status.status)}
    </div>
    <div class="detail-grid readiness-grid">
      ${detailRow("Pending Advisory Merges", status.pending_advisory_merges)}
      ${detailRow("Pending Impact Updates", status.pending_impact_updates)}
      ${detailRow("Advisory Groups Scanned", advisoryMerge.scanned_groups ?? 0)}
      ${detailRow("Impacts Scanned", impactBackfill.scanned ?? 0)}
      ${detailRow("Limit", status.limit)}
      ${detailRow("Dry Run", "yes")}
    </div>
    <div class="history readiness-checks">
      <h3>Advisory Merge Candidates</h3>
      <ul>${advisoryItems || "<li><span>No advisory merge candidates.</span></li>"}</ul>
      <h3>Impact Key Candidates</h3>
      <ul>${impactItems || "<li><span>No impact key candidates.</span></li>"}</ul>
    </div>
    <div class="inline-actions">
      <button type="button" id="canonicalization-apply" class="secondary" ${!can("manage_alert_channels") ? "disabled" : ""}>Apply Canonicalization</button>
      <span id="canonicalization-apply-result"></span>
    </div>
  `;
  const button = document.querySelector("#canonicalization-apply");
  if (button) {
    button.addEventListener("click", applyCanonicalization);
  }
}

async function applyCanonicalization() {
  if (!can("manage_alert_channels")) return;
  const target = document.querySelector("#canonicalization-apply-result");
  target.textContent = "Applying...";
  const data = await api.send("/api/v1/operations/canonicalization/apply", "POST", {
    limit: 100,
    actor: "web-console",
    reason: "manual canonicalization apply from overview",
  });
  target.textContent = `merged advisories ${data.merged_advisories}, updated impacts ${data.updated_impacts}, merged impacts ${data.merged_impacts}`;
  await Promise.all([loadOverview(), loadAdvisories(), loadImpacts(), loadAuditLogs()]);
}

async function loadServices() {
  const data = await api.get("/api/v1/services");
  document.querySelector("#service-count").textContent = `${data.services.length} registered`;
  const target = document.querySelector("#services-body");
  if (!data.services.length) {
    target.innerHTML = "";
    selectedServiceId = null;
    renderServiceDetailEmpty("No services registered.");
    return;
  }
  if (!selectedServiceId || !data.services.some((svc) => svc.service_id === selectedServiceId)) {
    selectedServiceId = data.services[0].service_id;
  }
  target.innerHTML = data.services.map((svc) => `
    <tr class="service-row ${svc.service_id === selectedServiceId ? "selected" : ""}" data-service-id="${escapeHtml(svc.service_id)}">
      <td><strong>${escapeHtml(svc.service_name)}</strong><br><span>${escapeHtml(svc.service_id)}</span></td>
      <td>${escapeHtml(svc.environment)}</td>
      <td>${escapeHtml(svc.owner_team)}</td>
      <td><span class="badge">${escapeHtml(svc.collection_status || "ok")} / ${escapeHtml(svc.freshness_status || "fresh")}</span><br><span>${escapeHtml(svc.status_auth_configured ? svc.status_auth_type : "no endpoint auth")}</span></td>
      <td>${escapeHtml(svc.open_impacts || 0)}</td>
    </tr>
  `).join("");
  target.querySelectorAll("[data-service-id]").forEach((row) => {
    row.addEventListener("click", () => selectService(row.dataset.serviceId));
  });
  await loadServiceDetail(selectedServiceId);
}

async function selectService(serviceId) {
  selectedServiceId = serviceId;
  document.querySelectorAll("[data-service-id]").forEach((row) => {
    row.classList.toggle("selected", row.dataset.serviceId === serviceId);
  });
  await loadServiceDetail(serviceId);
}

function renderServiceDetailEmpty(message) {
  document.querySelector("#service-detail").innerHTML = `<p>${escapeHtml(message)}</p>`;
}

async function loadServiceDetail(serviceId) {
  if (!serviceId) {
    renderServiceDetailEmpty("No service selected.");
    return;
  }
  const data = await api.get(`/api/v1/services/${encodeURIComponent(serviceId)}`);
  const service = data.service;
  const snapshot = data.latest_snapshot;
  const summary = data.dependency_summary.length
    ? data.dependency_summary.map((item) => `${item.ecosystem} ${item.count}`).join(" · ")
    : "no dependencies";
  const impacts = data.impacts.length
    ? data.impacts.slice(0, 5).map((impact) => `
      <li>
        <strong>${escapeHtml(impact.risk_level)} · ${escapeHtml(impact.package_name)}@${escapeHtml(impact.resolved_version)}</strong>
        <span>${escapeHtml(impact.advisory_id)} · ${escapeHtml(impact.status)}</span>
      </li>
    `).join("")
    : `<li><span>No impacts recorded.</span></li>`;
  document.querySelector("#service-detail").innerHTML = `
    <div class="section-header">
      <h3>${escapeHtml(service.service_name)}</h3>
      <span>${escapeHtml(service.environment)}</span>
    </div>
    <div class="detail-grid">
      ${detailRow("Owner", service.owner_team)}
      ${detailRow("Collection", service.collection_mode)}
      ${detailRow("Endpoint", service.status_endpoint_url || "-")}
      ${detailRow("Endpoint Health", `${service.collection_status || "ok"} / ${service.freshness_status || "fresh"}`)}
      ${detailRow("Snapshot", snapshot ? snapshot.snapshot_id : "-")}
      ${detailRow("Collected", snapshot ? snapshot.collected_at : "-")}
      ${detailRow("Dependencies", summary)}
      ${detailRow("Open Impacts", data.impacts.filter((impact) => ["open", "acknowledged", "in_progress"].includes(impact.status)).length)}
    </div>
    <div class="history">
      <h3>Service Impacts</h3>
      <ul>${impacts}</ul>
    </div>
  `;
}

async function loadImpacts() {
  const query = impactFilterQuery();
  syncImpactFiltersToUrl(query);
  const data = await api.get(`/api/v1/impacts${query ? `?${query}` : ""}`);
  const target = document.querySelector("#impacts-list");
  if (!data.impacts.length) {
    target.innerHTML = `<p>${query ? "No impacts match the selected filters." : "No open impacts. Push the demo lodash snapshot to see matching behavior."}</p>`;
    renderImpactPagination(data.pagination);
    selectedImpactId = null;
    renderImpactDetailEmpty("No impact selected.");
    return;
  }
  target.innerHTML = data.impacts.map((impact) => `
    <button class="impact ${escapeHtml(impact.risk_level)} ${impact.id === selectedImpactId ? "selected" : ""}" data-impact-id="${escapeHtml(impact.id)}">
      <div class="impact-header">
        <div>
          <strong>${escapeHtml(impact.service_id)} / ${escapeHtml(impact.package_name)}@${escapeHtml(impact.resolved_version)}</strong>
          <p>${escapeHtml(impact.summary)}</p>
        </div>
        <span class="badge">${escapeHtml(impact.risk_level)}</span>
      </div>
      <p>Advisory: ${escapeHtml(impact.advisory_id)} · Status: ${escapeHtml(impact.status)} · ${escapeHtml(impact.is_known_exploited ? "KEV" : "not KEV")} · ${escapeHtml(impact.is_malicious_package ? "malicious" : "not malicious")} · Fix: ${escapeHtml(impact.fixed_version || "remove/replace")}</p>
    </button>
  `).join("");
  target.querySelectorAll("[data-impact-id]").forEach((item) => {
    item.addEventListener("click", () => selectImpact(item.dataset.impactId));
  });
  if (selectedImpactId && data.impacts.some((impact) => impact.id === selectedImpactId)) {
    await loadImpactDetail(selectedImpactId);
  } else {
    selectedImpactId = data.impacts[0].id;
    await loadImpactDetail(selectedImpactId);
  }
  renderImpactPagination(data.pagination);
}

async function loadAdvisories() {
  const data = await api.get("/api/v1/advisories");
  const target = document.querySelector("#advisory-list");
  if (!data.advisories.length) {
    target.innerHTML = `<p>No advisories imported.</p>`;
    selectedAdvisoryId = null;
    renderAdvisoryDetailEmpty("No advisory selected.");
    return;
  }
  if (!selectedAdvisoryId || !data.advisories.some((advisory) => advisory.advisory_id === selectedAdvisoryId)) {
    selectedAdvisoryId = data.advisories[0].advisory_id;
  }
  target.innerHTML = data.advisories.map((advisory) => `
    <button class="impact ${escapeHtml(advisory.severity)} ${advisory.advisory_id === selectedAdvisoryId ? "selected" : ""}" data-advisory-id="${escapeHtml(advisory.advisory_id)}">
      <div class="impact-header">
        <div>
          <strong>${escapeHtml(advisory.advisory_id)} · ${escapeHtml(advisory.package_name || "-")}</strong>
          <p>${escapeHtml(advisory.summary || "-")}</p>
        </div>
        <span class="badge">${escapeHtml(advisory.source)} / ${escapeHtml(advisory.severity || "-")}</span>
      </div>
      <p>${escapeHtml(advisory.ecosystem || "-")} · fix ${escapeHtml(advisory.fixed_version || "remove/replace")} · modified ${escapeHtml(advisory.modified_at || "-")}</p>
    </button>
  `).join("");
  target.querySelectorAll("[data-advisory-id]").forEach((item) => {
    item.addEventListener("click", () => selectAdvisory(item.dataset.advisoryId));
  });
  await loadAdvisoryDetail(selectedAdvisoryId);
}

async function selectAdvisory(advisoryId) {
  selectedAdvisoryId = advisoryId;
  document.querySelectorAll("[data-advisory-id]").forEach((item) => {
    item.classList.toggle("selected", item.dataset.advisoryId === advisoryId);
  });
  await loadAdvisoryDetail(advisoryId);
}

function renderAdvisoryDetailEmpty(message) {
  document.querySelector("#advisory-detail").innerHTML = `<p>${escapeHtml(message)}</p>`;
}

async function loadAdvisoryDetail(advisoryId) {
  if (!advisoryId) {
    renderAdvisoryDetailEmpty("No advisory selected.");
    return;
  }
  const data = await api.get(`/api/v1/advisories/${encodeURIComponent(advisoryId)}`);
  const advisory = data.advisory;
  const aliases = Array.isArray(advisory.raw_payload?.aliases) ? advisory.raw_payload.aliases.join(", ") : "-";
  const impacts = data.impacts.length
    ? data.impacts.map((impact) => `
      <li>
        <strong>${escapeHtml(impact.service_id)} / ${escapeHtml(impact.package_name)}@${escapeHtml(impact.resolved_version)}</strong>
        <span>${escapeHtml(impact.risk_level)} · ${escapeHtml(impact.status)} · ${escapeHtml(impact.environment)} · ${escapeHtml(impact.owner_team || "-")}</span>
      </li>
    `).join("")
    : `<li><span>No matching impacts recorded.</span></li>`;
  document.querySelector("#advisory-detail").innerHTML = `
    <div class="detail-grid">
      ${detailRow("Advisory", `${advisory.source}:${advisory.advisory_id}`)}
      ${detailRow("Severity", advisory.severity)}
      ${detailRow("Package", `${advisory.ecosystem || "-"} / ${advisory.package_name || "-"}`)}
      ${detailRow("Fixed Version", advisory.fixed_version || "remove/replace")}
      ${detailRow("Known Exploited", advisory.is_known_exploited ? "yes" : "no")}
      ${detailRow("Malicious Package", advisory.is_malicious_package ? "yes" : "no")}
      ${detailRow("Published", advisory.published_at)}
      ${detailRow("Modified", advisory.modified_at)}
      ${detailRow("Aliases", aliases)}
      ${detailRow("Affected Versions", JSON.stringify(advisory.affected_versions || []))}
      ${detailRow("Affected Ranges", JSON.stringify(advisory.affected_ranges || []))}
    </div>
    <p class="detail-summary">${escapeHtml(advisory.summary || "-")}</p>
    <div class="history">
      <h3>Matched Impacts</h3>
      <ul>${impacts}</ul>
    </div>
  `;
}

async function selectImpact(impactId) {
  selectedImpactId = impactId;
  document.querySelectorAll("[data-impact-id]").forEach((item) => {
    item.classList.toggle("selected", item.dataset.impactId === impactId);
  });
  await loadImpactDetail(impactId);
}

function detailRow(label, value) {
  return `<div><span>${escapeHtml(label)}</span><strong>${escapeHtml(value ?? "-")}</strong></div>`;
}

function renderImpactDetailEmpty(message) {
  document.querySelector("#impact-detail").innerHTML = `<p>${escapeHtml(message)}</p>`;
}

async function loadImpactDetail(impactId) {
  const data = await api.get(`/api/v1/impacts/${encodeURIComponent(impactId)}`);
  const impact = data.impact;
  const affectedRanges = impact.affected_ranges ? JSON.stringify(impact.affected_ranges) : "-";
  const history = data.history.length
    ? data.history.map((item) => `
      <li>
        <strong>${escapeHtml(item.from_status)} → ${escapeHtml(item.to_status)}</strong>
        <span>${escapeHtml(item.actor || "system")} · ${escapeHtml(item.created_at)}</span>
        ${item.reason ? `<p>${escapeHtml(item.reason)}</p>` : ""}
      </li>
    `).join("")
    : `<li><span>No status changes recorded.</span></li>`;
  const acceptedRisk = data.accepted_risk
    ? `<p class="detail-summary"><strong>Accepted Risk</strong><br>Approved by ${escapeHtml(data.accepted_risk.approved_by)} until ${escapeHtml(data.accepted_risk.expires_at)} · ${escapeHtml(data.accepted_risk.reason)}</p>`
    : "";

  document.querySelector("#impact-detail").innerHTML = `
    <div class="detail-grid">
      ${detailRow("Service", `${impact.service_name} (${impact.service_id})`)}
      ${detailRow("Package", `${impact.package_name}@${impact.resolved_version}`)}
      ${detailRow("Advisory", `${impact.source}:${impact.advisory_id}`)}
      ${detailRow("Risk / Status", `${impact.risk_level} / ${impact.status}`)}
      ${detailRow("Fixed Version", impact.fixed_version || "remove/replace")}
      ${detailRow("Freshness", impact.freshness_status)}
      ${detailRow("First Detected", impact.first_detected_at)}
      ${detailRow("Last Seen", impact.last_seen_at)}
      ${detailRow("Alert Key", impact.alert_suppression_key)}
      ${detailRow("Affected Range", affectedRanges)}
    </div>
    <p class="detail-summary">${escapeHtml(impact.summary)}</p>
    ${acceptedRisk}
    <form id="impact-status-form" class="status-form">
      <label>Status
        <select name="status">
          ${impactStatuses.map((status) => {
            const disableAcceptedRisk = status === "accepted_risk" && !can("accept_risk") && status !== impact.status;
            return `<option value="${status}" ${status === impact.status ? "selected" : ""} ${disableAcceptedRisk ? "disabled" : ""}>${status}</option>`;
          }).join("")}
        </select>
      </label>
      <label>Actor<input name="actor" value="web-console" /></label>
      <label>Accepted Until<input name="expires_at" type="datetime-local" /></label>
      <label>Reason<input name="reason" placeholder="Short note for audit history" /></label>
      <button type="submit">Update Status</button>
    </form>
    <div class="history">
      <h3>Status History</h3>
      <ul>${history}</ul>
    </div>
  `;
  document.querySelector("#impact-status-form").addEventListener("submit", updateImpactStatus);
  applyRoleControls();
}

async function updateImpactStatus(event) {
  event.preventDefault();
  if (!selectedImpactId) return;
  const body = Object.fromEntries(new FormData(event.currentTarget).entries());
  if (!can("update_impacts") || (body.status === "accepted_risk" && !can("accept_risk"))) {
    return;
  }
  await api.send(`/api/v1/impacts/${encodeURIComponent(selectedImpactId)}/status`, "PATCH", body);
  await Promise.all([loadOverview(), loadServices(), loadImpacts()]);
}

function impactFilterQuery() {
  const form = document.querySelector("#impact-filter-form");
  const params = new URLSearchParams();
  for (const [key, value] of new FormData(form).entries()) {
    if (String(value).trim()) {
      params.set(key, String(value).trim());
    }
  }
  return params.toString();
}

function impactFilterObjectForBulk() {
  const form = document.querySelector("#impact-filter-form");
  const ignored = new Set(["offset", "limit", "sort", "direction"]);
  const filters = {};
  for (const [key, value] of new FormData(form).entries()) {
    const text = String(value).trim();
    if (text && !ignored.has(key)) {
      filters[key] = text;
    }
  }
  return filters;
}

function syncImpactFiltersToUrl(query) {
  const url = `${window.location.pathname}${query ? `?${query}` : ""}${window.location.hash}`;
  window.history.replaceState(null, "", url);
}

function loadImpactFiltersFromUrl() {
  const form = document.querySelector("#impact-filter-form");
  const params = new URLSearchParams(window.location.search);
  for (const element of form.elements) {
    if (!element.name || !params.has(element.name)) continue;
    element.value = params.get(element.name);
  }
}

function renderImpactPagination(pagination) {
  const target = document.querySelector("#impact-pagination");
  if (!pagination) {
    target.innerHTML = "";
    return;
  }
  const start = pagination.total ? pagination.offset + 1 : 0;
  const end = pagination.offset + pagination.returned;
  target.innerHTML = `
    <span>${escapeHtml(start)}-${escapeHtml(end)} of ${escapeHtml(pagination.total)}</span>
    <div>
      <button type="button" class="secondary" data-page-offset="${escapeHtml(pagination.prev_offset ?? "")}" ${pagination.prev_offset === null ? "disabled" : ""}>Prev</button>
      <button type="button" class="secondary" data-page-offset="${escapeHtml(pagination.next_offset ?? "")}" ${pagination.next_offset === null ? "disabled" : ""}>Next</button>
    </div>
  `;
  target.querySelectorAll("[data-page-offset]").forEach((button) => {
    button.addEventListener("click", async () => {
      if (!button.dataset.pageOffset) return;
      document.querySelector('#impact-filter-form input[name="offset"]').value = button.dataset.pageOffset;
      selectedImpactId = null;
      await loadImpacts();
    });
  });
}

async function refreshAll() {
  await loadSession();
  await Promise.all([loadOverview(), loadServices(), loadImpacts(), loadAdvisories(), loadAlertChannels(), loadDispatcherPreflight(), loadDispatcherActivationChecklist(), loadAlertEvents(), loadAuditLogs()]);
  applyRoleControls();
}

document.querySelector("#refresh").addEventListener("click", refreshAll);

document.querySelector("#impact-filter-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  event.currentTarget.elements.offset.value = "0";
  selectedImpactId = null;
  await loadImpacts();
  applyRoleControls();
});

document.querySelector("#clear-impact-filters").addEventListener("click", async () => {
  document.querySelector("#impact-filter-form").reset();
  document.querySelector('#impact-filter-form input[name="offset"]').value = "0";
  selectedImpactId = null;
  await loadImpacts();
  applyRoleControls();
});

document.querySelector("#impact-bulk-action-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!can("bulk_update_impacts")) return;
  const form = Object.fromEntries(new FormData(event.currentTarget).entries());
  if (!canBulkImpactTarget(form.target_status)) return;
  const data = await api.send("/api/v1/impacts/status", "POST", {
    target_status: form.target_status,
    filters: impactFilterObjectForBulk(),
    limit: form.limit,
    actor: "web-console",
    reason: form.reason || "bulk status update from web console",
  });
  document.querySelector("#impact-bulk-result").innerHTML = `
    <p><strong>${escapeHtml(data.updated)} impacts updated.</strong> ${escapeHtml(data.skipped)} skipped, ${escapeHtml(data.matched)} matched current filters.</p>
  `;
  selectedImpactId = null;
  await Promise.all([loadOverview(), loadServices(), loadImpacts(), loadAuditLogs()]);
});

document.querySelector("#alert-event-filter-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  await loadAlertEvents();
});

document.querySelector("#audit-log-filter-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  await loadAuditLogs();
});

document.querySelector("#dispatcher-preflight-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!can("manage_alert_channels")) return;
  await loadDispatcherPreflight();
});

document.querySelector("#dispatcher-activation-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!can("manage_alert_channels")) return;
  await loadDispatcherActivationChecklist();
});

document.querySelector("#daily-digest-preview-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!can("manage_alert_channels")) return;
  const form = Object.fromEntries(new FormData(event.currentTarget).entries());
  const body = {
    date: form.date,
    timezone: form.timezone || "Asia/Seoul",
    limit: form.limit,
    actor: "web-console",
  };
  const data = await api.send("/api/v1/alerts/daily-digest/preview", "POST", body);
  renderDailyDigestPreview(data);
});

document.querySelector("#bulk-requeue-alert-events").addEventListener("click", async () => {
  const form = Object.fromEntries(new FormData(document.querySelector("#alert-event-filter-form")).entries());
  const reason = alertEventRequeueReason(form, "bulk requeue from web console");
  const data = await api.send("/api/v1/alert-events/requeue", "POST", {
    status: "dead_letter",
    q: form.q,
    limit: form.limit,
    actor: "web-console",
    reason,
  });
  await Promise.all([loadAlertEvents(), loadOverview(), focusRequeueAuditLogs(reason)]);
  document.querySelector("#alert-event-list").insertAdjacentHTML(
    "afterbegin",
    `<p><strong>${escapeHtml(data.requeued)} dead-letter events requeued.</strong> Audit filter updated to alert_event.requeue.</p>`,
  );
});

document.querySelector("#service-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!can("manage_services")) return;
  const form = new FormData(event.currentTarget);
  await api.send("/api/v1/services", "POST", Object.fromEntries(form.entries()));
  event.currentTarget.reset();
  await refreshAll();
});

document.querySelector("#endpoint-test").addEventListener("click", async () => {
  if (!can("manage_services")) return;
  const form = Object.fromEntries(new FormData(document.querySelector("#service-form")).entries());
  const result = document.querySelector("#endpoint-test-result");
  await api.send("/api/v1/services", "POST", form);
  const data = await api.send(`/api/v1/services/${encodeURIComponent(form.service_id)}/endpoint/test`, "POST", {
    environment: form.environment,
    endpoint_url: form.status_endpoint_url,
    status_bearer_token: form.status_bearer_token,
  });
  result.innerHTML = `<p><strong>${escapeHtml(data.collection_status)} / ${escapeHtml(data.freshness_status)}</strong></p>`;
  await refreshAll();
});

document.querySelector("#credential-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!can("manage_credentials")) return;
  const form = Object.fromEntries(new FormData(event.currentTarget).entries());
  const data = await api.send(`/api/v1/services/${encodeURIComponent(form.service_id)}/push-credentials`, "POST", {
    environment: form.environment,
    ttl_days: form.ttl_days,
  });
  document.querySelector("#credential-result").innerHTML = `
    <p><strong>Token issued for ${escapeHtml(data.credential.service_id)} / ${escapeHtml(data.credential.environment)}</strong></p>
    <label>Token<input readonly value="${escapeHtml(data.token)}" /></label>
    <p>Prefix: ${escapeHtml(data.credential.token_prefix)} · Expires: ${escapeHtml(data.credential.expires_at)}</p>
  `;
  await loadPushCredentials(form.service_id, form.environment);
});

document.querySelector("#credential-form input[name='service_id']").addEventListener("change", refreshCredentialListFromForm);
document.querySelector("#credential-form select[name='environment']").addEventListener("change", refreshCredentialListFromForm);

async function refreshCredentialListFromForm() {
  const form = Object.fromEntries(new FormData(document.querySelector("#credential-form")).entries());
  if (!form.service_id) {
    document.querySelector("#credential-list").innerHTML = "";
    return;
  }
  await loadPushCredentials(form.service_id, form.environment);
}

async function loadPushCredentials(serviceId, environment) {
  const data = await api.get(`/api/v1/services/${encodeURIComponent(serviceId)}/push-credentials?environment=${encodeURIComponent(environment || "prod")}`);
  const target = document.querySelector("#credential-list");
  const canManageCredentials = can("manage_credentials");
  if (!data.credentials.length) {
    target.innerHTML = `<p>No push credentials issued.</p>`;
    return;
  }
  target.innerHTML = data.credentials.map((credential) => `
    <div class="credential-item">
      <div>
        <strong>${escapeHtml(credential.token_prefix)}</strong>
        <span>${escapeHtml(credential.revoked_at ? "revoked" : "active")} · expires ${escapeHtml(credential.expires_at || "-")}</span>
      </div>
      <button type="button" class="secondary" data-credential-rotate="${escapeHtml(credential.id)}" ${credential.revoked_at || !canManageCredentials ? "disabled" : ""}>Rotate</button>
      <button type="button" class="secondary" data-credential-id="${escapeHtml(credential.id)}" ${credential.revoked_at || !canManageCredentials ? "disabled" : ""}>Revoke</button>
    </div>
  `).join("");
  target.querySelectorAll("[data-credential-rotate]").forEach((button) => {
    button.addEventListener("click", async () => {
      if (!can("manage_credentials")) return;
      const data = await api.send(`/api/v1/services/${encodeURIComponent(serviceId)}/push-credentials/${encodeURIComponent(button.dataset.credentialRotate)}/rotate`, "POST", {
        environment,
        reason: "web console credential rotation",
      });
      document.querySelector("#credential-result").innerHTML = `
        <p><strong>Token rotated for ${escapeHtml(data.credential.service_id)} / ${escapeHtml(data.credential.environment)}</strong></p>
        <label>Token<input readonly value="${escapeHtml(data.token)}" /></label>
        <p>New prefix: ${escapeHtml(data.credential.token_prefix)} · Expires: ${escapeHtml(data.credential.expires_at)}</p>
      `;
      await loadPushCredentials(serviceId, environment);
    });
  });
  target.querySelectorAll("[data-credential-id]").forEach((button) => {
    button.addEventListener("click", async () => {
      if (!can("manage_credentials")) return;
      await api.send(`/api/v1/services/${encodeURIComponent(serviceId)}/push-credentials/${encodeURIComponent(button.dataset.credentialId)}/revoke`, "POST", {environment});
      await loadPushCredentials(serviceId, environment);
    });
  });
}

document.querySelector("#snapshot-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = Object.fromEntries(new FormData(event.currentTarget).entries());
  const headers = form.token ? {"Authorization": `Bearer ${form.token}`} : {};
  await api.send("/api/v1/snapshots", "POST", {
    schema_version: "1.0",
    service_id: form.service_id,
    environment: "prod",
    generated_at: new Date().toISOString(),
    artifact: {type: "container_image", name: form.service_id, digest: `sha256:${Date.now()}`},
    dependencies: [
      {
        ecosystem: "npm",
        name: form.package_name,
        version: form.version,
        purl: `pkg:npm/${form.package_name}@${form.version}`,
        scope: "production",
        direct: false,
        source: "demo",
      },
    ],
  }, headers);
  await refreshAll();
});

document.querySelector("#alert-channel-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!can("manage_alert_channels")) return;
  const form = Object.fromEntries(new FormData(event.currentTarget).entries());
  await api.send("/api/v1/settings/alert-channels", "POST", {
    name: form.name,
    channel_type: "webhook",
    target_url: form.target_url,
    is_default: form.is_default === "on",
  });
  event.currentTarget.reset();
  await loadAlertChannels();
});

async function loadAlertChannels() {
  const target = document.querySelector("#alert-channel-list");
  if (!target) return;
  const data = await api.get("/api/v1/settings/alert-channels");
  const canManageAlertChannels = can("manage_alert_channels");
  if (!data.channels.length) {
    target.innerHTML = `<p>No alert channels configured.</p>`;
    return;
  }
  target.innerHTML = data.channels.map((channel) => `
    <div class="credential-item">
      <div>
        <strong>${escapeHtml(channel.name)}</strong>
        <span>${escapeHtml(channel.channel_type)} · ${escapeHtml(channel.enabled ? "enabled" : "disabled")} · ${escapeHtml(channel.is_default ? "default" : "secondary")} · ${escapeHtml(channel.target_url_masked || "-")}</span>
        <div class="badge-row">
          ${channel.placeholder_target ? `<span class="badge danger">placeholder target</span>` : `<span class="badge">target ready</span>`}
          ${channel.is_default && channel.placeholder_target ? `<span class="badge danger">live dispatcher blocked</span>` : ""}
        </div>
      </div>
      <button type="button" class="secondary" data-channel-test="${escapeHtml(channel.id)}" ${!channel.enabled || !canManageAlertChannels ? "disabled" : ""}>Test</button>
      <button type="button" class="secondary" data-channel-default="${escapeHtml(channel.id)}" ${channel.is_default || !channel.enabled || !canManageAlertChannels ? "disabled" : ""}>Make Default</button>
      <button type="button" class="secondary" data-channel-disable="${escapeHtml(channel.id)}" ${!channel.enabled || !canManageAlertChannels ? "disabled" : ""}>Disable</button>
    </div>
  `).join("");
  target.querySelectorAll("[data-channel-test]").forEach((button) => {
    button.addEventListener("click", async () => {
      if (!can("manage_alert_channels")) return;
      await api.send(`/api/v1/settings/alert-channels/${encodeURIComponent(button.dataset.channelTest)}/test`, "POST", {
        actor: "web-console",
        reason: "manual alert channel smoke test",
      });
      await Promise.all([loadAlertChannels(), loadAuditLogs()]);
    });
  });
  target.querySelectorAll("[data-channel-default]").forEach((button) => {
    button.addEventListener("click", async () => {
      if (!can("manage_alert_channels")) return;
      await api.send(`/api/v1/settings/alert-channels/${encodeURIComponent(button.dataset.channelDefault)}`, "PATCH", {is_default: true, enabled: true});
      await loadAlertChannels();
    });
  });
  target.querySelectorAll("[data-channel-disable]").forEach((button) => {
    button.addEventListener("click", async () => {
      if (!can("manage_alert_channels")) return;
      await api.send(`/api/v1/settings/alert-channels/${encodeURIComponent(button.dataset.channelDisable)}`, "PATCH", {enabled: false});
      await loadAlertChannels();
    });
  });
}

async function loadDispatcherPreflight() {
  const target = document.querySelector("#dispatcher-preflight-result");
  const form = document.querySelector("#dispatcher-preflight-form");
  if (!target || !form) return;
  if (!can("manage_alert_channels")) {
    target.innerHTML = `<p>Admin role required.</p>`;
    return;
  }
  const params = new URLSearchParams();
  for (const [key, value] of new FormData(form).entries()) {
    if (String(value).trim()) {
      params.set(key, String(value).trim());
    }
  }
  if (!params.has("limit")) params.set("limit", "50");
  const data = await api.get(`/api/v1/alerts/dispatcher/preflight?${params.toString()}`);
  renderDispatcherPreflight(data);
}

function renderDispatcherPreflight(data) {
  const target = document.querySelector("#dispatcher-preflight-result");
  const checks = Object.entries(data.checks || {}).map(([name, passed]) => `
    <span class="badge ${passed ? "" : "danger"}">${escapeHtml(name)}: ${escapeHtml(passed ? "ok" : "failed")}</span>
  `).join("");
  const channel = data.default_alert_channel || {};
  const failures = data.failures?.length ? `<span>${escapeHtml(data.failures.join(", "))}</span>` : "";
  target.innerHTML = `
    <div class="credential-item">
      <div>
        <strong>${escapeHtml(data.status)} · pending ${escapeHtml(data.dry_run?.pending ?? 0)}</strong>
        <span>${escapeHtml(channel.configured ? channel.target_url_masked : "default channel not configured")}</span>
        ${failures}
        <div class="badge-row">${checks}</div>
      </div>
    </div>
  `;
}

async function loadDispatcherActivationChecklist() {
  const target = document.querySelector("#dispatcher-activation-result");
  const form = document.querySelector("#dispatcher-activation-form");
  if (!target || !form) return;
  if (!can("manage_alert_channels")) {
    target.innerHTML = `<p>Admin role required.</p>`;
    return;
  }
  const params = new URLSearchParams();
  for (const [key, value] of new FormData(form).entries()) {
    if (String(value).trim()) {
      params.set(key, String(value).trim());
    }
  }
  if (!params.has("limit")) params.set("limit", "50");
  const data = await api.get(`/api/v1/alerts/dispatcher/activation-checklist?${params.toString()}`);
  renderDispatcherActivationChecklist(data);
}

function renderDispatcherActivationChecklist(data) {
  const target = document.querySelector("#dispatcher-activation-result");
  const items = (data.items || []).map((item) => `
    <span class="badge ${item.status === "passed" ? "" : "danger"}" title="${escapeHtml(item.reason)}">${escapeHtml(item.name)}: ${escapeHtml(item.status)}</span>
  `).join("");
  const channel = data.preflight?.default_alert_channel || {};
  const failures = data.blocking_failures?.length ? `<span>${escapeHtml(data.blocking_failures.join(", "))}</span>` : "";
  target.innerHTML = `
    <div class="credential-item">
      <div>
        <strong>${escapeHtml(data.status)} · ${escapeHtml(data.next_action)}</strong>
        <span>${escapeHtml(channel.configured ? channel.target_url_masked : "default channel not configured")}</span>
        ${failures}
        <div class="badge-row">${items}</div>
      </div>
    </div>
  `;
}

async function loadAlertEvents() {
  const target = document.querySelector("#alert-event-list");
  if (!target) return;
  const query = alertEventFilterQuery();
  const data = await api.get(`/api/v1/alert-events?${query}`);
  if (!data.alert_events.length) {
    target.innerHTML = `<p>No alert events match the selected filters.</p>`;
    return;
  }
  target.innerHTML = data.alert_events.map((event) => `
    <div class="credential-item">
      <div>
        <strong>${escapeHtml(event.status)} · ${escapeHtml(event.service_id || "-")} / ${escapeHtml(event.package_name || "-")}</strong>
        <span>${escapeHtml(event.reason || "-")} · ${escapeHtml(event.advisory_id || event.alert_suppression_key || "-")} · retries ${escapeHtml(event.retry_count || 0)} · ${escapeHtml(event.created_at)}</span>
        ${renderAlertEventPayloadSummary(event.payload)}
        ${renderAlertEventPayloadDetails(event.payload)}
      </div>
      <button type="button" class="secondary" data-alert-requeue="${escapeHtml(event.id)}" ${event.status !== "dead_letter" ? "disabled" : ""}>Requeue</button>
    </div>
  `).join("");
  target.querySelectorAll("[data-alert-requeue]").forEach((button) => {
    button.addEventListener("click", async () => {
      const form = Object.fromEntries(new FormData(document.querySelector("#alert-event-filter-form")).entries());
      const reason = alertEventRequeueReason(form, "manual requeue");
      await api.send(`/api/v1/alert-events/${encodeURIComponent(button.dataset.alertRequeue)}/requeue`, "POST", {
        actor: "web-console",
        reason,
      });
      await Promise.all([loadAlertEvents(), loadOverview(), focusRequeueAuditLogs(reason)]);
    });
  });
}

function renderAlertEventPayloadSummary(payload) {
  if (!payload || typeof payload !== "object") return "";
  const fields = [
    ["source", payload.source],
    ["error", payload.error_message || payload.dispatch_error],
    ["resolved", payload.resolved_at],
    ["requeued", payload.requeued_at],
  ].filter(([, value]) => value);
  if (!fields.length) return "";
  return `<span>${fields.map(([label, value]) => `${escapeHtml(label)}: ${escapeHtml(value)}`).join(" · ")}</span>`;
}

function renderAlertEventPayloadDetails(payload) {
  if (!payload || typeof payload !== "object" || !Object.keys(payload).length) return "";
  return `
    <details class="payload-detail">
      <summary>Payload</summary>
      <pre>${escapeHtml(JSON.stringify(payload, null, 2))}</pre>
    </details>
  `;
}

function renderDailyDigestPreview(data) {
  const target = document.querySelector("#daily-digest-preview");
  const items = data.items || [];
  const sample = items.slice(0, 5).map((item) => `
    <div class="credential-item">
      <div>
        <strong>${escapeHtml(item.risk_level)} · ${escapeHtml(item.service_id)} / ${escapeHtml(item.package_name)}@${escapeHtml(item.resolved_version)}</strong>
        <span>${escapeHtml(item.environment)} · ${escapeHtml(item.advisory_id)} · ${escapeHtml(item.status)}</span>
      </div>
    </div>
  `).join("");
  target.innerHTML = `
    <div class="credential-item">
      <div>
        <strong>${escapeHtml(data.matched)} candidates · ${escapeHtml(data.digest_date)}</strong>
        <span>${escapeHtml(data.alert_suppression_key)} · ${escapeHtml(data.existing_alert_event_status || "not enqueued")}</span>
      </div>
    </div>
    ${sample || "<p>No digest candidates for the selected scope.</p>"}
  `;
}

function alertEventFilterQuery() {
  const form = document.querySelector("#alert-event-filter-form");
  const params = new URLSearchParams();
  for (const [key, value] of new FormData(form).entries()) {
    if (key === "requeue_reason") continue;
    if (String(value).trim()) {
      params.set(key, String(value).trim());
    }
  }
  if (!params.has("limit")) params.set("limit", "10");
  return params.toString();
}

function alertEventRequeueReason(form, fallback) {
  return String(form.requeue_reason || "").trim() || fallback;
}

async function focusRequeueAuditLogs(reason) {
  const form = document.querySelector("#audit-log-filter-form");
  if (!form) return;
  form.elements.action.value = "alert_event.requeue";
  form.elements.target_type.value = "alert_event";
  form.elements.q.value = reason || "";
  await loadAuditLogs();
  document.querySelector("#audit-log-list").insertAdjacentHTML(
    "afterbegin",
    `<p><strong>Audit filter updated to alert_event.requeue.</strong></p>`,
  );
}

async function loadAuditLogs() {
  const target = document.querySelector("#audit-log-list");
  if (!target) return;
  const query = auditLogFilterQuery();
  const data = await api.get(`/api/v1/audit-logs?${query}`);
  if (!data.audit_logs.length) {
    target.innerHTML = `<p>No audit logs match the selected filters.</p>`;
    return;
  }
  target.innerHTML = data.audit_logs.map((item) => `
    <div class="credential-item audit-item">
      <div>
        <strong>${escapeHtml(item.action)} · ${escapeHtml(item.actor || "-")}</strong>
        <span>${escapeHtml(item.target_type)}:${escapeHtml(item.target_id)} · ${escapeHtml(item.occurred_at)}</span>
        ${item.reason ? `<span>${escapeHtml(item.reason)}</span>` : ""}
        <span>${escapeHtml(auditChangeSummary(item))}</span>
      </div>
    </div>
  `).join("");
}

function auditLogFilterQuery() {
  const form = document.querySelector("#audit-log-filter-form");
  const params = new URLSearchParams();
  for (const [key, value] of new FormData(form).entries()) {
    if (String(value).trim()) {
      params.set(key, String(value).trim());
    }
  }
  if (!params.has("limit")) params.set("limit", "10");
  return params.toString();
}

function auditChangeSummary(item) {
  const before = item.before || {};
  const after = item.after || {};
  if (before.status || after.status) {
    return `status ${before.status || "-"} → ${after.status || "-"}`;
  }
  if (before.enabled !== undefined || after.enabled !== undefined) {
    return `enabled ${before.enabled ?? "-"} → ${after.enabled ?? "-"}`;
  }
  if (before.is_default !== undefined || after.is_default !== undefined) {
    return `default ${before.is_default ?? "-"} → ${after.is_default ?? "-"}`;
  }
  return "change recorded";
}

loadImpactFiltersFromUrl();

refreshAll().catch((error) => {
  document.querySelector("main").insertAdjacentHTML("afterbegin", `<div class="section"><strong>Load failed</strong><p>${error.message}</p></div>`);
});
