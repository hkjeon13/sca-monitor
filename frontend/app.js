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

async function loadOverview() {
  const overview = await api.get("/api/v1/overview");
  document.querySelector("#metrics").innerHTML = [
    metric("Services", overview.service_count),
    metric("Open Impacts", overview.open_impacts),
    metric("Critical", overview.critical_impacts),
    metric("High", overview.high_impacts),
    metric("Endpoint Unhealthy", overview.endpoint_unhealthy),
  ].join("");
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
      <p>Advisory: ${escapeHtml(impact.advisory_id)} · Status: ${escapeHtml(impact.status)} · Fix: ${escapeHtml(impact.fixed_version || "remove/replace")}</p>
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
  return `<div><span>${escapeHtml(label)}</span><strong>${escapeHtml(value || "-")}</strong></div>`;
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
          ${impactStatuses.map((status) => `<option value="${status}" ${status === impact.status ? "selected" : ""}>${status}</option>`).join("")}
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
}

async function updateImpactStatus(event) {
  event.preventDefault();
  if (!selectedImpactId) return;
  const body = Object.fromEntries(new FormData(event.currentTarget).entries());
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
  await Promise.all([loadOverview(), loadServices(), loadImpacts(), loadAdvisories(), loadAlertChannels(), loadAlertEvents(), loadAuditLogs()]);
}

document.querySelector("#refresh").addEventListener("click", refreshAll);

document.querySelector("#impact-filter-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  event.currentTarget.elements.offset.value = "0";
  selectedImpactId = null;
  await loadImpacts();
});

document.querySelector("#clear-impact-filters").addEventListener("click", async () => {
  document.querySelector("#impact-filter-form").reset();
  document.querySelector('#impact-filter-form input[name="offset"]').value = "0";
  selectedImpactId = null;
  await loadImpacts();
});

document.querySelector("#alert-event-filter-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  await loadAlertEvents();
});

document.querySelector("#audit-log-filter-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  await loadAuditLogs();
});

document.querySelector("#bulk-requeue-alert-events").addEventListener("click", async () => {
  const form = Object.fromEntries(new FormData(document.querySelector("#alert-event-filter-form")).entries());
  const data = await api.send("/api/v1/alert-events/requeue", "POST", {
    status: "dead_letter",
    q: form.q,
    limit: form.limit,
    actor: "web-console",
    reason: "bulk requeue from web console",
  });
  await Promise.all([loadAlertEvents(), loadOverview()]);
  document.querySelector("#alert-event-list").insertAdjacentHTML(
    "afterbegin",
    `<p><strong>${escapeHtml(data.requeued)} dead-letter events requeued.</strong></p>`,
  );
});

document.querySelector("#service-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  await api.send("/api/v1/services", "POST", Object.fromEntries(form.entries()));
  event.currentTarget.reset();
  await refreshAll();
});

document.querySelector("#endpoint-test").addEventListener("click", async () => {
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
      <button type="button" class="secondary" data-credential-id="${escapeHtml(credential.id)}" ${credential.revoked_at ? "disabled" : ""}>Revoke</button>
    </div>
  `).join("");
  target.querySelectorAll("[data-credential-id]").forEach((button) => {
    button.addEventListener("click", async () => {
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
  if (!data.channels.length) {
    target.innerHTML = `<p>No alert channels configured.</p>`;
    return;
  }
  target.innerHTML = data.channels.map((channel) => `
    <div class="credential-item">
      <div>
        <strong>${escapeHtml(channel.name)}</strong>
        <span>${escapeHtml(channel.channel_type)} · ${escapeHtml(channel.enabled ? "enabled" : "disabled")} · ${escapeHtml(channel.is_default ? "default" : "secondary")} · ${escapeHtml(channel.target_url_masked || "-")}</span>
      </div>
      <button type="button" class="secondary" data-channel-default="${escapeHtml(channel.id)}" ${channel.is_default || !channel.enabled ? "disabled" : ""}>Make Default</button>
      <button type="button" class="secondary" data-channel-disable="${escapeHtml(channel.id)}" ${!channel.enabled ? "disabled" : ""}>Disable</button>
    </div>
  `).join("");
  target.querySelectorAll("[data-channel-default]").forEach((button) => {
    button.addEventListener("click", async () => {
      await api.send(`/api/v1/settings/alert-channels/${encodeURIComponent(button.dataset.channelDefault)}`, "PATCH", {is_default: true, enabled: true});
      await loadAlertChannels();
    });
  });
  target.querySelectorAll("[data-channel-disable]").forEach((button) => {
    button.addEventListener("click", async () => {
      await api.send(`/api/v1/settings/alert-channels/${encodeURIComponent(button.dataset.channelDisable)}`, "PATCH", {enabled: false});
      await loadAlertChannels();
    });
  });
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
        <span>${escapeHtml(event.advisory_id || "-")} · retries ${escapeHtml(event.retry_count || 0)} · ${escapeHtml(event.created_at)}</span>
      </div>
      <button type="button" class="secondary" data-alert-requeue="${escapeHtml(event.id)}" ${event.status !== "dead_letter" ? "disabled" : ""}>Requeue</button>
    </div>
  `).join("");
  target.querySelectorAll("[data-alert-requeue]").forEach((button) => {
    button.addEventListener("click", async () => {
      await api.send(`/api/v1/alert-events/${encodeURIComponent(button.dataset.alertRequeue)}/requeue`, "POST", {
        actor: "web-console",
        reason: "manual requeue",
      });
      await Promise.all([loadAlertEvents(), loadAuditLogs(), loadOverview()]);
    });
  });
}

function alertEventFilterQuery() {
  const form = document.querySelector("#alert-event-filter-form");
  const params = new URLSearchParams();
  for (const [key, value] of new FormData(form).entries()) {
    if (String(value).trim()) {
      params.set(key, String(value).trim());
    }
  }
  if (!params.has("limit")) params.set("limit", "10");
  return params.toString();
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
