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
  document.querySelector("#services-body").innerHTML = data.services.map((svc) => `
    <tr>
      <td><strong>${escapeHtml(svc.service_name)}</strong><br><span>${escapeHtml(svc.service_id)}</span></td>
      <td>${escapeHtml(svc.environment)}</td>
      <td>${escapeHtml(svc.owner_team)}</td>
      <td><span class="badge">${escapeHtml(svc.collection_status || "ok")} / ${escapeHtml(svc.freshness_status || "fresh")}</span><br><span>${escapeHtml(svc.status_auth_configured ? svc.status_auth_type : "no endpoint auth")}</span></td>
      <td>${escapeHtml(svc.open_impacts || 0)}</td>
    </tr>
  `).join("");
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
    <form id="impact-status-form" class="status-form">
      <label>Status
        <select name="status">
          ${impactStatuses.map((status) => `<option value="${status}" ${status === impact.status ? "selected" : ""}>${status}</option>`).join("")}
        </select>
      </label>
      <label>Actor<input name="actor" value="web-console" /></label>
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
  await Promise.all([loadOverview(), loadServices(), loadImpacts(), loadAlertChannels()]);
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
        <span>${escapeHtml(channel.channel_type)} · ${escapeHtml(channel.is_default ? "default" : "secondary")} · ${escapeHtml(channel.target_url_masked || "-")}</span>
      </div>
    </div>
  `).join("");
}

loadImpactFiltersFromUrl();

refreshAll().catch((error) => {
  document.querySelector("main").insertAdjacentHTML("afterbegin", `<div class="section"><strong>Load failed</strong><p>${error.message}</p></div>`);
});
