const api = {
  async get(path) {
    const res = await fetch(path);
    if (!res.ok) throw new Error(await res.text());
    return res.json();
  },
  async send(path, method, body) {
    const res = await fetch(path, {
      method,
      headers: {"Content-Type": "application/json"},
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
      <td><span class="badge">${escapeHtml(svc.collection_status || "ok")} / ${escapeHtml(svc.freshness_status || "fresh")}</span></td>
      <td>${escapeHtml(svc.open_impacts || 0)}</td>
    </tr>
  `).join("");
}

async function loadImpacts() {
  const query = impactFilterQuery();
  const data = await api.get(`/api/v1/impacts${query ? `?${query}` : ""}`);
  const target = document.querySelector("#impacts-list");
  if (!data.impacts.length) {
    target.innerHTML = `<p>${query ? "No impacts match the selected filters." : "No open impacts. Push the demo lodash snapshot to see matching behavior."}</p>`;
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

async function refreshAll() {
  await Promise.all([loadOverview(), loadServices(), loadImpacts()]);
}

document.querySelector("#refresh").addEventListener("click", refreshAll);

document.querySelector("#impact-filter-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  selectedImpactId = null;
  await loadImpacts();
});

document.querySelector("#clear-impact-filters").addEventListener("click", async () => {
  document.querySelector("#impact-filter-form").reset();
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

document.querySelector("#snapshot-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = Object.fromEntries(new FormData(event.currentTarget).entries());
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
  });
  await refreshAll();
});

refreshAll().catch((error) => {
  document.querySelector("main").insertAdjacentHTML("afterbegin", `<div class="section"><strong>Load failed</strong><p>${error.message}</p></div>`);
});
