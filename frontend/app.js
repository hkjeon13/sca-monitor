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

function metric(label, value) {
  return `<div class="metric"><strong>${value}</strong><span>${label}</span></div>`;
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
      <td><strong>${svc.service_name}</strong><br><span>${svc.service_id}</span></td>
      <td>${svc.environment}</td>
      <td>${svc.owner_team}</td>
      <td><span class="badge">${svc.collection_status || "ok"} / ${svc.freshness_status || "fresh"}</span></td>
      <td>${svc.open_impacts || 0}</td>
    </tr>
  `).join("");
}

async function loadImpacts() {
  const data = await api.get("/api/v1/impacts");
  const target = document.querySelector("#impacts-list");
  if (!data.impacts.length) {
    target.innerHTML = `<p>No open impacts. Push the demo lodash snapshot to see matching behavior.</p>`;
    return;
  }
  target.innerHTML = data.impacts.map((impact) => `
    <article class="impact ${impact.risk_level}">
      <div class="impact-header">
        <div>
          <strong>${impact.service_id} / ${impact.package_name}@${impact.resolved_version}</strong>
          <p>${impact.summary}</p>
        </div>
        <span class="badge">${impact.risk_level}</span>
      </div>
      <p>Advisory: ${impact.advisory_id} · Status: ${impact.status} · Fix: ${impact.fixed_version || "remove/replace"}</p>
    </article>
  `).join("");
}

async function refreshAll() {
  await Promise.all([loadOverview(), loadServices(), loadImpacts()]);
}

document.querySelector("#refresh").addEventListener("click", refreshAll);

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

