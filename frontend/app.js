/* Account-scoped SCA workspace. No credentials are stored in browser storage. */
const $ = (s) => document.querySelector(s);
const esc = (v) =>
  String(v ?? "").replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ],
  );
const number = (v) => Number(v || 0).toLocaleString("ko-KR");
const date = (v) =>
  v
    ? new Intl.DateTimeFormat("ko-KR", {
        dateStyle: "short",
        timeStyle: "short",
        timeZone: "Asia/Seoul",
      }).format(new Date(v))
    : "기록 없음";
const sources = ["OSV", "GHSA", "OpenSSF", "CISA_KEV", "NVD"];
const stateLabels = {
  running: "수집 중",
  potential: "검토 후보",
  unknown: "판단 정보 부족",
  active: "활성",
  archived: "보관",
  owner: "소유자",
  maintainer: "관리·조치",
  viewer: "조회",
  fresh: "최신",
  stale: "지연",
  failed: "실패",
  partial: "부분 수집",
  not_initialized: "미수집",
  open: "미확인",
  acknowledged: "확인함",
  in_progress: "조치 중",
  fixed: "해결",
  not_affected: "영향 없음",
  false_positive: "오탐",
  accepted_risk: "위험 수용",
  pending: "대기",
  sent: "발송 완료",
  dead_letter: "재시도 종료",
  dispatching: "발송 중",
  resolved: "종료",
};
let user = null,
  projects = [],
  scope = "",
  renderId = 0,
  activeHelp = null;
let setupToken = location.hash.startsWith("#setup=")
  ? location.hash.slice(7)
  : "";
const help = (description, label = "항목") =>
  `<button type="button" class="info-trigger" data-help="${esc(description)}" aria-label="${esc(label)} 설명" aria-expanded="false">i</button>`;
const pill = (value) =>
  `<span class="badge ${["critical", "failed", "error", "dead_letter"].includes(value) ? "danger" : ["high", "stale", "partial", "pending", "unknown"].includes(value) ? "warning" : ["fresh", "fixed", "sent"].includes(value) ? "ok" : ""}">${esc(stateLabels[value] || value || "정보 없음")}</span>`;
const field = (label, control, description = "") =>
  `<label><span class="field-label">${esc(label)}${description ? help(description, label) : ""}</span>${control}</label>`;
const input = (name, placeholder = "", value = "", type = "text", extra = "") =>
  `<input name="${name}" type="${type}" placeholder="${esc(placeholder)}" value="${esc(value)}" ${extra}>`;
const select = (name, items, selected = "") =>
  `<select name="${name}">${items.map(([value, label]) => `<option value="${esc(value)}" ${String(value) === String(selected) ? "selected" : ""}>${esc(label)}</option>`).join("")}</select>`;
const query = (params) => {
  const p = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => {
    if (v !== "" && v != null) p.set(k, v);
  });
  return p.toString();
};
function route() {
  const [path, q = ""] = location.hash.slice(1).split("?");
  return {
    path: path || "overview",
    params: Object.fromEntries(new URLSearchParams(q)),
  };
}
function go(path, params = {}) {
  location.hash = path + (query(params) ? "?" + query(params) : "");
}
function toast(text, error = false) {
  $("#toast").textContent = text;
  $("#toast").className = "toast" + (error ? " error" : "");
  $("#toast").hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => ($("#toast").hidden = true), 6000);
}
async function api(path, method = "GET", body) {
  const response = await fetch("/api/v2/" + path, {
    method,
    headers: {
      "Content-Type": "application/json",
      ...(user ? { "X-CSRF-Token": user.csrf_token } : {}),
    },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  const data = await response.json();
  if (!response.ok) {
    if (response.status === 401 && !path.startsWith("auth/")) showAuth();
    throw new Error(data.error || "요청을 처리하지 못했습니다.");
  }
  return data;
}
function showAuth() {
  user = null;
  $("#console").hidden = true;
  $("#auth-screen").hidden = false;
  const setup = Boolean(setupToken);
  $("#auth-title").textContent = setup ? "계정 설정" : "로그인";
  $("#auth-description").textContent = setup
    ? "설정 링크로 계정의 이름과 비밀번호를 등록합니다."
    : "내 프로젝트의 패키지와 보안 영향을 확인하세요.";
  $("#display-name-field").hidden = !setup;
  $("#password-hint").hidden = !setup;
  $("#auth-submit").textContent = setup ? "계정 설정 완료" : "로그인";
  const password = $("#auth-form [name=password]");
  password.autocomplete = setup ? "new-password" : "current-password";
  password.minLength = setup ? 12 : 1;
  $("#auth-form [name=display_name]").required = setup;
}
async function loadSession() {
  const session = await api("auth/session");
  if (!session.user || setupToken) {
    showAuth();
    return;
  }
  user = session.user;
  projects = (await api("projects")).items;
  $("#auth-screen").hidden = true;
  $("#console").hidden = false;
  $("#account-name").textContent =
    user.display_name + " · " + user.email + (user.is_admin ? " · 관리자" : "");
  updateScope();
  await render();
}
function updateScope() {
  if (scope && !projects.some((p) => p.id === scope)) scope = "";
  $("#project-scope").innerHTML =
    '<option value="">내 전체 프로젝트</option>' +
    projects
      .map((p) => `<option value="${esc(p.id)}">${esc(p.name)}</option>`)
      .join("");
  $("#project-scope").value = scope;
}
function section(title, description, body, extra = "") {
  return `<section class="section workspace-section"><div class="section-header"><div><h2>${title}</h2>${description ? `<p>${description}</p>` : ""}</div>${extra}</div>${body}</section>`;
}
function empty(title, description, link = "") {
  return `<div class="empty-state"><strong>${esc(title)}</strong><p>${esc(description)}</p>${link}</div>`;
}
function freshness(items) {
  const bad = items.filter((s) => s.status !== "fresh");
  return `<div class="coverage-note ${bad.length ? "attention" : "healthy"}">${bad.length ? "◷ " + esc(bad.map((s) => s.source).join(", ")) + " 수집 상태를 확인해 주세요." : "● 모든 소스의 수집 시각이 설정 기준 안에 있습니다."} ${help("영향이 0건이어도 인벤토리나 외부 보안 정보 수집이 오래됐다면 현재 안전 여부를 판단할 수 없습니다. 소스별 저장 건수는 수집된 기록 수이며 전 세계 CVE 전체 수가 아닙니다.", "수집 신선도")}<a href="#operations">수집 상태 보기 ↗</a></div>`;
}
function pagination(data, path, params) {
  return `<div class="pagination"><span>검색 결과 ${number(data.total)}건 · ${data.total ? data.offset + 1 : 0}–${Math.min(data.offset + data.items.length, data.total)}</span><div>${data.offset ? `<button type="button" class="secondary" data-page-path="${path}" data-page-params="${esc(JSON.stringify({ ...params, cursor: "" }))}">처음</button>` : ""}${data.next_cursor ? `<button type="button" class="secondary" data-page-path="${path}" data-page-params="${esc(JSON.stringify({ ...params, cursor: data.next_cursor }))}">다음 →</button>` : ""}</div></div>`;
}
function metric(label, value, description, href, tone = "") {
  return `<div class="metric metric-${tone}"><a class="metric-link" href="${href}"><span class="metric-label">${esc(label)}</span><strong>${number(value)}</strong></a>${help(description, label)}</div>`;
}
function advisoryRows(items) {
  return items
    .map(
      (a) =>
        `<button type="button" class="result-row" data-advisory="${esc(a.id)}"><span class="result-copy"><strong>${esc(a.advisory_id)}</strong><span>${esc(a.summary)}</span><small>${esc(a.package_name || a.ecosystem || "제품/패키지 정보 없음")} · 수정 ${date(a.modified_at)}</small></span><span class="row-badges">${pill(a.severity)}<span class="state-pill">${esc(a.source)}</span>${a.is_known_exploited ? '<span class="state-pill critical">KEV</span>' : ""}${a.is_malicious_package ? '<span class="state-pill critical">악성</span>' : ""}</span></button>`,
    )
    .join("");
}
async function overview() {
  const data = await api("overview?" + query({ project_id: scope }));
  const c = data.counts;
  const cards =
    metric(
      "프로젝트",
      c.projects,
      "내가 접근할 수 있는 프로젝트 수입니다. 프로젝트 하나를 선택하면 1개 범위로 집계합니다.",
      "#projects",
    ) +
    metric(
      "열린 영향",
      c.open_findings,
      "미확인·확인함·조치 중인 프로젝트/서비스/패키지별 매칭 결과입니다. 동일 취약점이 여러 서비스에 있으면 여러 건입니다.",
      "#findings",
      "cyan",
    ) +
    metric(
      "관련 보안 정보",
      c.unique_advisories,
      "열린 영향에 연결된 서로 다른 저장 어드바이저리 수입니다. CVE 별칭이나 패키지별 기록은 별도로 존재할 수 있습니다.",
      "#findings",
    ) +
    metric(
      "Critical / High",
      c.critical + c.high,
      "열린 영향 중 Critical " +
        c.critical +
        "건, High " +
        c.high +
        "건입니다. 외부 심각도와 서비스 환경을 고려한 우선순위입니다.",
      "#findings",
      "critical",
    ) +
    metric(
      "신규 영향 · 7일",
      c.new_7d,
      "최근 7일에 처음 발견되어 아직 조치가 열려 있는 영향입니다. 공개된 CVE 전체 수와 다릅니다.",
      "#findings",
      "high",
    ) +
    metric(
      "수집 확인 필요",
      c.stale_targets,
      "최신 패키지 목록이 없거나 신선도 기준을 넘긴 서비스/환경 수입니다.",
      "#projects",
      "high",
    );
  const bars = data.trend
    .map(
      (t) =>
        `<div class="trend-day" title="${esc(t.date)} 신규 ${t.new} / 해결 ${t.resolved}"><i style="height:${Math.max(2, Math.min(90, t.new * 8))}px"></i><b style="height:${Math.max(2, Math.min(90, t.resolved * 8))}px"></b></div>`,
    )
    .join("");
  return (
    freshness(data.coverage) +
    `<div class="metrics">${cards}</div><div class="workspace-grid">` +
    section(
      "지금 조치할 영향 " +
        help(
          "미해결 영향 중 위험도가 높은 순서입니다. 오래된 수집 데이터에 기반한 결과는 상세에서 다시 확인하세요.",
          "우선 조치",
        ),
      "프로젝트와 사용 중인 패키지를 함께 확인합니다.",
      data.urgent_findings.length
        ? data.urgent_findings
            .map(
              (f) =>
                `<button class="result-row" type="button" data-finding="${esc(f.id)}"><span class="result-copy"><strong>${esc(f.project_name)} / ${esc(f.service_name)}</strong><span>${esc(f.package_name)}@${esc(f.resolved_version)}</span><small>${esc(f.advisory_id)} · ${pill(f.status)}</small></span>${pill(f.risk_level)}</button>`,
            )
            .join("")
        : empty(
            "열린 영향이 없습니다",
            "등록된 대상과 수집 상태를 함께 확인해 주세요.",
          ),
    ) +
    section(
      scope ? "프로젝트 내 대상" : "프로젝트별 현황",
      "보안 영향과 수집 범위를 확인합니다.",
      data.project_risk.length
        ? data.project_risk
            .map(
              (p) =>
                `<a href="#projects/${esc(p.id)}" class="project-risk-row"><strong>${esc(p.name)}</strong><span>대상 ${number(p.target_count)} · 열린 영향 ${number(p.open_findings)}</span></a>`,
            )
            .join("")
        : empty(
            "프로젝트를 등록하세요",
            "서비스의 패키지 목록을 연결하면 영향 분석이 시작됩니다.",
            '<a class="button-link" href="#projects">프로젝트 등록 ↗</a>',
          ),
    ) +
    section(
      "최근 수정된 보안 정보 " +
        help(
          "전체 소스에서 로컬 DB에 수집한 최근 수정 기록입니다. 내 프로젝트에 영향을 준다는 의미는 아닙니다. 공개일, 소스 수정일, 로컬 최초 수집일은 상세에서 구분합니다.",
          "최근 보안 정보",
        ),
      "수정일 기준 · 전체 소스",
      advisoryRows(data.recent_advisories),
      '<a class="panel-link" href="#intel">전체 탐색 ↗</a>',
    ) +
    section(
      "영향 발생·해결 추세",
      "최근 30일 · 신규와 해결 건수",
      `<div class="trend-legend"><span>● 신규</span><span>● 해결</span></div><div class="trend-chart">${bars}</div><p class="muted">수집이 중단된 기간의 0건은 신규 취약점이 없다는 뜻이 아닙니다.</p>`,
    ) +
    `</div><p class="as-of">집계 ${date(data.as_of)} · ${esc(data.scope.project_name)}</p>`
  );
}
async function intel(params) {
  const data = await api("intel/advisories?" + query(params));
  const tabs = ["", ...sources]
    .map(
      (s) =>
        `<a class="tab ${String(params.source || "") === s ? "active" : ""}" href="#intel?${query({ ...params, source: s, cursor: "" })}">${s || "통합"} ${s ? number(data.source_freshness.find((x) => x.source === s)?.stored_count) : ""}</a>`,
    )
    .join("");
  const filters = `<form id="intel-search" class="search-form"><div class="search-primary">${field("검색", input("q", "CVE, GHSA, MAL ID · 패키지 · 키워드", params.q || ""))}<button>검색</button><a class="button-link secondary" href="#intel">초기화</a></div><input type="hidden" name="source" value="${esc(params.source || "")}"><details class="advanced-filters"><summary>고급 필터</summary><div class="form-grid">${field("생태계", input("ecosystem", "npm, PyPI, Maven 등", params.ecosystem || ""), "패키지가 배포된 생태계입니다. 소스에서 제공하지 않으면 검색되지 않을 수 있습니다.")}${field("심각도", select("severity", [["", "전체"], ...["critical", "high", "medium", "low"].map((x) => [x, x])], params.severity))}${field(
    "KEV",
    select(
      "kev",
      [
        ["", "전체"],
        ["true", "실제 악용 이력 있음"],
      ],
      params.kev,
    ),
    "CISA가 실제 악용 이력을 확인한 취약점입니다.",
  )}${field(
    "악성 패키지",
    select(
      "malicious",
      [
        ["", "전체"],
        ["true", "보고된 악성 패키지"],
      ],
      params.malicious,
    ),
  )}${field("내 프로젝트 관련", select("project_id", [["", "전체 보안 정보"], ...projects.map((p) => [p.id, p.name])], params.project_id), "선택한 프로젝트에 영향 기록이 있는 보안 정보만 표시합니다.")}${field("수정일 이후", input("modified_from", "", params.modified_from || "", "date"))}</div></details></form>`;
  return (
    freshness(data.source_freshness) +
    section(
      "보안 정보 검색",
      "외부에 보고되어 로컬에 수집된 자료를 검색합니다. 각 소스의 저장 건수와 검색 결과는 CVE 전체 건수와 다릅니다.",
      `<div class="tabs">${tabs}</div>${filters}<p class="scope-note">${esc(data.coverage_note)}</p><div class="results">${data.items.length ? advisoryRows(data.items) : empty("검색 결과가 없습니다", "필터를 줄이거나 ID·패키지명을 확인해 주세요.")}</div>${pagination(data, "intel", params)}`,
    )
  );
}
async function projectList() {
  return section(
    "내 프로젝트",
    "프로젝트는 서비스·환경·패키지와 접근 권한을 묶는 단위입니다.",
    `<div class="project-cards">${projects.map((p) => `<a class="project-card" href="#projects/${esc(p.id)}"><div class="section-header"><h3>${esc(p.name)}</h3>${pill(p.status)}</div><p>${esc(p.description || "설명이 없습니다.")}</p><div class="project-stats"><span>대상 <strong>${number(p.target_count)}</strong></span><span>열린 영향 <strong>${number(p.open_findings)}</strong></span></div><small>${esc(p.role)}</small></a>`).join("") || empty("첫 프로젝트를 등록하세요", "등록 후 패키지 목록을 연결하면 자동 매칭됩니다.")}</div><details class="creation-panel" ${!projects.length ? "open" : ""}><summary>＋ 프로젝트 등록</summary><form id="create-project" class="form-grid">${field("프로젝트 이름", input("name", "예: 결제 플랫폼", "", "text", 'required maxlength="100"'))}${field("설명", input("description", "관리 범위와 담당 팀"))}<div class="form-actions"><button>프로젝트 만들기</button></div></form></details>`,
  );
}
async function projectDetail(pid, params) {
  const project = await api("projects/" + pid);
  scope = pid;
  updateScope();
  const tab = params.tab || "targets";
  const write = project.role !== "viewer";
  const tabs = [
    ["targets", "서비스·환경"],
    ["inventory", "패키지 인벤토리"],
    ["environment", "환경 검토"],
    ["members", "구성원"],
    ["settings", "설정"],
  ]
    .map(
      ([key, title]) =>
        `<a class="tab ${tab === key ? "active" : ""}" href="#projects/${pid}?tab=${key}">${title}</a>`,
    )
    .join("");
  let body = "";
  if (tab === "targets") {
    const data = await api(`projects/${pid}/targets`);
    body = data.items.length
      ? `<div class="target-cards">${data.items.map((t) => `<article class="target-card"><div class="section-header"><h3>${esc(t.service_name)}</h3>${pill(t.environment)}</div><p>수집 방식 ${esc(t.collection_mode)} · 열린 영향 ${number(t.open_findings)}</p><p>마지막 수집 ${date(t.last_collected_at)} ${pill(t.latest_snapshot_id ? t.freshness_status : "unknown")}</p><p>OS ${esc(t.metadata.os || "미제공")} · 런타임 ${esc(t.metadata.runtime || "미제공")}</p><div class="inline-actions">${write ? `<button type="button" class="secondary" data-edit-target="${t.id}" data-project="${pid}">대상 설정</button><button type="button" data-import-target="${t.id}" data-project="${pid}">패키지 목록 전송</button><button type="button" class="secondary" data-credential-target="${t.id}" data-project="${pid}">연동 토큰 발급</button>` : ""}</div></article>`).join("")}</div>`
      : empty(
          "등록된 서비스·환경이 없습니다",
          "예: payment-api / prod를 등록하고 사용 중인 패키지 목록을 보내 주세요.",
        );
    if (write)
      body += `<details class="creation-panel" ${!data.items.length ? "open" : ""}><summary>＋ 서비스·환경 추가</summary><form id="create-target" data-project="${pid}" class="form-grid">${field("서비스 이름", input("name", "payment-api", "", "text", "required"))}${field(
        "환경",
        select("environment", [
          ["prod", "운영 (prod)"],
          ["stage", "검증 (stage)"],
          ["dev", "개발 (dev)"],
        ]),
      )}${field(
        "수집 방식",
        select("collection_mode", [
          ["push", "CI/CD·API에서 전송 (push)"],
          ["poll", "등록한 endpoint 주기 조회 (poll)"],
        ]),
      )}${field("Endpoint URL", input("status_endpoint_url", "https://service/.well-known/sca/dependencies", "", "url"), "poll 방식을 선택할 때 의존성 JSON을 제공하는 내부 주소입니다.")}${field("OS 정보", input("os", "예: Ubuntu 24.04"), "OS 취약점 매칭에는 OS 패키지의 정확한 버전을 인벤토리에 포함하는 것이 필요합니다.")}${field("런타임", input("runtime", "예: Node.js 22"))}${field("CPE (선택)", input("cpe", "cpe:2.3:a:vendor:product:version:..."), "NVD 제품 식별자입니다. 제품명이 같아도 영향 확정은 아니며 환경 검토 후보로 표시됩니다.")}<div class="form-actions"><button>서비스·환경 등록</button></div></form></details>`;
  } else if (tab === "inventory") {
    const data = await api(`projects/${pid}/inventory?` + query(params));
    body = `<form class="search-primary" id="inventory-search" data-project="${pid}">${field("패키지 검색", input("q", "패키지명", params.q || ""))}<button>검색</button></form>${data.items.length ? `<div class="table-wrap"><table><thead><tr><th>패키지 / 버전</th><th>생태계</th><th>서비스·환경</th><th>수집 시각</th></tr></thead><tbody>${data.items.map((d) => `<tr><td><strong>${esc(d.package_name)}</strong><br>${esc(d.resolved_version)}</td><td>${esc(d.ecosystem)}</td><td>${esc(d.service_name)} / ${esc(d.environment)}</td><td>${date(d.collected_at)} ${pill(d.freshness_status)}</td></tr>`).join("")}</tbody></table></div>` : empty("패키지 목록이 없습니다", "서비스·환경 탭에서 목록을 전송하거나 CI/CD 연동을 설정하세요.")}${pagination(data, "projects/" + pid, { ...params, tab: "inventory" })}`;
  } else if (tab === "environment") {
    const data = await api(`projects/${pid}/environment-candidates`);
    body =
      `<div class="coverage-note attention">환경 검토 후보는 CPE 제품 식별자가 일치한 NVD 기록입니다. 버전·구성 조건을 검토해야 하며 확정 영향/외부 알림에 자동 포함되지 않습니다.</div>` +
      (data.items.length
        ? data.items
            .map(
              (a) =>
                `<button class="result-row" data-advisory="${a.id}"><span class="result-copy"><strong>${esc(a.target_name)} · ${esc(a.advisory_id)}</strong><span>${esc(a.summary)}</span><small>${esc(a.evidence)}</small></span>${pill("potential")}</button>`,
            )
            .join("")
        : empty(
            "검토 후보가 없습니다",
            "CPE가 등록되지 않았거나 현재 수집 자료에서 일치하는 제품을 찾지 못했습니다.",
          ));
  } else if (tab === "members") {
    const data = await api(`projects/${pid}/members`);
    body = `<div class="member-list">${data.items.map((m) => `<div class="project-risk-row"><span><strong>${esc(m.display_name)}</strong><br>${esc(m.email)}</span>${pill(m.role)}</div>`).join("")}</div>`;
    if (project.role === "owner")
      body += `<details class="creation-panel"><summary>구성원 추가·역할 변경</summary><p>등록된 계정의 이메일을 입력합니다. 신규 계정은 관리자가 설정 링크를 발급할 수 있습니다.</p><form id="add-member" data-project="${pid}" class="form-grid">${field("이메일", input("email", "member@example.com", "", "email", "required"))}${field(
        "권한",
        select("role", [
          ["viewer", "조회"],
          ["maintainer", "관리·조치"],
          ["owner", "소유자"],
        ]),
        "소유자는 구성원과 알림 정책을 관리합니다. 관리·조치는 자산 등록과 영향 상태 변경을 할 수 있습니다.",
      )}<button>구성원 저장</button></form></details>`;
  } else if (tab === "settings")
    body = write
      ? `<form id="edit-project" data-project="${pid}" class="form-grid">${field("이름", input("name", "", project.name, "text", "required"))}${field("설명", input("description", "", project.description))}${field(
          "상태",
          select(
            "status",
            [
              ["active", "활성"],
              ["archived", "보관"],
            ],
            project.status,
          ),
          "보관은 기존 인벤토리와 이력을 삭제하지 않습니다.",
        )}<button>변경 저장</button></form>`
      : empty("조회 권한입니다", "설정 변경은 프로젝트 관리자에게 요청하세요.");
  return section(
    esc(project.name),
    esc(
      project.description || "이 프로젝트의 대상·인벤토리·영향을 관리합니다.",
    ),
    `<div class="tabs">${tabs}</div>${body}`,
    `<a class="panel-link" href="#findings?project_id=${pid}">영향 보기 ↗</a>`,
  );
}
async function findings(params) {
  const filters = { ...params, project_id: params.project_id || scope };
  const data = await api("findings?" + query(filters));
  return (
    freshness(data.source_freshness) +
    section(
      "프로젝트 영향",
      "사용 중인 패키지의 버전이 보고된 취약 범위와 일치한 결과입니다. 동일 보안 정보가 여러 서비스에 있으면 여러 건입니다.",
      `<form id="finding-search" class="search-form"><div class="search-primary">${field("검색", input("q", "서비스, 패키지, 보안 정보 ID", params.q || ""))}<button>검색</button></div><div class="form-grid compact-grid">${field("프로젝트", select("project_id", [["", "내 전체 프로젝트"], ...projects.map((p) => [p.id, p.name])], filters.project_id))}${field("위험도", select("risk", [["", "전체"], ...["critical", "high", "medium", "low"].map((x) => [x, x])], params.risk), "서비스 환경과 보안 정보의 심각도 등을 고려한 조치 우선순위입니다.")}${field("조치 상태", select("status", [["", "미해결 전체"], ...["open", "acknowledged", "in_progress", "fixed", "accepted_risk", "not_affected", "false_positive"].map((x) => [x, stateLabels[x]])], params.status))}${field(
        "환경",
        select(
          "environment",
          [
            ["", "전체"],
            ["prod", "운영"],
            ["stage", "검증"],
            ["dev", "개발"],
          ],
          params.environment,
        ),
      )}</div></form><div class="results">${data.items.length ? data.items.map((f) => `<button class="result-row" data-finding="${f.id}"><span class="result-copy"><strong>${esc(f.project_name)} / ${esc(f.service_name)} <small>${esc(f.environment)}</small></strong><span>${esc(f.package_name)}@${esc(f.resolved_version)} · ${esc(f.advisory_id)}</span><small>${esc(f.summary)}</small>${f.data_stale ? '<small class="text-attention">현재 영향 여부 재확인을 위해 수집 갱신이 필요합니다.</small>' : ""}</span><span class="row-badges">${pill(f.risk_level)}${pill(f.status)}</span></button>`).join("") : empty("일치하는 영향이 없습니다", "등록 범위와 수집 시각을 함께 확인하세요. 환경 제품 정보는 프로젝트의 환경 검토 탭에서 확인할 수 있습니다.")}</div>${pagination(data, "findings", params)}`,
    )
  );
}
async function alerts(params) {
  const pid = scope || params.project_id;
  const data = await api(
    "alert-events?" + query({ ...params, project_id: pid }),
  );
  let config = "";
  if (pid) {
    const rule = await api(`projects/${pid}/alert-rules`);
    const project = projects.find((p) => p.id === pid);
    config = section(
      "프로젝트 알림 규칙",
      "영향은 화면에 항상 기록됩니다. 외부 발송은 활성 규칙과 HTTPS 채널 주소가 있을 때 적용됩니다.",
      `<form id="alert-rule" data-project="${pid}" class="form-grid">${field(
        "외부 발송",
        select(
          "enabled",
          [
            ["true", "활성"],
            ["false", "중지"],
          ],
          String(Boolean(rule.enabled)),
        ),
      )}${field(
        "최소 위험도",
        select(
          "minimum_risk",
          ["critical", "high", "medium", "low", "info"].map((x) => [x, x]),
          rule.minimum_risk,
        ),
      )}${field(
        "채널 유형",
        select(
          "channel_type",
          [
            ["webhook", "Webhook JSON"],
            ["slack_webhook", "Slack Incoming Webhook"],
          ],
          rule.channel_type,
        ),
      )}${field("HTTPS 채널 주소", input("target_url", "https://...", rule.target_url, "url"), "프로젝트 소유자만 변경할 수 있습니다. 전송 주소에는 자격 증명을 URL 사용자명으로 포함하지 마세요.")}<div class="form-actions"><button ${project?.role !== "owner" ? "disabled" : ""}>알림 규칙 저장</button></div></form>`,
    );
  } else
    config = empty(
      "프로젝트를 선택해 알림 규칙을 설정하세요",
      "상단 프로젝트 범위를 선택하면 해당 프로젝트의 채널을 설정할 수 있습니다.",
    );
  return (
    config +
    section(
      "알림 이력",
      "프로젝트 영향에 대한 발송 대기·성공·실패 기록입니다.",
      data.items.length
        ? `<div class="table-wrap"><table><thead><tr><th>프로젝트 / 대상</th><th>내용</th><th>상태</th><th>생성 / 발송</th></tr></thead><tbody>${data.items.map((e) => `<tr><td>${esc(e.project_name)}<br>${esc(e.service_name)}</td><td>${esc(e.package_name)}<br>${esc(e.reason)}</td><td>${pill(e.status)}<br>재시도 ${number(e.retry_count)}</td><td>${date(e.created_at)}<br>${date(e.sent_at)}</td></tr>`).join("")}</tbody></table></div>` +
            pagination(data, "alerts", params)
        : empty(
            "알림 기록이 없습니다",
            "영향이 생성되면 기록됩니다. 채널과 수집 상태를 함께 확인하세요.",
          ),
    )
  );
}
async function operations() {
  const data = await api("intel/sources");
  let admin = "";
  if (user.is_admin) {
    const targets = await api("admin/unassigned-targets");
    admin =
      section(
        "기존 서비스의 프로젝트 연결",
        "기존 서비스·스냅샷·영향 이력은 그대로 보관되어 있습니다. 소유 프로젝트를 지정하면 해당 멤버에게 표시됩니다.",
        targets.items.length
          ? `<form id="assign-target" class="form-grid">${field(
              "기존 서비스",
              select(
                "service_pk",
                targets.items.map((t) => [
                  t.id,
                  `${t.service_name} / ${t.environment}`,
                ]),
              ),
            )}${field(
              "연결할 프로젝트",
              select(
                "project_id",
                projects.map((p) => [p.id, p.name]),
              ),
            )}<button ${!projects.length ? "disabled" : ""}>프로젝트에 연결</button></form>`
          : empty(
              "모든 서비스가 연결되어 있습니다",
              "서비스의 소유 프로젝트는 프로젝트 화면에서 확인하세요.",
            ),
      ) +
      section(
        "계정 초대",
        "설정 링크는 24시간 동안 한 번 사용할 수 있습니다. 이메일은 자동으로 보내지 않습니다.",
        `<form id="invite-account" class="search-primary">${field("초대할 이메일", input("email", "member@example.com", "", "email", "required"))}<button>계정 설정 링크 만들기</button></form><div id="invite-result"></div><p><a class="panel-link" href="/admin.html" target="_blank" rel="noopener">고급 운영 콘솔 ↗</a></p>`,
      );
  }
  return (
    section(
      "데이터 수집 상태",
      "실제 저장 건수와 소스별 마지막 성공을 표시합니다. 누적 import 횟수와 구분하며, 전 세계 자료 전체의 완전성을 보장하지 않습니다.",
      `<div class="source-cards">${data.items.map((s) => `<article class="target-card"><div class="section-header"><h3>${s.source}</h3>${pill(s.status)}</div><strong class="source-count">${number(s.stored_count)}</strong><p>저장된 보안 정보 기록</p><p>${esc(s.configured_scope)}</p><p>마지막 성공 ${date(s.last_success_at)}</p>${s.last_error_message ? `<p class="form-error">${esc(s.last_error_message)}</p>` : ""}<a class="panel-link" href="#intel?source=${s.source}">이 소스 검색 ↗</a></article>`).join("")}</div>`,
    ) + admin
  );
}
function guide() {
  return section(
    "프로젝트 연동 순서",
    "서비스의 실제 패키지 버전을 보내야 외부 보안 정보와 매칭할 수 있습니다.",
    `<ol class="guide-steps"><li>프로젝트를 만들고 서비스·환경을 등록합니다.</li><li>프로젝트 상세에서 <strong>연동 토큰 발급</strong>을 눌러 대상별 토큰을 만듭니다.</li><li>CI/CD에서 아래 JSON 형태로 패키지 목록을 전송합니다. 웹의 <strong>패키지 목록 전송</strong>으로도 검증할 수 있습니다.</li><li>프로젝트 인벤토리와 영향 화면을 확인하고 알림 채널을 설정합니다.</li></ol><pre><code>${esc(JSON.stringify({ schema_version: "1.0", service_id: "발급된 토큰의 service_id", environment: "prod", generated_at: "ISO 8601 시각", dependencies: [{ ecosystem: "npm", name: "lodash", version: "4.17.20", scope: "production", direct: false }] }, null, 2))}</code></pre><p>POST /api/v1/services/{service_id}/status · Authorization: Bearer {대상 토큰}</p><p>토큰은 발급 시 한 번만 표시됩니다. 환경 패키지도 OSV가 지원하는 생태계와 정확한 버전으로 함께 보내세요.</p><details class="creation-panel"><summary>검색·조회 API</summary><pre><code>GET /api/v2/intel/sources\nGET /api/v2/intel/advisories?q=CVE-...&amp;source=NVD\nGET /api/v2/intel/records?source=OSV&amp;ecosystem=npm\nGET /api/v2/projects\nGET /api/v2/projects/{id}/inventory\nGET /api/v2/findings?project_id={id}\nGET /api/v2/overview?project_id={id}</code></pre><p>조회는 로그인 세션을 사용합니다. 변경 요청에는 세션 API가 반환한 X-CSRF-Token이 필요합니다.</p></details>`,
  );
}
async function render() {
  if (!user) return;
  const id = ++renderId;
  const { path, params } = route();
  const root = path.split("/")[0];
  const descriptions = {
    overview: [
      "Overview",
      "내 프로젝트의 위험과 데이터 신선도를 한눈에 확인합니다.",
    ],
    projects: ["프로젝트", "관리하는 서비스·환경과 구성원을 연결합니다."],
    intel: [
      "보안 정보 탐색",
      "다섯 소스의 보고된 취약점과 악성 패키지를 검색합니다.",
    ],
    findings: [
      "영향 및 조치",
      "프로젝트에 해당하는 근거를 확인하고 조치 상태를 관리합니다.",
    ],
    alerts: ["알림", "프로젝트별 발송 정책과 전송 이력을 확인합니다."],
    guide: ["연동 가이드", "사용 중인 패키지 목록을 연결하는 방법입니다."],
    operations: [
      "수집·계정 관리",
      "데이터 신선도와 계정·기존 서비스 연결을 확인합니다.",
    ],
  };
  const info = descriptions[root] || descriptions.overview;
  $("#view-title").textContent = info[0];
  $("#view-subtitle").textContent = info[1];
  document.querySelectorAll("nav a").forEach((a) => {
    a.classList.toggle("active", a.hash === "#" + root);
    if (a.hash === "#" + root) a.setAttribute("aria-current", "page");
    else a.removeAttribute("aria-current");
  });
  $("#page").innerHTML =
    '<div class="empty-state">데이터를 불러오는 중입니다…</div>';
  closeHelp();
  try {
    let html;
    if (root === "projects")
      html = path.includes("/")
        ? await projectDetail(path.split("/")[1], params)
        : await projectList();
    else if (root === "intel") html = await intel(params);
    else if (root === "findings") html = await findings(params);
    else if (root === "alerts") html = await alerts(params);
    else if (root === "operations") html = await operations();
    else if (root === "guide") html = guide();
    else html = await overview();
    if (id === renderId) {
      $("#page").innerHTML = html;
      window.scrollTo(0, 0);
    }
  } catch (error) {
    if (id === renderId)
      $("#page").innerHTML = empty("화면을 불러오지 못했습니다", error.message);
  }
}
function openDialog(title, html) {
  $("#detail-title").textContent = title;
  $("#detail-body").innerHTML = html;
  if (!$("#detail-dialog").open) $("#detail-dialog").showModal();
}
async function advisoryDetail(id) {
  const data = await api("intel/advisories/" + encodeURIComponent(id));
  const a = data.advisory;
  const refs = Array.isArray(a.raw_payload?.references)
    ? a.raw_payload.references
    : [];
  const links = refs
    .map((r) => (typeof r === "string" ? r : r.url))
    .filter((u) => /^https?:\/\//i.test(u || ""))
    .slice(0, 10);
  openDialog(
    a.advisory_id,
    `<div class="badge-row">${pill(a.source)}${pill(a.severity)}${a.is_known_exploited ? pill("KEV") : ""}${a.is_malicious_package ? pill("악성 패키지") : ""}</div><p class="detail-summary">${esc(a.summary)}</p><div class="detail-grid">${detail("패키지 / 생태계", `${a.package_name || "미제공"} / ${a.ecosystem || "미제공"}`)}${detail("수정 버전", a.fixed_version || "소스에 정보 없음")}${detail("소스 공개일", date(a.published_at))}${detail("소스 수정일", date(a.modified_at))}${detail("로컬 최초 수집일", date(a.first_seen_at))}${detail("별칭", (a.aliases || []).map((x) => x.alias_value || x).join(", "))}</div><h3>영향 버전 범위 ${help("소스가 보고한 버전 범위입니다. 실제 영향은 프로젝트의 설치 버전과 비교해야 합니다.", "영향 버전 범위")}</h3><pre>${esc(JSON.stringify(a.affected_ranges?.length ? a.affected_ranges : a.affected_versions, null, 2))}</pre><h3>내 프로젝트의 영향</h3>${data.impacts.length ? data.impacts.map((i) => `<button class="result-row" data-finding="${i.id}"><span>${esc(i.project_name)} / ${esc(i.service_name)}</span>${pill(i.risk_level)}${pill(i.status)}</button>`).join("") : "<p>접근 가능한 프로젝트의 영향 기록이 없습니다.</p>"}${links.length ? "<h3>출처</h3>" + links.map((u) => `<p><a href="${esc(u)}" target="_blank" rel="noopener">${esc(u)}</a></p>`).join("") : ""}<details class="creation-panel"><summary>수집 원문 보기</summary><pre>${esc(JSON.stringify(a.raw_payload, null, 2))}</pre></details>`,
  );
}
function detail(label, value) {
  return `<div><span>${esc(label)}</span><strong>${esc(value || "정보 없음")}</strong></div>`;
}
async function findingDetail(id) {
  const data = await api("findings/" + id);
  const f = data.impact;
  openDialog(
    "영향 근거와 조치",
    `<div class="badge-row">${pill(f.risk_level)}${pill(f.status)}${pill(f.freshness_status)}</div><p class="detail-summary">${esc(f.summary)}</p><div class="detail-grid">${detail("서비스 / 환경", `${f.service_name} / ${f.environment}`)}${detail("사용 중인 패키지", `${f.package_name}@${f.resolved_version}`)}${detail("보안 정보", f.advisory_id)}${detail("수정 버전", f.fixed_version || "소스에 정보 없음")}${detail("최초 발견", date(f.first_detected_at))}${detail("최근 관측", date(f.last_seen_at))}${detail("판정 근거", f.risk_reason)}</div><p class="coverage-note attention">버전 범위와 일치한 기록입니다. 인벤토리와 외부 소스가 오래됐다면 최신 상태를 다시 수집해 주세요.</p><pre>${esc(JSON.stringify(f.affected_ranges || f.affected_versions, null, 2))}</pre><form id="update-finding" data-finding="${id}" class="form-grid">${field(
      "조치 상태",
      select(
        "status",
        [
          "open",
          "acknowledged",
          "in_progress",
          "fixed",
          "not_affected",
          "false_positive",
          ...(user.is_admin ? ["accepted_risk"] : []),
        ].map((x) => [x, stateLabels[x]]),
        f.status,
      ),
    )}${field("사유", input("reason", "변경 사유를 남겨 주세요", "", "text", "required"))}${field("위험 수용 만료", input("expires_at", "", "", "datetime-local"), "위험 수용 시에만 필요합니다. 관리자 승인과 만료 시각을 기록합니다.")}<button>조치 상태 저장</button></form><h3>변경 이력</h3>${(data.history || []).map((h) => `<div class="history-entry">${esc(h.from_status)} → ${esc(h.to_status)}<p>${esc(h.reason || "")} · ${esc(h.actor)} · ${date(h.created_at)}</p></div>`).join("") || "<p>변경 이력이 없습니다.</p>"}`,
  );
}
function closeHelp() {
  if (activeHelp) {
    activeHelp.setAttribute("aria-expanded", "false");
    activeHelp.removeAttribute("aria-describedby");
  }
  activeHelp = null;
  $("#info-popover").hidden = true;
}
function showHelp(button) {
  if (activeHelp === button) {
    closeHelp();
    return;
  }
  closeHelp();
  activeHelp = button;
  button.setAttribute("aria-expanded", "true");
  button.setAttribute("aria-describedby", "info-popover");
  const pop = $("#info-popover");
  (button.closest("dialog") || document.body).appendChild(pop);
  pop.textContent = button.dataset.help;
  pop.hidden = false;
  const r = button.getBoundingClientRect();
  pop.style.left =
    Math.max(12, Math.min(r.left, innerWidth - pop.offsetWidth - 12)) + "px";
  pop.style.top =
    (r.bottom + 10 + pop.offsetHeight > innerHeight
      ? Math.max(12, r.top - pop.offsetHeight - 10)
      : r.bottom + 10) + "px";
}
$("#auth-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const button = $("#auth-submit");
  button.disabled = true;
  $("#auth-error").textContent = "";
  try {
    const body = Object.fromEntries(new FormData(form));
    if (setupToken) body.token = setupToken;
    await api(setupToken ? "auth/setup" : "auth/login", "POST", body);
    setupToken = "";
    form.reset();
    history.replaceState(null, "", "#overview");
    await loadSession();
  } catch (error) {
    $("#auth-error").textContent = error.message;
  } finally {
    button.disabled = false;
  }
});
$("#logout").addEventListener("click", async () => {
  try {
    await api("auth/logout", "POST", {});
    showAuth();
  } catch (error) {
    toast(error.message, true);
  }
});
$("#project-scope").addEventListener("change", (event) => {
  scope = event.target.value;
  if (route().path.startsWith("projects/"))
    go(scope ? "projects/" + scope : "projects");
  else render();
});
$("#refresh").addEventListener("click", async () => {
  projects = (await api("projects")).items;
  updateScope();
  await render();
});
$("#close-dialog").addEventListener("click", () => $("#detail-dialog").close());
$("#detail-dialog").addEventListener("close", closeHelp);
window.addEventListener("hashchange", () => {
  if (location.hash.startsWith("#setup=")) {
    setupToken = location.hash.slice(7);
    showAuth();
    return;
  }
  render();
});
window.addEventListener("resize", closeHelp);
window.addEventListener("scroll", closeHelp, true);
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") closeHelp();
});
document.addEventListener("click", async (event) => {
  const info = event.target.closest(".info-trigger");
  if (info) {
    event.preventDefault();
    showHelp(info);
    return;
  }
  if (!event.target.closest("#info-popover")) closeHelp();
  const button = event.target.closest("button");
  if (!button) return;
  try {
    if (button.dataset.editTarget)
      await editTargetDialog(button.dataset.project, button.dataset.editTarget);
    if (button.dataset.advisory) await advisoryDetail(button.dataset.advisory);
    if (button.dataset.finding) await findingDetail(button.dataset.finding);
    if (button.dataset.pagePath)
      go(button.dataset.pagePath, JSON.parse(button.dataset.pageParams));
    if (button.dataset.importTarget)
      openDialog(
        "패키지 목록 전송",
        `<p>dependencies 배열 또는 이를 포함한 snapshot JSON을 입력합니다. 프로젝트와 대상은 서버에서 확인합니다.</p><form id="import-snapshot" data-project="${button.dataset.project}" data-target="${button.dataset.importTarget}"><label>Snapshot JSON<textarea name="snapshot" rows="12" required spellcheck="false">${esc(JSON.stringify({ dependencies: [{ ecosystem: "npm", name: "lodash", version: "4.17.21" }] }, null, 2))}</textarea></label><button>전송 및 영향 매칭</button></form>`,
      );
    if (button.dataset.credentialTarget) {
      const data = await api(
        `projects/${button.dataset.project}/targets/${button.dataset.credentialTarget}/credentials`,
        "POST",
        {},
      );
      openDialog(
        "대상별 연동 토큰",
        `<p>토큰은 지금 한 번만 표시됩니다. 안전한 CI/CD 비밀 저장소에 보관하세요.</p><pre>${esc(data.token)}</pre><p>서비스 ID: ${esc(data.credential.service_id)} · 환경: ${esc(data.credential.environment)}</p><pre>${esc(data.usage.curl)}</pre>`,
      );
    }
  } catch (error) {
    toast(error.message, true);
  }
});
document.addEventListener("submit", async (event) => {
  const form = event.target;
  if (form.id === "auth-form") return;
  event.preventDefault();
  const body = Object.fromEntries(new FormData(form));
  const submit = form.querySelector("button[type=submit],button:not([type])");
  if (submit) submit.disabled = true;
  try {
    if (form.id === "intel-search") go("intel", body);
    else if (form.id === "finding-search") go("findings", body);
    else if (form.id === "inventory-search")
      go("projects/" + form.dataset.project, { ...body, tab: "inventory" });
    else if (form.id === "create-project") {
      const p = await api("projects", "POST", body);
      projects = (await api("projects")).items;
      updateScope();
      go("projects/" + p.id);
    } else if (form.id === "edit-target") {
      body.metadata = { os: body.os, runtime: body.runtime, cpe: body.cpe };
      await api(
        `projects/${form.dataset.project}/targets/${form.dataset.target}`,
        "PATCH",
        body,
      );
      $("#detail-dialog").close();
      await render();
      toast("대상 설정을 저장했습니다.");
    } else if (form.id === "create-target") {
      body.metadata = { os: body.os, runtime: body.runtime, cpe: body.cpe };
      await api(`projects/${form.dataset.project}/targets`, "POST", body);
      projects = (await api("projects")).items;
      updateScope();
      await render();
      toast("서비스·환경을 등록했습니다.");
    } else if (form.id === "import-snapshot") {
      const snapshot = JSON.parse(body.snapshot);
      const now = new Date().toISOString();
      const payload = {
        schema_version: "1.0",
        generated_at: now,
        snapshot_id: crypto.randomUUID(),
        ...(Array.isArray(snapshot) ? { dependencies: snapshot } : snapshot),
      };
      await api(
        `projects/${form.dataset.project}/targets/${form.dataset.target}/snapshots`,
        "POST",
        payload,
      );
      $("#detail-dialog").close();
      projects = (await api("projects")).items;
      updateScope();
      await render();
      toast("패키지 목록을 반영하고 영향을 매칭했습니다.");
    } else if (form.id === "add-member") {
      await api(`projects/${form.dataset.project}/members`, "POST", body);
      await render();
      toast("구성원 권한을 저장했습니다.");
    } else if (form.id === "edit-project") {
      await api("projects/" + form.dataset.project, "PATCH", body);
      projects = (await api("projects")).items;
      updateScope();
      await render();
      toast("프로젝트 설정을 저장했습니다.");
    } else if (form.id === "update-finding") {
      if (body.status === "accepted_risk" && body.expires_at)
        body.expires_at = new Date(body.expires_at).toISOString();
      else delete body.expires_at;
      await api("findings/" + form.dataset.finding, "PATCH", body);
      $("#detail-dialog").close();
      projects = (await api("projects")).items;
      updateScope();
      await render();
      toast("조치 상태를 저장했습니다.");
    } else if (form.id === "alert-rule") {
      body.enabled = body.enabled === "true";
      await api(`projects/${form.dataset.project}/alert-rules`, "PATCH", body);
      toast("알림 규칙을 저장했습니다.");
    } else if (form.id === "invite-account") {
      const data = await api("admin/invitations", "POST", body);
      const url = location.origin + "/" + data.setup_fragment;
      $("#invite-result").innerHTML =
        `<p>24시간 유효한 계정 설정 링크입니다. 수신자에게 직접 전달해 주세요.</p><textarea rows="3" readonly aria-label="계정 설정 링크">${esc(url)}</textarea>`;
    } else if (form.id === "assign-target") {
      await api("admin/assign-target", "POST", body);
      projects = (await api("projects")).items;
      updateScope();
      await render();
      toast("기존 서비스를 프로젝트에 연결했습니다.");
    }
  } catch (error) {
    toast(error.message, true);
  } finally {
    if (submit) submit.disabled = false;
  }
});
loadSession().catch((error) => {
  showAuth();
  $("#auth-error").textContent = error.message;
});

async function editTargetDialog(pid, tid) {
  const data = await api(`projects/${pid}/targets/${tid}`);
  const t = data.target,
    m = t.metadata;
  openDialog(
    "서비스·환경 설정",
    `<p>대상의 환경(${esc(t.environment)})과 기존 수집 이력은 보존됩니다.</p><form id="edit-target" data-project="${pid}" data-target="${tid}" class="form-grid">${field("서비스 이름", input("name", "", t.service_name, "text", "required"))}${field(
      "수집 방식",
      select(
        "collection_mode",
        [
          ["push", "CI/CD·API에서 전송"],
          ["poll", "Endpoint 주기 조회"],
        ],
        t.collection_mode,
      ),
    )}${field("Endpoint URL", input("status_endpoint_url", "https://...", t.status_endpoint_url || "", "url"))}${field("OS 정보", input("os", "", m.os || ""))}${field("런타임", input("runtime", "", m.runtime || ""))}${field("CPE", input("cpe", "cpe:2.3:...", m.cpe || ""))}<button>대상 설정 저장</button></form>`,
  );
}
