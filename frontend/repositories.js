/* Repository reporting: request execution explicitly, retain preliminary reports. */
let repoPollTimer = null;
const repoStates = { queued: "대기", preparing: "준비", fetching: "저장소 수집", analyzing: "정적 분석", llm_analysis: "LLM 근거 분석", matching: "취약점 대조", reporting: "리포트 생성", sandbox_preparing: "격리 환경 준비", sandbox_building: "격리 빌드", sandbox_observing: "실행 관찰", completed: "완료", partial: "부분 완료", failed: "실패", cancelled: "취소" };
function stopRepositoryPolling() { clearTimeout(repoPollTimer); repoPollTimer = null; }
function repositoryScanCards(pid, scans, write, caps) {
  return scans.length ? scans.map(s => `<article class="repository-job"><div class="section-header"><div><strong>${s.mode === "deep" ? "심층 분석" : "1차 분석"}</strong><small>${date(s.created_at)} · ${esc((s.commit_sha || "commit 확인 중").slice(0, 12))}</small></div>${pill(repoStates[s.phase] || s.status)}</div>${s.cancel_requested && !["completed","partial","failed","cancelled"].includes(s.status) ? '<p>취소 요청을 처리 중입니다.</p>' : ""}${s.error ? `<p class="form-error">${esc(s.error)}</p>` : ""}<div class="inline-actions">${s.has_report ? `<button type="button" data-repo-report="${esc(s.id)}" data-project="${pid}">리포트 보기</button>` : ""}${write && !["completed","partial","failed","cancelled"].includes(s.status) ? `<button type="button" class="secondary" data-repo-cancel="${esc(s.id)}" data-project="${pid}">분석 취소</button>` : ""}${write && s.has_report && s.mode === "preliminary" ? `<button type="button" class="secondary" data-repo-deep="${esc(s.id)}" data-project="${pid}" ${caps.deep_analysis ? "" : "disabled"}>심층 분석 요청</button>` : ""}</div></article>`).join("") : empty("분석 기록이 없습니다", "저장소를 등록하면 1차 분석을 시작합니다.");
}
async function repositoryPanel(pid, write, owner) {
  const data = await api(`projects/${pid}/repositories`);
  const caps = data.capabilities;
  return `<div class="coverage-note">1차 분석은 대상 코드를 실행하지 않습니다. 설치·빌드·실행은 리포트에서 심층 분석을 요청했을 때만 격리 환경에서 수행합니다. ${help("저장소에서 확인한 선언과 이미지·실행 환경의 관찰은 다릅니다. 확인되지 않은 버전·설치 경로는 리포트의 미확인 영역에 표시합니다.", "분석 범위")}</div><div class="repo-capabilities">LLM: ${esc(caps.llm.provider)} · ${esc(caps.llm.model)} · ${caps.llm.configured ? "연결 키 설정됨" : "API 키 등록 필요"}<br>심층 분석 워커: ${caps.deep_analysis ? "준비됨" : "준비 중"}</div><div class="target-cards">${data.items.map(r => `<article class="target-card"><h3>${esc(r.namespace)}</h3><p>${esc(r.url)}</p><p>ref ${esc(r.ref)} · 경로 ${esc(r.subpath || ".")} · ${r.llm_enabled ? "LLM 분석 사용" : "정적 분석"}</p><p>마지막 commit ${esc((r.last_commit || "아직 없음").slice(0, 12))}</p>${write ? `<button type="button" class="secondary" data-repo-scan="${esc(r.id)}" data-project="${pid}">1차 분석 갱신</button>` : ""}</article>`).join("")}</div>${write ? `<details class="creation-panel" ${!data.items.length ? "open" : ""}><summary>＋ GitHub/GitLab 저장소 등록</summary><form id="repo-create" data-project="${pid}" class="form-grid">${field("저장소 URL", input("url", "https://github.com/owner/repository", "", "url", "required"))}${field("분석 ref", input("ref", "브랜치·태그·commit", "HEAD", "text", "required"))}${field("하위 경로", input("subpath", "전체 저장소면 비워 두세요"))}${field("모니터링 환경", select("environment", [["dev","개발"],["stage","검증"],["prod","운영"]]), "저장소 관찰만으로 해당 환경의 실제 배포 여부를 확인한 것은 아닙니다.")}${field("비공개 저장소 자격 증명", select("credential_id", [["","공개 저장소 · 자격 증명 없음"],...data.credentials.map(c=>[c.id,c.label])]))}<label class="repository-check"><input type="checkbox" name="llm_enabled" value="true" checked>OpenRouter / DeepSeek V4.1 Flash로 선별된 코드를 전송해 설치 행위 분석 (비밀 파일 제외)</label><div class="form-actions"><button>저장소 등록 · 1차 분석</button></div></form></details>` : ""}${owner ? `<details class="creation-panel"><summary>비공개 저장소 자격 증명 등록·교체</summary><p>사용자명과 토큰은 서버에서 암호화해 보관하며, 원문은 다시 조회하지 않습니다.</p><form id="repo-credential" data-project="${pid}" class="form-grid">${field("기존 자격 증명 교체", select("credential_id", [["","새로 등록"],...data.credentials.map(c=>[c.id,c.label])]))}${field("표시 이름", input("label","예: 팀 GitLab 읽기 토큰","","text","required"))}${field("연결할 저장소 URL",input("repository_url","https://gitlab.com/group/repository","","url","required"))}${field("사용자명",input("username","선택 사항","","text",'autocomplete="off"'))}${field("읽기 전용 접근 토큰",input("secret","토큰 원문","","password",'required autocomplete="new-password"'))}<button>암호화 저장</button></form></details>` : ""}<section class="repository-scan-section"><h3>분석 이력</h3><div id="repository-scan-cards" data-project="${pid}" data-write="${write}" class="repository-jobs">${repositoryScanCards(pid,data.scans,write,caps)}</div></section>`;
}
function startRepositoryPolling() {
  const element = $("#repository-scan-cards");
  if (!element) return;
  const tick = async () => {
    if (!element.isConnected || !user) return;
    try {
      const data = await api(`projects/${element.dataset.project}/repositories`);
      if (!element.isConnected) return;
      const html = repositoryScanCards(element.dataset.project,data.scans,element.dataset.write === "true",data.capabilities);
      if (element.innerHTML !== html && !element.contains(document.activeElement)) element.innerHTML = html;
    } catch (error) { if (element.isConnected) element.setAttribute("aria-label",error.message); }
    if (element.isConnected && user) repoPollTimer = setTimeout(tick,5000);
  };
  repoPollTimer = setTimeout(tick,3000);
}
function repositoryGap(reason) {
  const messages = { dependency_version_unresolved: "버전이 확정되지 않은 의존성", transitive_dependency_graph_incomplete: "전이 의존성 관계가 완전히 확인되지 않았습니다", image_contents_require_artifact_analysis: "이미지 내부 패키지는 심층 이미지 분석이 필요합니다", base_image_digest_unresolved: "베이스 이미지 digest를 확인하지 못했습니다", unsupported_image_platform: "이 이미지 플랫폼은 현재 KVM 프로파일에서 지원하지 않습니다", base_image_not_pinned: "베이스 이미지 digest가 고정되지 않아 빌드를 실행하지 않았습니다", llm_input_scope_limited: "LLM 입력 한도로 일부 코드만 분석했습니다", llm_analysis_unavailable: "LLM 연결 또는 응답 검증을 완료하지 못했습니다", application_runtime_not_requested: "애플리케이션 실행 명령이 없어 설치/빌드만 관찰했습니다", python_optional_markers_require_review: "Python 선택 의존성·환경 조건의 추가 검토가 필요합니다", dynamic_setup_not_executed: "setup.py를 실행하지 않아 동적 설정을 확인하지 못했습니다", no_supported_dependency_manifest: "지원하는 의존성 파일을 확인하지 못했습니다", ecosystem_parser_not_yet_supported: "이 파일 형식의 정적 분석기가 아직 지원되지 않습니다", docker_build_failed: "격리 환경의 Docker 빌드가 완료되지 않았습니다", sandbox_execution_partial: "격리 실행이 일부만 완료됐습니다", sbom_graph_not_provided: "SBOM에 의존 관계가 제공되지 않았습니다", requirements_include_cycle: "requirements 포함 관계에 순환 참조가 있습니다" };
  const [code, ...details] = String(reason).split(":");
  return (messages[code] || code.replaceAll("_", " ")) + (details.length ? " · " + details.join(":") : "");
}
async function repositoryReport(pid,sid) {
  const data = await api(`projects/${pid}/repository-scans/${sid}/report`);
  const r = data.report;
  if (!r) { toast("리포트가 아직 준비되지 않았습니다."); return; }
  openDialog(data.scan.mode === "deep" ? "심층 분석 리포트" : "1차 분석 리포트", `<p>commit <strong>${esc(r.commit_sha)}</strong></p><p class="scope-note">${esc(r.coverage_note)}</p>${data.scan.mode === "preliminary" && projects.find(p=>p.id===pid)?.role !== "viewer" ? `<div class="inline-actions"><button type="button" data-repo-deep="${sid}" data-project="${pid}" ${data.capabilities.deep_analysis ? "" : "disabled"}>심층 분석 요청</button></div>` : ""}<div class="project-stats"><span>패키지 <strong>${number(r.component_count)}</strong></span><span>버전 확인 <strong>${number(r.exact_version_count)}</strong></span><span>버전 미확인 <strong>${number(r.unresolved_version_count)}</strong></span><span>취약점 일치 <strong>${number(r.finding_count)}</strong></span></div>${r.comparison ? `<div class="coverage-note">1차 리포트 보존 · 추가 패키지 ${number(r.comparison.added_component_count)}개 · 새 취약점 ${r.comparison.new_finding_count == null ? "집계 범위 확인 필요" : number(r.comparison.new_finding_count) + "건"} · 남은 미확인 ${number(r.comparison.remaining_gap_count)}건</div><details><summary>추가 발견 패키지 보기</summary><ul>${(r.comparison.added_components || []).map(c=>`<li>${esc(c.name)}@${esc(c.version)} · ${esc(c.origin)}</li>`).join("")}</ul></details>` : ""}<h3>직접·전이 의존성 ${help("펼치면 확인된 자식 관계를 조회합니다. 관계가 없는 항목은 의존성이 없다는 뜻이 아니라 관계 미확인일 수 있습니다.","의존성 관계")}</h3><div id="repository-tree" data-project="${pid}" data-scan="${sid}">불러오는 중…</div><h3>확인된 취약점</h3>${r.findings?.length ? r.findings.map(f=>`<button class="result-row" data-advisory="${esc(f.advisory_pk)}"><span>${esc(f.package)}@${esc(f.version)} · ${esc(f.advisory_id)}</span>${pill(f.severity)}</button>`).join("") : "<p>현재 수집 자료와 일치한 취약점이 없습니다. 미확인 영역을 함께 확인하세요.</p>"}<h3>설치·다운로드·동적 실행 후보</h3>${(r.installation_candidates || []).slice(0,100).map(e=>`<div class="history-entry"><strong>${esc(e.file)}:${number(e.line)}</strong><pre>${esc(e.evidence)}</pre><p>${esc(e.reason || "정적 분석 후보이며 실제 설치 여부는 확인하지 않았습니다.")}</p></div>`).join("") || "<p>발견된 후보가 없습니다.</p>"}<h3>LLM 분석 요약</h3><p>${esc(r.llm?.summary || "LLM 결과가 없거나 이 단계에서는 사용하지 않았습니다.")}</p><h3>미확인 영역 · 수집 범위</h3><p>파일 ${number(r.files_scanned)}개 · 의존성 파일 ${number(r.dependency_files?.length)}개 · LLM ${esc({disabled:"미사용",not_requested:"이 단계에서는 사용 안 함",not_configured:"API 키 미등록",completed:"완료",failed:"응답 검증 실패"}[r.llm?.status] || r.llm?.status || "미사용")}</p><ul>${(r.gaps || []).slice(0,100).map(g=>`<li>${esc(g.file || "분석 범위")}: ${esc(repositoryGap(g.reason))}</li>`).join("")}</ul>${r.runtime ? `<h3>격리 실행 결과</h3><p>${r.execution_performed ? "설치·빌드·실행 명령을 격리 VM에서 관찰했습니다." : "프로젝트 코드 실행을 확인하지 못했습니다."} SBOM ${number(r.runtime.sbom_count)}개 · 소요 ${number(r.runtime.elapsed_seconds)}초</p><details><summary>실행 단계와 통신 증거</summary><pre>${esc(JSON.stringify({...r.runtime,sboms:undefined},null,2))}</pre></details>` : ""}<details class="creation-panel"><summary>분석 근거 JSON</summary><pre>${esc(JSON.stringify({...r,runtime:r.runtime?{...r.runtime,sboms:undefined}:undefined},null,2))}</pre></details>`);
  await repositoryChildren(pid,sid,"",$("#repository-tree"),[]);
}
function repositoryTreeRows(pid,sid,items,ancestors) {
  return items.map(c=>`<div class="repository-tree-node"><div class="repository-tree-label"><span><strong>${esc(c.name)}@${esc(c.version || "버전 미확인")}</strong><small>${esc(c.ecosystem)} · ${esc({direct:"직접",transitive:"전이",unknown:"관계 미확인"}[c.relationship])} · ${esc({repository:"저장소",base_image:"베이스 이미지",build:"빌드 결과",runtime:"격리 실행"}[c.origin] || c.origin)} · ${esc(c.module)}</small></span>${c.child_count && !ancestors.includes(c.id) && ancestors.length < 20 ? `<button type="button" class="secondary" data-repo-children="${esc(c.id)}" data-project="${pid}" data-scan="${sid}" data-ancestors="${esc(JSON.stringify([...ancestors,c.id]))}">하위 ${number(c.child_count)}개 보기</button>` : c.child_count ? "<small>순환 참조 또는 표시 깊이 제한</small>" : ""}</div><div class="repository-tree-children" hidden></div></div>`).join("");
}
async function repositoryChildren(pid,sid,parent,element,ancestors,cursor="") {
  const data = await api(`projects/${pid}/repository-scans/${sid}/components?`+query({parent,cursor}));
  if (!element.isConnected) return;
  const html = repositoryTreeRows(pid,sid,data.items,ancestors) || "<p>확인된 패키지가 없습니다.</p>";
  if (!cursor) element.innerHTML = html; else element.insertAdjacentHTML("beforeend",html);
  if (data.next_cursor) element.insertAdjacentHTML("beforeend",`<button type="button" class="secondary" data-repo-tree-more="${esc(data.next_cursor)}" data-parent="${esc(parent)}" data-project="${pid}" data-scan="${sid}" data-ancestors="${esc(JSON.stringify(ancestors))}">다음 구성 불러오기</button>`);
}
async function repositoryDeep(pid,sid) {
  const basis = await api(`projects/${pid}/repository-scans/${sid}/report`);
  openDialog("심층 분석 요청",`<p>1차 리포트와 같은 commit을 별도 일회용 VM에서 분석합니다. 제한된 외부 통신과 최대 15분의 실행 한도를 적용합니다. 관찰하지 못한 실행 경로는 미확인으로 남습니다.</p><form id="repo-deep" data-project="${pid}" data-scan="${sid}">${field("실행 프로파일",select("profile",[["python","Python 설치·의존성 관찰"],["node","Node.js 설치·의존성 관찰"],["docker","Dockerfile 빌드·이미지 관찰"]]))}${field("Python 설치 입력",select("manifest",[["","자동 선택 (대표 파일 1개)"],...(basis.report?.dependency_files || []).map(f=>[f,f])]),"Python 프로파일에서 사용할 파일을 선택합니다. 여러 환경의 파일을 한꺼번에 설치하지 않습니다.")}${field("실행 명령 (선택)", input("run_command", "예: python app.py · 비우면 설치/빌드만 수행", "", "text", 'maxlength="2000"'), "입력한 명령은 격리 VM에서만 실행하며 최대 120초 관찰합니다.")}<button>심층 분석 시작</button></form>`);
}
async function repositoryAdminSettings() {
  const settings = await api("admin/repository-analysis/settings");
  return section("저장소 분석 LLM 연결","OpenRouter · DeepSeek V4.1 Flash. 키는 서버에서 암호화 보관하며 모델에 전달하지 않습니다.",`<p>현재 상태: ${settings.llm.configured ? "API 키 설정됨" : "API 키 등록 필요"}</p><form id="repo-llm-settings" class="search-primary">${field("OpenRouter API 키",input("api_key","sk-or-…","","password",'required autocomplete="new-password"'))}<button>암호화 저장</button></form>`);
}
async function repositorySubmit(form,body) {
  const pid = form.dataset.project;
  if (form.id === "repo-create") {
    body.llm_enabled = form.elements.llm_enabled.checked;
    body.idempotency_key = crypto.randomUUID();
    await api(`projects/${pid}/repositories`,"POST",body);
    projects = (await api("projects")).items; updateScope(); await render(); toast("저장소를 등록하고 1차 분석을 요청했습니다.");
  } else if (form.id === "repo-credential") {
    const cid = body.credential_id;
    await api(`projects/${pid}/repository-credentials`+(cid?"/"+cid:""),cid?"PATCH":"POST",body);
    form.reset(); await render(); toast("자격 증명을 암호화 저장했습니다.");
  } else if (form.id === "repo-deep") {
    await api(`projects/${pid}/repository-scans/${form.dataset.scan}/deep-analysis`,"POST",{...body,idempotency_key:crypto.randomUUID()});
    $("#detail-dialog").close(); await render(); toast("심층 분석을 요청했습니다.");
  } else if (form.id === "repo-llm-settings") {
    await api("admin/repository-analysis/settings","POST",body); form.reset(); await render(); toast("OpenRouter 키를 암호화 저장했습니다.");
  }
}
async function repositoryClick(button) {
  const pid = button.dataset.project;
  if (button.dataset.repoReport) await repositoryReport(pid,button.dataset.repoReport);
  else if (button.dataset.repoDeep) await repositoryDeep(pid,button.dataset.repoDeep);
  else if (button.dataset.repoScan) { await api(`projects/${pid}/repositories/${button.dataset.repoScan}/scans`,"POST",{idempotency_key:crypto.randomUUID()}); await render(); }
  else if (button.dataset.repoCancel) { await api(`projects/${pid}/repository-scans/${button.dataset.repoCancel}/cancel`,"POST",{}); await render(); }
  else if (button.dataset.repoChildren) {
    const child = button.closest(".repository-tree-node").querySelector(".repository-tree-children");
    child.hidden = !child.hidden;
    if (!child.hidden && !child.childElementCount) await repositoryChildren(pid,button.dataset.scan,button.dataset.repoChildren,child,JSON.parse(button.dataset.ancestors));
    button.setAttribute("aria-expanded",String(!child.hidden));
  } else if (button.dataset.repoTreeMore) {
    await repositoryChildren(pid,button.dataset.scan,button.dataset.parent,button.parentElement,JSON.parse(button.dataset.ancestors),button.dataset.repoTreeMore);button.remove();
  }
}
