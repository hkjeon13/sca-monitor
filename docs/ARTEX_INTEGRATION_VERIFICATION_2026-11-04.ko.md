# ARTEX CVE 연동 구현·운영 검증 — 2026-11-04

## 구현 결과

ARTEX가 이 서비스의 최신 저장 CVE를 실제 Worker 분석 근거로 읽도록 배포했다. SCA 운영 인스턴스는 `ai-assistant`의 systemd 사용자 서비스이며, 이번 연동에 별도 Kubernetes SCA 인스턴스는 사용하지 않았다. 수집기와 사용자 데이터는 유지했다.

- 계약: [intel-integration-api.md](intel-integration-api.md), schema `sca-intel.v1`.
- GET `/api/v2/integration/intel/sources`, `/advisories`, `/advisories/{record_id}`, `/advisories/{record_id}/raw`.
- 인증: 별도 `intel:read` 서비스 토큰, 해시 저장, 만료/회전/폐기, 120회/분. 사용자·프로젝트·관리자·push API 권한을 주지 않는다.
- migration 23은 credential 테이블을 추가한다. SQLite/PostgreSQL SQL을 제공했고 운영 SQLite에서 적용했다. 운영 PostgreSQL SCA를 배포·검증한 것은 아니다.
- 원문 전체 hash 및 hash 고정 Unicode 조각 조회, 요약/참조 잘림 표시, 신선도/커서/수집 범위, 검색 0건의 no_local_match를 제공한다.
- 목록은 modified_at DESC NULLS LAST, record_id DESC의 고정 정렬이며 `ordering`을 응답한다. 제품/패키지별 행이므로 unique CVE 수와 다르다. live-offset은 동시 갱신 중 중복·누락 가능성이 있다.

ARTEX의 `cve_sources`, `cve_search`, `cve_detail`은 별도의 정보 조회 VM 및 기존 SOCKS5 경로로 접근한다. 모델 입력에는 URL/token이 없고 일반 Bash VM에는 인증값을 주지 않는다. TLS/HTTP/body 오류는 실패로 남긴다. 기존 Bash/Python/브라우저/interactive/background/검색/traffic 도구를 유지했다.

## 데이터 보존과 최신성

운영 증거: `/data/psyche/Projects/sca-monitor/releases/cve-intel-integration-20261103/`.

추가 migration 전에 온라인 SQLite 백업 4,186,222,592 bytes를 만들고 별도 복원 smoke/schema 22/22 및 무결성을 검증했다. 파일은 `/home/psyche/.local/share/sca-monitor/integration-backups/sca-monitor-20261103T141504Z-gve2pu2x.sqlite3`이며 기존 HDD 원본·SSD DB·수집 복구 증거와 백업을 모두 보존했다.

Migration 직전/직후 보호 대상 14개 테이블의 내용 hash, 권고 ID hash, 기존 테이블 건수가 같았다. 이후 실제 수집 및 ARTEX 분석을 마친 **2026-11-04 00:33 KST**에도 사전 백업과 다시 비교했다.

- services/dependency_snapshots/dependencies/workspace_users/workspace_sessions/workspace_setup_tokens/push_credentials/alert_channels/projects/project_memberships/project_targets/repository_credentials/repository_connections/repository_llm_settings 전체 내용 동일.
- 기존 권고 ID 누락 0. 권고 364,500→364,599, 별칭 407,398→407,499로 정상 수집 추가분 증가.
- impacts 60, impact_history 20, alert_events 175, audit_logs 1,039 유지.
- 상세 증거: `migration-verification.json`, `final-data-preservation.json`.

다섯 소스가 11월 3일 23:39~23:40 KST에 모두 ok로 완료됐으며, 최종 운영 정보 VM 조회 11월 4일 00:32:38 KST에도 fresh=true였다.

| 소스 | 마지막 성공 UTC | 저장 레코드 |
| --- | --- | ---: |
| OSV | 2026-11-03T14:40:00.292162Z | 9,208 |
| GHSA | 2026-11-03T14:39:30.935455Z | 5,979 |
| OpenSSF | 2026-11-03T14:40:24.400267Z | 223,009 |
| CISA KEV | 2026-11-03T14:39:29.119969Z | 1,766 |
| NVD | 2026-11-03T14:40:40.100313Z | 124,637 |

NVD 완료 커서는 `2026-11-03T14:40:31.000` UTC, 즉 **23:40:31 KST**다. 정기 수집을 유지했으며 fresh는 마지막 성공 및 지연 기준이다. 실시간 무지연이나 과거 전체 적재 완전성을 뜻하지 않는다. 기록 수는 고유 CVE 수가 아니다.

## 테스트와 실제 분석/UI

- 전체 Python suite **362 passed**(마지막 정렬/조각 hash 메타데이터 추가 전), 최종 변경 후 관련 integration/workspace **22 passed**. 후자의 결과를 전체 suite 결과로 확대하지 않는다.
- 실제 HTTPS: 정상 200, 잘못된 토큰 401, 정상 토큰으로 POST 405, 사용자 프로젝트 API 접근 401 확인. 오류(scope/expiry/revoke/rate/busy/invalid/hash drift 등)는 자동 테스트에서 별도 검증했다.
- 실제 운영 정보 VM: GET→NVD 검색→상세→전체 raw hash→로컬 0건 처리, 별도 일반 Bash VM 환경의 인증 분리 확인. 최종 metadata 변경 후 같은 실제 VM 경로로 ordering/chunk_sha256 전달까지 재검증했다.
- 실제 인증 브라우저 대화 239→작업 66 생성→Planner→Worker/Bash/Python/CVE→record_fact→최종 보고서→새로고침 후 보고서 UI 재조회 완료. <https://artex.fin-ally.net/function/tasks/detail/?id=66>의 보고서 탭, 관리자·기존 자료 작업 공간.
- CVE 호출 22회 모두 GET/200/body_complete=true. 모델 요청 46건에 서비스 토큰이 없고, CVE 도구를 가진 Worker 요청 26건에 기존 진단 도구도 함께 있었다. 보고서 fact 4244/4245/4247을 영속 저장했다.
- npm/lodash 4.17.20이 CVE-2021-23337의 저장 SEMVER 범위에 포함되고 4.17.21은 fixed 경계로 제외됨을 비교했다. 다른 CVE 또는 실제 런타임 안전성으로 확대하지 않았다. 가상 CVE 0건은 no_local_match로 남겼다.
- NVD CVE-2026-113903의 visionos/ipados 두 행은 같은 CVE의 제품별 레코드였다. 원문 3,016자를 4조각(1,000/1,000/1,000/16)으로 끝까지 읽고 실제 trace에서 독립 재조립·JSON·SHA-256을 검증했다: `c961c4ed24aadfccac22140c7a3870029143a4ccd728512ddeb3b7f7ef0521d9`.
- 검증되지 않은 후보를 finding으로 등록하지 않았다. 실제 설치·노출·함수 사용·백포트·exploit 조건은 fixture_only=true/runtime_attestation=false이므로 미검증이다.
- 별도 소유 KVM/target/SOCKS에서 기존 진단 46개 operation(메서드/헤더/쿠키/본문, HTTPS/리다이렉트, runtime/scanner, browser JS, interactive/background/취소, durable traffic 등) 통과. ARTEX streaming/Complete 모델-facing catalog 및 정책/취소/오류 회귀는 테스트로 검증했고 모든 provider·MCP/custom 각각을 실통신으로 재검증하지는 않았다.

## 기존 관찰과 사후 수정

당시 native 보고서의 정렬 계약 미확인 관찰은 보존한다. 이를 보고 응답에 고정 정렬/제품별 단위를 추가하고 raw에 chunk_sha256을 추가했다. 변경 후 실제 HTTPS 및 운영 VM에서 검증했으며, 예전 보고서가 새 필드를 이미 봤다고 바꾸지 않았다.

보강 Worker의 4번째 NVD 페이지는 modified_from 필터가 추가됐다. 20개 관찰값의 비증가는 확인했지만 동일한 무필터 쿼리의 연속 4페이지 완전성을 입증한 것으로 취급하지 않는다. 상위 대화의 조기 완료 안내/추정 링크도 실제 종료·보고서 저장·canonical UI URL로 별도 확인했다. 상세 원본/정정은 ARTEX `deploy/cve-intelligence-release-2026-11-04.md` 및 원격 `/data/psyche/Projects/artex/releases/cve-intel-20261103/native-task-66/`에 있다.

## 운영/복구

Credential ID `424c1dd4-268e-4716-b28d-ca6e3fb98819`, 만료 `2027-02-01T14:39:25.094493Z`. 평문은 operator 전용 private 파일에만 있다. `scripts/intel_credentials.py`로 독점 생성 파일/회전/폐기를 관리한다. 회전 시 새 private 설정 적용과 앱 재시작을 함께 계획한다. 인증값을 Git·프롬프트·로그·Helm values·진단 VM에 복사하지 않는다.

ARTEX의 명시적 `AIMEMBER_CVE_INTEL_ENABLED=false` 또는 browsable workspace 밖 private 설정의 enabled=false로 연동만 끌 수 있다. 기존 데이터/진단 기능을 삭제하지 않는다. SCA schema 23은 추가 테이블이므로 앱 복구를 이유로 운영 DB를 과거 백업으로 덮어쓰지 않는다. 기존 소스는 `source-before` 및 `source-before-contract-metadata`에 보존했다. 기존 백업·수집 복구 기록·계획서의 최초 관찰은 유지한다.
