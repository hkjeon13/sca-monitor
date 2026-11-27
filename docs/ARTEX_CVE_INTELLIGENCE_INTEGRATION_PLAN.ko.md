# ARTEX용 SCA Monitor CVE 정보 연동 계획

작성일: 2026-11-03 (Asia/Seoul)  
상태: 타당성 분석 및 구현 계획. 구현·설정 변경·수집 재실행·배포는 수행하지 않음.  
분석 소스: SCA Monitor 로컬/원격 체크아웃 `d2674ed`, ARTEX 현재 작업 트리. ARTEX의 기존 미커밋 변경은 보존함.

## 1. 결론

**SCA Monitor를 ARTEX의 구조화된 CVE 정보원으로 재사용할 수 있다.** OSV·GHSA·NVD·CISA KEV·OpenSSF 수집 코드와 검색·상세·신선도 API가 이미 있어 수집기를 ARTEX에 중복 구현할 필요는 없다.

다만 **현재 배포를 그대로 최신 정보원으로 연결하는 것은 준비되지 않았다.** 운영 수집 실패, ARTEX 실행 경로에서의 접근성 미검증, 브라우저 세션 중심 인증이 우선 해결 과제다. SCA Monitor는 취약점 후보와 근거를 공급하고, ARTEX는 대상 식별·적용 조건 확인·승인 범위의 PoC 실행·증거·발견 검증·보고서를 담당한다. KEV 등재와 버전 일치는 해당 ARTEX 대상에서의 exploit 성공을 뜻하지 않는다.

## 2. 확인한 현재 상태

### 2.1 실제 운영 관찰

2026-11-03 17:00 KST 전후 SSH로 읽기 전용 상태를 확인했다. 사용자 기록·자격증명·로그 본문은 조회하지 않았다.

- 문서에 지정된 `ai-assistant` 서버의 원격 프로젝트가 존재하며 체크아웃은 로컬과 동일한 `d2674ed`다. 실행 프로세스가 이 소스를 모두 반영했는지 파일별 대조는 하지 않았다.
- `sca-monitor-api.service`는 사용자 systemd 서비스로 `active/running`이다. `sca-monitor-source-sync.service`는 `failed`, 대응 타이머는 `active/waiting`이다.
- 해당 서버의 현재 kubectl 컨텍스트에서 Deployment·Service·CronJob 이름에 `sca-monitor`가 포함된 리소스는 없었다. 다른 Kubernetes 클러스터의 존재까지 배제하지 않는다.
- 호스트 loopback의 `GET /health`, `GET /ready`는 HTTP 200이었다. 그러나 `/ready` 내부의 advisory 상태는 `degraded`였으며, `/ready`의 200은 정보 최신성 보증이 아니다.
- loopback `GET /api/v2/intel/sources`는 인증 없이 HTTP 401이었다.
- 같은 서버에서 공개 HTTPS의 `/health`, `/ready`, `/api/v2/intel/sources`는 HTTP 403이었다. 403의 발생 계층·원인과 ARTEX 진단 VM/SOCKS5 출발 결과는 미확인이다. 이를 전체 외부 접속 불가로 일반화하지 않는다.
- 최근 수집 주기 진행 파일은 2026-11-03 11:55:31 KST에 종료됐고 실패 소스는 CISA_KEV·OSV·OpenSSF·NVD였다. 진행 파일의 `complete`는 성공을 뜻하지 않는다.

운영 SQLite의 `advisory_sync_state`에서 소스명·상태·실행/성공 시각만 읽었다. 아래 시각은 KST다.

| 소스 | 마지막 상태 | 마지막 성공 시각 | 해석 |
|---|---|---|---|
| CISA_KEV | error | 2026-10-30 13:43:14 | 최근 수집 실패, 마지막 성공도 오래됨 |
| GHSA | ok | 2026-11-02 17:54:56 | 성공 이력이 있으나 전체 공개 기록의 완전성을 뜻하지 않음 |
| NVD | error | 2026-09-25 14:16:23 | 최신 CVE 조회에 의존하기 전 수집 복구·누락 구간 확인 필요 |
| OSV | error | 2026-11-02 23:54:48 | 비교적 최근 성공 뒤 실패; 최신 상태로 단정 불가 |
| OpenSSF | error | 2026-11-03 05:54:53 | 비교적 최근 성공 뒤 실패; 최신 상태로 단정 불가 |

실패 원인은 이번에 조사하지 않았다. 누적 `imported_count`는 실제 저장 행 수나 고유 CVE 수로 사용하지 않았다.

### 2.2 재사용 가능한 구현

| 기능 | 소스 | 연동 시 활용 |
|---|---|---|
| 5개 소스 수집 | `backend/sca_monitor/advisory_sync.py`, `scripts/sync_sources_serial.py` | 중앙 수집 유지 |
| 6시간 후 재수집 | `deploy/sca-monitor-source-sync.timer` | 완료 후 6시간이므로 실행 시간만큼 간격이 늘어남 |
| 검색·별칭 조회 | `backend/sca_monitor/workspace.py:advisory_search` | CVE/GHSA ID, 제품·패키지, 소스, KEV, 변경 시각 필터 |
| 상세·원문 | `backend/sca_monitor/app.py:get_advisory`, `workspace.py:advisory_detail` | 버전 범위·원문·참고 링크를 근거로 활용 |
| 소스 상태 | `workspace.py:sources` | 5개 소스의 상태·마지막 성공·수집 범위 |
| NVD 정보 보강 | `app.py:enrich_nvd_advisories` | 원문, CWE, CPE, references 재사용 |

현재 v2 API는 다음과 같다.

```text
GET /api/v2/intel/sources
GET /api/v2/intel/advisories?q=<CVE-ID 또는 검색어>&page_size=25
GET /api/v2/intel/advisories/{저장 레코드 ID}
```

`q`는 완전한 CVE/GHSA ID의 별칭 검색을 지원한다. 상세는 검색 결과의 저장 레코드 `id`로 조회해야 하며, CVE 하나가 패키지별 여러 레코드일 수 있다. 상세에 CVE 별칭을 그대로 전달하면 같은 검색 의미가 보장되지 않는다. 목록만으로 영향 버전 범위·전체 원문을 얻었다고 간주해서는 안 된다.

## 3. 연동을 위해 필요한 SCA Monitor 변경

### P0-A. 수집 복구 및 신선도 의미 보완

1. 소스별 실패 유형을 자격증명을 노출하지 않는 형태로 분류한다. 타임아웃·상류 429/5xx·변경 구간 크기·DB 경합·프로세스 중단을 구분하고, 원인을 확인한 범위만 수정한다. 이번 관찰만으로 원인을 확정하지 않는다.
2. NVD는 저장된 완료 커서와 실제 처리 구간을 확인하고 누락 구간을 이어받는다. 부분 처리·실패 시 완료 커서를 앞당기거나 기존 데이터를 초기화하지 않는다. 장기간 지연 구간은 제한된 변경 구간으로 나눠 복구한다.
3. GHSA·OSV 등에서도 마지막 성공 시각과 실제 수집 범위를 구분한다. OSV는 설정된 생태계만, OpenSSF 경로는 현재 코드상 npm MAL 보고를 수집한다. 환경 설정상의 실제 생태계 목록은 별도로 확인한다.
4. 기존 `/ready`의 가용성 의미는 보존하고, 연동 API에는 5개 소스의 신선도/범위 상태를 제공한다. 현재 `INITIAL_ADVISORY_SYNC_SOURCES`는 OSV·CISA_KEV·OpenSSF만 포함하므로 NVD/GHSA 최신성 판단에 그대로 사용하지 않는다.
5. `last_success_at`은 전체 범위의 완료 성공을 뜻하도록 정리하고, 기록별 진행 성공과 주기 완료 성공을 구분한다. 다중 OSV 생태계가 있을 때 하나의 소스 상태가 범위별 실패를 숨기지 않게 한다.
6. `fresh`는 요청한 수집 범위와 허용 지연 이내라는 뜻으로 한정한다. 원천 공개 데이터 전체 수집·즉시 반영을 뜻하지 않는다. `running`이어도 마지막 완료 결과의 실패·지연을 함께 유지한다.

관련 파일: `advisory_sync.py`, `app.py`, `workspace.py`, `scripts/sync_sources_serial.py`, `scripts/nvd_cve_sync.py`, 소스별 수집 스크립트 및 해당 테스트.

### P0-B. 읽기 전용 서비스 인증

현재 `WorkspaceAPI.session_user`는 쿠키의 세션 토큰을 조회한다. 운영 `local` 모드에서는 v1 관리 API도 관리자 세션을 요구한다. 기존 snapshot push Bearer 토큰은 대상별 업로드용이므로 CVE 조회용으로 재사용하지 않는다.

추가 설계:

- 전용 서비스 자격증명과 `intel:read` scope를 추가한다. 브라우저 사용자 세션·계정 비밀번호를 ARTEX에 보관하지 않는다.
- 전용 경로에서만 Bearer 인증을 받는다. 기존 브라우저 API의 인증·CSRF를 우회하거나 전역적으로 Bearer를 허용하지 않는다.
- 토큰은 발급 시 한 번만 표시하고 해시·식별자·scope·만료·폐기 상태·마지막 사용 시각만 저장한다. 발급/회전/폐기용 관리 CLI를 먼저 제공하고, 관리 UI는 후속으로 둘 수 있다.
- 권한은 공개 취약점 정보 조회에 한정한다. 프로젝트·자산·저장소·계정·impact·snapshot 업로드와 변경 API는 허용하지 않는다.
- SQLite와 PostgreSQL에 같은 의미의 추가 migration을 작성한다. 기존 테이블·세션·사용자 데이터는 유지한다.
- 인증 실패와 권한 거부, 429를 구분하고 토큰과 원문 Authorization 헤더는 로그·모델 요청·도구 결과에 넣지 않는다.

관련 파일: 신규 서비스 인증 모듈/관리 CLI, `app.py` 라우팅, `migrations/sqlite/`, `migrations/postgres/`, `tests/`.

### P0-C. 프로젝트 데이터가 섞이지 않는 정보 조회 계약

기존 상세 API는 프로젝트 impact도 함께 조회한다. 연동 API는 기존 검색/자료 변환 로직을 재사용하되 공개 권고 데이터만 반환하는 별도 조회 계층을 둔다.

제안 경로(아직 구현되지 않음):

| 요청 | 목적 |
|---|---|
| `GET /api/v2/integration/intel/sources` | 5개 소스의 상태·범위·완료 시각 |
| `GET /api/v2/integration/intel/advisories` | 기존 필터를 활용한 후보 검색 |
| `GET /api/v2/integration/intel/advisories/{record_id}` | 버전 범위·참고 자료·검증 조건 조회 |

필수 응답 내용:

- `schema_version`, 서버 응답 시각 `as_of`, 안정적인 `record_id`, 원본 권고 ID·별칭·소스.
- 설명, 제품/생태계/패키지, 영향 버전 및 범위, 수정 버전, KEV 여부, 원문에 존재하는 CVSS/CWE와 참고 링크. 없는 값은 null/unknown으로 명시한다. 기존 추정 severity를 공식 CVSS 점수로 표시하지 않는다.
- 소스 `published_at`·`modified_at`, 수집 완료 구간, 신선도 상태, 설정 범위, 과거 적재 범위의 알려진 한계.
- 자료 조회 시각과 근거 내용 hash. hash 산출 범위·직렬화 규칙을 버전별로 고정한다. `as_of`를 원천 데이터 갱신 시각으로 사용하지 않는다.
- 목록 페이지 크기·다음 커서·한도/잘림 상태. 목록의 현재 offset 커서는 동시 갱신 시 결과 중복/누락이 가능함을 명시한다. 초기 ARTEX 소비자는 ID 중복 제거와 조회 시간 범위를 기록한다. 전체 증분 복제나 완전 순회가 필요해지면 고정 snapshot/keyset 계약을 별도 구현한다.

원문·범위의 보존:

- 모델에는 정규화된 핵심 근거를 제공하고 큰 원문은 레코드/내용 hash로 분리 조회할 수 있게 한다. 잘린 본문으로 전체 검토를 완료했다고 표시하지 않는다.
- NVD의 AND/OR, negate, 환경 조건을 평탄화한 CPE 목록만으로 적용 여부를 확정하지 않는다. 원래 configurations와 참고 자료를 보존하며 자동 해석 미지원은 `unknown`으로 반환한다.
- `first_seen_at`, 소스 `modified_at`, 마지막 전체 수집 성공 시각은 서로 대체하지 않는다. 기록별 마지막 수집 시각이 필요하면 새 nullable 필드를 추가해 이후 실제 수집부터 기록한다. 과거 값을 현재 시각으로 소급 채우지 않는다.
- 과거 alias merge로 소실된 소스별 원문은 복구됐다고 표시하지 않는다. 현재 보존된 출처와 누락 가능성을 명시한다.

오류 의미:

- 인증 없음/만료/폐기는 401, scope 부족은 403, 유효하지 않은 입력은 400, 레코드 부재는 404, 제한은 429, 일시적 DB 경합/불가용은 503 등으로 구분한다.
- 소스 지연·실패 시 저장 자료는 읽을 수 있으나 `fresh=false`와 구체 상태를 유지한다. API 장애·수집 실패를 빈 검색 결과로 바꾸지 않는다.
- 검색 0건은 `no_local_match`이며 취약점 부재나 대상 안전을 의미하지 않는다. 호출 자체가 수집 재실행·외부 PoC 다운로드·대상 진단을 유발하지 않는다.

## 4. ARTEX 측 연동안과 경계

```text
SCA Monitor 소스 수집 → 저장 권고 + 범위/신선도
    → 인증된 읽기 전용 API → ARTEX 전용 정보 조회 도구
    → Planner 후보 계획 → Worker 대상/버전/구성 확인
    → 필요한 공식 자료·PoC 분석 → 승인된 대상에서 실제 검증
    → 사실/미결론 또는 검증된 finding → 증거·보고서·영속 조회·UI
```

- 우선 전용 도구 `cve_search`, `cve_detail`, `cve_sources`를 연결한다(이름은 제안). 정보원 주소와 자격증명은 관리 설정으로 고정하고 모델 입력에서 임의 주소·토큰을 받지 않는다.
- 현재 `sandbox/search.go`처럼 정보 조회용 별도 도구 VM/브로커 경로를 사용하고, 자격증명은 모델·일반 Bash 작업공간과 분리한다. 준비 래퍼·side-question/capture 훅 이후 실제 Worker의 모델 요청에 도구가 남는지 검증한다.
- 외부 트래픽은 ARTEX 진단 VM과 SOCKS5를 통한 지원 경로로 보낸다. 일반 Bash·Python·브라우저·백그라운드·MCP·커스텀 도구를 제한하지 않는다. 이번 추가를 위해 전체 진단 도구를 GET/HEAD 전용으로 바꾸지 않는다.
- 현재 공개 HTTPS의 403을 ARTEX 실제 도구 VM 경로에서 재검증한다. 호스트 loopback이나 별도 클러스터의 ClusterIP를 외부 VM이 사용할 수 있다고 가정하지 않는다. 공개/사설 API 경로 선택은 실제 라우팅·TLS·접근제어 증거를 보고 결정한다.
- `component-cve-check`에 SCA 조회→신선도/범위 확인→상세/공식 권고문 확인 순서를 추가한다. SCA 자료가 없거나 오래되면 그 한계를 남기고, 가능한 공식 출처 조회 또는 미결론으로 이어간다.
- 권고문과 PoC 코드는 분석 대상 데이터다. 자료에 포함된 명령을 지시로 취급하거나 조회 즉시 실행하지 않는다. 공개 PoC 보유/실행 가능성 필드는 별도 검증 없이는 단정하지 않는다.
- 현재 확인한 SCA 구현은 exploit 실행 서비스나 검증된 exploit 저장소가 아니다. 실제 공격 조건·인증·패치/백포트·노출 경로 확인과 실행 판단은 ARTEX가 담당한다.
- SCA 후보를 곧바로 ARTEX finding으로 등록하지 않는다. 실제 증거가 없으면 `record_fact`와 미검증 후보로 남긴다. 기존 오프라인 Trivy 검사는 독립 경로로 유지하며 이 연동으로 그 DB가 자동 갱신됐다고 표시하지 않는다.

ARTEX 관련 소스: `agent/worker.go`, `agent/sandbox_session.go`, `sandbox/search.go`, `server/assembly.go`, `skills/component-cve-check/SKILL.md`.

## 5. 구현 순서와 완료 조건

| 단계 | 작업 | 다음 단계로 넘어갈 조건 |
|---|---|---|
| 1 | 실패 원인 분석·수집 복구, 범위/완료 상태 정리 | 요청할 소스의 실제 완료 범위와 지연이 확인됨 |
| 2 | 서비스 인증·정보 전용 조회 계약·문서 | 기존 UI/API를 보존하고 scope 격리 및 오류 의미 검증 |
| 3 | 실제 ARTEX VM에서 TLS/인증/GET 본문/페이지 조회 | 정상·거부·실패·취소 경로와 비밀 분리 확인 |
| 4 | ARTEX 도구·스킬·근거 저장 연동 | 실제 Worker 모델 요청과 도구 입출력 관찰 |
| 5 | 소유 테스트 대상의 전체 native 평가 | 보고서 영속 조회와 실제 결과 UI까지 관찰 |

단계 1과 2의 로컬 개발은 병행할 수 있다. 운영 수집 복구 전까지 연동 데이터에 최신성 보증을 표시하지 않는다. 초기 서비스 인증과 순수 조회는 필수이며, 전체 CVE 과거 적재·범용 CPE 자동 판정·PoC 저장소·자동 exploit 선택은 별도 후속 범위다.

## 6. 검증 계획

### SCA Monitor 계약 및 회귀

- SQLite/PostgreSQL의 추가 migration, 기존 사용자·세션·snapshot·권고·커서 보존과 이전 버전 호환 복구를 확인한다.
- 읽기 토큰의 정상·만료·폐기·scope 부족·회전·동시 사용을 검증한다. 변경 API, 프로젝트/계정/저장소/impact 데이터에 접근하지 못하는지 확인한다.
- CVE/GHSA 별칭·다중 패키지·정확한 레코드 상세·페이지 경계·빈 결과·잘못된 입력·큰 원문·잘림/내용 hash를 확인한다.
- 소스별 fresh/stale/partial/failed/running/미적재 상태와 마지막 전체 완료 시각을 검증한다. NVD/GHSA가 누락된 3개 소스 readiness를 최신성 판단에 쓰지 않는지 확인한다.
- 수집 중 DB 경합·503·클라이언트 취소·재개, 상류 제한/오류·부분 처리·커서 보존을 테스트한다. 운영 원인 분석과 독립적인 fixture 결과는 구분한다.
- 기존 로그인·프로젝트 경계·브라우저 CSRF·push credential·검색 화면을 회귀 확인한다. 변경이 화면에 영향을 주면 실제 인증 후 UI도 확인한다.

### ARTEX native 경로

- 실제 도구 VM에서 정확한 GET 요청·응답 본문·TLS·페이지/본문 전체 조회·정책 거부·401/403/429/503·타임아웃·대기·취소·재개를 관찰한다. HTTP 200이나 검색 도구 단독 fixture만으로 성공 처리하지 않는다.
- 모델-facing 도구 카탈로그를 모든 준비/캡처 래퍼 이후 확인하고, 영향받는 streaming/non-streaming provider 경로의 요청 직렬화와 도구 결과를 각각 검증한다.
- 도구 네트워크/실행 경로를 바꾸는 경우 소유 대상에서 메서드·헤더·쿠키·본문·리다이렉트·HTTPS·런타임/스캐너·브라우저 JS·interactive/background·취소·영속 traffic 검색/조회도 회귀 검증한다.
- 서로 다른 경우를 평가한다: 적용 조건이 맞는 소유 테스트 대상, 패치/백포트 또는 구성상 비적용 대상, 로컬 검색 0건, 오래되거나 실패한 소스, 근거 부족으로 PoC 미결론인 경우.
- 각 경우에 채팅→작업 생성→계획→Worker/도구→증거→finding 검증 또는 정직한 음성/미결론→최종 보고서→영속 재조회→실제 UI 표시를 확인한다. planner `met`/task `done` 대신 실제 도구 입출력과 저장 결과를 대조한다.
- 양성 finding 연계는 소유 테스트 DB에서 작업별/전역 API 모두 독립 finding ID·exploration node ID·triage·상세 보고서를 검증한다. 음성 결과나 일반 권고 일치를 finding으로 만들지 않는다.
- terminal 결과 없는 stream은 interrupted/uncertain으로 남기고 미결 도구 흔적을 보존한다. 불확실한 PoC를 자동 재실행하지 않는다.
- ARTEX 배포 시 `-tags embedui`, release UI guard, root/login/JS/CSS 및 공개 브라우저 결과 UI를 확인한다.

## 7. 배포·보존·복구

- 구현 전 SCA의 현재 DB·소스·서비스/타이머 구성에 대해 백업과 읽기/복원 검증 경로를 확보한다. 수집 복구를 이유로 원본 데이터·커서·기존 백업·임시 증거를 삭제하지 않는다.
- 서비스 인증 migration은 추가 방식으로 적용하고, 이전 브라우저 API는 유지한다. ARTEX 연동은 별도 feature flag로 단계적으로 활성화한다.
- 장애 시 ARTEX 연동 비활성화와 해당 서비스 토큰 폐기를 우선한다. 이전 애플리케이션 코드로 되돌릴 수 있게 하고 기존 사용자·프로젝트를 과거 DB로 덮어쓰지 않는다.
- 수집 재개와 데이터 보정은 변경 원인·대상 범위·완료 커서를 기록한다. 이번 분석 문서의 최초 관찰은 남겨 두고 복구 결과를 날짜와 함께 추가한다.

## 8. 이번 분석에서 수행하지 않은 것

수집 실패 원인·원문 로그 조사, 소스 수집 재실행, 인증 자격증명 발급, 인증 후 실제 권고 검색/상세 조회, ARTEX 진단 VM/SOCKS5에서의 SCA 연결, exploit 실행, 전체 native 평가 및 결과 UI는 수행하지 않았다. 공개 HTTPS 403의 원인과 다른 Kubernetes 환경의 존재도 확인하지 않았다. 따라서 현재 확인은 재사용 가능성 및 필요한 변경 범위의 분석이며 연동 완료나 최신 CVE 기반 진단 성공의 증거가 아니다.

## 9. 소스 참고

- [기존 workspace API·범위·배포 문서](workspace-api.md)
- [서버 라우팅·상세·신선도](../backend/sca_monitor/app.py)
- [세션 인증·5개 소스 상태·검색·프로젝트별 상세](../backend/sca_monitor/workspace.py)
- [소스 수집·NVD CPE 변환](../backend/sca_monitor/advisory_sync.py)
- [순차 수집·재개·실패 소스 기록](../scripts/sync_sources_serial.py)
- [수집 타이머](../deploy/sca-monitor-source-sync.timer)
- [기존 운영 접속 정보 문서](../harness/values/deployment-inputs.md)


## 10. 2026-11-03 수집 복구 후속 기록

위 최초 분석 이후 별도 작업으로 수집 실패 원인과 운영 저장소 병목을 수정하고, 누락된 NVD 변경 구간 및 기존 5개 소스의 실제 전체 수집 주기를 완료했다. NVD 완료 커서는 2026-11-03 19:49:52 KST까지 전진했다. 공식 API 최근 수정 271건과 신규 등록 438건의 전체 원문도 DB와 별도 대조했다. 데이터 보존·복원·실행 증거와 한계는 [수집 복구 기록](COLLECTOR_RECOVERY_2026-11-03.ko.md)에 있다. 최초 분석 시점의 실패/미수행 관찰은 위에 보존했다.

이는 구현 순서의 1단계 수집 복구에 대한 후속 결과다. 서비스 인증, ARTEX 도구 연결, 실제 진단 VM 경로, native 전체 평가 및 결과 UI는 계속 후속 작업으로 남는다.


## 11. 2026-11-04 ARTEX 연동 구현·배포 후속 기록

서비스 인증·읽기 API·격리된 정보 VM·Worker 3개 CVE 도구를 구현하고 운영 배포했다. 기존 보호 테이블과 권고 ID를 보존했으며 5개 소스 수집이 성공했고 NVD 완료 커서는 2026-11-03 23:40:31 KST까지 전진했다. 실제 인증 대화 239에서 작업 66을 생성하여 분석·도구 실행·사실/보고서 저장과 새로고침 후 결과 UI까지 확인했다.

실행 조건, 백업·보존 비교, 정확한 GET/본문/hash, 버전 비교의 한계, native 보고서의 정렬 관찰 이후 메타데이터 보강, 상위 대화의 조기 완료 안내 등 불일치도 [연동 검증 기록](ARTEX_INTEGRATION_VERIFICATION_2026-11-04.ko.md)에 남겼다. 위 8절과 10절의 미수행 내용은 각 작성 시점의 관찰로 보존한다. 실제 런타임/exploit 검증 및 과거 전체 CVE 완전성은 여전히 입증하지 않았다.
