# Project workspace API and deployment

2026-10-28 구현 기준. 화면 레이아웃은 기존 dark sidebar/card shell을 유지한다.

## 로그인과 계정

운영 환경은 `SCA_MONITOR_AUTH_MODE=local`, `APP_ENV=prod`를 사용한다. 비밀번호는 salt와 PBKDF2-SHA256 600,000회로 저장한다. 12시간 세션 쿠키는 Secure, HttpOnly, SameSite=Lax이며 세션 원문 대신 해시를 DB에 저장한다. 변경 API는 세션의 `X-CSRF-Token`과 Origin을 검사한다. 로그인에는 이메일/IP별 시도 제한이 있다. HTTPS 배포가 필요하다.

초기 관리자 설정은 서버에서 다음 명령으로 한 번 발급한다. 비밀번호는 사용자가 화면에서 직접 정한다.

```sh
python3 scripts/workspace_admin.py --public-url https://monitoring.fin-ally.net --output .data/admin-setup-link.txt
```

출력 파일은 0600 권한이며 링크는 24시간·1회 유효하다. 링크 토큰은 URL fragment에 있어 웹 서버 요청 로그에 포함되지 않는다. 관리자가 로그인한 뒤 `수집·계정 관리`에서 다른 계정의 설정 링크를 발급할 수 있다. 기존 계정에 발급하면 비밀번호 재설정으로 동작하고 기존 세션을 폐기한다. 이메일을 자동 발송하지 않는다.

| Endpoint | 동작 |
|---|---|
| `POST /api/v2/auth/setup` | token, email, display_name, password로 계정 생성/재설정 |
| `POST /api/v2/auth/login` | email, password 로그인 |
| `GET /api/v2/auth/session` | user(없으면 null), csrf_token, auth_mode |
| `POST /api/v2/auth/logout` | 현재 세션 종료 |
| `GET /api/v2/me` | 계정과 접근 가능한 프로젝트 |
| `POST /api/v2/admin/invitations` | 관리자 전용. email에 한정한 1회 설정 링크 |

local 인증에서는 v1 관리 API와 `/metrics`도 관리자에게 한정한다. v1 snapshot 수신은 대상에 묶인 Bearer push credential을 요구한다. 브라우저 세션을 통한 프로젝트 작업은 v2를 사용한다. 고급 기존 콘솔은 `/admin.html`이며 API 권한 검사와 CSRF를 적용한다.

## 보안 정보

- `GET /api/v2/intel/sources`: 5개 소스의 실제 저장 건수, 수집 범위, 지연/실패/부분/실행 중 상태.
- `GET /api/v2/intel/advisories`: q, source, ecosystem, package, severity, kev, malicious, modified_from, project_id, page_size, cursor.
- `GET /api/v2/intel/advisories/{id}`: 원문, 별칭, 버전 범위, 권한 내 프로젝트 영향.
- `GET /api/v2/intel/records?source=OSV` 및 `GET /api/v2/intel/records/{source}/{id}`: 저장된 소스 기록 조회.

목록은 `items,total,page_size,offset,next_cursor,as_of`를 반환한다. 기본 25, 최대 100건씩 페이지 이동하며 200건 고정 제한을 제거했다. 별칭을 함께 검색한다. 현재 저장 모델에는 패키지별 분리 행과 기존 alias merge 결과가 포함되어 있어 저장 건수는 unique CVE 수가 아니다. 기존 merge 과정에서 사라진 소스 원본은 재구성했다고 표시하지 않는다. 전체 공개 데이터의 완전성도 보장하지 않는다.

수집 범위는 현재 OSV 지정 생태계(`SCA_MONITOR_OSV_ECOSYSTEMS`, 기본 npm), GHSA reviewed 변경분 전체 페이지, npm MAL 보고, KEV 카탈로그, NVD 저장 커서 이후 변경분이다. 다른 OSV 생태계는 운영자가 환경 변수에 추가할 수 있다. NVD 변경 구간의 일부만 처리한 경우 완료 커서를 앞당기지 않는다.

## 프로젝트와 자산

- `GET/POST /api/v2/projects`, `GET/PATCH /api/v2/projects/{id}`.
- `GET/POST /api/v2/projects/{id}/members`: owner/maintainer/viewer. 등록 계정의 이메일로 구성원 추가·역할 변경. 마지막 owner를 제거하지 않는다.
- `GET/POST /api/v2/projects/{id}/targets`, `GET/PATCH /api/v2/projects/{id}/targets/{target_id}`.
- `GET /api/v2/projects/{id}/inventory`: 최신 snapshot 패키지 목록, q/target_id/page_size/cursor.
- `POST /api/v2/projects/{id}/targets/{target_id}/snapshots`: JSON dependencies 배열 또는 이를 포함한 snapshot.
- `POST /api/v2/projects/{id}/targets/{target_id}/credentials`: 대상별 CI/CD push 토큰. 발급 시 한 번만 반환.
- `GET /api/v2/projects/{id}/environment-candidates`: 제공된 CPE 제품과 일치하는 NVD 검토 후보. 버전·구성 적용 여부를 확정하지 않으며 외부 알림에 자동 포함하지 않는다.

기존 서비스는 자동 이동하지 않는다. 관리자는 `GET /api/v2/admin/unassigned-targets`와 `POST /api/v2/admin/assign-target`로 소유 프로젝트에 연결할 수 있다. 연결은 새 테이블의 관계를 추가하며 기존 서비스/snapshot/impact를 삭제하지 않는다.

실제 인벤토리 신선도는 조회 시점과 마지막 수신 확인 시각을 비교한다. 기본 prod 1시간, stage 24시간, dev 7일이며 서비스의 freshness_threshold_seconds를 우선한다. 수집 데이터가 오래된 영향은 현재 판단에 재확인이 필요하다고 표시한다.

## 영향, Overview, 알림

- `GET /api/v2/findings`: 권한 내 프로젝트의 영향 검색. project_id, q, risk, status, environment, page_size, cursor.
- `GET/PATCH /api/v2/findings/{id}`: 근거·수정 버전·상태 이력. accepted_risk는 관리자 승인 필요.
- `GET /api/v2/overview?project_id=...`: 내 전체/프로젝트별 KPI, 우선 영향, 프로젝트별 상태, 최근 수정된 보안 정보, 30일 추세, 5개 소스 신선도.
- `GET/PATCH /api/v2/projects/{id}/alert-rules`: owner가 enabled, minimum_risk, channel_type, target_url 설정.
- `GET /api/v2/alert-events?project_id=...`: 권한 내 프로젝트 알림의 전송/실패/재시도 이력.

프로젝트 alert는 프로젝트 규칙의 HTTPS 목적지에만 전송한다. 채널이 없거나 꺼져 있거나 위험도 기준 미만이면 외부 발송하지 않고 outbox 기록을 보존한다. 전역 채널로 fallback하지 않는다. 프로젝트 worker의 `project_only` 모드는 미연결 기존 알림을 전송하지 않는다. 재시도·중복 억제는 기존 outbox 경로를 재사용한다. 주요 변경은 인증 주체와 경로를 audit log에 남기며 비밀번호/토큰/요청 본문을 audit에 저장하지 않는다.

## 배포/복구

Migration 020은 users/sessions/setup tokens/projects/memberships/target links/project alert rules와 검색 인덱스를 추가한다. 기존 테이블 행을 삭제하거나 프로젝트에 자동 할당하지 않는다. 배포 전 SQLite backup API로 일관된 DB 복사본을 만들고 quick_check, 테이블 건수를 확인한다. 배포 전 코드, `.env`, 사용자 systemd 구성도 release backup에 보관한다.

새 타이머:

- `sca-monitor-source-sync.timer`: 소스 수집을 순차 실행. 완료 후 6시간 뒤 재실행. 진행 상태는 `.data/source-sync-progress.json`.
- `sca-monitor-project-worker.timer`: 대상 polling과 설정된 프로젝트 알림을 5분 간격으로 처리.
- 기존 source별 타이머는 중복 실행하지 않는다. ZIP 최신 10개 보관 정책은 유지한다.

복구는 새 두 타이머/API 중지 → 저장한 코드·환경 복구 → 필요 시 검증된 DB backup을 별도 경로로 복원하여 검증 → DB 경로 전환 → API 재시작 순서로 한다. 배포 후 새 프로젝트 데이터가 생긴 DB를 과거 백업으로 덮어쓰지 않는다. 읽기/호환성 문제라면 먼저 코드만 되돌리고 추가 테이블을 보존한다.
