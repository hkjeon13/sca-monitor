# Deployment and Implementation Requirements

이 문서는 SCA Monitor 실제 개발과 배포 자동화를 시작하기 전에 확정해야 할 요구사항을 정리한다.

상태 값:

| 상태 | 의미 |
|---|---|
| REQUIRED | 사용자가 확정해야 함 |
| ASSUMED | 문서 작성을 위해 임시 가정 |
| CONFIRMED | 확정됨 |

## 1. 배포 환경 요구사항

| ID | 항목 | 상태 | 필요 결정 |
|---|---|---|---|
| REQ-ENV-001 | 배포 대상 | REQUIRED | 컨테이너 사용을 기본 가정하고 Docker Compose, Kubernetes, managed PaaS 중 orchestration 방식 선택 |
| REQ-ENV-002 | 운영 도메인 | REQUIRED | Web Console HTTPS 주소. 예: `https://sca.example.com` |
| REQ-ENV-003 | API 도메인 | REQUIRED | API 주소. 예: `https://api.sca.example.com` 또는 Web Console과 동일 도메인 `/api` |
| REQ-ENV-004 | TLS 인증서 | REQUIRED | managed certificate, Let's Encrypt, 사내 인증서 중 선택 |
| REQ-ENV-005 | 배포 환경 구분 | REQUIRED | `dev`, `stage`, `prod` 운영 여부 |
| REQ-ENV-006 | 컨테이너 registry | REQUIRED | image push/pull registry 주소와 인증 방식 |
| REQ-ENV-007 | 서버 OS/runtime | ASSUMED | Linux x86_64, container runtime 사용 |

## 2. 네트워크 요구사항

| ID | 항목 | 상태 | 필요 결정 |
|---|---|---|---|
| REQ-NET-001 | Backend inbound HTTPS | REQUIRED | API 서버 외부 노출 여부와 443 ingress 허용 |
| REQ-NET-002 | Frontend inbound HTTPS | REQUIRED | Web Console 443 ingress 허용 |
| REQ-NET-003 | Service endpoint 접근 | REQUIRED | 중앙 서버가 등록 서비스의 dependency status endpoint에 접근 가능한 네트워크 경로 |
| REQ-NET-004 | 중앙 서버 egress IP | REQUIRED | 서비스 endpoint allowlist에 등록할 고정 egress IP |
| REQ-NET-005 | PostgreSQL 접근 | REQUIRED | API/worker만 DB 접근 가능하도록 private network 구성 |
| REQ-NET-006 | 외부 advisory source outbound | REQUIRED | OSV, GitHub, NVD, CISA, OpenSSF 접근 허용 |
| REQ-NET-007 | Slack/Webhook outbound | REQUIRED | Slack 또는 webhook endpoint 접근 허용 |

## 3. 인증/인가 요구사항

| ID | 항목 | 상태 | 필요 결정 |
|---|---|---|---|
| REQ-AUTH-001 | Web Console 로그인 | REQUIRED | OIDC, SSO, basic auth, 사내 인증 프록시 중 선택 |
| REQ-AUTH-002 | 역할 모델 | PARTIAL | `admin`, `service-owner`, `security-approver`, `viewer`. `SCA_MONITOR_AUTH_MODE=header`에서는 `X-SCA-Principal`, `X-SCA-Roles`, `X-SCA-Owner-Teams`를 인증 프록시가 주입해야 하며, `SCA_MONITOR_AUTH_PROXY_SHARED_SECRET`이 설정된 경우 `X-SCA-Proxy-Secret` 일치도 요구한다. Web Console은 `/api/v1/session` capability로 action을 제어한다 |
| REQ-AUTH-003 | 서비스 owner 매핑 | REQUIRED | team/user 정보를 어디서 가져올지 결정 |
| REQ-AUTH-004 | push credential 발급 | PARTIAL | API/UI 발급, rotate, revoke, service/environment 바인딩 검증은 구현됨. CI/CD secret 주입 방식과 조직별 rotation 주기 결정 필요 |
| REQ-AUTH-005 | endpoint polling 인증 | PARTIAL | endpoint test API/UI, schema 검증, polling worker, DB lease 기반 중복 실행 방지, bearer token 전달은 구현됨. mTLS/HMAC 지원 범위와 secret manager/KMS 연동 방식 결정 필요 |

## 4. 외부 데이터 소스 요구사항

| ID | 항목 | 상태 | 필요 결정 |
|---|---|---|---|
| REQ-DEP-SRC-001 | OSV 데이터 수집 | ASSUMED | OSV feed-sync 기본, `querybatch` 보조 |
| REQ-DEP-SRC-002 | CISA KEV 수집 | ASSUMED | JSON/CSV catalog 주기 동기화 |
| REQ-DEP-SRC-003 | GitHub Advisory API | REQUIRED | GitHub API token 사용 여부와 rate limit 정책 |
| REQ-DEP-SRC-004 | NVD API | REQUIRED | NVD API key 사용 여부 |
| REQ-DEP-SRC-005 | OpenSSF malicious packages | PARTIAL | OSV-format `MAL-*` record를 `scripts/osv_sync.py --source OpenSSF --malicious-only`로 수집하는 경로는 구현됨. GitHub repository mirror 직접 수집 여부는 결정 필요 |
| REQ-DEP-SRC-006 | 상용 threat intelligence | REQUIRED | Snyk, Mend, Socket, Checkmarx 등 사용 여부 |

## 5. 데이터베이스 요구사항

| ID | 항목 | 상태 | 필요 결정 |
|---|---|---|---|
| REQ-DB-001 | PostgreSQL 배포 방식 | REQUIRED | managed PostgreSQL, self-hosted container, VM package 중 선택 |
| REQ-DB-002 | PostgreSQL version | ASSUMED | PostgreSQL 16 이상 |
| REQ-DB-003 | backup | REQUIRED | backup 주기, 보존 기간, 복구 테스트 방식 |
| REQ-DB-004 | migration tool | REQUIRED | Alembic, Prisma, Flyway, Liquibase 등 선택 |
| REQ-DB-005 | retention | ASSUMED | 설계서 13.4 기준 |

## 6. Frontend 요구사항

| ID | 항목 | 상태 | 필요 결정 |
|---|---|---|---|
| REQ-FE-001 | Web Console URL | REQUIRED | 실제 HTTPS 주소 |
| REQ-FE-002 | API base URL | REQUIRED | same-origin `/api` 또는 별도 API domain |
| REQ-FE-003 | 인증 연동 | REQUIRED | OIDC redirect URL, cookie/session/JWT 방식 |
| REQ-FE-004 | 정적 자산 배포 | REQUIRED | CDN, reverse proxy, object storage, container serving 중 선택 |
| REQ-FE-005 | 모바일 지원 범위 | ASSUMED | dashboard, impact detail, 기본 상태 변경 |

## 7. 알림 요구사항

| ID | 항목 | 상태 | 필요 결정 |
|---|---|---|---|
| REQ-ALERT-001 | Slack workspace | REQUIRED | webhook 방식 기본 channel 등록/API/UI는 구현됨. Slack app 방식은 후속 결정 필요 |
| REQ-ALERT-002 | webhook 대상 | PARTIAL | 기본 webhook channel 등록과 dispatcher 기본 target 사용은 구현됨. 운영 alert router/Jira/Teams 실제 URL과 secret 보관 방식 결정 필요 |
| REQ-ALERT-003 | Daily Digest 채널 | REQUIRED | 팀별 digest 또는 중앙 digest |
| REQ-ALERT-004 | escalation 채널 | REQUIRED | SLA 초과 시 순차 알림 대상 |
| REQ-ALERT-005 | Daily Digest 시각 | REQUIRED | 발송 시각과 timezone. 예: 매일 09:00 Asia/Seoul |
| REQ-ALERT-006 | SLA calendar | REQUIRED | SLA 계산에 영업일/휴일을 반영할지 결정 |

## 8. 관측성 요구사항

| ID | 항목 | 상태 | 필요 결정 |
|---|---|---|---|
| REQ-OBS-001 | metrics 수집 스택 | REQUIRED | Prometheus/Grafana, Cloud Monitoring, Datadog 등 선택 |
| REQ-OBS-002 | 로그 수집/보관 | REQUIRED | 로그 backend와 보관 기간 결정 |
| REQ-OBS-003 | 시스템 자체 장애 alert 채널 | REQUIRED | 제품 alert과 분리된 운영 alert 채널 결정 |
| REQ-OBS-004 | frontend error tracking | REQUIRED | Sentry 등 사용 여부와 DSN 결정 |

## 9. 자동화 요구사항

| ID | 항목 | 상태 | 필요 결정 |
|---|---|---|---|
| REQ-AUTO-001 | CI/CD 시스템 | REQUIRED | GitHub Actions, Jenkins, GitLab CI, Harness, Argo CD 등 선택 |
| REQ-AUTO-002 | 배포 승인 | REQUIRED | main push 자동 배포, tag 배포, 수동 승인 중 선택 |
| REQ-AUTO-003 | rollback 방식 | REQUIRED | 이전 image tag rollback, DB migration rollback 정책 |
| REQ-AUTO-004 | smoke test endpoint | ASSUMED | `/health`, `/ready`, `/api/v1/overview`, `/api/v1/operations/cutover-readiness-report` |
| REQ-AUTO-005 | release artifact | REQUIRED | container image tag, frontend build artifact, migration bundle |
| REQ-AUTO-006 | smoke 자격증명 | REQUIRED | 환경별 `SMOKE_TEST_TOKEN`과 synthetic service credential 발급 방식 |
| REQ-AUTO-007 | bootstrap owner | REQUIRED | 최초 admin, default SLA, default alert channel seed 책임자 |
