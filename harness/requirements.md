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
| REQ-AUTH-002 | 역할 모델 | ASSUMED | `admin`, `service-owner`, `security-approver`, `viewer` |
| REQ-AUTH-003 | 서비스 owner 매핑 | REQUIRED | team/user 정보를 어디서 가져올지 결정 |
| REQ-AUTH-004 | push credential 발급 | PARTIAL | API/UI 발급, revoke, service/environment 바인딩 검증은 구현됨. CI/CD secret 주입과 rotation 운영 방식 결정 필요 |
| REQ-AUTH-005 | endpoint polling 인증 | PARTIAL | endpoint test API/UI와 schema 검증은 구현됨. bearer token, mTLS, HMAC 중 운영 인증 범위와 저장 방식 결정 필요 |

## 4. 외부 데이터 소스 요구사항

| ID | 항목 | 상태 | 필요 결정 |
|---|---|---|---|
| REQ-DEP-SRC-001 | OSV 데이터 수집 | ASSUMED | OSV feed-sync 기본, `querybatch` 보조 |
| REQ-DEP-SRC-002 | CISA KEV 수집 | ASSUMED | JSON/CSV catalog 주기 동기화 |
| REQ-DEP-SRC-003 | GitHub Advisory API | REQUIRED | GitHub API token 사용 여부와 rate limit 정책 |
| REQ-DEP-SRC-004 | NVD API | REQUIRED | NVD API key 사용 여부 |
| REQ-DEP-SRC-005 | OpenSSF malicious packages | ASSUMED | GitHub repository 또는 OSV `MAL-*` record 수집 |
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
| REQ-ALERT-001 | Slack workspace | REQUIRED | Slack app/webhook 방식 |
| REQ-ALERT-002 | webhook 대상 | REQUIRED | 사내 alert router, Jira, Teams 등 |
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
| REQ-AUTO-004 | smoke test endpoint | ASSUMED | `/health`, `/ready`, `/api/v1/overview` |
| REQ-AUTO-005 | release artifact | REQUIRED | container image tag, frontend build artifact, migration bundle |
| REQ-AUTO-006 | smoke 자격증명 | REQUIRED | 환경별 `SMOKE_TEST_TOKEN`과 synthetic service credential 발급 방식 |
| REQ-AUTO-007 | bootstrap owner | REQUIRED | 최초 admin, default SLA, default alert channel seed 책임자 |
