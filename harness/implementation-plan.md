# Implementation Plan

이 문서는 `docs/software-design-specification.md`를 기준으로 실제 구현 순서를 정의한다.

## 1. 구현 원칙

- SDS를 단일 기준 설계 문서로 사용한다.
- Platform 문서는 제품 개념과 운영 방향 참고용으로 사용한다.
- 기능은 backend, worker, database, frontend를 독립 배포 가능한 단위로 나눈다.
- external advisory source 연동은 mock connector와 fixture test를 먼저 만든 뒤 실제 API/feed를 연결한다.
- 모든 배포 가능한 기능은 health check와 smoke test를 함께 정의한다.

## 2. 권장 Repository 구조

```text
sca-monitor/
  backend/
    api/
    workers/
    domain/
    db/
    tests/
  frontend/
    src/
    tests/
  migrations/
  deploy/
    docker/
    compose/
    k8s/
  harness/
  docs/
```

실제 framework 선택 전까지 위 구조는 가이드이다.

## 3. 구현 단계

### Phase 0. 기술 스택 확정

Phase 0 착수 전 선행 조건:

- `docs/software-design-specification.md`가 design review의 Blocker/Major 적용사항을 반영한 최신 기준 문서여야 한다.
- `harness/requirements.md`의 REQUIRED 항목 중 배포 방식, 도메인, DB, 인증, CI/CD, 관측성 항목의 owner가 지정되어야 한다.
- `harness/bootstrap.md`의 cold-start 절차가 선택한 배포 환경에 맞게 검증되어야 한다.

결정 필요:

- backend framework
- frontend framework
- DB migration tool
- CI/CD 시스템
- 배포 방식
- 인증 방식
- 관측성 스택

산출물:

- `harness/requirements.md`의 REQUIRED 항목 업데이트
- local development runbook
- 첫 CI pipeline skeleton
- bootstrap dry-run checklist

### Phase 1. Database and Domain Model

구현 대상:

- PostgreSQL schema
- migration baseline
- service, endpoint, snapshot, advisory, impact, alert, audit table
- repository layer
- seed/test fixture

검증:

- migration up/down
- FK/unique constraint test
- impact identity unique test
- content hash dedup test

현재 진행 상태:

- `migrations/sqlite/001_initial.sql` baseline 추가
- `migrations/postgres/001_initial.sql` baseline 추가
- `migrations/sqlite/002_advisory_sync_state.sql` 추가
- `migrations/postgres/002_advisory_sync_state.sql` 추가
- `migrations/sqlite/003_advisory_affected_ranges.sql` 추가
- `migrations/postgres/003_advisory_affected_ranges.sql` 추가
- `migrations/sqlite/004_advisory_sync_lock.sql` 추가
- `migrations/postgres/004_advisory_sync_lock.sql` 추가
- `scripts/migrate.py` 추가
- `scripts/db_smoke.py` 기반 DB read/write rollback smoke gate 추가
- `scripts/postgres_integration_smoke.py` 기반 실제 PostgreSQL migration/db smoke/API workflow gate 추가
- `scripts/deploy_db_gate.sh` 기반 배포 시 PostgreSQL URL 자동 integration smoke gate 추가
- `API_DATABASE_URL`/`WORKER_DATABASE_URL` 기반 API/worker DB URL 분리와 worker read-only smoke gate 추가
- `SCA_MONITOR_AUTO_MIGRATE`/컴포넌트별 auto-migrate flag 기반 runtime migration 비활성화 지원
- `/ready` migration 상태 노출 추가
- SQLite fallback 유지
- `psycopg` 기반 PostgreSQL runtime query adapter 1차 추가
- OSV 단건 import API와 advisory 조회 API 추가
- OSV affected range version matcher 추가
- `scripts/osv_sync.py` OSV ecosystem dump sync worker CLI 추가
- `scripts/osv_sync.py --source OpenSSF --malicious-only` 기반 OSV-format `MAL-*` malicious package sync 추가
- `scripts/bootstrap_advisory_sync.py` 기반 OSV/CISA KEV/OpenSSF initial sync 순차 실행 gate 추가
- OSV source별 sync lock/TTL 추가
- advisory 변경 감지 후 관련 latest snapshot 재매칭 추가
- `scripts/dispatch_alerts.py` webhook alert outbox dispatcher CLI 추가
- alert 재시도/backoff와 per-alert dispatcher lock 추가

남은 작업:

- repository/query adapter 고도화
- stage PostgreSQL credential로 정기 integration test 실행
- API/worker DB 계정 분리
- production migration tool 확정
- OSV dump sync scheduler
- 재매칭 job queue와 대량 변경 batch 처리
- Slack app 방식, dead-letter 정책, idempotency header
- ecosystem별 정밀 version matcher와 pre-release 정책 보강

### Phase 2. API Server

구현 대상:

- service registration API
- endpoint test API
- snapshot push API
- impact workflow API
- overview API
- auth/role middleware

검증:

- API contract test
- push payload validation
- role-based authorization test
- `approved_by` server-side principal test

### Phase 3. Workers

구현 대상:

- endpoint polling worker
- snapshot normalization
- advisory feed-sync worker
- advisory canonicalization
- impact matcher
- risk scoring
- alert outbox dispatcher
- SLA/digest worker

검증:

- worker lease test
- retry/backoff test
- OSV fixture import test
- version matcher golden test
- outbox pending reprocessing test

### Phase 4. Web Console

구현 대상:

- Web Console shell/navigation
- overview dashboard
- service list/detail
- service registration wizard
- impact list/detail/action panel
- settings and integration guide

현재 MVP 구현 상태:

- 완료: shell/navigation, overview dashboard, service list/detail, basic service registration, endpoint test action, endpoint one-shot polling worker, push credential issue/rotate/revoke, integration guide, impact list, impact server-side filters, impact 고급 필터 UI, impact pagination/sorting, impact detail, impact status action panel, impact bulk action, header-auth impact/admin API 인가, Web Console role-aware UI 제어, alert channel settings, alert event operations, audit log, advisory detail, accepted risk 승인/만료 workflow
- 부분 완료: service registration wizard는 기본 등록, endpoint test, push credential 발급/회전/폐기 form을 제공하며 endpoint 인증 설정, polling scheduler, 조직별 credential rotation 주기 정책은 미구현
- 완료: impact filtering은 API와 Web Console에서 status/risk/service/team/environment/package/advisory/KEV/malicious/search와 pagination/sorting을 제공하며, 필터 결과에 대한 bulk status action을 지원한다
- 완료: push API hardening은 service/environment credential binding, payload size limit, dependency count limit, snapshot_id/content_hash 기반 멱등 replay, conflict 감지, `last_confirmed_at` 갱신, service credential 또는 service/environment 기준 분당 rate limit을 제공한다
- 부분 완료: role-aware API 인가는 `SCA_MONITOR_AUTH_MODE=header` impact workflow와 admin-only service registration, endpoint test, push credential, alert channel 설정 범위에서 동작한다. Web Console은 `GET /api/v1/session` capability 기반으로 역할별 action을 비활성화한다. OIDC/JWT 검증과 인증 프록시 연동은 미구현
- 부분 완료: 운영 scheduler 등록은 `scripts/install_systemd_units.sh` 기반 VM systemd unit/timer 생성과 `scripts/systemd_scheduler_status.py` read-only 검증까지 구현됨. SLA escalation, Daily Digest, OSV, OpenSSF malicious package, CISA KEV sync timer 정의 포함. 실제 운영 enable/start는 배포 환경별 승인 후 실행

검증:

- header-auth session capability test
- API integration mock test
- responsive smoke check for mobile width
- error/empty/loading state test

### Phase 5. Deployment Automation

구현 대상:

- container build
- frontend build
- DB migration job
- backend deploy
- worker deploy
- frontend deploy
- health/smoke test
- rollback script

검증:

- clean environment bootstrap
- redeploy idempotency
- failed migration stop rule
- failed smoke rollback rule

## 4. Definition of Done

각 phase는 다음 조건을 만족해야 완료로 본다.

- 코드와 문서가 함께 갱신됨
- 자동 테스트가 통과함
- 배포 절차가 재현 가능함
- 운영자가 확인할 health endpoint 또는 UI 화면이 있음
- rollback 또는 실패 중단 조건이 정의됨
