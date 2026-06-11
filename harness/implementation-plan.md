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
- `scripts/migrate.py` 추가
- `/ready` migration 상태 노출 추가
- SQLite fallback 유지
- OSV 단건 import API와 advisory 조회 API 추가
- OSV affected range version matcher 추가
- `scripts/osv_sync.py` OSV ecosystem dump sync worker CLI 추가

남은 작업:

- PostgreSQL driver dependency 선택 및 설치
- repository/query adapter 분리
- 실제 PostgreSQL integration test
- API/worker DB 계정 분리
- production migration tool 확정
- OSV dump sync scheduler와 source별 worker lease
- advisory 변경 감지 후 latest snapshot 재매칭
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

검증:

- role-aware UI test
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
