# CI/CD Automation

이 문서는 SCA Monitor 자동화 pipeline 기준을 정의한다.

## 1. Pipeline 목표

CI/CD는 다음을 자동화한다.

- lint
- unit test
- integration test
- frontend build
- backend build
- container image build
- database migration validation
- deployment
- health check
- smoke test
- rollback trigger

## 2. Pipeline Stages

```mermaid
flowchart LR
    A["Checkout"] --> B["Install Dependencies"]
    B --> C["Lint/Test"]
    C --> D["Build Backend Image"]
    C --> E["Build Frontend"]
    D --> F["Push Images"]
    E --> F
    F --> G["Run Expand-Compatible DB Migration"]
    G --> H["Deploy API"]
    H --> I["Deploy Workers"]
    I --> J["Deploy Frontend"]
    J --> K["Health Checks"]
    K --> L["Smoke Tests"]
    L --> M["Promote or Rollback"]
```

## 3. Required Checks

| 단계 | 실패 시 |
|---|---|
| lint/test 실패 | 배포 중단 |
| image build 실패 | 배포 중단 |
| migration 실패 | 배포 중단 |
| API readiness 실패 | rollback |
| worker health 실패 | rollback 또는 worker 이전 버전 유지 |
| frontend smoke 실패 | frontend rollback |
| smoke test 실패 | 배포 실패 처리 |

## 4. Release Inputs

필수 입력:

```text
GIT_SHA
VERSION
ENVIRONMENT
BACKEND_IMAGE
WORKER_IMAGE
FRONTEND_ARTIFACT_OR_IMAGE
MIGRATION_VERSION
```

## 5. Smoke Test Scenarios

Smoke test는 환경별 machine credential을 사용한다.
브라우저 기반 OIDC 로그인에 의존하지 않는다.

필요 secret:

```text
SMOKE_TEST_TOKEN
SMOKE_TEST_SYNTHETIC_SERVICE_ID
SMOKE_TEST_PUSH_TOKEN
```

```text
GET /health
GET /ready
python3 scripts/db_smoke.py --json
python3 scripts/postgres_integration_smoke.py --database-url "$SCA_MONITOR_DATABASE_URL" --with-api-workflow --json
SCA_MONITOR_SYSTEMD_MODE=validate bash scripts/deploy_systemd_gate.sh
GET /api/v1/overview
GET frontend /
GET frontend static asset
POST /api/v1/snapshots with test credential in stage
GET /api/v1/impacts
```

운영 환경에서는 destructive test를 실행하지 않는다.
prod smoke는 read-only와 synthetic service에 한정한다.

## 6. Rollback Automation

Rollback은 다음 단계를 자동화한다.

1. 이전 image tag 확인
2. API/worker 이전 image 배포
3. frontend 이전 artifact 배포
4. health check
5. smoke test
6. incident note 생성

DB migration rollback은 자동화하지 않는다.
expand/contract 원칙을 지킨 상태에서 image-only rollback을 기본으로 한다.
DB 되돌리기가 필요한 경우 운영자 수동 승인, backup 확인, 영향 분석 이후에만 수행한다.
rollback이 안전하지 않으면 forward fix로 전환한다.
