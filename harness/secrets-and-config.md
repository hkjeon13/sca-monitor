# Secrets and Configuration

이 문서는 SCA Monitor 배포에 필요한 환경 변수와 secret 관리 기준을 정의한다.

## 1. 원칙

- secret은 git에 저장하지 않는다.
- endpoint credential은 평문 저장하지 않는다.
- push token은 hash만 저장한다.
- API key는 secret manager 또는 CI/CD secret store에서 주입한다.
- 환경별 config는 분리한다.

## 2. Required Environment Variables

### Common

```text
APP_ENV
LOG_LEVEL
FRONTEND_PUBLIC_URL
API_BASE_URL
SCA_MONITOR_DATABASE_URL
API_DATABASE_URL
WORKER_DATABASE_URL
ENCRYPTION_KEY_REF
```

현재 MVP는 `SCA_MONITOR_DATABASE_URL`을 우선 사용한다.
이 값이 없으면 API runtime은 `API_DATABASE_URL`, worker/scheduler runtime은 `WORKER_DATABASE_URL`을 우선 사용한다.
PostgreSQL 전환 전 임시값은 SQLite URL이다.

```text
SCA_MONITOR_DATABASE_URL=sqlite:////data/psyche/Projects/sca-monitor/.data/sca-monitor.sqlite3
# PostgreSQL 계정 분리 시에는 SCA_MONITOR_DATABASE_URL을 비우고 아래 값을 사용한다.
API_DATABASE_URL=postgresql://sca_api:...
WORKER_DATABASE_URL=postgresql://sca_worker:...
```

`SCA_MONITOR_DB`는 이전 MVP 호환용 path 설정으로만 유지한다.

### API Server

```text
SCA_MONITOR_AUTH_MODE
SESSION_SECRET or JWT_SECRET
OIDC_AUTHORITY
OIDC_CLIENT_ID
OIDC_CLIENT_SECRET
OIDC_REDIRECT_URI
CORS_ALLOWED_ORIGINS
SCA_MONITOR_MAX_SNAPSHOT_PAYLOAD_BYTES
SCA_MONITOR_MAX_SNAPSHOT_DEPENDENCIES
SCA_MONITOR_MAX_SNAPSHOT_PUSHES_PER_MINUTE
SCA_MONITOR_POSTGRES_INTEGRATION_SMOKE
```

`CORS_ALLOWED_ORIGINS`는 frontend와 API가 split domain일 때만 필수이다.

현재 구현된 API 인가 첫 단계는 `SCA_MONITOR_AUTH_MODE=header`이다.
이 모드에서는 신뢰된 reverse proxy 또는 gateway가 다음 헤더를 주입해야 한다.

```text
X-SCA-Principal: user@example.com
X-SCA-Roles: admin,service-owner,security-approver
X-SCA-Owner-Teams: platform-security,billing
```

`SCA_MONITOR_AUTH_MODE` 기본값은 `disabled`이며, 운영에서 `header`를 사용할 경우 public 인터넷에서 클라이언트가 임의 헤더를 직접 주입할 수 없도록 proxy에서 외부 입력 헤더를 제거하고 인증 후 재주입해야 한다.

Snapshot push 보호 기본값:

```text
SCA_MONITOR_MAX_SNAPSHOT_PAYLOAD_BYTES=10485760
SCA_MONITOR_MAX_SNAPSHOT_DEPENDENCIES=10000
SCA_MONITOR_MAX_SNAPSHOT_PUSHES_PER_MINUTE=30
```

운영 환경에서 service dependency 규모가 더 크거나 CI/CD fan-out이 큰 경우 먼저 stage에서 push smoke와 rate-limit 동작을 통과시킨 뒤 상향한다.

PostgreSQL integration smoke gate:

```text
SCA_MONITOR_POSTGRES_INTEGRATION_SMOKE=auto
```

`auto`는 PostgreSQL DB URL일 때만 integration smoke를 실행한다.
`required`는 DB URL 종류와 관계없이 실행을 강제하며, `disabled`는 임시 비활성화에만 사용한다.
`WORKER_DATABASE_URL`이 별도로 설정되고 `SCA_MONITOR_DATABASE_URL`이 비어 있으면 `deploy_db_gate.sh`는 API DB smoke 이후 worker DB read-only smoke를 추가 실행한다.

### Worker

```text
WORKER_ROLE
OSV_SYNC_ENABLED
CISA_KEV_SYNC_ENABLED
GITHUB_ADVISORY_SYNC_ENABLED
NVD_SYNC_ENABLED
ALERT_DISPATCH_ENABLED
```

### External Sources

```text
GITHUB_TOKEN
NVD_API_KEY
```

`GITHUB_TOKEN`과 `NVD_API_KEY`는 해당 source sync를 활성화할 때 필요하다.

### Alerting

```text
SLACK_BOT_TOKEN
SLACK_WEBHOOK_URL
DEFAULT_ALERT_CHANNEL
SCA_MONITOR_DEFAULT_ALERT_CHANNEL_NAME
SCA_MONITOR_DEFAULT_ALERT_WEBHOOK_URL
DEFAULT_DAILY_DIGEST_CHANNEL
```

Slack app 방식을 선택하면 `SLACK_BOT_TOKEN`을 사용하고, incoming webhook 방식을 선택하면 `SLACK_WEBHOOK_URL`을 사용한다.
배포 bootstrap 자동화는 `SCA_MONITOR_DEFAULT_ALERT_WEBHOOK_URL`을 우선 사용해 `scripts/seed_default_alert_channel.py`로 기본 webhook channel을 생성 또는 갱신한다.
이 값은 secret으로 취급하며 git, 로그, 문서 예시에 실제 token path를 남기지 않는다.

### Frontend

```text
FRONTEND_PUBLIC_URL
API_BASE_URL
OIDC_AUTHORITY
OIDC_CLIENT_ID
OIDC_REDIRECT_URI
```

### Smoke Test

```text
SMOKE_TEST_TOKEN
SMOKE_TEST_SYNTHETIC_SERVICE_ID
SMOKE_TEST_PUSH_TOKEN
```

Smoke token은 최소 권한 machine credential이어야 하며 환경별로 분리한다.

### Observability

```text
METRICS_EXPORTER_ENABLED
METRICS_ENDPOINT_PATH
LOG_EXPORTER_ENDPOINT
ERROR_TRACKING_DSN
SYSTEM_ALERT_CHANNEL
```

## 3. REQUIRED Decisions

| ID | 항목 |
|---|---|
| REQ-SEC-001 | secret manager 종류 |
| REQ-SEC-002 | DB credential rotation 방식 |
| REQ-SEC-003 | push credential 만료 기본값 |
| REQ-SEC-004 | endpoint polling token 저장/암호화 방식 |
| REQ-SEC-005 | OIDC/SSO provider |
| REQ-SEC-006 | API/worker DB 계정 분리 여부 |
| REQ-SEC-007 | smoke test token rotation 주기 |
