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
API_DATABASE_URL
WORKER_DATABASE_URL
ENCRYPTION_KEY_REF
```

### API Server

```text
SESSION_SECRET or JWT_SECRET
OIDC_AUTHORITY
OIDC_CLIENT_ID
OIDC_CLIENT_SECRET
OIDC_REDIRECT_URI
CORS_ALLOWED_ORIGINS
```

`CORS_ALLOWED_ORIGINS`는 frontend와 API가 split domain일 때만 필수이다.

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
DEFAULT_DAILY_DIGEST_CHANNEL
```

Slack app 방식을 선택하면 `SLACK_BOT_TOKEN`을 사용하고, incoming webhook 방식을 선택하면 `SLACK_WEBHOOK_URL`을 사용한다.

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
