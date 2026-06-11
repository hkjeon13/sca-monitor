# Backend Deployment

이 문서는 API Server와 worker의 배포 기준을 정의한다.

## 1. Backend 구성

| 프로세스 | 책임 |
|---|---|
| API Server | service, endpoint, snapshot push, impact workflow, overview API |
| Snapshot Worker | endpoint polling, schema validation, snapshot normalization |
| Advisory Worker | OSV/CISA/GHSA/NVD/OpenSSF 동기화 |
| Matching Worker | latest snapshot 기준 impact matching, risk scoring |
| Alert Worker | alert outbox dispatch, Slack/webhook 발송 |
| SLA/Digest Worker | SLA escalation, Daily Digest |

초기 구현에서는 worker를 하나의 worker image로 묶고 command 또는 queue type으로 역할을 분리할 수 있다.

## 2. 배포 순서

1. image pull
2. environment variable validation
3. database connectivity check
4. migration 실행
5. API Server 배포
6. Worker 배포
7. `/health`, `/ready` 확인
8. smoke test 실행

## 3. Health Check

API Server:

```text
GET /health
GET /ready
GET /metrics
```

`/ready`는 다음을 확인한다.

- DB 연결
- 현재 코드가 요구하는 최소 migration version 이상인지 여부
- required config 존재 여부

`/ready`는 "DB가 최신 migration version과 정확히 동일한지"를 검사하지 않는다.
rolling deployment와 image-only rollback 중 구버전 인스턴스가 새 schema 위에서 계속 동작해야 하기 때문이다.

현재 MVP에서는 `/ready`가 다음 정보를 노출한다.

```json
{
  "status": "ready",
  "database": "ok",
  "database_backend": "sqlite",
  "migration": {
    "current": 1,
    "required": 1,
    "minimum_supported": 1,
    "compatible": true
  }
}
```

Worker:

```text
worker health command
```

확인 항목:

- DB 연결
- advisory_sync_state 접근
- alert_events pending 조회
- lease 획득 가능 여부
- metrics exporter 동작 여부

## 4. Deployment Stop Rules

다음 조건이면 배포를 중단한다.

- required env var 누락
- DB migration 실패
- API `/ready` 실패
- frontend가 참조하는 API base URL 불일치
- smoke test 실패

## 5. Rollback

Rollback 기준:

- API readiness 실패
- 주요 endpoint 5xx 증가
- worker가 pending alert를 처리하지 못함
- migration 후 query 실패

Rollback 방식:

1. 이전 backend/worker image로 되돌림
2. DB는 기본적으로 rollback하지 않음
3. health check 재실행
4. smoke test 재실행

DB migration rollback은 자동화 대상이 아니다.
데이터 손실 가능성이 있으므로 운영자 승인, backup 확인, 영향 분석 후 수동으로만 수행한다.
기본 대응은 expand/contract 호환성을 전제로 한 image-only rollback 또는 forward fix이다.

## 6. Worker Concurrency Rules

| Worker role | Replica 정책 | 동시성 제어 |
|---|---|---|
| Snapshot Poll Scheduler | single-active 권장 | DB lease 또는 advisory lock |
| Snapshot Poll Worker | multi-replica 가능 | job row `FOR UPDATE SKIP LOCKED` |
| Advisory Sync Worker | source별 single-active | source별 sync lock |
| Matching Worker | multi-replica 가능 | snapshot/advisory job lock |
| Alert Dispatcher | multi-replica 가능 | `alert_events` pending row `FOR UPDATE SKIP LOCKED` |
| SLA/Digest Worker | single-active 권장 | schedule lock |

Graceful shutdown:

```text
SIGTERM 수신
새 job lease 획득 중단
처리 중 job 최대 30초 대기
완료하지 못한 job은 lease timeout 후 다른 worker가 재처리
```

Alert dispatch는 at-least-once를 전제로 한다.
외부 채널이 idempotency key를 지원하면 `alert_suppression_key`를 함께 전달한다.
지원하지 않으면 `alert_events` 상태 전이를 이용해 중복 가능성을 최소화하고, 재발송 가능성을 운영 로그에 남긴다.
