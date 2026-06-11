# Operations Runbook

이 문서는 배포 후 운영 검증과 장애 대응 절차를 정의한다.

## 1. 배포 후 검증

배포 직후 확인:

1. API `/health` 200
2. API `/ready` 200
3. Web Console HTTPS 접근 가능
4. Overview API 정상
5. DB가 현재 배포 코드의 최소 required migration version 이상
6. worker process running
7. advisory sync state 갱신
8. alert outbox pending 처리 가능
9. metrics 수집 정상
10. system alert channel 수신 가능

## 2. 주요 운영 지표

| 지표 | 설명 |
|---|---|
| sca_monitor_advisory_sync_lag_seconds | source별 마지막 성공 동기화 이후 경과 |
| sca_monitor_endpoint_poll_success_rate | 등록 endpoint polling 성공률 |
| new_advisory_to_alert_latency | 신규 advisory 수집부터 alert 발송까지 지연 |
| sca_monitor_alert_delivery_success_rate | alert 발송 성공률 |
| sca_monitor_critical_impacts | open Critical impact 수 |
| sca_monitor_stale_services | freshness 기준 초과 서비스 수 |
| sca_monitor_alert_outbox_pending_count | pending alert outbox 수 |
| sca_monitor_alert_dead_letter_count | dead-letter alert 수 |

## 3. 장애 대응

### API down

1. load balancer health 확인
2. API container/process 상태 확인
3. DB 연결 확인
4. 최근 배포 확인
5. rollback 또는 재시작

### Worker stopped

1. worker process 상태 확인
2. DB lock/lease 확인
3. pending alert count 확인
4. worker 재시작
5. outbox 재처리 확인

### Advisory sync failed

1. source별 last_error 확인
2. rate limit 여부 확인
3. API key/credential 확인
4. 수동 재시도
5. 실패 지속 시 운영 alert

OSV 수동 재시도 예시:

```bash
python3 scripts/osv_sync.py --ecosystem npm --limit 100 --lock-ttl-seconds 3600
```

운영에서 `--limit` 없이 전체 dump를 실행하기 전에는 dump 크기, 디스크 여유 공간, 실행 시간, worker 중복 실행 여부를 먼저 확인한다.
중복 실행은 `advisory_sync_state.lock_owner`, `lock_expires_at` 기준으로 차단된다.
테스트 또는 폐쇄망 검증에는 `--zip-path /path/to/osv-fixture.zip`을 사용할 수 있다.

### Endpoint polling failed

1. endpoint_health 확인
2. `endpoint_poll_state`에서 `status`, `lock_owner`, `lock_expires_at`, 실패 count 확인
3. auth_failed와 unreachable 구분
4. 서비스 owner에게 설정 확인 요청
5. egress IP allowlist 확인
6. mTLS/HMAC clock skew 확인

bearer token endpoint는 서비스 등록 값의 `status_auth_type=bearer_token` 설정 여부를 먼저 확인한다.
서비스 조회 API는 token 원문을 반환하지 않고 `status_auth_configured`만 표시한다.

수동 1회 polling:

```bash
python3 scripts/poll_endpoints.py --limit 50 --worker-name default --lock-owner manual-$(hostname)
```

간단한 반복 실행:

```bash
python3 scripts/poll_endpoints.py --limit 50 --iterations 0 --interval-seconds 300 --lock-ttl-seconds 240
```

### Alert delivery failed

1. alert_events failed row 확인
2. Slack/webhook credential 확인
3. target channel 권한 확인
4. 재시도
5. alternative channel escalation

Alert outbox 확인:

```bash
python3 scripts/dispatch_alerts.py --dry-run --limit 50
```

Webhook 수동 발송:

```bash
ALERT_WEBHOOK_URL=https://alert-router.example/webhook python3 scripts/dispatch_alerts.py --limit 50 --retry-backoff-seconds 300
```

기본 alert channel을 등록한 경우 `ALERT_WEBHOOK_URL` 없이 실행할 수 있다.

```bash
python3 scripts/dispatch_alerts.py --limit 50 --retry-backoff-seconds 300
```

기본 channel이 잘못된 경우 Settings 화면에서 다른 channel을 default로 전환하거나 disable한다.

반복 실행:

```bash
ALERT_WEBHOOK_URL=https://alert-router.example/webhook python3 scripts/dispatch_alerts.py --limit 50 --iterations 0 --interval-seconds 30 --retry-backoff-seconds 300 --max-retries 5
```

현재 MVP dispatcher는 webhook JSON 발송, 재시도 backoff, per-alert dispatch lock, 반복 실행 옵션을 지원한다.
webhook 발송 시 idempotency header를 포함하고, max retry 초과 alert는 `dead_letter` 상태로 격리한다.

Dead-letter 재처리:

```bash
python3 scripts/requeue_alerts.py --all --limit 20 --actor operator --reason "webhook target recovered"
python3 scripts/requeue_alerts.py --alert-event-id <alert_event_id> --actor operator --reason "manual retry"
```

Slack app 방식과 dead-letter bulk UI는 후속 구현 대상이다.

## 4. 운영자 수동 작업

| 작업 | 위치 |
|---|---|
| 서비스 등록 | Web Console Services |
| endpoint test | Service Registration Wizard |
| push credential 발급 | Service Detail 또는 Settings |
| impact acknowledge | Impact Detail |
| accepted risk 승인 | Impact Detail, security-approver 권한 |
| alert channel 변경 | Settings |

## 5. 신규 환경 Bootstrap

신규 환경 최초 기동은 `harness/bootstrap.md`를 따른다.
bootstrap 완료 전에는 advisory matching 결과를 완전한 운영 결과로 간주하지 않는다.

## 6. Incident 기록

장애 발생 시 다음 정보를 기록한다.

```text
incident_id
start_time
end_time
affected_components
customer_impact
root_cause
mitigation
follow_up_actions
related_deployment_version
```
