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
| advisory_sync_lag_seconds | source별 마지막 성공 동기화 이후 경과 |
| endpoint_poll_success_rate | 등록 endpoint polling 성공률 |
| new_advisory_to_alert_latency | 신규 advisory 수집부터 alert 발송까지 지연 |
| alert_delivery_success_rate | alert 발송 성공률 |
| open_critical_impacts | open Critical impact 수 |
| stale_services | freshness 기준 초과 서비스 수 |
| alert_outbox_pending_count | pending alert outbox 수 |

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
2. auth_failed와 unreachable 구분
3. 서비스 owner에게 설정 확인 요청
4. egress IP allowlist 확인
5. mTLS/HMAC clock skew 확인

### Alert delivery failed

1. alert_events failed row 확인
2. Slack/webhook credential 확인
3. target channel 권한 확인
4. 재시도
5. alternative channel escalation

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
