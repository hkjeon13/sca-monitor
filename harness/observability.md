# Observability

이 문서는 SCA Monitor의 metrics, logs, error tracking, system alert 기준을 정의한다.

## 1. REQUIRED Decisions

| ID | 항목 |
|---|---|
| REQ-OBS-001 | metrics 수집 스택 |
| REQ-OBS-002 | 로그 수집/보관 |
| REQ-OBS-003 | 시스템 자체 장애 운영 alert 채널 |
| REQ-OBS-004 | frontend error tracking |

## 2. Metrics Endpoint

API Server와 worker는 다음 중 하나의 방식으로 metrics를 노출한다.

```text
GET /metrics
```

또는 선택한 cloud monitoring agent/exporter를 사용한다.

## 3. 필수 Metrics

| Metric | 설명 |
|---|---|
| sca_monitor_advisory_sync_lag_seconds | source별 마지막 성공 동기화 이후 경과 |
| sca_monitor_endpoint_poll_success_rate | 등록 endpoint polling 성공률 |
| new_advisory_to_alert_latency_seconds | 신규 advisory 수집부터 alert 발송까지 지연 |
| sca_monitor_alert_delivery_success_rate | alert 발송 성공률 |
| sca_monitor_alert_outbox_pending_count | pending alert outbox 수 |
| sca_monitor_critical_impacts | open Critical impact 수 |
| sca_monitor_stale_services | freshness 기준 초과 서비스 수 |
| worker_lease_acquire_failures | worker lease 획득 실패 수 |

현재 MVP `/metrics`는 `sca_monitor_services`, `sca_monitor_open_impacts`, `sca_monitor_critical_impacts`, `sca_monitor_high_impacts`, `sca_monitor_endpoint_unhealthy`, `sca_monitor_advisory_sync_lag_seconds`, `sca_monitor_endpoint_poll_success_rate`, `sca_monitor_alert_delivery_success_rate`, `sca_monitor_alert_outbox_pending_count`, `sca_monitor_stale_services`를 노출한다.
`new_advisory_to_alert_latency_seconds`와 `worker_lease_acquire_failures`는 별도 event timestamp/lease failure counter가 필요하므로 후속 구현 대상이다.

## 4. Logs

로그는 다음 필드를 포함한다.

```text
timestamp
level
component
environment
request_id
trace_id
service_id
job_id
error_code
message
```

secret, token, endpoint credential, private registry credential은 로그에 남기지 않는다.

## 5. System Alerts

제품 alert과 시스템 자체 장애 alert은 분리한다.

시스템 alert 대상:

- advisory sync lag 임계값 초과
- worker down
- alert outbox pending 급증
- DB connection failure
- endpoint polling success rate 급락
- frontend error rate 급증

## 6. Frontend Error Tracking

Web Console은 frontend error tracking을 선택적으로 연동한다.

필수 context:

- app version
- environment
- route
- user role
- request_id

사용자 개인정보와 secret은 전송하지 않는다.
