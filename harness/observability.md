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
| sca_monitor_advisory_sync_ready | 필수 advisory source initial sync 완료 여부 |
| sca_monitor_advisory_sync_initialized | source별 initial sync 완료 여부 |
| sca_monitor_advisory_sync_lag_seconds | source별 마지막 성공 동기화 이후 경과 |
| sca_monitor_advisory_sync_failed | source별 마지막 동기화 실패 여부 |
| sca_monitor_advisory_sync_last_error_age_seconds | source별 마지막 동기화 오류 이후 경과 |
| sca_monitor_endpoint_poll_success_rate | 등록 endpoint polling 성공률 |
| new_advisory_to_alert_latency_seconds | 신규 advisory 수집부터 alert 발송까지 지연 |
| sca_monitor_alert_delivery_success_rate | alert 발송 성공률 |
| sca_monitor_alert_outbox_pending_count | pending alert outbox 수 |
| sca_monitor_alert_dead_letter_count | dead-letter alert 수 |
| sca_monitor_critical_impacts | open Critical impact 수 |
| sca_monitor_stale_services | freshness 기준 초과 서비스 수 |
| sca_monitor_database_ready | DB readiness 통과 여부 |
| sca_monitor_database_backend_info | 현재 DB backend label |
| sca_monitor_migration_current_version | 현재 적용된 migration version |
| sca_monitor_migration_required_version | 코드가 요구하는 migration version |
| sca_monitor_migration_compatible | 현재 DB schema 호환 여부 |
| sca_monitor_postgres_configured | PostgreSQL URL 설정 여부 |
| sca_monitor_postgres_cutover_status | 현재 cutover mode/status label |
| sca_monitor_postgres_cutover_required_ready | require-postgres cutover ready 여부 |
| sca_monitor_postgres_cutover_blockers | require-postgres cutover blocking check 수 |
| sca_monitor_postgres_split_required | split credential cutover 강제 여부 |
| sca_monitor_postgres_split_ready | split credential cutover 준비 완료 여부 |
| sca_monitor_worker_lease_acquire_failures | worker lease 획득 실패 수 |

현재 MVP `/metrics`는 `sca_monitor_services`, `sca_monitor_open_impacts`, `sca_monitor_critical_impacts`, `sca_monitor_high_impacts`, `sca_monitor_endpoint_unhealthy`, `sca_monitor_advisory_sync_ready`, `sca_monitor_advisory_sync_initialized`, `sca_monitor_advisory_sync_lag_seconds`, `sca_monitor_advisory_sync_failed`, `sca_monitor_advisory_sync_last_error_age_seconds`, `sca_monitor_endpoint_poll_success_rate`, `sca_monitor_worker_lease_acquire_failures`, `new_advisory_to_alert_latency_seconds`, `sca_monitor_alert_delivery_success_rate`, `sca_monitor_alert_outbox_pending_count`, `sca_monitor_alert_dead_letter_count`, `sca_monitor_stale_services`, DB readiness/migration/PostgreSQL cutover metric을 노출한다.

## 4. Logs

MVP는 상태 변경 감사 추적을 위해 `GET /api/v1/audit-logs`를 제공한다.
운영자는 impact status 변경, alert channel 설정 변경, alert event requeue를 actor/action/target 기준으로 조회할 수 있다.

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
- advisory source sync 실패
- worker down
- alert outbox pending 급증
- DB connection failure
- endpoint polling success rate 급락
- frontend error rate 급증

advisory source sync 실패는 `/metrics`의 `sca_monitor_advisory_sync_failed`로 노출되며, 동시에 `reason='system_advisory_sync_failed'` alert outbox row로 기록된다.
source별 suppression key는 `system:advisory_sync:{source}:failed`이다. 같은 source sync가 이후 성공하면 active 실패 alert는 `resolved`로 해소되고, 그 뒤 재실패하면 새 pending alert가 생성된다.

`GET /api/v1/overview`의 `advisory_sync_readiness.freshness`는 source별 최신 성공 lag를 `fresh`, `stale`, `partial`, `failed`, `pending`으로 요약한다.
기본 stale 기준은 24시간이며, `SCA_MONITOR_ADVISORY_SYNC_STALE_AFTER_SECONDS`로 환경별 조정이 가능하다.
Web Console Overview는 stale/partial/failed count를 Advisory Sync 카드에 표시한다.

## 6. Frontend Error Tracking

Web Console은 frontend error tracking을 선택적으로 연동한다.

필수 context:

- app version
- environment
- route
- user role
- request_id

사용자 개인정보와 secret은 전송하지 않는다.
