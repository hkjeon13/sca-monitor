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

read-only HTTP smoke:

```bash
SCA_MONITOR_PUBLIC_URL=https://monitoring.fin-ally.net python3 scripts/http_smoke.py --json
```

이 검증은 `/health`, `/ready`, `/api/v1/overview`, `/`만 조회하며 운영 데이터를 변경하지 않는다.

VM systemd scheduler 등록:

```bash
cd /data/psyche/Projects/sca-monitor
scripts/install_systemd_units.sh --user --dry-run
python3 scripts/systemd_scheduler_status.py --user --json
scripts/install_systemd_units.sh --user --repo-dir /data/psyche/Projects/sca-monitor --python /usr/bin/python3 --enable
python3 scripts/systemd_scheduler_status.py --user --systemctl --json
systemctl --user list-timers 'sca-monitor-*'
systemctl --user status sca-monitor-api.service
```

`--dry-run`은 unit 파일만 생성하고 `systemctl`을 호출하지 않는다.
운영 자동화는 먼저 `--dry-run`으로 unit 파일 경로와 내용을 검증한 뒤 `--enable`을 실행한다.
`scripts/systemd_scheduler_status.py`는 unit 파일 검증과 optional systemctl 상태 확인을 read-only로 수행한다.

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

감사 로그 확인:

```bash
curl -fsS "$SCA_MONITOR_PUBLIC_URL/api/v1/audit-logs?limit=20"
curl -fsS "$SCA_MONITOR_PUBLIC_URL/api/v1/audit-logs?target_type=impact&target_id=<impact_id>"
```

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

OpenSSF malicious package 수동 재시도 예시:

```bash
python3 scripts/osv_sync.py --ecosystem npm --source OpenSSF --malicious-only --limit 100 --lock-ttl-seconds 3600
```

이 경로는 OSV-format `MAL-*` record만 수집해 `source=OpenSSF`, `is_malicious_package=true`로 저장한다.
매칭된 impact는 risk scoring에서 Critical로 승격된다.

CISA KEV 수동 재시도 예시:

```bash
python3 scripts/cisa_kev_sync.py --limit 100 --lock-ttl-seconds 3600
```

CISA KEV는 `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` JSON feed를 기본으로 사용한다.
운영 검증에는 작은 `--limit`으로 먼저 실행하고, 폐쇄망 또는 테스트 fixture 검증에는 `--json-path /path/to/cisa-kev.json`을 사용할 수 있다.
실행 결과의 `imported_rows`, `enriched_advisories`, `rematched_impacts`, `failed`를 확인한다.

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

Overview의 Alert Pending, Dead Letters, Alert Readiness 카드에서도 outbox 처리 지연과 default channel 준비 상태를 확인한다.

Live dispatcher preflight:

```bash
python3 scripts/alert_dispatcher_preflight.py --json
```

이 검증은 DB readiness, enabled default webhook channel, dry-run dispatcher 결과, alert outbox 상태를 확인하며 실제 alert 발송이나 row update는 수행하지 않는다.
같은 검증은 `GET /api/v1/alerts/dispatcher/preflight`와 Web Console Settings의 Dispatcher Preflight에서도 확인할 수 있다.
Settings의 Configured Channels 목록에서 `placeholder target` 또는 `live dispatcher blocked` badge가 보이면 실제 webhook URL로 교체하고 channel test를 통과시킨 뒤 live dispatcher enable을 검토한다.

Webhook endpoint smoke:

```bash
ALERT_WEBHOOK_URL=https://alert-router.example/webhook python3 scripts/alert_webhook_smoke.py --json
```

이 검증은 `alert_events`를 claim/send 처리하지 않고 synthetic payload만 전송한다.
기본 alert channel이 Settings에 등록된 경우 Web Console의 Settings > Configured Channels에서 `Test` action으로 같은 목적의 synthetic payload 검증을 수행할 수 있다.

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

SLA escalation 후보 생성:

```bash
python3 scripts/evaluate_sla_escalations.py --dry-run --limit 100
python3 scripts/evaluate_sla_escalations.py --limit 100 --actor sla-scheduler
```

첫 명령은 active impact 중 SLA가 초과된 항목만 확인한다.
두 번째 명령은 중복되지 않는 `sla_expired` alert outbox row를 생성한다.

Daily Digest 후보 생성:

```bash
python3 scripts/create_daily_digest.py --dry-run --limit 100 --timezone Asia/Seoul
python3 scripts/create_daily_digest.py --limit 100 --timezone Asia/Seoul --actor digest-scheduler
```

Daily Digest는 active impact 중 Medium 이하 또는 비운영 환경 이슈를 `reason=daily_digest` outbox row 하나로 묶는다.
기본 중복 억제 key는 `daily_digest:{YYYY-MM-DD}:all`이며, VM systemd timer는 매일 09:00 `Asia/Seoul` 운영 기준으로 실행하도록 설치된다.
Web Console Settings의 Daily Digest preview와 `POST /api/v1/alerts/daily-digest/preview`는 같은 후보를 dry-run으로 확인하며 outbox row를 만들지 않는다.

Dead-letter 재처리:

```bash
python3 scripts/requeue_alerts.py --all --limit 20 --actor operator --reason "webhook target recovered"
python3 scripts/requeue_alerts.py --alert-event-id <alert_event_id> --actor operator --reason "manual retry"
```

Web Console Settings 화면에서도 status/search/limit 기반 alert event 조회와 dead-letter 단건/일괄 requeue action을 확인할 수 있다.

Slack app 방식은 후속 구현 대상이다.

### Accepted risk expired

만료 예정/만료된 accepted risk는 먼저 dry-run으로 확인한다.

```bash
python3 scripts/expire_accepted_risks.py --dry-run --limit 100
```

결과의 `expired`가 예상 범위이면 실제 전환을 수행한다.

```bash
python3 scripts/expire_accepted_risks.py --limit 100 --actor risk-scheduler
```

실행 시 만료된 impact는 `open`으로 전환되고, 기존 accepted risk row는 revoked 처리되며 impact history와 audit log에 `accepted_risk.expire`가 기록된다.

## 4. 운영자 수동 작업

| 작업 | 위치 |
|---|---|
| 서비스 등록 | Web Console Services |
| endpoint test | Service Registration Wizard |
| push credential 발급/회전/폐기 | Service Detail 또는 Settings |
| impact acknowledge | Impact Detail |
| accepted risk 승인 | Impact Detail, security-approver 권한 |
| alert channel 변경 | Settings |

Push credential 수동 회전:

```bash
python3 scripts/rotate_push_credential.py \
  --service-id <service_id> \
  --credential-id <credential_id> \
  --environment prod \
  --actor operator \
  --reason "scheduled rotation"
```

회전 결과로 새 token이 1회 출력된다.
기존 token은 즉시 revoked 처리되므로 CI/CD secret store 갱신을 먼저 계획하고, 새 token 배포 후 smoke push를 수행한다.

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
