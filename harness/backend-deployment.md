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
4. 기존 worker 일시 중지(systemd 배포 시)
5. migration 실행
6. DB smoke test 실행
7. Worker 재시작 또는 systemd gate 실행
8. API Server 배포
9. `/health`, `/ready` 확인
10. smoke test 실행

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
  "advisory_sync_readiness": {
    "status": "initializing",
    "required_count": 3,
    "initialized_count": 0
  },
  "migration": {
    "current": 5,
    "required": 5,
    "minimum_supported": 1,
    "compatible": true
  }
}
```

Worker:

```text
worker health command
```

Advisory worker command examples:

```bash
python3 scripts/osv_sync.py --ecosystem npm --limit 100 --lock-ttl-seconds 3600
python3 scripts/osv_sync.py --ecosystem npm --source OpenSSF --malicious-only --limit 100 --scan-limit 1000 --lock-ttl-seconds 3600
python3 scripts/cisa_kev_sync.py --limit 100 --lock-ttl-seconds 3600
python3 scripts/ghsa_sync.py --limit 100 --lock-ttl-seconds 3600
python3 scripts/ghsa_sync.py --type malware --limit 100 --lock-ttl-seconds 3600
python3 scripts/nvd_cve_sync.py CVE-2026-0001 --lock-ttl-seconds 3600
python3 scripts/nvd_cve_sync.py --cve-list-path reported-cves.txt --limit 100 --lock-ttl-seconds 3600
python3 scripts/nvd_cve_sync.py --use-cursor --lookback-hours 24 --modified-results-per-page 2000 --limit 100 --lock-ttl-seconds 3600
python3 scripts/merge_canonical_advisories.py --dry-run --limit 100
python3 scripts/backfill_canonical_impact_keys.py --dry-run --limit 100
```

`merge_canonical_advisories.py`는 dry-run으로 alias-related advisory row merge 후보를 확인하고, apply 시 canonical target advisory로 alias, metadata, impact FK를 이관한다. 기본 apply는 이어서 impact canonical backfill도 실행하며, 분리 실행이 필요하면 `--skip-impact-backfill`을 사용한다.

`backfill_canonical_impact_keys.py`는 dry-run 결과의 `action`이 `update`인 항목은 key만 갱신하고, `merge`인 항목은 apply 시 target impact로 alert event, impact history, accepted risk를 이관한 뒤 legacy impact를 제거한다.

확인 항목:

- DB 연결
- advisory_sync_state 접근
- alert_events pending 조회
- lease 획득 가능 여부
- metrics exporter 동작 여부

DB smoke command:

```bash
python3 scripts/db_smoke.py
python3 scripts/db_smoke.py --json
bash scripts/deploy_db_gate.sh
```

현재 SQLite fallback과 PostgreSQL runtime adapter에서는 `services`, `advisory_sync_state`, `alert_events` read와 `audit_logs` transactional write/rollback을 검증한다.
PostgreSQL URL에서는 `psycopg` 설치, DB network, credential, migration 상태, API workflow별 integration smoke를 통과해야 운영 DB 전환을 진행한다.
`scripts/deploy_db_gate.sh`는 `SCA_MONITOR_POSTGRES_INTEGRATION_SMOKE=auto` 기본값에서 `postgres://` 또는 `postgresql://` DB URL일 때 `scripts/postgres_integration_smoke.py --database-url`을 배포 stop gate로 실행한다.
운영 전환 검증을 강제하려면 `required`, 임시로 끄려면 `disabled`를 사용한다.

## 4. Deployment Stop Rules

다음 조건이면 배포를 중단한다.

- required env var 누락
- DB migration 실패
- DB smoke test 실패
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
| Snapshot Poll Scheduler | single-active 권장 | `endpoint_poll_state` DB lease |
| Snapshot Poll Worker | multi-replica 가능 | job row `FOR UPDATE SKIP LOCKED` |
| Advisory Sync Worker | source별 single-active | source별 sync lock |
| Matching Worker | multi-replica 가능 | snapshot/advisory job lock |
| Alert Dispatcher | multi-replica 가능 | `alert_events` pending row `FOR UPDATE SKIP LOCKED` |
| SLA/Digest Worker | single-active 권장 | schedule lock |

Alert Dispatcher는 MVP에서 DB row 상태 전이로 per-alert claim을 수행한다.
운영 프로세스는 다음 형태로 구성할 수 있다.

```bash
ALERT_WEBHOOK_URL=https://alert-router.example/webhook python3 scripts/dispatch_alerts.py --iterations 0 --interval-seconds 30 --limit 50
```

Dead-letter는 target 복구 후 다음 방식으로 재처리한다.

```bash
python3 scripts/requeue_alerts.py --all --limit 50 --reason "target recovered"
```

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

## 7. VM systemd Scheduler Registration

VM 기반 MVP 배포에서는 다음 스크립트로 API와 worker scheduler unit을 생성한다.

```bash
scripts/install_systemd_units.sh --user --dry-run
scripts/systemd_scheduler_status.py --user --json
scripts/install_systemd_units.sh --user --enable
```

원격 운영 경로 예시:

```bash
cd /data/psyche/Projects/sca-monitor
scripts/install_systemd_units.sh --user --repo-dir /data/psyche/Projects/sca-monitor --python /usr/bin/python3 --enable
```

Live alert dispatcher를 켜기 전 advisory 수집 scheduler만 운영화하려면 다음 중간 모드를 사용한다.
이 모드는 API, endpoint poller, dry-run dispatcher, advisory freshness, CISA/GHSA/NVD/OSV/OpenSSF sync, canonical merge timer를 enable/restart하고 live dispatcher는 disable 상태로 유지한다.

```bash
SCA_MONITOR_SYSTEMD_MODE=enable-advisory-sync-dry-run \
SCA_MONITOR_SYSTEMD_SCOPE=user \
SCA_MONITOR_SYSTEMD_PYTHON=/usr/bin/python3 \
bash scripts/deploy_systemd_gate.sh
```

생성되는 unit:

| Unit | 역할 | 실행 방식 |
|---|---|---|
| `sca-monitor-api.service` | API server | long-running service |
| `sca-monitor-endpoint-poller.service` | endpoint polling | long-running loop, DB lease |
| `sca-monitor-alert-dispatcher.service` | alert outbox dispatch | long-running loop, per-alert lock |
| `sca-monitor-alert-dispatcher-dry-run.service` | alert outbox dry-run dispatch | long-running loop, no row update/send |
| `sca-monitor-accepted-risk-expiry.timer` | accepted risk 만료 처리 | 15분 주기 oneshot |
| `sca-monitor-sla-escalation.timer` | SLA 만료 alert 후보 생성 | 15분 주기 oneshot |
| `sca-monitor-advisory-freshness.timer` | advisory sync stale source system alert 생성/해소 | 15분 주기 oneshot |
| `sca-monitor-daily-digest.timer` | Medium 이하/비운영 이슈 Daily Digest 생성 | 매일 09:00 oneshot |
| `sca-monitor-cisa-kev-sync.timer` | CISA KEV sync | 1시간 주기 oneshot |
| `sca-monitor-ghsa-sync.timer` | GitHub Security Advisory sync | 1시간 주기 oneshot |
| `sca-monitor-nvd-cve-sync.timer` | NVD CVE modified-window sync | 6시간 주기 oneshot |
| `sca-monitor-osv-npm-sync.timer` | OSV npm sync | 1시간 주기 oneshot |
| `sca-monitor-openssf-malicious-sync.timer` | OpenSSF malicious package sync | 1시간 주기 oneshot |
| `sca-monitor-canonical-advisory-merge.timer` | alias 기반 canonical advisory merge 및 impact key backfill | 1시간 주기 oneshot |

모든 unit은 repository의 `.env`를 `EnvironmentFile`로 읽는다.
`SCA_MONITOR_DATABASE_URL`, `SCA_MONITOR_FRONTEND_DIR`, alert webhook 설정은 `.env`에서 유지한다.

상태 확인:

```bash
python3 scripts/systemd_scheduler_status.py --user --systemctl --json
python3 scripts/systemd_scheduler_status.py --user --systemctl --require-active-unit sca-monitor-accepted-risk-expiry.timer --json
systemctl --user status sca-monitor-api.service
systemctl --user list-timers 'sca-monitor-*'
journalctl --user -u sca-monitor-alert-dispatcher.service -n 100
```

`scripts/systemd_scheduler_status.py`는 unit 파일 존재 여부, 필수 `ExecStart`/timer fragment, optional systemctl enabled/active 상태를 read-only로 조회한다.
운영 자동화는 `scripts/install_systemd_units.sh --dry-run --unit-dir <staging-dir>` 후 `scripts/systemd_scheduler_status.py --unit-dir <staging-dir> --json`을 먼저 통과시킨 뒤, 별도 승인된 환경에서만 `--enable`을 실행한다.
`scripts/deploy_systemd_gate.sh`는 이 절차를 배포 gate로 감싼다.

배포 자동화 설정:

| 환경변수 | 기본값 | 설명 |
|---|---:|---|
| `SCA_MONITOR_SYSTEMD_MODE` | `validate` | `off`, `validate`, `install`, `enable-api`, `enable-poller`, `enable-dispatcher-dry-run`, `enable` 중 하나. `validate`는 staging directory에 unit을 생성하고 검증만 한다. |
| `SCA_MONITOR_SYSTEMD_SCOPE` | `user` | `user` 또는 `system`. 운영 system unit은 root 권한이 필요하다. |
| `SCA_MONITOR_SYSTEMD_PREFIX` | `sca-monitor` | unit 이름 prefix |
| `SCA_MONITOR_SYSTEMD_PYTHON` | `python3` | unit `ExecStart`에 사용할 Python 실행 파일 |
| `SCA_MONITOR_SYSTEMD_REPO_DIR` | 현재 checkout | unit `WorkingDirectory`와 `EnvironmentFile` 기준 repository 경로 |
| `SCA_MONITOR_SYSTEMD_REQUIRE_ACTIVE_UNITS` | empty | 쉼표 또는 공백으로 구분한 unit 목록. `enable*` 모드의 systemd status gate에서 지정 unit이 `enabled` 및 `active`가 아니면 배포를 실패시킨다. |

원격 배포 스크립트는 DB gate 후 `scripts/deploy_systemd_gate.sh`를 실행한다.
`enable-poller`, `enable-dispatcher-dry-run`, `enable` mode에서는 migration과 DB gate 실행 전에 기존 systemd worker unit을 잠시 중지하고, gate가 끝나면 다시 시작한다.
이는 SQLite fallback 운영 중 endpoint poller 또는 alert dispatcher가 DB write lock을 잡아 migration/gate가 실패하는 상황을 줄이기 위한 절차이다.
생성되는 systemd unit은 `Environment=SCA_MONITOR_AUTO_MIGRATE=false`를 포함한다.
따라서 VM systemd 배포에서는 `scripts/migrate.py`와 `deploy_db_gate.sh`가 schema 적용을 담당하고, API/worker 시작 시 runtime DDL은 수행하지 않는다.
운영에서 실제 unit 파일만 설치하려면 `SCA_MONITOR_SYSTEMD_MODE=install`, API service만 canary로 enable/start하려면 `SCA_MONITOR_SYSTEMD_MODE=enable-api`, API와 endpoint poller만 canary로 enable/start하려면 `SCA_MONITOR_SYSTEMD_MODE=enable-poller`, dry-run dispatcher까지 canary로 enable/start하려면 `SCA_MONITOR_SYSTEMD_MODE=enable-dispatcher-dry-run`, live dispatcher와 timer까지 전체 enable/start하려면 `SCA_MONITOR_SYSTEMD_MODE=enable`을 명시한다.
`enable-api`, `enable-poller`, `enable-dispatcher-dry-run`, `enable` 모드에서는 기존 `.data/sca-monitor.pid` 기반 legacy API process를 먼저 정리하고 systemd `sca-monitor-api.service`가 API runtime을 담당한다.
이미 active 상태인 unit도 새 코드와 unit 파일을 반영하도록 `enable --now` 이후 대상 service/timer를 명시적으로 restart한다.
live dispatcher를 포함하는 `enable` 전환 전에는 `python3 scripts/alert_dispatcher_go_live_gate.py --json`으로 default webhook/Slack channel, placeholder target, dry-run dispatcher, dead-letter blocking condition, systemd unit 상태를 확인한다.
go-live gate의 `alert_channel_readiness`는 `configured`, `ready`, `channel_type`, `target_url_masked`, `placeholder_target`을 top-level로 제공해 배포 자동화가 Slack/Webhook 준비 상태를 직접 판단할 수 있게 한다.
`off`, `validate`, `install` 모드에서는 기존 nohup API runtime을 유지한다.
`enable-api`, `enable-poller`, `enable-dispatcher-dry-run`, `enable` 모드는 `systemctl` 명령 존재와 `systemctl --user list-unit-files` 접근성을 preflight로 확인한 뒤 진행하며, 성공 결과에는 `systemctl is-enabled/is-active` 상태가 포함된다.
systemd deploy gate가 실패하면 원격 배포 스크립트는 legacy nohup API runtime을 다시 시작하고 실패를 반환한다.
원격 배포는 기본적으로 원격 `.env`의 `SCA_MONITOR_SYSTEMD_*` 값을 사용한다.
CI/CD 또는 수동 자동화에서 `SCA_MONITOR_SYSTEMD_MODE`, `SCA_MONITOR_SYSTEMD_SCOPE`, `SCA_MONITOR_SYSTEMD_PREFIX`, `SCA_MONITOR_SYSTEMD_PYTHON`, `SCA_MONITOR_SYSTEMD_REQUIRE_ACTIVE_UNITS`를 로컬 환경변수로 명시하면 해당 값이 원격 `.env` 값을 override한다.

운영에서 system unit으로 설치하려면 `--system`을 사용한다.
이 경우 root 권한과 `/etc/systemd/system` 쓰기 권한이 필요하다.
