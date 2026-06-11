# Database Deployment

이 문서는 PostgreSQL 배포와 migration 기준을 정의한다.

## 1. PostgreSQL 기준

```text
Database: PostgreSQL
Recommended version: 16+
Required extension: pgcrypto
Public exposure: forbidden
Access: API/worker private network only
```

현재 MVP 배포는 PostgreSQL 전환 전 단계로 SQLite fallback을 사용한다.
애플리케이션은 `SCA_MONITOR_DATABASE_URL`을 우선 사용하며, 값이 없으면 API runtime은 `API_DATABASE_URL`, worker/scheduler runtime은 `WORKER_DATABASE_URL`, 기존 `SCA_MONITOR_DB`, 마지막으로 `.data/sca-monitor.sqlite3` 순서로 DB URL을 구성한다.
PostgreSQL 계정 분리를 활성화하려면 `SCA_MONITOR_DATABASE_URL`을 비우고 `API_DATABASE_URL`/`WORKER_DATABASE_URL`을 각각 설정한다.
DDL 권한은 `MIGRATION_DATABASE_URL`에만 부여하는 것을 권장한다.
배포 pipeline이 `scripts/migrate.py`와 `deploy_db_gate.sh`를 먼저 실행하는 운영 환경에서는 `SCA_MONITOR_AUTO_MIGRATE=false` 또는 컴포넌트별 `SCA_MONITOR_API_AUTO_MIGRATE=false`, `SCA_MONITOR_WORKER_AUTO_MIGRATE=false`로 runtime DDL을 비활성화할 수 있다.

```text
Temporary fallback: sqlite:////data/psyche/Projects/sca-monitor/.data/sca-monitor.sqlite3
Target production: postgresql://...
```

PostgreSQL URL을 배포 환경에 넣기 전에는 실제 PostgreSQL instance, credential, network access, migration dry-run이 먼저 완료되어야 한다.
전환 직전에는 `scripts/postgres_cutover_readiness.py --require-postgres --json`을 실행해 DB URL 조합, PostgreSQL 여부, integration smoke 설정, runtime auto-migrate 비활성화 여부를 먼저 확인한다.
운영자는 Web Console Overview, `/ready`, 또는 `GET /api/v1/operations/database-readiness`에서 현재 DB backend, DB URL source, migration version, cutover mode, require-postgres preflight 요약, split credential 준비 여부, 차단 사유를 확인할 수 있다.
`database_url_source`는 `SCA_MONITOR_DATABASE_URL`, `API_DATABASE_URL`, `WORKER_DATABASE_URL`, `SCA_MONITOR_DB`, `default_sqlite` 중 어떤 설정이 선택됐는지만 표시하며 URL 원문이나 credential은 노출하지 않는다.
`runtime_database_urls`는 `api`, `worker`, `migration` role별 source/backend/configured 여부만 표시한다.
`MIGRATION_DATABASE_URL`, `API_DATABASE_URL`, `WORKER_DATABASE_URL` 원문, host, username, password는 readiness와 Web Console에 노출하지 않는다.
`postgres_preflight`는 blocker/warning/ok 개수와 다음 조치 문구를 제공해 배포 자동화와 운영자가 PostgreSQL 전환 준비 상태를 같은 기준으로 확인하게 한다.
`SCA_MONITOR_POSTGRES_REQUIRE_SPLIT` 값이 잘못 설정되면 `/ready`와 database-readiness 응답의 `postgres_require_split_flag` blocker로 노출되며, 배포 gate는 같은 오류를 stop condition으로 처리한다.

## 2. Migration

Migration 구조는 repository의 `migrations/` 디렉터리를 기준으로 시작한다.

```text
migrations/sqlite/001_initial.sql
migrations/postgres/001_initial.sql
scripts/migrate.py
```

현재 구현은 SQLite와 PostgreSQL migration 실행, version 기록을 지원한다.
`scripts/db_smoke.py`는 배포 후 DB smoke gate로 사용하며 SQLite fallback과 PostgreSQL runtime adapter에서 schema read와 `audit_logs` transactional write/rollback을 검증한다.
PostgreSQL 운영 적용 전 실제 PostgreSQL instance, credential, network access, migration dry-run, API workflow별 integration test가 필요하다.

장기 Migration tool은 아직 REQUIRED이다.

후보:

- Alembic
- Prisma Migrate
- Flyway
- Liquibase

배포 pipeline은 backend/worker 시작 전에 migration을 실행한다.
현재 임시 배포 스크립트도 서버 시작 전에 `python3 scripts/migrate.py`를 실행한다.
VM systemd 배포에서 이미 endpoint poller 또는 alert dispatcher가 실행 중이면 migration과 DB gate 전에 worker unit을 일시 중지하고 gate 후 재시작한다.
SQLite fallback에서는 장시간 실행 worker의 write lock이 migration 또는 smoke gate와 경합할 수 있으므로 이 순서를 배포 자동화의 기본값으로 둔다.
VM systemd unit은 `SCA_MONITOR_AUTO_MIGRATE=false`를 명시해 API/worker 재시작 시 runtime migration을 반복하지 않는다.
이 모드에서는 배포 migration gate 실패가 stop condition이며, unit start로 schema를 보정하지 않는다.

## 3. Migration Rules

- migration은 idempotent하지 않아도 되지만 순서가 보장되어야 한다.
- destructive migration은 별도 승인 필요.
- prod migration 전 backup snapshot 생성.
- rollback 불가능한 migration은 forward-fix 절차를 문서화.
- 모든 migration은 직전 배포 버전(N-1) 코드와 호환되어야 한다.
- 컬럼/테이블 제거 또는 rename은 expand/contract 방식으로 분리한다.
- NOT NULL 추가는 nullable column 추가, backfill, constraint 적용을 분리한다.
- migration 도구의 lock 기능 또는 PostgreSQL advisory lock으로 동일 환경 동시 migration 실행을 차단한다.
- CI/CD는 동일 환경에 대한 중복 배포를 금지하거나 queueing해야 한다.

### 3.1 Expand/Contract 원칙

배포 중에는 구버전 API/worker와 신버전 API/worker가 동시에 존재할 수 있다.
따라서 DB schema 변경은 다음 순서를 따른다.

1. expand: 새 column/table/index를 추가하되 기존 코드와 호환되게 유지
2. deploy: 새 코드가 새 schema를 사용하도록 배포
3. backfill: 필요한 데이터 보정
4. contract: 이전 코드가 더 이상 참조하지 않는 column/table을 다음 release에서 제거

contract migration은 자동 배포에서 실행하지 않고 별도 승인 gate를 둔다.

## 4. Backup

필수 결정:

| 항목 | 필요 결정 |
|---|---|
| backup 주기 | 예: 매일 |
| PITR | 사용 여부 |
| retention | 예: 30일 |
| 복구 테스트 | stage에서 월 1회 등 |

현재 SQLite fallback VM 배포에서는 migration 전에 read-only 파일 백업을 생성한다.
기본 경로는 `SCA_MONITOR_DATA_DIR/backups`이며, 원격 배포 자동화에서 이 gate를 강제하려면 다음처럼 실행한다.

```bash
python3 scripts/backup_database.py --json
python3 scripts/backup_database.py --required --json
python3 scripts/verify_backup_restore.py --backup-path "$BACKUP_PATH" --json

SCA_MONITOR_BACKUP_BEFORE_MIGRATION=required \
SCA_MONITOR_VERIFY_BACKUP_RESTORE=required \
scripts/deploy_remote.sh
```

`auto` 모드는 SQLite DB 파일이 이미 있으면 백업하고, 초기 bootstrap처럼 파일이 아직 없으면 skip한다.
`required` 모드는 SQLite DB 파일이 없거나 PostgreSQL처럼 애플리케이션 외부 백업이 필요한 backend이면 배포를 중단한다.
`scripts/verify_backup_restore.py`는 backup 파일을 임시 위치로 복사한 뒤 read-only DB smoke를 실행해 schema와 migration compatibility를 확인한다.
검증 출력에는 backup 원본 경로나 SQLite URL을 포함하지 않는다.
원격 배포에서 `SCA_MONITOR_VERIFY_BACKUP_RESTORE=required`를 설정하면 backup 생성 직후, migration 실행 전에 restore-check를 stop gate로 실행한다.
PostgreSQL 전환 후에는 managed backup/PITR 정책과 복구 테스트 결과를 별도 운영 증적으로 확인한다.

## 5. Retention

SDS 기준:

| 데이터 | 보존 |
|---|---|
| latest dependency snapshot | 삭제 전까지 |
| historical dependency snapshots | 90일 |
| fixed impacts | 1년 |
| alert events | 1년 |
| audit logs | 3년 또는 조직 정책 |
| advisory data | 삭제하지 않음 |

open impact가 참조하는 snapshot/dependency는 보존하거나 FK를 `ON DELETE SET NULL`로 처리한다.

## 6. DB Smoke Test

배포 후 확인:

- 현재 배포 코드가 요구하는 최소 migration version 이상
- API user로 read/write 가능
- worker user로 outbox 조회 가능
- advisory_sync_state upsert 가능
- audit_logs insert 가능

현재 자동화 명령:

```bash
python3 scripts/db_smoke.py --json
curl -fsS "$PUBLIC_URL/api/v1/operations/database-readiness"
```

실제 PostgreSQL 연결 검증:

```bash
python3 scripts/postgres_cutover_readiness.py --json
python3 scripts/postgres_cutover_readiness.py --require-postgres --require-split --json
python3 scripts/deployment_input_readiness.py --env-file .env --json
python3 scripts/deployment_input_readiness.py --env-file .env --require-postgres --require-split --json
python3 scripts/cutover_readiness_report.py \
  --env-file .env \
  --database-env-file /data/psyche/Projects/sca-monitor/.secrets/postgres.env \
  --backup-path "$BACKUP_PATH" \
  --require-postgres \
  --require-split \
  --require-runtime-inputs \
  --json
python3 scripts/postgres_integration_smoke.py --production-preflight --json
python3 scripts/postgres_integration_smoke.py --database-url "$SCA_MONITOR_DATABASE_URL" --json
python3 scripts/postgres_integration_smoke.py --database-url "$SCA_MONITOR_DATABASE_URL" --with-api-workflow --json
python3 scripts/postgres_integration_smoke.py --use-docker --with-api-workflow --json
SCA_MONITOR_POSTGRES_DOCKER_SMOKE=required bash scripts/postgres_docker_smoke_gate.sh
bash scripts/deploy_db_gate.sh
```

원격 VM 배포에서 PostgreSQL split credential을 `.env`에 병합할 때는 DB URL을 로컬 shell 인자로 직접 전달하지 않는다.
원격 서버에 root/user 권한으로 보호된 env file을 먼저 준비하고, 배포 시 remote path만 지정한다.

```bash
python3 scripts/prepare_database_env_file.py \
  --database-env-file /data/psyche/Projects/sca-monitor/.secrets/postgres.env \
  --json
$EDITOR /data/psyche/Projects/sca-monitor/.secrets/postgres.env
python3 scripts/validate_database_env_file.py --database-env-file /data/psyche/Projects/sca-monitor/.secrets/postgres.env --json

SCA_MONITOR_DATABASE_ENV_FILE=/data/psyche/Projects/sca-monitor/.secrets/postgres.env \
SCA_MONITOR_POSTGRES_PRODUCTION_PREFLIGHT=required \
SCA_MONITOR_POSTGRES_REQUIRE_SPLIT=true \
scripts/deploy_remote.sh
```

`scripts/configure_runtime_inputs.py`는 `MIGRATION_DATABASE_URL`, `API_DATABASE_URL`, `WORKER_DATABASE_URL`과 PostgreSQL 전환 flag만 allowlist로 병합하며,
배포 로그에는 DB URL 원문을 출력하지 않는다.
`scripts/prepare_database_env_file.py`는 `deploy/postgres.env.example`을 mode `0600`의 protected file로 생성하고, 기본값으로 기존 secret 파일을 덮어쓰지 않는다.
생성 직후 validator 결과는 placeholder 때문에 `blocked`가 정상이며, 운영자가 실제 값을 입력한 뒤 `validate_database_env_file.py`가 `ok`가 되어야 배포 병합을 진행한다.
`scripts/validate_database_env_file.py`는 `deploy/postgres.env.example` 같은 placeholder 파일을 차단하고, 검증 출력에 DB URL 원문을 포함하지 않는다.
`SCA_MONITOR_DATABASE_ENV_FILE`이 설정된 `scripts/deploy_remote.sh` 실행은 `.env` 병합 전에 이 validator를 stop gate로 먼저 실행한다.
`SCA_MONITOR_POSTGRES_PRODUCTION_PREFLIGHT=required`는 worker stop 및 backup gate 이후, 일반 migration 실행 전에 `scripts/postgres_integration_smoke.py --production-preflight --json`을 실행한다.
이 gate는 migration credential로 migration/write-rollback smoke를 수행하고 API/worker credential은 read-only smoke로 확인한다.
실제 PostgreSQL 운영 전환에서는 managed backup/PITR 증적을 먼저 확인하고, SQLite file backup 전용인 `SCA_MONITOR_BACKUP_BEFORE_MIGRATION=required`와 충돌하지 않게 backup mode를 별도 운영 절차에 맞춘다.

실제 secret 파일을 준비하기 전에는 synthetic split credential로 같은 병합/준비도 경로를 dry-run한다.
이 검증은 DB에 접속하지 않고 `validate_database_env_file.py`, `configure_runtime_inputs.py`, `deployment_input_readiness.py` 흐름이 서로 맞물리는지만 확인하며, 출력에는 DB URL 원문이나 password를 포함하지 않는다.

```bash
python3 scripts/database_env_dry_run_gate.py --json
python3 scripts/database_env_dry_run_gate.py --database-env-file deploy/postgres.env.example --json
```

첫 번째 명령은 synthetic split credential로 성공해야 한다.
두 번째 명령은 placeholder template 검증 예시이며 `placeholder_values` blocker로 중단되는 것이 정상이다.
원격 배포 자동화에서 같은 dry-run을 stop gate로 연결하려면 `.env` 병합 전에 다음 입력을 사용한다.

```bash
SCA_MONITOR_DATABASE_ENV_DRY_RUN=synthetic scripts/deploy_remote.sh

SCA_MONITOR_DATABASE_ENV_FILE=/data/psyche/Projects/sca-monitor/.secrets/postgres.env \
SCA_MONITOR_DATABASE_ENV_DRY_RUN=provided \
scripts/deploy_remote.sh
```

`synthetic`은 실제 secret 없이 split credential 병합/준비도 흐름만 검증한다.
`provided` 또는 `required`는 `SCA_MONITOR_DATABASE_ENV_FILE`이 지정된 경우에만 실행되며, 실제 secret 파일을 `.env`에 병합하기 전에 같은 파일을 dry-run gate로 먼저 검증한다.

`--database-url`은 stage/운영 PostgreSQL에 대해 migration과 DB smoke를 직접 실행한다.
`--use-docker`는 CI 또는 개발 환경에서 임시 PostgreSQL 16 container를 띄워 같은 검증을 수행한다.
`scripts/postgres_docker_smoke_gate.sh`는 CI/stage에서 Docker가 있으면 `--use-docker --with-api-workflow` smoke를 실행하고, `SCA_MONITOR_POSTGRES_DOCKER_SMOKE=auto`에서는 Docker executable 미설치 또는 daemon unavailable 시 skip, `required`에서는 배포 stop condition으로 처리한다.
`SCA_MONITOR_POSTGRES_DOCKER_IMAGE`, `SCA_MONITOR_POSTGRES_DOCKER_API_WORKFLOW`, `SCA_MONITOR_POSTGRES_DOCKER_TIMEOUT_SECONDS`로 이미지, API workflow 실행 여부, startup timeout을 조정한다.
`--with-api-workflow`는 synthetic service 등록과 snapshot push까지 실행하므로 CI 또는 stage DB에서 사용하고, 운영 DB에서는 승인된 synthetic service 정책이 있을 때만 사용한다.
`deploy_db_gate.sh`는 배포 자동화에서 `db_smoke.py`를 항상 실행하고, PostgreSQL URL이면 integration smoke를 추가 실행한다.
`scripts/cutover_readiness_report.py`는 runtime `.env`, protected PostgreSQL env file, backup restore-check, 선택적 production preflight 결과를 하나의 sanitized JSON으로 묶어 운영 전환 증적으로 사용한다.
이 report는 DB URL 원문, password, backup 원본 경로를 출력하지 않는다.
`MIGRATION_DATABASE_URL`이 설정되면 migration owner URL로 migration smoke를 실행하고, `API_DATABASE_URL`은 `--skip-migrate` runtime smoke, `WORKER_DATABASE_URL`은 `--skip-migrate --read-only` smoke로 분리 검증한다.
`--production-preflight`는 split credential 운영 전환 직전에 `MIGRATION_DATABASE_URL`, `API_DATABASE_URL`, `WORKER_DATABASE_URL`을 한 번에 검증한다. migration role은 migration과 transactional write/rollback smoke를 수행하고, API/worker role은 migrate 없이 read-only schema smoke만 수행한다.
`SCA_MONITOR_POSTGRES_INTEGRATION_SMOKE=required`이면 `deploy_db_gate.sh`는 smoke 실행 전에 `scripts/postgres_cutover_readiness.py --require-postgres`를 stop gate로 실행한다.
`SCA_MONITOR_POSTGRES_REQUIRE_SPLIT=true`를 함께 설정하면 `deploy_db_gate.sh`가 `--require-split`도 적용하여 `MIGRATION_DATABASE_URL`, `API_DATABASE_URL`, `WORKER_DATABASE_URL` 분리 credential 구성이 아니면 배포를 중단한다.
runtime auto-migrate를 끈 환경에서는 이 migration/gate 단계가 API/worker 시작 전 필수 stop gate이다.

PostgreSQL split credential cutover ready 조건:

- `SCA_MONITOR_DATABASE_URL`은 비워 둔다.
- `MIGRATION_DATABASE_URL`, `API_DATABASE_URL`, `WORKER_DATABASE_URL`은 모두 `postgresql://` 또는 `postgres://` URL이어야 한다.
- `SCA_MONITOR_POSTGRES_INTEGRATION_SMOKE`는 `auto` 또는 `required`이어야 한다. 운영 전환 gate에서는 `required`를 권장한다.
- 운영 split credential 전환 gate에서는 `SCA_MONITOR_POSTGRES_REQUIRE_SPLIT=true`를 설정한다.
- `SCA_MONITOR_AUTO_MIGRATE=false` 또는 `SCA_MONITOR_API_AUTO_MIGRATE=false`와 `SCA_MONITOR_WORKER_AUTO_MIGRATE=false`를 설정해 runtime DDL을 비활성화한다.

SQLite fallback과 PostgreSQL adapter에서 공통 검증하는 항목:

- `services` read
- `advisory_sync_state` read
- `advisory_sync_state` cursor/last_run/records_processed migration
- `alert_events` read
- JSON/JSONB 컬럼 read normalization
  - SQLite fallback은 JSON 문자열을 반환한다.
  - PostgreSQL `psycopg` + `dict_row`는 JSONB 컬럼을 list/dict로 반환할 수 있다.
  - advisory affected versions/ranges, alert payload, raw payload 조회 경로는 두 반환 타입을 모두 처리해야 한다.
- `audit_logs` write 후 rollback cleanup

PostgreSQL URL을 넣었을 때 `psycopg` import/connection/query 오류가 나오면 배포 stop condition이다.
이 상태에서는 운영 전환하지 말고 dependency 설치, network allowlist, credential, migration 상태를 먼저 확인한다.
