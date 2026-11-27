# Deployment Inputs for Current Temporary Deployment

이 문서는 사용자가 말로 제공한 현재 배포 입력값을 구조화한 것이다.

## Confirmed Inputs

| 항목 | 값 |
|---|---|
| 배포 서버 접속 | `ssh ai-assistant` |
| 원격 배포 디렉터리 | `/data/psyche/Projects/sca-monitor` |
| 코드 반영 방식 | 로컬 commit/push 후 원격 디렉터리에서 `git fetch` / `git pull` |
| HTTPS 최종 연결 | 사용자가 수동으로 `https://monitoring.fin-ally.net` 연결 |
| 임시 포트 정책 | Codex가 임시 포트를 선택하고 배포 후 사용자에게 보고 |

## Selected Temporary Values

| 항목 | 값 |
|---|---|
| 임시 API/Web Console 포트 | `18780` |
| API 내부 URL | `http://127.0.0.1:18780/api` |
| Web Console 내부 URL | `http://127.0.0.1:18780/` |
| 원격 env 파일 | `/data/psyche/Projects/sca-monitor/.env` |
| 원격 로그 파일 | `/data/psyche/Projects/sca-monitor/logs/sca-monitor.log` |
| 현재 DB fallback | `sqlite:////data/psyche/Projects/sca-monitor/.data/sca-monitor.sqlite3` |
| 목표 DB | PostgreSQL, 세부 접속 정보 REQUIRED |

## Current Database State

현재 배포는 PostgreSQL이 아니라 SQLite fallback으로 동작한다.
자동화는 `.env`에 `SCA_MONITOR_DATABASE_URL`이 없으면 `deploy/sca-monitor.env.example` 기준 값을 추가하거나, 기존 `.data/sca-monitor.sqlite3`를 유지해야 한다.

PostgreSQL 전환 시 REQUIRED 입력값:

| 항목 | 상태 |
|---|---|
| PostgreSQL host/port | REQUIRED |
| database name | REQUIRED |
| API DB user/password | REQUIRED |
| worker DB user/password | REQUIRED |
| SSL mode | REQUIRED |
| backup/PITR 정책 | REQUIRED |
| migration dry-run 환경 | REQUIRED |
| PostgreSQL env file mode `0600` | REQUIRED |

## Manual Follow-up Required

사용자가 수동으로 다음 연결을 설정한다.

```text
https://monitoring.fin-ally.net -> http://127.0.0.1:18780
```

reverse proxy에서 `/api`와 `/` 모두 같은 upstream으로 전달한다.

## Automation Preflight

배포 자동화는 원격 `.env` 또는 배포 시 주입할 env file을 대상으로 다음 명령을 먼저 실행한다.

```bash
python3 scripts/deployment_input_readiness.py --env-file .env --json
```

PostgreSQL split credential 전환 stage에서는 다음 명령을 stop gate로 사용한다.

```bash
python3 scripts/deployment_input_readiness.py --env-file .env --require-postgres --require-split --json
```

이 preflight는 public URL, API port, systemd mode, smoke token 설정 여부와 PostgreSQL cutover readiness를 확인한다.
출력에는 DB URL 원문이나 password를 포함하지 않고, 환경 변수 source와 check 결과만 포함한다.


## 2026-11-03 Collector Recovery Storage Note

수집 복구 중 SQLite의 실제 저장 위치를 SSD로 전환했다. 위 fallback URL과 환경 설정은 유지하며, `/data/psyche/Projects/sca-monitor/.data/sca-monitor.sqlite3`는 `/home/psyche/.local/share/sca-monitor/sca-monitor.sqlite3`를 가리키는 symlink다. DB와 WAL을 함께 지원하는 SQLite 온라인 backup API를 사용해야 한다. symlink 또는 본체 파일만 복사한 백업은 최신 커밋을 보장하지 못한다.

기존 HDD DB는 `.data/sca-monitor.before-ssd-20261103.sqlite3`에 보존했고, 검증된 초기/운영 백업과 전환 증거도 보존했다. 새 커밋이 있으므로 과거 HDD DB를 현재 DB 위에 덮어쓰지 않는다. 전환/복원/정상 수집 검증과 정확한 증거 경로는 [수집 복구 기록](../../docs/COLLECTOR_RECOVERY_2026-11-03.ko.md)을 따른다. PostgreSQL 전환은 이번에 수행하지 않았다.
