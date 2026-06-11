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
