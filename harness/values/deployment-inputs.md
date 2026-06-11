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

## Manual Follow-up Required

사용자가 수동으로 다음 연결을 설정한다.

```text
https://monitoring.fin-ally.net -> http://127.0.0.1:18780
```

reverse proxy에서 `/api`와 `/` 모두 같은 upstream으로 전달한다.

