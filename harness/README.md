# SCA Monitor Harness

이 폴더는 SCA Monitor의 실제 개발, 배포, 운영 자동화를 준비하기 위한 지침서 모음이다.

기준 설계 문서:

- `docs/software-design-specification.md`
- `docs/reported-supply-chain-alert-platform.md`

## 문서 구성

| 문서 | 목적 |
|---|---|
| `requirements.md` | 배포 자동화 전에 확정해야 할 요구사항과 미결정 항목 |
| `implementation-plan.md` | 설계기술서 기반 구현 절차와 단계별 산출물 |
| `deployment-environment.md` | 서버, 런타임, 데이터베이스, 도메인, 환경 구성 기준 |
| `network-and-ports.md` | 외부 통신, inbound/outbound 포트, 방화벽 요구사항 |
| `backend-deployment.md` | API 서버와 worker 배포 기준 |
| `frontend-deployment.md` | Web Console 배포 기준, HTTPS 주소, 정적 자산 정책 |
| `database-deployment.md` | PostgreSQL 배포, migration, backup, retention 기준 |
| `secrets-and-config.md` | 환경 변수, secret, credential 관리 기준 |
| `cicd-automation.md` | CI/CD 자동화 pipeline 설계 |
| `bootstrap.md` | 신규 환경 최초 기동과 synthetic service 등록 절차 |
| `observability.md` | metrics, logs, error tracking, system alert 기준 |
| `operations-runbook.md` | 배포 후 검증, 장애 대응, rollback 기준 |

## 기본 배포 가정

초기 배포는 다음 구성으로 가정한다.

```text
Frontend Web Console
Backend API Server
Background Workers
PostgreSQL
External Advisory Sources
Slack/Webhook Notification Targets
```

초기 구현에서는 Kubernetes를 필수로 두지 않는다.
Docker Compose, VM 기반 systemd, Kubernetes 중 실제 운영 환경에 맞는 배포 방식을 `requirements.md`에서 확정한다.

## 자동화 목표

최종 자동화 프로세스는 다음 작업을 반복 가능하게 수행해야 한다.

1. 코드 checkout
2. 환경 변수와 secret 검증
3. backend build/test
4. frontend build/test
5. database migration
6. service deployment
7. worker deployment
8. health check
9. smoke test
10. rollback 또는 release promotion
