# Deployment Environment

이 문서는 SCA Monitor의 운영 환경 구성 기준을 정의한다.

## 1. 구성 요소

| 구성 요소 | 설명 | 배포 단위 |
|---|---|---|
| Web Console | 사용자 UI | static build 또는 frontend container |
| API Server | REST API, auth, service/impact workflow | backend container |
| Worker | polling, advisory sync, matching, alert, SLA | worker container |
| PostgreSQL | 영속 저장소 | managed DB 또는 DB container |
| Reverse Proxy | HTTPS termination, routing | nginx, ingress, load balancer |

## 2. 권장 환경

초기 권장값:

```text
OS: Linux x86_64
Runtime: Docker or container runtime
Database: PostgreSQL 16+
TLS: HTTPS mandatory
Backend protocol: HTTP behind reverse proxy
Frontend: HTTPS static serving
```

## 3. 도메인 구성

다음 중 하나를 선택한다.

### Option A. Same-Origin

```text
Web Console: https://sca.example.com
API:         https://sca.example.com/api
```

장점:

- CORS 단순화
- cookie/session 인증 구성 쉬움

### Option B. Split Domain

```text
Web Console: https://sca.example.com
API:         https://api.sca.example.com
```

장점:

- API와 frontend scaling 분리
- API gateway 정책 분리

필요 결정:

- `REQ-ENV-002`: Web Console 실제 HTTPS 주소
- `REQ-ENV-003`: API 실제 HTTPS 주소

## 4. 환경 구분

권장 환경:

| 환경 | 목적 | 배포 방식 |
|---|---|---|
| dev | 개발/통합 테스트 | 자동 배포 가능 |
| stage | 운영 전 검증 | 승인 후 배포 |
| prod | 운영 | tag 또는 승인 기반 배포 |

## 5. Health Endpoint

API Server는 다음 endpoint를 제공한다.

```text
GET /health
GET /ready
GET /api/v1/overview
```

Worker는 HTTP endpoint를 열거나, deployment platform의 command-based health check를 제공한다.

권장 worker health 항목:

- DB 연결 가능
- advisory sync state 조회 가능
- alert outbox pending count 조회 가능
- worker lease 획득 가능

## 6. 배포 산출물

| 산출물 | 예 |
|---|---|
| backend image | `registry.example.com/sca-monitor-api:<version>` |
| worker image | `registry.example.com/sca-monitor-worker:<version>` |
| frontend artifact | `frontend/dist` 또는 frontend image |
| DB migration bundle | `migrations/` |
| deployment manifest | `deploy/compose` 또는 `deploy/k8s` |

