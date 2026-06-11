# Network and Ports

이 문서는 SCA Monitor 서버에서 필요한 inbound/outbound 통신과 포트를 정의한다.

## 1. Inbound Ports

| 대상 | 포트 | 프로토콜 | 접근 주체 | 필수 여부 | 설명 |
|---|---:|---|---|---|---|
| Reverse Proxy / Load Balancer | 443 | HTTPS | 사용자, CI/CD, 등록 서비스 push client | 필수 | Web Console 및 API 진입점 |
| Reverse Proxy / Load Balancer | 80 | HTTP | Let's Encrypt 또는 HTTP redirect | 선택 | 인증서 발급 또는 443 redirect |
| API Server 내부 | 8080 | HTTP | reverse proxy | ASSUMED | 실제 포트는 구현 시 확정 |
| Frontend 내부 | 3000 또는 8081 | HTTP | reverse proxy | 선택 | static container 사용 시 |
| PostgreSQL | 5432 | TCP | API/worker private network | 필수 | 외부 공개 금지 |

## 2. Outbound Access

| 목적 | 대상 | 포트 | 프로토콜 | 필수 여부 |
|---|---|---:|---|---|
| OSV API 보조 조회 | `api.osv.dev` | 443 | HTTPS | 필수 |
| OSV 데이터 덤프 | `osv-vulnerabilities.storage.googleapis.com` | 443 | HTTPS | 필수 |
| CISA KEV 수집 | `www.cisa.gov` | 443 | HTTPS | 필수 |
| GitHub Advisory / OpenSSF | `api.github.com`, `github.com`, `raw.githubusercontent.com` | 443 | HTTPS | 조건부 |
| NVD CVE API | `services.nvd.nist.gov` | 443 | HTTPS | 조건부 |
| Slack alert | Slack webhook/API endpoint | 443 | HTTPS | 조건부 |
| 사용자 webhook | 사용자 지정 webhook endpoint | 443 | HTTPS | 조건부 |
| Registered service polling | 각 서비스 dependency status endpoint | 443 또는 내부 포트 | HTTPS 권장 | 필수 |
| Container registry | registry endpoint | 443 | HTTPS | 배포 시 필수 |

외부 advisory source allowlist와 실제 egress 연결은 다음 preflight로 확인한다.
기본 CI는 네트워크를 호출하지 않고 목록만 검증하며, stage/prod 배포 전에는 `--check`를 실행한다.

```bash
python3 scripts/advisory_source_preflight.py --list-only --json
python3 scripts/advisory_source_preflight.py --check --json
SCA_MONITOR_ADVISORY_SOURCE_PREFLIGHT=required scripts/deploy_remote.sh
```

`--check`는 OSV API, OSV dump, CISA KEV, GitHub Security Advisory, NVD CVE API, OpenSSF malicious packages source에 HTTP GET을 수행한다.
출력에는 query string이나 token 값을 포함하지 않고 host/port, requirement reference, HTTP status만 남긴다.
`REQ-NET-006`이 미확정이거나 방화벽 allowlist가 적용되지 않은 환경에서는 이 gate가 `blocked` 또는 `degraded`를 반환할 수 있다.
`SCA_MONITOR_ADVISORY_SOURCE_PREFLIGHT=required`는 원격 배포 중 migration 전에 같은 check를 stop gate로 실행한다.
timeout은 `SCA_MONITOR_ADVISORY_SOURCE_PREFLIGHT_TIMEOUT`으로 조정한다.

## 3. Registered Service Endpoint 접근

중앙 서버가 polling하는 경우 등록 서비스는 다음 endpoint를 제공한다.

```text
GET https://<service-host>/.well-known/sca/dependencies
GET https://<service-host>/internal/sca/dependencies
GET https://<service-host>/status/dependencies
```

요구사항:

- 중앙 서버 egress IP allowlist
- bearer token, mTLS, HMAC 중 하나 이상
- 현재 MVP 자동화는 bearer token endpoint를 지원한다. mTLS/HMAC과 secret manager/KMS 연동은 배포 입력값 확정 후 추가한다.
- endpoint 접근 로그
- 응답에 secret/token/env 포함 금지

## 4. Push API 접근

endpoint 공개가 어려운 서비스는 outbound로 중앙 API에 push한다.

```text
POST https://<api-host>/api/v1/services/<service_id>/status
```

요구사항:

- push credential은 service/environment에 바인딩
- body에 `service_id`가 있으면 path의 `<service_id>`와 일치해야 함
- payload size limit
- rate limit
- idempotency rule
- 기존 `POST /api/v1/snapshots`는 호환 경로로 남기되 신규 자동화는 service-scoped status endpoint를 우선 사용

## 5. Firewall Checklist

| 체크 | 설명 |
|---|---|
| inbound 443 허용 | 사용자와 service push client 접근 |
| DB 5432 private 제한 | public internet 노출 금지 |
| outbound 443 허용 | advisory source, alert target, registry 접근 |
| egress IP 고정 | 등록 서비스 allowlist용 |
| service endpoint 접근성 검증 | stage/prod 서비스별 test 필요 |

## 6. Requirements Reference

`harness/requirements.md`를 단일 결정 원장으로 사용한다.
이 문서는 신규 requirement ID를 만들지 않고 관련 결정 ID를 참조한다.

| 참조 ID | 항목 |
|---|---|
| REQ-ENV-002 | 운영 Web Console HTTPS 주소 |
| REQ-ENV-003 | 운영 API HTTPS 주소 |
| REQ-NET-004 | 중앙 서버 고정 egress IP |
| REQ-NET-005 | PostgreSQL private network CIDR |
| REQ-NET-003 | 등록 서비스 endpoint 접근 경로 |
| REQ-DEP-SRC-001 | OSV 데이터 수집 방식 |
