# Frontend Deployment

이 문서는 SCA Monitor Web Console 배포 기준을 정의한다.

## 1. Web Console 목적

사용자가 손쉽게 다음 작업을 수행할 수 있어야 한다.

- 서비스 등록
- endpoint polling 또는 push 방식 설정
- endpoint test
- 전체 보안 현황 모니터링
- service impact 조회
- impact 상태 변경
- accepted risk 요청/승인
- alert channel 설정: MVP는 Settings 화면에서 default webhook channel 등록/조회 지원

## 2. URL 요구사항

필수 결정:

```text
FRONTEND_PUBLIC_URL=https://sca.example.com
API_BASE_URL=https://sca.example.com/api
```

또는 split domain:

```text
FRONTEND_PUBLIC_URL=https://sca.example.com
API_BASE_URL=https://api.sca.example.com
```

## 3. 배포 방식

가능한 방식:

| 방식 | 설명 |
|---|---|
| Static files behind reverse proxy | `dist/`를 nginx 등으로 제공 |
| Frontend container | build artifact를 포함한 container 배포 |
| Object storage + CDN | S3/GCS 등 정적 호스팅 |

초기 자동화는 frontend container 또는 reverse proxy static serving 중 하나를 선택한다.

## 3.1 Artifact Versioning

rollback을 위해 frontend artifact는 version별로 보관한다.

권장:

```text
frontend-artifacts/<version>/
frontend-artifacts/<git_sha>/
```

또는 frontend container image를 사용한다.

```text
registry.example.com/sca-monitor-web:<version>
registry.example.com/sca-monitor-web:<git_sha>
```

보관 정책:

- 최근 10개 release artifact 보관
- prod에 배포된 artifact는 최소 90일 보관
- `index.html`은 no-cache
- hashed static assets는 long-cache

## 4. Build-Time Config

프론트 빌드 시 필요한 값:

```text
APP_ENV
FRONTEND_PUBLIC_URL
API_BASE_URL
OIDC_AUTHORITY
OIDC_CLIENT_ID
OIDC_REDIRECT_URI
SENTRY_DSN or equivalent observability endpoint
```

인증 방식이 확정되지 않았으면 OIDC 관련 값은 REQUIRED로 둔다.

## 5. Required Screens for MVP

| 화면 | MVP 포함 |
|---|---|
| Overview Dashboard | 필수 |
| Services List | 필수 |
| Service Registration Wizard | 필수 |
| Service Detail | 필수 |
| Impact List | 필수 |
| Impact Detail | 필수 |
| Impact Action Panel | 필수 |
| Integration Guide | 필수 |
| Alert Channel Settings | 선택 |
| Advisory Detail | 선택 |

## 6. Smoke Test

배포 후 다음을 확인한다.

- `FRONTEND_PUBLIC_URL` 접근 가능
- 정적 asset 200
- API base URL 연결 가능
- 로그인 redirect 정상
- Overview API 호출 성공
- 주요 route 직접 접근 시 200 또는 SPA fallback

## 7. Mobile Scope

모바일에서 우선 지원할 기능:

- Overview 핵심 지표 확인
- Impact detail 확인
- acknowledge/in-progress 상태 변경

모바일에서 후순위:

- 서비스 등록 wizard
- alert channel 설정
- 복잡한 다중 필터
