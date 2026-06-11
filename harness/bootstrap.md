# Bootstrap Guide

이 문서는 신규 환경을 처음 기동할 때 필요한 cold-start 절차를 정의한다.

## 1. Bootstrap 목표

신규 환경은 다음 상태가 되어야 운영 가능한 것으로 본다.

- DB schema가 최신 baseline migration까지 적용됨
- 최초 admin 또는 admin role mapping이 설정됨
- Web Console 로그인 가능
- default SLA policy가 생성됨
- default alert channel이 설정됨
- advisory initial sync가 시작됨
- initial sync 상태가 UI와 API에 표시됨
- synthetic service가 등록됨
- smoke test credential이 발급됨

## 2. Bootstrap 순서

1. PostgreSQL 생성
2. secret/config 주입
3. DB migration baseline 적용
4. admin role seed 또는 OIDC group mapping 적용
5. default SLA policy seed
6. default alert channel seed
7. smoke test service account/token 생성
8. synthetic service 등록
9. SCA Monitor 자기 자신의 dependency snapshot push 설정
10. advisory initial sync 시작
11. Web Console 접근 확인
12. smoke test 실행

## 3. Initial Advisory Sync

OSV 최초 데이터 덤프 import는 오래 걸릴 수 있다.
initial sync가 완료되기 전에는 매칭 결과가 불완전하다.

정책:

- initial sync 완료 전 dashboard에는 `advisory data initializing` 상태를 표시한다.
- initial sync 완료 전에는 "영향 없음" 결론을 확정하지 않는다.
- Critical/High alert 발송은 source별 initial sync 완료 후 활성화한다.
- 수동으로 smoke test용 synthetic advisory fixture를 사용할 수 있다.

## 4. Synthetic Service

첫 등록 서비스는 SCA Monitor 자기 자신을 권장한다.

목적:

- snapshot push flow 검증
- impact 조회 flow 검증
- Web Console service/impact 화면 검증
- CI/CD smoke test 대상 확보
- SCA Monitor 자체 공급망 보안 모니터링

권장 service_id:

```text
sca-monitor
```

권장 environment:

```text
stage
prod
```

## 5. Smoke Credential

CI/CD smoke test는 별도 machine credential을 사용한다.

권장 권한:

```text
viewer
synthetic-service:push
```

금지:

- 전체 admin 권한 부여
- prod 실제 서비스에 대한 write 권한 부여
- 만료일 없는 token

## 6. Bootstrap 완료 기준

```text
GET /health -> 200
GET /ready -> 200
Web Console login -> success
GET /api/v1/overview -> 200
synthetic service visible -> true
synthetic snapshot accepted -> true
worker health -> ok
alert outbox processing -> ok
```

