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
- `GET /api/v1/overview`의 `advisory_sync_readiness.status`가 `ready`가 될 때까지 bootstrap 초기화 상태로 간주한다.
- initial sync 완료 전에는 "영향 없음" 결론을 확정하지 않는다.
- Critical/High alert 발송은 source별 initial sync 완료 후 활성화한다.
- 수동으로 smoke test용 synthetic advisory fixture를 사용할 수 있다.

bootstrap 자동화는 다음 명령으로 필수 advisory source의 initial sync를 순차 실행할 수 있다.

```bash
python3 scripts/bootstrap_advisory_sync.py --json
```

기본 실행 대상은 OSV npm dump, CISA KEV catalog, OpenSSF `MAL-*` malicious package record이다.
대용량 OpenSSF scan을 bootstrap window 안에 제한해야 하면 `--openssf-scan-limit`을 사용할 수 있으며, 이 경우 dump 전체를 끝까지 확인하지 못하면 결과는 `blocked`로 반환된다.

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

## 6. Default Alert Channel Seed

배포 자동화는 secret store 또는 원격 `.env`에 실제 alert router webhook URL을 주입한 뒤 기본 alert channel을 seed한다.
placeholder/example target은 운영 seed에서 거부된다.

```bash
SCA_MONITOR_DEFAULT_ALERT_CHANNEL_NAME=default-webhook \
SCA_MONITOR_DEFAULT_ALERT_WEBHOOK_URL=https://alert-router.example.internal/webhook \
python3 scripts/seed_default_alert_channel.py --json
```

dev fixture에서만 placeholder URL이 필요하면 `--allow-placeholder`를 명시한다.
seed 이후에는 live dispatcher enable 전 `python3 scripts/alert_dispatcher_activation_check.py --json`이 `ready`를 반환해야 한다.

## 7. Bootstrap Readiness Check

bootstrap 자동화는 최종 완료 판정 전에 read-only gate를 실행한다.

```bash
python3 scripts/bootstrap_readiness_check.py --json
```

이 gate는 DB migration/readiness, `advisory_sync_readiness`, alert dispatcher activation checklist를 확인한다.
alert target이 아직 없는 advisory-only bootstrap 단계에서는 다음처럼 alert gate를 제외할 수 있다.

```bash
python3 scripts/bootstrap_readiness_check.py --json --skip-alert-activation
```

원격 배포 자동화에서 같은 gate를 강제하려면 `SCA_MONITOR_BOOTSTRAP_READINESS`를 설정한다.
`advisory`는 alert dispatcher activation을 제외한 bootstrap readiness만 확인하고, `advisory-freshness`는 여기에 advisory source freshness까지 stop gate로 추가한다.
`required`는 alert activation까지 포함한 full readiness를 요구한다.

```bash
SCA_MONITOR_BOOTSTRAP_READINESS=advisory scripts/deploy_remote.sh
SCA_MONITOR_BOOTSTRAP_READINESS=advisory-freshness scripts/deploy_remote.sh
SCA_MONITOR_BOOTSTRAP_READINESS=required scripts/deploy_remote.sh
```

`advisory-freshness` 모드는 내부적으로 다음 검증을 수행한다.

```bash
python3 scripts/bootstrap_readiness_check.py --json --skip-alert-activation --require-advisory-freshness
```

## 8. Bootstrap 완료 기준

```text
GET /health -> 200
GET /ready -> 200
Web Console login -> success
GET /api/v1/overview -> 200
bootstrap_readiness_check -> ready
synthetic service visible -> true
synthetic snapshot accepted -> true
worker health -> ok
alert outbox processing -> ok
```
