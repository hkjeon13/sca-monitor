# SCA Monitor Harness(배포 자동화 지침서) 검토 보고서

- 검토일: 2026-06-10
- 검토 대상: `harness/` 폴더 전체 (11개 문서)
  - `README.md`, `requirements.md`, `implementation-plan.md`
  - `deployment-environment.md`, `network-and-ports.md`
  - `backend-deployment.md`, `frontend-deployment.md`, `database-deployment.md`
  - `secrets-and-config.md`, `cicd-automation.md`, `operations-runbook.md`
- 관련 문서: `docs/software-design-specification.md`(SDS), `docs/design-review-2026-06-10.md`(설계 검토 보고서)
- 검토 관점: 구현 가능성, 구체성, 문서 체계 무결성, 배포 절차 안전성

## 1. 총평

배포 자동화 지침서로서의 뼈대가 잘 갖춰져 있다. 특히 다음이 강점이다.

- 설계 검토 보고서(design-review)의 권고가 다수 선반영됨: advisory feed-sync, alert outbox, canonicalization, content hash dedup, `approved_by` 서버 측 결정, push credential 바인딩, `ON DELETE SET NULL` retention 처리 등.
- REQUIRED / ASSUMED / CONFIRMED 상태 관리로 미결정 항목이 명시적으로 추적됨.
- 배포 중단(stop rule), rollback 기준, 운영 지표, 장애 대응 절차가 구체적으로 정의됨.

다만 **문서 체계상의 모순 1건(기준 문서 역전)과, 그대로 자동화하면 실제 배포 사고로 이어지는 절차 결함(migration 호환성, readiness 체크, DB rollback 자동화)** 이 있다. 본 문서는 발견 사항을 심각도 순으로 정리하고 권장 수정안을 제시한다.

### 심각도 정의

| 심각도 | 의미 |
|---|---|
| Blocker | 해소하지 않으면 자동화가 잘못된 기준으로 구축되거나 배포 사고로 직결됨 |
| Major | 자동화 구현 전 반드시 결정/보완이 필요함 |
| Minor | 문서 일관성 또는 품질 개선 사항 |

### 발견 사항 요약

| ID | 심각도 | 분류 | 제목 |
|---|---|---|---|
| HR-01 | Blocker | 문서 체계 | 기준 문서 역전 — implementation-plan이 SDS에 없는 내용을 기준으로 함 |
| HR-02 | Major | 문서 체계 | 요구사항 ID 충돌 및 중복 등록 |
| HR-03 | Major | 문서 체계 | Web Console과 overview API가 SDS에 존재하지 않음 |
| HR-04 | Blocker | 배포 절차 | Migration 호환성(expand/contract) 규칙 부재 |
| HR-05 | Blocker | 배포 절차 | `/ready`의 "migration version 최신" 체크가 롤링 배포를 깨뜨림 |
| HR-06 | Major | 배포 절차 | DB migration rollback이 자동화 단계에 포함됨 |
| HR-07 | Major | 배포 절차 | Smoke test의 인증 수단 미정의 |
| HR-08 | Major | 배포 절차 | Cold-start/bootstrap 절차 부재 |
| HR-09 | Major | 배포 절차 | Worker 동시성·graceful shutdown·중복 발송 방지 미정 |
| HR-10 | Major | 누락 결정 | 관측성 스택이 REQUIRED 목록에 없음 |
| HR-11 | Major | 누락 결정 | OSV 데이터 덤프의 실제 도메인 미명시 |
| HR-12 | Minor | 누락 결정 | DB 사용자 모델 불일치 |
| HR-13 | Minor | 정합성 | env var 네이밍·조건부 표기·container 전제 정리 |
| HR-14 | Minor | 정합성 | Frontend artifact 버전 보관 규칙 부재 |
| HR-15 | Minor | 누락 결정 | Daily Digest 발송 시각/timezone 미결정 |
| HR-16 | 제안 | 품질 | Dogfooding — 자기 자신을 첫 등록 서비스로 사용 |

## 2. Blocker

### HR-01. 기준 문서 역전 — implementation-plan이 SDS에 없는 내용을 기준으로 함

- 위치: `harness/implementation-plan.md` 1장·3장, `harness/README.md`
- 심각도: Blocker

**문제.** implementation-plan은 "SDS를 단일 기준 설계 문서로 사용한다"고 선언하지만, Phase 1~3의 구현·검증 항목은 설계 검토 보고서(design-review)의 **권고안이지 현재 SDS에는 없는 내용**이다.

- Phase 1: "impact identity unique test", "content hash dedup test" — 현재 SDS는 여전히 `unique(dedupe_key)`(RV-01 미반영), content hash dedup 미기술(RV-16 미반영).
- Phase 3: "advisory feed-sync worker", "advisory canonicalization", "alert outbox dispatcher", "SLA/digest worker" — 현재 SDS는 querybatch 중심 수집(RV-02), canonicalization 부재(RV-03), 전달 메커니즘 미정(RV-12), Daily Digest 부재(RV-09).

이 상태로 구현을 시작하면 "SDS 기준"이라는 선언과 실제 구현 기준이 다르고, SDS·design-review·harness 세 문서가 서로 다른 내용을 기준으로 발산한다.

**권장.**

1. Phase 0에 선행 작업을 명시한다: "design-review의 Blocker(RV-01~05) 및 관련 Major 항목을 SDS에 반영하고, SDS 개정판을 기준으로 Phase 1을 시작한다."
2. 또는 SDS를 먼저 개정한 뒤 harness 문서가 개정판 절 번호를 참조하게 한다.
3. implementation-plan의 각 Phase 항목에 SDS 절 번호(또는 RV ID)를 표기해 기준을 추적 가능하게 만든다.

### HR-04. Migration 호환성(expand/contract) 규칙 부재

- 위치: `harness/cicd-automation.md` 2장, `harness/database-deployment.md` 3장
- 심각도: Blocker

**문제.** pipeline은 DB migration 실행(stage G) 후 API 배포(stage H) 순서다. migration이 실행되는 시점에 **구버전 API/worker가 살아서 트래픽을 처리 중**이므로, migration이 구버전 코드와 호환되지 않으면(컬럼 삭제, rename, NOT NULL 추가 등) 배포 때마다 장애가 난다. database-deployment의 Migration Rules에는 destructive migration 승인 규칙만 있고 **호환성 규칙이 없다**. 동시에 두 pipeline이 migration을 실행하는 경합에 대한 언급도 없다.

**권장.** Migration Rules에 다음을 추가한다.

1. **expand/contract 원칙**: 모든 migration은 직전 배포 버전(N-1) 코드와 호환되어야 한다. 컬럼/테이블 제거·rename은 "코드에서 참조 제거 배포 → 다음 릴리스에서 contract migration" 2단계로 분리한다.
2. **NOT NULL/default 추가**는 backfill과 분리해 lock 시간을 최소화한다.
3. **migration lock**: migration 도구의 lock 기능(또는 advisory lock)으로 동시 실행을 차단하고, CI에서 동일 환경 동시 배포를 금지한다.
4. CI에 "migration이 N-1 코드와 호환되는가" 리뷰 체크리스트를 추가한다.

### HR-05. `/ready`의 "migration version 최신" 체크가 롤링 배포를 깨뜨림

- 위치: `harness/backend-deployment.md` 3장
- 심각도: Blocker

**문제.** `/ready`가 "migration version 최신 여부"를 확인한다. migration이 코드 배포보다 먼저 실행되는 pipeline 구조에서는, migration 직후 **아직 교체되지 않은 구버전 인스턴스 전체가 일제히 not-ready**가 되어 롤링 배포 중 가용성이 무너진다. 또한 rollback(이전 image 배포) 시에도 DB는 새 version이므로 rollback된 인스턴스가 영구 not-ready가 되어 HR-06의 rollback 절차 자체를 막는다.

**권장.** readiness 기준을 "현재 코드가 요구하는 **최소 migration version 이상**인지"로 변경한다 (코드마다 `required_migration_version`을 내장). HR-04의 expand/contract 원칙이 지켜지면 구버전 코드는 신규 스키마 위에서 정상 동작하므로 이 기준으로 충분하다.

## 3. Major — 문서 체계

### HR-02. 요구사항 ID 충돌 및 중복 등록

- 위치: `harness/requirements.md` 4장, `harness/network-and-ports.md` 6장, SDS 5.7
- 심각도: Major

**문제.**

1. **ID 충돌**: `harness/requirements.md`의 `REQ-SRC-001~006`이 SDS 5.7의 `REQ-SRC-001~007`과 같은 ID 체계를 쓰면서 의미가 다르다. (SDS REQ-SRC-001 = 내부 서비스 dependency source 결정 / harness REQ-SRC-001 = OSV 수집 방식). 추적성 매트릭스 작성 시 충돌한다.
2. **중복 등록**: `network-and-ports.md`의 `REQ-NET-PORT-001~005`는 requirements.md의 기존 항목과 같은 결정이다.
   - REQ-NET-PORT-001 (Web Console 주소) = REQ-ENV-002
   - REQ-NET-PORT-002 (API 주소) = REQ-ENV-003
   - REQ-NET-PORT-003 (egress IP) = REQ-NET-004
   - REQ-NET-PORT-004 (DB private network) = REQ-NET-005
   같은 결정이 두 ID로 추적되면 한쪽만 CONFIRMED로 바뀌는 불일치가 생긴다.

**권장.**

- harness 쪽 ID에 SDS와 겹치지 않는 네임스페이스를 사용한다 (예: `REQ-DEP-SRC-*` 또는 문서 prefix).
- **결정 1건 = ID 1개** 원칙으로 `requirements.md`를 단일 결정 원장으로 삼고, 다른 harness 문서는 신규 ID를 만들지 않고 기존 ID를 참조만 한다. `REQ-NET-PORT-*` 절은 참조 표로 교체한다.

### HR-03. Web Console과 overview API가 SDS에 존재하지 않음

- 위치: `harness/frontend-deployment.md` 전체, `harness/cicd-automation.md` 5장, SDS 6·14장
- 심각도: Major

**문제.** harness는 Web Console을 상세히 정의한다 — 화면 10종(MVP 필수 8종), 서비스 등록 wizard, accepted risk 승인 UI, OIDC 인증, 모바일 지원 범위. 그러나 SDS에는 "Admin UI / API Client" 박스 하나뿐이고 대응하는 FR이 없다. smoke test와 health check가 참조하는 `GET /api/v1/overview`도 SDS 14장 인터페이스 설계에 없다. 구현 범위가 설계서 밖에서 정의되고 있다.

**권장.**

- SDS에 Web Console 관련 FR을 추가한다 (예: FR-026 overview/dashboard 조회 API, FR-027 Web Console 제공 및 역할별 기능 범위). CSCI 분해에도 frontend 또는 BFF 위치를 반영한다.
- overview API의 응답 설계(집계 항목: open impact 수, risk별 분포, stale 서비스 수, sync 상태)를 SDS 14장에 추가한다.
- 즉시 반영이 어렵다면 requirements.md에 "SDS 보강 필요" 항목으로 등록해 추적한다.

## 4. Major — 배포 절차

### HR-06. DB migration rollback이 자동화 단계에 포함됨

- 위치: `harness/cicd-automation.md` 6장, `harness/backend-deployment.md` 5장
- 심각도: Major

**문제.** rollback 자동화 절차에 "DB rollback 가능 여부 확인"(step 4)이 포함돼 있다. prod에서 DB migration 자동 rollback은 migration 이후 쓰인 데이터를 파괴할 수 있어 자동화 대상이 아니다. backend-deployment 5장도 "migration rollback 가능 여부 확인"을 절차에 두어 같은 모호함이 있다.

**권장.**

- 원칙을 명시한다: **"rollback은 image-only가 기본이며, DB는 건드리지 않는다."** HR-04의 expand/contract가 지켜지면 구버전 image는 신규 스키마 위에서 동작하므로 image rollback만으로 안전하다.
- DB rollback은 자동화에서 제외하고 **수동 게이트**(운영자 승인 + backup 확인) 뒤에만 둔다. 기본 대응은 forward fix.

### HR-07. Smoke test의 인증 수단 미정의

- 위치: `harness/cicd-automation.md` 5장, `harness/secrets-and-config.md`
- 심각도: Major

**문제.** smoke 시나리오의 `GET /api/v1/overview`, `GET /api/v1/impacts`, `POST /api/v1/snapshots`는 모두 인증 뒤의 API다. CI는 OIDC 브라우저 로그인을 할 수 없으므로 별도 자격증명이 필요한데 secrets-and-config에 정의가 없다.

**권장.**

- 환경별 **smoke용 service account/token**을 정의한다: `SMOKE_TEST_TOKEN` — 최소 권한(viewer + synthetic service에 한정된 push 권한), 환경별 분리, 정기 rotation.
- secrets-and-config의 env var 목록과 REQ-SEC 항목에 추가한다.
- API 인증 설계에 "비대화형(machine) 자격증명" 유형을 포함하도록 SDS 인증 모델(RV-14)과 연결한다.

### HR-08. Cold-start/bootstrap 절차 부재

- 위치: `harness/implementation-plan.md` Phase 5, `harness/operations-runbook.md`
- 심각도: Major

**문제.** "clean environment bootstrap"이 Phase 5 검증 항목으로만 존재하고 실제 절차가 없다. 신규 환경 첫 기동 시 필요한 작업이 정의돼야 자동화할 수 있다.

- **OSV 최초 전체 import는 수 시간 소요**될 수 있다. 그동안 매칭 결과가 비어 있는 것이 정상인지, advisory sync 완료 전까지 "no impact" 결론과 alert을 보류할지(initial sync 완료 플래그) 결정이 필요하다.
- 초기 admin 계정 생성 방식 (OIDC 첫 로그인 사용자? seed script?)
- OIDC client 등록, redirect URI 설정
- smoke용 synthetic service 등록과 smoke credential 발급
- 기본 alert channel, SLA 설정값 seed

**권장.** `harness/bootstrap.md`(또는 operations-runbook 내 절)로 첫 기동 체크리스트를 작성하고, "initial advisory sync 완료 전에는 매칭 결과를 incomplete로 표시한다"는 동작을 SDS에 반영한다.

### HR-09. Worker 동시성·graceful shutdown·중복 발송 방지 미정

- 위치: `harness/backend-deployment.md` 1장, `harness/cicd-automation.md`
- 심각도: Major

**문제.** worker를 단일 image + `WORKER_ROLE`로 분리하는 방향은 좋으나, 배포·운영 관점의 동시성 규칙이 없다.

1. **역할별 replica 정책**: poll scheduler, advisory sync는 중복 실행 시 중복 polling/재매칭이 발생하므로 single-active(lease) 필요. matching/alert dispatcher는 다중 실행 가능하되 job 단위 lock 필요. 어느 역할이 몇 개 떠도 되는지 미정.
2. **graceful shutdown**: 배포로 worker가 교체될 때 처리 중 job의 완료 대기 시간, 미완료 job의 lease 회수(timeout 후 다른 인스턴스가 재처리) 규칙이 없다.
3. **alert 중복 발송**: outbox 발송 도중 worker가 종료되면 재기동 후 같은 alert이 재발송될 수 있다. at-least-once를 전제로 발송 기록 선커밋(sent 마킹) 또는 채널 측 멱등 키 전략이 필요하다.

**권장.** backend-deployment에 "Worker Concurrency Rules" 절을 추가한다: 역할별 replica 허용치 표, lease timeout과 회수 규칙, graceful shutdown 대기 시간(SIGTERM → N초), alert dispatch의 멱등 처리 방식. CI/CD의 worker 배포 단계에 drain 절차를 반영한다.

## 5. Major — 누락 결정

### HR-10. 관측성 스택이 REQUIRED 목록에 없음

- 위치: `harness/operations-runbook.md` 2장, `harness/requirements.md`
- 심각도: Major

**문제.** runbook의 운영 지표 6종(advisory_sync_lag_seconds 등)은 잘 정의됐지만, 이 지표를 **어디서 수집·조회·경보하는지**(Prometheus + Grafana? cloud monitoring? 로그 기반?)가 어느 문서에도 없다. 지표 노출 방식(/metrics endpoint? push?)도 미정이다. 또한 "모니터를 누가 모니터하는가" — 시스템 자체 장애(advisory sync 실패 = NFR-006, worker 정지, outbox 적체)를 받을 **운영 alert 채널**이 제품 alert 채널과 분리 정의돼 있지 않다.

**권장.**

- requirements.md에 추가: REQ-OBS-001 metrics 수집 스택, REQ-OBS-002 로그 수집/보관, REQ-OBS-003 시스템 자체 장애 운영 alert 채널(제품 alert과 분리), REQ-OBS-004 error tracking(frontend의 SENTRY_DSN 언급과 연결).
- backend-deployment health check 절에 `/metrics`(또는 선택한 노출 방식)를 추가한다.

### HR-11. OSV 데이터 덤프의 실제 도메인 미명시

- 위치: `harness/network-and-ports.md` 2장
- 심각도: Major

**문제.** outbound 표에 "OSV data dump endpoint"라고만 적혀 있다. OSV 덤프는 GCS 버킷(`gs://osv-vulnerabilities`)에서 제공되며 HTTPS로는 `storage.googleapis.com`을 통해 받는다. 이 표 그대로 방화벽 allowlist를 만들면 feed-sync(HR-01에서 기본 모델로 확정한 방식)가 차단된다.

**권장.** outbound 표의 OSV 행을 분리해 명시한다: `api.osv.dev`(query/단건 조회), `storage.googleapis.com`(데이터 덤프). CISA KEV도 redirect 가능성을 고려해 실제 feed URL 도메인을 배포 전 확인 항목으로 둔다.

## 6. Minor

### HR-12. DB 사용자 모델 불일치

- 위치: `harness/database-deployment.md` 6장, `harness/secrets-and-config.md` 2장
- 심각도: Minor

DB smoke test는 "API user로 read/write", "worker user로 outbox 조회"라며 **컴포넌트별 DB 계정**을 전제하는데, env var는 공용 `DATABASE_URL` 하나뿐이다. 계정 분리 여부를 결정하고(분리 권장: 최소 권한 + 감사 식별), 분리한다면 `API_DATABASE_URL`/`WORKER_DATABASE_URL`로 env var를 맞춘다.

### HR-13. env var 네이밍·조건부 표기·container 전제 정리

- 위치: `harness/secrets-and-config.md`, `harness/requirements.md`, `harness/cicd-automation.md`
- 심각도: Minor

1. **네이밍 불일치**: common의 `PUBLIC_BASE_URL` vs frontend의 `FRONTEND_PUBLIC_URL` — 같은 값이면 하나로 통일.
2. **조건부 표기**: `CORS_ALLOWED_ORIGINS`는 split domain(Option B) 선택 시에만 필요. `SLACK_BOT_TOKEN`과 `SLACK_WEBHOOK_URL`은 REQ-ALERT-001 결정에 따라 둘 중 하나만 필요. 조건을 표기하지 않으면 배포 시 "required env var 누락" stop rule과 충돌한다.
3. **container 전제 정리**: REQ-ENV-001은 "VM/Compose/K8s/PaaS 중 선택"으로 미결정인데, cicd pipeline·배포 산출물·rollback은 전부 container image를 전제한다. "container 사용은 ASSUMED, 미결정은 orchestration 방식(Compose/K8s/PaaS)"으로 좁혀 기술하는 것이 정확하다.

### HR-14. Frontend artifact 버전 보관 규칙 부재

- 위치: `harness/frontend-deployment.md` 3장, `harness/cicd-automation.md` 6장
- 심각도: Minor

rollback 자동화가 "frontend 이전 artifact 배포"를 포함하는데, static serving 방식에서는 이전 build artifact를 버전별로 보관해야 rollback이 가능하다. "최근 N개 release artifact를 버전 태그와 함께 보관"(object storage 경로 규칙 또는 frontend image 태그)을 명시한다. SPA의 index.html no-cache + hashed asset long-cache 정책도 함께 적는 것을 권장한다.

### HR-15. Daily Digest 발송 시각/timezone 미결정

- 위치: `harness/requirements.md` 7장
- 심각도: Minor

REQ-ALERT-003은 digest 채널만 다루고 발송 시각과 timezone(조직 단일 timezone vs 팀별)이 없다. SLA 계산의 영업일/휴일 처리 여부와 함께 REQ-ALERT 항목으로 추가한다.

## 7. 제안

### HR-16. Dogfooding — 자기 자신을 첫 등록 서비스로 사용

SCA Monitor 자신의 dependency snapshot을 CI/CD에서 push하는 **synthetic service로 등록**하면 다음을 한 번에 해결한다.

- smoke test의 push/매칭/조회 시나리오가 실제 데이터로 동작 (HR-07의 synthetic service)
- 모니터 자체의 공급망 보안 셀프 모니터링
- 신규 기능의 end-to-end 회귀 검증 환경

bootstrap 절차(HR-08)에 "self-registration" 단계로 포함하는 것을 권장한다.

## 8. 권장 반영 순서

1. **기준 정리 (HR-01, HR-02)**: SDS에 design-review 반영 → implementation-plan이 개정 SDS를 참조. 요구사항 ID 네임스페이스 정리. 이후 모든 작업의 전제.
2. **배포 안전성 (HR-04, HR-05, HR-06)**: migration 호환성 원칙, readiness 기준 수정, image-only rollback 원칙. CI/CD 구현(Phase 5) 전 필수이며, 사실상 Phase 1 migration baseline 작성 시점부터 적용해야 한다.
3. **자동화 전제 (HR-07, HR-08, HR-09, HR-10, HR-11)**: smoke 자격증명, bootstrap 절차, worker 동시성 규칙, 관측성 스택 결정, 방화벽 도메인 확정.
4. **정리 (HR-03, HR-12~HR-15)**: SDS에 Web Console FR 추가, env var·artifact·digest 시각 등 보완.

1~2번은 Phase 0(기술 스택 확정)과 함께 처리하고, 3번은 Phase 5(Deployment Automation) 착수 전까지 확정하면 된다.
