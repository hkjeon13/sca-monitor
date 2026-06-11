# SCA Monitor 설계 검토 보고서

- 검토일: 2026-06-10
- 검토 대상:
  - `docs/software-design-specification.md` (이하 SDS)
  - `docs/reported-supply-chain-alert-platform.md` (이하 Platform)
- 검토 관점: 구현 가능성, 구체성, 설계 무결성, 품질/운영 최적화

## 1. 총평

범위 정의(자체 탐지를 하지 않고 보고된 advisory를 자산과 매칭)가 명확하고, 외부 소스 조사(수집 API·필드까지 확정), DB 설계, 요구사항 추적성 매트릭스를 갖춘 완성도 높은 설계서이다.

다만 구현 착수 시 바로 막히거나 운영에서 alert 품질을 해치는 **모순/공백이 일부 존재**한다. 본 문서는 발견 사항을 심각도 순으로 정리하고 권장 결정안을 제시한다.

### 심각도 정의

| 심각도 | 의미 |
|---|---|
| Blocker | 해소하지 않으면 구현이 잘못된 방향으로 진행되거나 핵심 목표(NFR)와 모순됨 |
| Major | 구현 단계에서 반드시 결정이 필요하나, 설계서 보완으로 해소 가능 |
| Minor | 문서 일관성 또는 품질 개선 사항 |

### 발견 사항 요약

| ID | 심각도 | 분류 | 제목 |
|---|---|---|---|
| RV-01 | Blocker | 설계 무결성 | dedupe key에 artifact_digest 포함 → 배포마다 재알림 |
| RV-02 | Blocker | 설계 무결성 | Advisory 수집 모델이 query형과 feed-sync형을 혼용 |
| RV-03 | Blocker | 설계 무결성 | 소스 간 동일 취약점 중복(canonicalization 부재) |
| RV-04 | Blocker | 설계 무결성 | Retention 정책이 impacts FK를 깨뜨림 |
| RV-05 | Blocker | 설계 무결성 | "최신 snapshot" 개념 부재로 재매칭 범위 불명확 |
| RV-06 | Major | 설계 무결성 | 서비스 식별 모델과 environment 차원 불일치 |
| RV-07 | Major | 설계 무결성 | 상태 enum이 절마다 상이 |
| RV-08 | Major | 설계 무결성 | 클래스 다이어그램과 DB 모델 불일치 |
| RV-09 | Major | 설계 무결성 | 두 문서 간 기능 누락/모순 (Daily Digest, Risk 규칙, SLA, 보안 항목) |
| RV-10 | Major | 구현 가능성 | Version range matcher의 범위·실패 정책 미정 |
| RV-11 | Major | 구현 가능성 | 패키지명 정규화 규칙 부재 → false negative 위험 |
| RV-12 | Major | 구현 가능성 | 컴포넌트 간 전달 메커니즘(큐/outbox) 미정의 |
| RV-13 | Major | 구현 가능성 | Push API 자격증명 모델 부재 |
| RV-14 | Major | 구현 가능성 | 관리 API 인증/인가 모델 부재, approved_by 무결성 결함 |
| RV-15 | Major | 구현 가능성 | 외부 API rate limit·동기화 커서 미반영 |
| RV-16 | Major | 품질 최적화 | Snapshot 저장량 — content hash dedup 필요 |
| RV-17 | Major | 품질 최적화 | Freshness 정의가 미재배포 서비스를 영구 stale로 만듦 |
| RV-18 | Major | 품질 최적화 | Risk 산정 규칙의 비결정성 ("후보" 표현) |
| RV-19 | Minor | 품질 최적화 | Impact 상태 전이 누락 |
| RV-20 | Minor | 품질 최적화 | Alert payload에 행동 가능한 링크 부재 |
| RV-21 | Minor | 품질 최적화 | 관측성 NFR 누락 |
| RV-22 | Minor | 품질 최적화 | Push API 입력 제한·멱등 규약 미정의 |

## 2. Blocker — 구현 착수 전 반드시 해소

### RV-01. dedupe key에 artifact_digest 포함 → 배포마다 재알림

- 위치: SDS 16.1, 13.2 `impacts`, Platform 14장
- 심각도: Blocker

**문제.** dedupe key가 `service_id + advisory_id + package_name + resolved_version + artifact_digest + environment` 조합이다.

1. 매일 배포하는 서비스는 취약점을 고치지 않아도 배포마다 `artifact_digest`가 바뀌어 새 impact와 새 alert이 발생한다. NFR-007(alert fatigue 억제)과 정면 충돌한다.
2. `impacts.dedupe_key`가 unique 제약이므로 regression(Fixed → Open) 시 같은 키로 새 row를 만들 수 없어 기존 row를 재사용해야 하는데, 이 경우 `first_detected_at`의 의미가 모호해진다.

**권장.** "impact의 식별자"와 "alert 억제 키"를 분리한다.

- impact identity: `(service_id, environment, advisory_id, package_name)` — 이 단위로 unique 제약.
- `resolved_version`, `artifact_digest`, `snapshot_id`는 impact의 발생 이력 속성(최신 관측값 + `impact_history`)으로 관리.
- alert 억제는 `(impact identity + 마지막 발송 시점의 risk_level/상태)` 기준으로 판단. 버전이 바뀌었지만 여전히 취약한 경우의 재알림 여부는 별도 정책으로 명시(권장: risk 변동 없으면 억제, digest에 포함).

### RV-02. Advisory 수집 모델이 query형과 feed-sync형을 혼용

- 위치: SDS 5.2, 6장 개념도, FR-009, 10.2, NFR-010
- 심각도: Blocker

**문제.** SDS 5.2는 "snapshot의 package 목록을 `querybatch`로 질의"하는 query-per-snapshot 모델을 기술하지만, 6장 개념도·FR-009·10.2 시퀀스는 advisory를 통째로 동기화해 두고 로컬 매칭하는 feed-sync 모델이다. 두 모델은 서로 다른 아키텍처이다.

- NFR-010("외부 소스 장애 시 기존 advisory DB로 매칭 지속")은 query 방식으로는 신규 패키지에 대해 충족 불가능하다.
- `POST /v1/querybatch`는 vulnerability의 **id와 modified만** 반환하므로 어차피 건별 `GET /v1/vulns/{id}` 후속 호출이 필요하다.
- 대량 동기화 용도로는 OSV가 공식 제공하는 GCS 데이터 덤프(`gs://osv-vulnerabilities`, ecosystem별 `all.zip`)가 정석이다.

**권장.** feed-sync를 기본 모델로 확정한다.

- 최초 적재: OSV 데이터 덤프 일괄 import (MVP 대상 ecosystem만).
- 증분: `modified` 기준 주기 동기화.
- `querybatch`는 신규 snapshot 수집 직후 즉시 매칭의 보조 수단으로만 명시(로컬 DB 매칭 결과와 병합).
- SDS 5.2를 위 구조로 수정하고, 6장 개념도와 일치시킨다.

### RV-03. 소스 간 동일 취약점 중복 — canonicalization 부재

- 위치: SDS 13.2 `advisories`/`advisory_aliases`, 5.8
- 심각도: Blocker

**문제.** 같은 CVE 하나가 OSV record, GHSA record, NVD record로 각각 수집되면 `advisories.advisory_id`(text unique)가 모두 달라 advisory row가 3개 생기고, 같은 서비스·패키지에 impact가 3건 생겨 alert도 3번 발송된다. alias 테이블은 존재하지만 병합 규칙이 없다. GitHub `type=malware` advisory와 OpenSSF `MAL-*` record도 상당 부분 중복된다.

**권장.**

- alias 그룹 단위 canonical advisory 결정 규칙을 명시: 소스 우선순위 `OSV > GHSA > NVD`(KEV·NVD는 enrichment 전용으로 advisory row를 만들지 않음).
- advisory ingest 시 alias로 기존 advisory를 조회해 신규 생성 대신 병합(enrichment)한다.
- impact 생성/dedupe는 canonical advisory 기준으로 수행한다.
- `advisories`에 `canonical_advisory_id`(self FK, nullable) 또는 "merged into" 상태를 추가해 사후 병합도 지원한다.

### RV-04. Retention 정책이 impacts FK를 깨뜨림

- 위치: SDS 13.4, 13.2 `impacts`
- 심각도: Blocker

**문제.** historical snapshot 보존 기간은 90일인데, `impacts`는 `snapshot_id`, `dependency_id`를 FK로 참조하고 open impact는 "해결 후에도 보존"이다. 90일 이상 열려 있는 impact의 참조 대상이 삭제되어 FK 위반 또는 dangling reference가 발생한다.

**권장.** 다음 중 하나를 명시한다.

1. (권장) impact에 필요한 값(package, version, digest 등 — 이미 비정규화돼 있음)을 신뢰 원본으로 삼고, `snapshot_id`/`dependency_id` FK는 nullable + `ON DELETE SET NULL`로 정의.
2. open/acknowledged/in_progress impact가 참조하는 snapshot은 retention 예외로 보존.

### RV-05. "최신 snapshot" 개념 부재 — 재매칭 범위 불명확

- 위치: SDS 13.2 `dependencies`, FR-013, 10.2
- 심각도: Blocker

**문제.** advisory 변경 시 재매칭(FR-013)은 각 서비스의 **현재 배포 상태**, 즉 최신 snapshot에 대해서만 수행해야 한다. 그러나 데이터 모델에 latest/current 개념이 없어, 문면대로 구현하면 90일치 historical snapshot 전체를 재매칭하게 되고, 과거 snapshot에서 impact가 생성되는 오동작 여지가 있다.

**권장.**

- `services`(또는 service-environment 단위)에 `latest_snapshot_id` FK를 추가하거나 `dependency_snapshots.is_latest` partial unique index를 도입.
- 재매칭 대상을 "각 서비스의 latest snapshot"으로 FR-013에 명시.
- 새 snapshot 수집 시 open impact의 `snapshot_id`/`last_seen_at`을 최신으로 갱신하는 규칙을 10.3 시퀀스에 추가.

## 3. Major — 설계 무결성

### RV-06. 서비스 식별 모델과 environment 차원 불일치

- 위치: SDS 13.2 `services`, FR-001, NFR-004
- 심각도: Major

**문제.** `services.service_id`가 text unique인데 `environment`가 같은 테이블의 일반 컬럼이다. 동일 서비스의 prod/stage를 등록하려면 service_id 자체를 다르게 발급해야 하고, 그러면 NFR-004의 spoofing 검증(응답 `service_id` 대조)과 snapshot의 `environment` 필드 검증 의미가 흔들린다.

**권장.** `unique (service_id, environment)`로 변경하거나, service(논리 서비스)와 deployment(환경별 인스턴스)를 분리한다. snapshot 검증 규칙도 "등록된 (service_id, environment) 쌍과 응답 값이 모두 일치해야 함"으로 명시한다.

### RV-07. 상태 enum이 절마다 상이

- 위치: SDS FR-007, 13.2 `endpoint_health`·`dependency_snapshots`, Platform 8·9장
- 심각도: Major

**문제.** 같은 개념의 상태값이 네 곳에서 서로 다르게 정의된다.

| 위치 | 값 |
|---|---|
| FR-007 | fresh, stale, unreachable, invalid |
| endpoint_health.snapshot_status | fresh, stale, unreachable, auth_failed, invalid_response |
| dependency_snapshots.snapshot_status | fresh, stale, invalid |
| Platform 8장 | healthy, stale, unreachable, auth_failed, invalid_response |

**권장.** 직교하는 두 개념으로 분리해 통일한다.

- endpoint 수집 상태: `ok | unreachable | auth_failed | invalid_response` (endpoint_health 소관)
- snapshot freshness: `fresh | stale` (dependency_snapshots 소관)

FR-007과 Platform 문서를 이 두 enum 기준으로 재기술한다.

### RV-08. 클래스 다이어그램과 DB 모델 불일치

- 위치: SDS 11장, 13.2
- 심각도: Major

**문제.**

1. `Advisory` 클래스는 단일 `ecosystem/packageName`을 갖지만, OSV advisory 하나가 여러 패키지·여러 ecosystem에 영향을 줄 수 있다. DB는 `affected_ranges` 1:N으로 올바르게 정규화돼 있으므로 클래스 모델이 틀렸다.
2. `AuditLog` 클래스에 DB의 `before/after` 컬럼이 없다.

**권장.** 클래스 다이어그램에 `AffectedPackage`(ecosystem, packageName, ranges, fixedVersions)를 분리해 `Advisory "1" --> "*" AffectedPackage`로 수정하고, AuditLog에 before/after를 추가한다.

### RV-09. 두 문서 간 기능 누락/모순

- 위치: Platform 15·16·19장 ↔ SDS 전반
- 심각도: Major

**문제.**

1. **Daily Digest**(Platform 16장)가 SDS에 없다 — 대응 FR, CSU(digest scheduler), alert_events 모델 반영 모두 누락.
2. **Risk 규칙 모순**: Platform 15장은 "fix version 없음 + 운영 영향 = Critical"(severity 무관이라 low severity까지 Critical로 승격되는 과도한 규칙), SDS 15장은 "fix 없음 = 조치 난이도 표시 및 우선순위 보강"으로 상이.
3. **SLA 기본값**(Critical 24h / High 7d / Medium 30d / Low 추적만)이 Platform에만 있고 SDS에는 FR-022("risk level별 SLA 계산")만 있다. SLA 설정의 저장 위치(전역 설정 vs 서비스별 override)도 미정.
4. **보안 항목 누락**: egress IP allowlist, endpoint 접근 로그(Platform 7장)가 SDS 17장 보안 설계에 없다.

**권장.** SDS를 단일 기준 문서로 삼아 위 4건을 SDS에 흡수하고(FR 추가, Risk 규칙은 SDS안 채택 권장), Platform 문서에는 "설계 상세는 SDS 기준" 문구를 추가해 이중 관리를 끊는다.

## 4. Major — 구현 가능성

### RV-10. Version range matcher의 범위·실패 정책 미정

- 위치: SDS 7.2 `EcosystemVersionRangeMatcher`, FR-014
- 심각도: Major

**문제.** 이 시스템에서 구현 난도가 가장 높은 부분이 CSU 한 줄로만 표현돼 있다.

- ecosystem별 버전 체계가 전부 다르다: npm semver, PyPI PEP 440, Maven 버전 정렬, Go module pseudo-version 등.
- OSV affected range는 `type: SEMVER | ECOSYSTEM | GIT` + `events(introduced/fixed/last_affected/limit)` 구조다. `affected_ranges.version_range text` 단일 컬럼으로는 의미가 보존되지 않는다(원문은 raw_range jsonb에 있으나 매칭 시맨틱이 미정의). GIT 타입은 패키지 버전 매칭에 사용할 수 없다.
- 버전 문자열 파싱 실패 시 정책이 없다: fail-open이면 false negative(취약점 누락), fail-closed면 noise.

**권장.**

- MVP 지원 ecosystem을 명시(예: npm, PyPI, Maven, Go)하고 ecosystem별 매칭 라이브러리/구현 방식을 결정 항목으로 추가.
- `affected_ranges`를 OSV events 구조(introduced/fixed/last_affected)로 저장하도록 스키마를 보강하고, GIT 타입 range는 매칭 제외 규칙을 명시.
- 파싱 실패 정책은 **match-with-low-confidence**(매칭으로 처리하되 confidence flag를 낮춰 alert에 표시) 권장 — 보안 시스템은 false negative가 더 위험하다.
- 매칭 골든 테스트 셋(ecosystem별 edge case fixture)을 품질 활동으로 명시.

### RV-11. 패키지명 정규화 규칙 부재 → false negative 위험

- 위치: SDS 7.2 `DependencyNormalizer`, FR-008
- 심각도: Major

**문제.** ecosystem별 canonical name 규칙이 정의돼 있지 않다. PyPI는 대소문자·`-`/`_`/`.` 동치(PEP 503 normalization), npm은 scoped package(`@scope/name`), Maven은 `groupId:artifactId` 표기다. 정규화 없이 snapshot의 `Django`와 advisory의 `django`를 문자열 비교하면 매칭이 조용히 누락된다.

**권장.** "snapshot dependency와 advisory affected package 양쪽 모두 ecosystem별 canonical name으로 정규화 후 비교"를 FR-008에 명시하고, ecosystem별 규칙(PyPI: PEP 503 / npm: 소문자+scope 보존 / Maven: `group:artifact` 소문자)을 부록으로 추가한다. purl을 canonical key로 삼는 것을 권장한다.

### RV-12. 컴포넌트 간 전달 메커니즘 미정의

- 위치: SDS 6장, 10.1~10.3 시퀀스, 12장
- 심각도: Major

**문제.** "Matcher→Alert: alert candidate 발행"이 동기 함수 호출인지, job queue인지, DB 기반인지 정해져 있지 않다. 인프라 구성에 DB와 Audit Log만 있고 큐가 없다.

- alert은 at-least-once 전달 보장이 필요하다(매칭 트랜잭션 커밋 후 발송 실패 시 유실되면 안 됨).
- 워커(CSCI-002~005) 다중 인스턴스 운영 시 동일 endpoint 중복 polling, 동일 advisory 중복 재매칭 방지가 필요하다.

**권장.**

- MVP는 인프라 추가 없이 **DB outbox 패턴**(alert_events를 `pending` 상태로 같은 트랜잭션에 기록 → 발송 워커가 polling)을 권장. 별도 메시지 브로커 도입은 확장 시점 결정으로 미룬다.
- polling job은 `FOR UPDATE SKIP LOCKED` 또는 advisory lock 기반 lease를 명시해 다중 인스턴스 안전성을 확보한다.
- 18장 장애 처리 표에 "발송 워커 중단 시 pending alert은 재기동 후 발송"을 추가한다.

### RV-13. Push API 자격증명 모델 부재

- 위치: SDS 7.2 `PushAuthValidator`, 14.2, 13.2
- 심각도: Major

**문제.** `PushAuthValidator` CSU는 있으나 push용 credential 데이터 모델이 없다(`service_endpoints`는 polling용 인증 설정). 토큰 발급·회전·폐기 절차와, credential이 어느 service_id로 push할 수 있는지의 **바인딩**(타 서비스 service_id로 push하는 spoofing 방지 — NFR-004의 push 측면)이 미정의다. HMAC replay 방지(17장)에 필요한 nonce 저장소도 DB 설계에 없다.

**권장.**

- `push_credentials` 테이블 추가: `id, service_id FK, token_hash, scopes, expires_at, revoked_at, last_used_at`. 토큰은 해시만 저장.
- "push payload의 service_id/environment는 credential에 바인딩된 값과 일치해야 한다"를 NFR로 추가.
- HMAC nonce는 TTL 기반 저장(테이블 또는 캐시)으로 명시.

### RV-14. 관리 API 인증/인가 모델 부재, approved_by 무결성 결함

- 위치: SDS 8장 Auth Middleware, 14.3, FR-023
- 심각도: Major

**문제.**

1. Admin/Workflow API의 인증 방식(OIDC? API key?)과 역할 모델(누가 서비스 등록·impact 상태 변경·accepted risk 승인을 할 수 있는가)이 없다. `audit_logs.actor`는 인증된 주체의 존재를 전제한다.
2. 14.3에서 `approved_by`를 클라이언트가 request body로 보낸다 — 호출자가 임의 승인자를 기재할 수 있는 무결성 결함이다.

**권장.**

- `approved_by`는 인증된 principal에서 서버가 채우도록 API 명세 수정.
- 최소 역할 모델 정의: `admin`(서비스 등록/설정), `service-owner`(자기 서비스 impact 상태 변경), `security-approver`(accepted_risk 승인). 요청자 ≠ 승인자 분리를 REQ-SRC-006과 연결해 명시.
- 인증 방식 결정을 REQUIRED 항목(REQ-SRC-008)으로 추가.

### RV-15. 외부 API rate limit·동기화 커서 미반영

- 위치: SDS 5.4, 5.5, 7.2 connectors
- 심각도: Major

**문제.** NVD API는 API key 없이 30초당 5요청(키 보유 시 50), GitHub advisory API도 rate limit이 있다. connector 설계에 API key 관리, 백오프/재시도, 증분 동기화 커서(`lastModified`/`modified` window)의 저장 위치가 없다. 10.2의 "sync metadata 저장"이 유일한 언급이나 모델이 없다.

**권장.** `advisory_sync_state` 테이블 추가: `source, cursor(lastModified watermark), last_run_at, last_success_at, last_error, records_processed`. connector 공통 요구로 "rate limit 준수, 지수 백오프, 부분 실패 시 커서 미전진"을 명시. NVD/GitHub API key는 REQUIRED 결정 항목에 추가.

## 5. Major — 품질/운영 최적화

### RV-16. Snapshot 저장량 — content hash dedup 필요

- 위치: SDS 13.2 `dependencies`, 13.4
- 심각도: Major

**문제.** prod 1시간 polling 기준 1,000개 서비스 × 의존성 2,000개면 `dependencies`에 하루 약 4,800만 row가 적재된다. 대부분의 polling은 직전과 동일한 내용이다.

**권장.**

- snapshot 정규화 결과의 content hash를 `dependency_snapshots`에 저장하고, **직전 snapshot과 hash가 같으면 새 snapshot/dependencies row를 만들지 않고 `last_seen_at`(또는 `last_confirmed_at`)만 갱신**한다.
- 내용이 동일한 snapshot은 매칭도 생략한다(advisory 변경 재매칭 경로가 이미 별도로 존재하므로 안전).
- 이 경우 13.4의 partition/retention 부담도 크게 줄어 MVP 단일 테이블 기간이 길어진다.

### RV-17. Freshness 정의가 미재배포 서비스를 영구 stale로 만듦

- 위치: SDS FR-007, Platform 9장
- 심각도: Major

**문제.** freshness가 `now - generated_at` 기준인데, 권장 구현(빌드 시점 snapshot을 런타임에 서빙, Platform 7장)을 따르는 안정적인 서비스는 몇 주간 재배포가 없으면 polling이 정상이어도 **영원히 stale**이 되어 모든 alert에 불필요한 신뢰도 경고가 붙는다.

**권장.** 두 신호를 분리한다.

- **수집 신선도**: `now - last_successful_poll_at` (polling 방식의 기본 신뢰도 지표 — 수집이 정상이면 현재 배포 상태를 반영한다고 간주)
- **snapshot 나이**: `now - generated_at` (push 방식 및 "배포 artifact가 오래됨" 보조 지표)

polling 서비스의 stale 판정은 수집 신선도 기준으로, NFR-005의 임계값(1h/24h/7d)은 수집 신선도에 적용하는 것으로 재기술한다.

### RV-18. Risk 산정 규칙의 비결정성

- 위치: SDS 15장
- 심각도: Major

**문제.** "risk 1단계 상승 **후보**", "1단계 하향 **후보**"는 구현 불가능한 표현이다. 조정 규칙 간 적용 순서·중첩 시 상한/하한도 없다(예: dev dependency 하향이 KEV Critical을 깎을 수 있는가).

**권장.** 결정적 알고리즘으로 재기술한다.

1. base = severity 매핑 (critical→Critical, high→High, medium→Medium, low→Low)
2. override: malicious package 또는 (KEV ∧ prod) → Critical 확정 (이후 하향 불가)
3. modifier 합산: internet_facing +1, business_criticality=critical +1, environment∈{dev,stage} −1, scope=development −1 (단계 이동, 누적 상한 ±1 권장)
4. floor: KEV 또는 malicious는 High 미만으로 내리지 않음
5. snapshot freshness는 risk level이 아닌 confidence flag로만 반영 (현행 유지)

severity 매핑 자체도 명시 필요: OSV `severity`는 CVSS vector 배열이므로 점수→레이블 변환 규칙(CVSS 9.0+ → critical 등)과 소스 간 충돌 시 우선순위(GHSA 레이블 > NVD CVSS > OSV 계산값 등)를 정한다.

## 6. Minor

### RV-19. Impact 상태 전이 누락

- 위치: SDS 9.2
- 심각도: Minor

`Acknowledged`/`InProgress`에서 `NotAffected`/`FalsePositive`/`AcceptedRisk`로 가는 전이가 없다(조사 중 false positive 판명은 흔한 흐름). `AcceptedRisk → Fixed`(예외 승인 중 수정 완료)도 필요하다. 또한 `AcceptedRisk → Open`(만료)과 `NotAffected → Open`(evidence 변경)을 수행할 주체가 CSU에 배정돼 있지 않다 — `SlaEvaluator` 또는 별도 만료 평가 워커에 책임을 명시한다.

### RV-20. Alert payload에 행동 가능한 링크 부재

- 위치: SDS 16.3
- 심각도: Minor

payload에 `impact_id`와 콘솔/워크플로 deep link가 없어 수신자가 alert에서 ack·상태 변경으로 이어갈 수 없다. `impact_id`, `impact_url`, `dedupe_key` 추가를 권장한다.

### RV-21. 관측성 NFR 누락

- 위치: SDS 4.2
- 심각도: Minor

NFR-006(동기화 실패 alert) 외에 운영 메트릭 요구가 없다. 최소 셋: advisory sync lag(소스별 마지막 성공 이후 경과), poll 성공률, 신규 advisory 수집→alert 발송까지의 end-to-end 지연(이 시스템의 핵심 SLI), alert 발송 성공률. NFR로 1~2줄 추가를 권장한다.

### RV-22. Push API 입력 제한·멱등 규약 미정의

- 위치: SDS 14.2
- 심각도: Minor

payload 최대 크기, dependency 최대 개수, rate limit이 없다(인증된 클라이언트의 실수만으로 저장소가 부풀 수 있음). 중복 push(`unique(service_id, snapshot_id)` 충돌) 시 응답 규약도 필요하다 — 동일 내용이면 멱등 200, 동일 snapshot_id에 다른 내용이면 409를 권장한다.

## 7. 권장 반영 순서

1. **아키텍처 확정 (RV-02, RV-12)**: advisory feed-sync 모델 + DB outbox. 이후 모든 설계의 전제.
2. **데이터 모델 수정 (RV-01, RV-03, RV-04, RV-05, RV-06)**: impact identity 재정의, advisory canonicalization, latest snapshot, retention 예외, (service_id, environment) unique. 13장 스키마와 11장 클래스 다이어그램(RV-08) 동시 갱신.
3. **매칭 정밀도 (RV-10, RV-11)**: ecosystem 범위, affected range 저장 구조, 이름 정규화 규칙, 파싱 실패 정책.
4. **보안/인증 (RV-13, RV-14)**: push credential 모델, 관리 API 역할 모델, approved_by 서버 결정.
5. **정합화 (RV-07, RV-09, RV-15~RV-22)**: enum 통일, 두 문서 정합, 나머지 보완.

1~2번은 MVP 구현 순서(SDS 20장) 1단계 착수 전에 SDS에 반영하는 것을 권장한다. 3번은 OSV connector(5단계) 전까지, 4번은 push API 및 workflow API 구현 전까지 확정하면 된다.
