# 저장소 기반 프로젝트 모니터링 구현 계획

상태: 설계안. 이번 배포의 구현 범위는 목록 무한 스크롤이며, 아래 저장소·자격 증명·의존성 그래프 기능은 아직 구현하지 않는다.

## 사용자 흐름

1. 프로젝트에 GitHub/GitLab 저장소 URL, 브랜치 또는 태그, 선택적 하위 경로를 입력한다.
2. 비공개 저장소는 별도 자격 증명 보관함에서 연결 정보를 만들고 프로젝트에 연결한다. 저장소 URL에 토큰을 넣지 않는다.
3. 저장소의 특정 commit SHA를 기준으로 분석하고 모듈·의존성 파일 후보를 보여준다.
4. 발견한 구성은 자동 수집하고, 해석되지 않는 구성은 근거와 함께 검토 대상으로 제시한다.
5. 직접·전이 의존성 및 OS/런타임 패키지를 환경별로 확인하고 모니터링한다.
6. 저장소 변경 시 인벤토리를 갱신한다. 취약점 데이터가 갱신되면 기존 인벤토리를 재매칭하므로 매번 빌드하지 않는다.

기존 프로젝트·서비스·환경·인벤토리 기록은 유지한다. 저장소 연결은 프로젝트에 추가하는 입력 방식이다.

## 다양한 파일명·경로·형식 탐지

요구사항은 모든 프로젝트가 비정형이라는 전제가 아니라, 이름·위치·형식이 다를 가능성에 대응하는 것이다. 파일명만으로 의존성 파일을 확정하지 않는다.

| 사례 | 탐지 및 해석 |
| --- | --- |
| `requirements.txt`, `requirements.dev.txt`, `requirements/base.txt` | 알려진 파일명 패턴과 requirements 문법으로 후보 탐지. Dockerfile·CI·Makefile·스크립트의 `pip install -r PATH` 참조를 근거로 우선 확정 |
| 이름이 전혀 다른 `deps/backend-prod.list` | 설치 명령의 파일 참조 추적. 내용 분석만으로 발견하면 후보로 남기고 분석 범위 검토 화면에 표시 |
| requirements의 `-r`·`--requirement` | 포함 파일을 재귀 추적. 순환·중복 참조를 감지하고 저장소 경로 경계를 검증 |
| `-c`·`--constraint` | 버전 제약으로 적용. 제약 파일에만 등장한 패키지를 설치 패키지로 간주하지 않음 |
| `pyproject.toml` | `project.dependencies`, optional dependencies, dependency groups, Poetry 설정 등 지원하는 구조를 파서로 읽음. 임의의 TOML을 의존성 파일로 확정하지 않음 |
| `setup.cfg`, `setup.py` | 정적 메타데이터 우선. 동적으로 계산되는 부분은 미해결로 표시하고 빌드 환경의 수집 결과로 보완 |
| 모노레포 | 하위 경로별 manifest·lockfile·설치 명령을 모듈로 묶고 workspace 관계를 보존 |
| 다른 생태계 | manifest/lockfile 탐지·파싱을 어댑터로 확장. npm/pnpm/Yarn, Maven/Gradle, Go 등은 별도 지원표 관리 |

개발·테스트·운영·optional·platform 조건은 별도 속성으로 저장한다. 선언에만 있고 버전이 확정되지 않은 항목과 실제 빌드·설치 결과를 구분한다. 저장소 정보만으로 운영 배포 상태를 확정하지 않는다.

LLM은 설치 파일·모듈·명령 후보와 파일 간 연결을 설명하는 보조 단계로 사용한다. 출력에 파일 경로·행·근거·확신도를 요구하고 구조화된 스키마로 검증한다. 최종 패키지명·버전·간선은 파서, 패키지 매니저, SBOM 근거로 확인한다. 미해결 후보는 사용자 검토 목록에 남긴다.

LLM 연동은 별도 설정 단계로 둔다. 비공개 소스의 전송 범위와 모델 제공자를 명시하고 자격 증명·키·비밀 파일은 입력에서 제외한다. 이 설계 단계에서는 외부 모델에 저장소를 전송하지 않는다.

## 전이 의존성 수집과 계층 표시

수집 경로는 다음 순서로 구성한다. 지원 여부와 완전성은 수집기별로 표시한다.

1. **lockfile + manifest**: 실제 고정 버전 및 지원되는 관계를 파싱하고 루트 직접 의존성을 구분한다. 평면 lockfile처럼 관계 정보가 부족하면 그래프 완전성을 낮춰 표시한다.
2. **패키지 매니저 해석 결과**: 해당 환경의 의존성 그래프를 수집한다. Node의 설치 트리, Maven/Gradle 해석 결과 등 생태계별 어댑터를 둔다. Python은 설치 목록만으로 원래 직접 의존성·설치 의도를 복원할 수 없으므로 선언·환경 마커·설치 메타데이터를 함께 사용한다.
3. **CI/빌드에서 생성한 CycloneDX SBOM**: exact version, component, dependency edge를 받아 동일한 내부 그래프로 변환한다. 그래프가 없는 SBOM은 패키지 목록으로 수용하되 관계를 추측하지 않는다.
4. **배포 산출물·실행 환경 보완**: 이미지/환경 SBOM에서 OS·런타임·포함 라이브러리를 더한다. 패키지 발견과 부모 관계의 확인 상태를 분리한다.

저장소 스캔 서버에서 임의의 설치·빌드 스크립트를 바로 실행하지 않는다. 동적 해석이 필요한 경우 사용자 CI의 수집 작업 또는 자원·네트워크·수명이 제한된 격리 runner에서 검토된 수집 프로파일을 실행한다. 설치 훅·빌드 메타데이터 단계도 실행 가능 코드로 취급한다.

### 저장 모델

- `repository_connections`: 프로젝트, provider, URL, ref, subpath, credential 참조, 마지막 분석 commit.
- `repository_credentials`: 프로젝트 접근 범위, 암호화된 username/secret, 키 버전, nonce, 암호화 인증 태그. API에는 상태와 표시용 이름만 반환.
- `repository_scan_runs`: commit SHA, 환경/모듈, 실행 상태, 수집기 버전, 시간, 오류, 완전성.
- `dependency_components`: 스냅샷 내 패키지 식별자, 생태계, 이름, exact version, purl/qualifier, declared range, 확인 상태.
- `dependency_edges`: 동일 스냅샷·모듈·환경의 parent → child 관계, scope, platform/optional 조건, 근거 참조.
- `dependency_evidence`: 파일 경로·행·수집기·빌드/산출물 식별자·관찰 시각.

패키지와 간선을 분리한 그래프를 저장한다. 동일 패키지가 여러 경로에 나타나거나 직접·전이 의존성 역할을 동시에 가질 수 있다. 버전·플랫폼·해석 문맥이 다르면 별도 component로 유지한다. 기존 `direct_dependency`, `dependency_path`는 이전 데이터 호환에 사용하며, 하나의 경로 필드만으로 다중 부모를 표현하지 않는다.

화면은 `프로젝트 → 모듈/환경 → 직접 의존성 → 전이 의존성`으로 펼친다. 자식은 펼칠 때 제한된 개수씩 조회한다. 순환 참조는 현재 경로의 방문 집합으로 감지하여 표시한다. 관계 미확인 패키지는 별도 그룹에 표시한다.

```text
backend / prod
├─ web-framework@1.0.0       직접
│  └─ common-util@3.0.0     전이 · 취약점 1건
└─ persistence@3.1.0        직접
   └─ common-util@3.0.0     전이 · 같은 패키지의 다른 유입 경로
```

트리에는 유입 경로를 보존하지만 KPI는 동일 환경·스냅샷의 component 식별자를 기준으로 중복 집계하지 않는다. 취약점 상세에 모든 유입 경로와 어느 상위 직접 의존성을 갱신해야 하는지 보여준다. 상위 버전 변경으로 해결되는지는 실제 재해석 결과로 검증한다.

## 비공개 저장소 자격 증명

HTTPS 저장소 URL과 별도 credential ID를 사용한다. username/secret은 인증 암호화(AES-256-GCM 등)로 보관하고, 암호화 키는 DB·저장소와 분리한 서버 비밀 설정 또는 KMS에서 관리한다. 키 버전 기반 교체 절차를 둔다. 화면에서 기존 secret 원문을 다시 조회하지 않는다.

프로젝트 권한을 적용하고 저장소·레지스트리에 필요한 읽기 범위로 제한한다. credential은 clone/API 호출 시에만 복호화하며 URL·프로세스 인자·로그·오류·LLM 입력에 원문을 남기지 않는다. private package registry 자격 증명은 저장소 자격 증명과 구분해 연결한다. GitHub App/GitLab 접근 토큰 지원을 고려하되 최종 provider별 권한표를 구현 전에 확인한다.

GitLab Self-Managed는 provider host를 명시적으로 등록한다. 저장소 조회와 리다이렉트에 목적지 검증·시간/크기 제한을 적용하고 임의 서버 접근 경로로 사용되지 않도록 한다.

## API·화면 초안

| API | 목적 |
| --- | --- |
| `POST/GET /api/v2/projects/{id}/repositories` | 저장소 연결 및 상태 목록 |
| `POST/PATCH /api/v2/projects/{id}/repository-credentials` | 자격 증명 등록·교체. 원문 GET 없음 |
| `POST /api/v2/projects/{id}/repositories/{rid}/scans` | 비동기 분석 시작, `202` + scan ID |
| `GET /api/v2/projects/{id}/repository-scans/{scan_id}` | 단계·진행·근거·미해결 파일·완전성 조회 |
| `GET /api/v2/projects/{id}/dependency-roots` | 모듈·환경별 직접 의존성, keyset cursor |
| `GET /api/v2/projects/{id}/dependency-components/{cid}/children` | 스냅샷 범위의 자식 간선, keyset cursor |
| `GET /api/v2/projects/{id}/dependency-components/{cid}/paths` | 유입 경로를 제한·페이지 처리하여 조회 |
| `POST /api/v2/projects/{id}/targets/{tid}/sboms` | CI/산출물 CycloneDX 업로드와 구조 검증 |

프로젝트 상세에 `저장소 / 분석 결과 / 의존성 트리 / 영향 / 자격 증명`을 둔다. 기존 수동 전송·endpoint 방식도 유지한다. `확정 버전`, `선언 범위`, `관계 미확인`, `수집 일부 실패`를 구분해 완전 수집으로 오인하지 않도록 한다.

## 단계와 완료 기준

1. **탐지 기반**: Python 파일명 변형·TOML·포함/제약 파일·모노레포 fixture로 탐지/파서 검증. 설치 참조 없는 후보와 실제 입력 구분.
2. **저장소 및 비밀 관리**: GitHub/GitLab 연결·읽기 권한·암호화·교체·권한 분리·오류 비밀 마스킹 검증. 기존 데이터 백업 후 추가형 migration 적용.
3. **수집/그래프**: 고정 commit 분석, lockfile/해석 결과/SBOM 수용, 다중 부모·다중 버전·순환·부분 그래프·platform 조건 검증. 취약점 매칭은 직접·전이 패키지 모두 수행.
4. **화면과 재분석**: 파일 탐지 검토, 지연 로딩 트리, 유입 경로, 중복 없는 KPI, 예약/웹훅 분석과 취약점 갱신 재매칭.
5. **LLM 보조**: 앞 단계가 처리하지 못한 구성의 근거 추출과 검토 UX. 비정형 fixture, 오탐, 미탐, 비밀 제외 및 제공자 설정 검증.

## 근거 문서

- [CycloneDX Software Dependencies](https://www.cyclonedx.org/use-cases/software-dependencies/): component와 `dependsOn` 관계, 미확인 그래프 구분.
- [GitHub dependency graph](https://docs.github.com/en/code-security/concepts/supply-chain-security/dependency-graph): manifest·lockfile·dependency submission 및 지원 생태계의 전이 경로.
- [GitLab dependency scanning](https://docs.gitlab.com/user/application_security/dependency_scanning/): CycloneDX SBOM 기반 수집·연속 재매칭 흐름. 이 계획은 해당 GitLab 유료 기능 사용을 전제로 하지 않는다.
