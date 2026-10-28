# 저장소 분석 운영

## 사용 순서

프로젝트 상세 **저장소·분석**에서 GitHub/GitLab HTTPS URL, ref, 하위 경로와 환경을 등록한다. 비공개 저장소는 owner가 읽기 토큰과 선택적 username을 별도 등록한다. URL에 토큰을 넣지 않는다.

등록 즉시 실행 없는 1차 분석을 요청하고 이후 6시간마다 갱신한다. 리포트의 패키지·설치 행위 후보·미확인 영역을 검토한 뒤 **심층 분석 요청**으로 Python/Node/Docker 프로파일과 선택적 실행 명령을 지정한다. Python 설치 입력 파일 하나를 선택할 수 있다. 심층 분석은 같은 commit의 검증된 보관본을 사용하며 예약 갱신이 실행을 시작하지 않는다.

트리는 확인된 간선만 펼친다. 다중 부모와 관계 미확인 패키지도 표시하며 KPI는 생태계·이름·버전 기준이다. 모든 실행 경로 또는 실제 운영 배포 환경을 확인했다는 의미는 아니다.

## OpenRouter와 자격 증명

모델은 `deepseek/deepseek-v4.1-flash`로 고정한다. Ollama를 호출하거나 로컬 모델로 대체하지 않는다. 관리자 **수집·계정 관리 → 저장소 분석 LLM 연결**에 API 키를 입력한다. 또는 서비스 환경 `OPENROUTER_API_KEY`를 제공한다. 환경 변수가 DB보다 우선하며, “키 설정됨”은 실제 인증 성공을 뜻하지 않는다.

LLM 사용을 선택한 저장소는 비밀 파일을 제외한 최대 50개 파일, 총 45,000자의 선택 범위를 OpenRouter로 전송한다. 비밀 패턴 마스킹은 보조 장치이며 모든 코드 내 비밀을 보증하지 않는다. 구조화된 후보의 파일·행·근거를 검증하고 근거가 없는 결과를 버린다. LLM은 도구를 실행하거나 권한을 변경하지 않는다. 범위 한도와 호출 실패는 미확인 영역에 남긴다. 제공자에 `data_collection=deny`, `require_parameters=true`를 요청한다.

토큰과 OpenRouter 키는 AES-256-GCM으로 암호화하며 원문 GET을 제공하지 않는다. 암호화 키 기본 경로는 `.data/repository-credentials.key`, 별도 설정은 `SCA_REPOSITORY_KEY_FILE`이다. 32바이트, 권한 0600이며 DB와 함께 별도 보호 백업이 필요하다. 기존 키를 덮어쓰거나 잃으면 저장된 토큰을 복호화할 수 없다. 자동 암호화 키 회전은 없고 `key_version`은 키 식별용이다. 토큰 교체는 동일 provider/host 안에서만 허용한다.

Self-managed GitLab은 `SCA_REPOSITORY_GITLAB_HOSTS`로 host를 등록한다. 내부 IP가 필요한 host는 별도로 `SCA_REPOSITORY_PRIVATE_GITLAB_HOSTS`에 등록하며 loopback/link-local 등은 계속 거부한다. 저장소 credential은 심층 VM·이미지 registry로 전달하지 않는다.

## KVM 워커 설치

운영 호스트는 `server-4096`이다. 대상 프로젝트 설치·빌드·실행은 작업별 KVM VM 내부에서만 수행한다. 호스트 Docker 소켓은 전달하지 않는다. 같은 서버에서 VM을 운영하므로 자원 경합 가능성이 있으며 규모가 늘면 별도 KVM 호스트로 분리한다.

호스트 도구: `qemu-system-x86_64`, `qemu-img`, `cloud-localds`, OpenSSH client. API/워커 Python 환경에 `pyproject.toml` 의존성을 설치한다. 공식 서명·체크섬을 검증한 Ubuntu cloud image에 Python venv/pip, Node/npm, Docker, strace와 공식 release 체크섬을 검증한 Syft를 설치한 뒤 VM을 종료해 root 소유 읽기 전용 템플릿을 만든다.

`scripts/sandbox_launch.py`를 root 소유 `/usr/local/libexec/sca-monitor-sandbox`로 설치한다. 전용 `sca-analysis` 사용자와 KVM 접근, 서비스 계정의 해당 helper UUID start/stop sudo 권한이 필요하다. 템플릿 `/data/sca-monitor-sandbox/runner-base.qcow2`, 작업 경로 `/data/sca-monitor-sandbox/jobs`는 helper에서 고정한다.

실제 격리 검증 후 `.data/sandbox-ready.json`을 생성한다. `SCA_SANDBOX_READY_FILE`로 위치를 지정할 수 있다.

```json
{
  "isolation": "kvm",
  "jobs_root": "/data/sca-monitor-sandbox/jobs",
  "base_image": "/data/sca-monitor-sandbox/runner-base.qcow2",
  "launcher": "/usr/local/libexec/sca-monitor-sandbox"
}
```

준비 파일·KVM·템플릿·helper가 없으면 심층 요청을 거부한다. 일반 프로세스/컨테이너로 대체하지 않는다. user systemd `deploy/sca-monitor-repository-worker.service`와 `.timer`를 명시적 migration 후 활성화한다. DB 자동 migration은 꺼 둔다. 워커는 한 작업씩 처리한다.

- VM: 2 vCPU, RAM 2.5GiB, systemd 메모리 한도 4GiB, 실행 최대 15분, unit 수명 1100초, 디스크 파일당 8GiB.
- QEMU: 전용 사용자·seccomp·mount namespace. `/data` 마스킹 후 읽기 전용 템플릿과 해당 UUID 디렉터리만 노출한다. 홈과 운영 컨테이너 저장소 접근을 차단한다.
- 네트워크: QEMU `restrict=on`으로 직접 외부/호스트 접속 차단. SSH reverse forwarding으로 작업별 제한 프록시만 전달한다. 프록시는 고정 도메인과 공인 IP를 검사한다. 기본 목록은 `repository/sandbox.py`의 `DEFAULT_HOSTS`, 운영 설정은 `SCA_SANDBOX_EGRESS_HOSTS`다. 내부망/IP 주소를 허용하지 않는다.

## 범위·보존·복구

구현 API의 공통 prefix는 `/api/v2`다. 로그인 세션과 변경 요청의 CSRF 토큰이 필요하다. 프로젝트 권한은 읽기/쓰기/owner별로 검사한다.

| 경로 | 기능 |
| --- | --- |
| `GET/POST projects/{pid}/repositories` | 저장소·최근 작업·기능 상태 조회 / 등록 |
| `POST projects/{pid}/repositories/{rid}/scans` | 1차 분석 요청, idempotency key 필수 |
| `POST/PATCH projects/{pid}/repository-credentials[/{cid}]` | owner 자격 증명 등록 / 교체 |
| `GET projects/{pid}/repository-scans/{sid}[/report]` | 상태 / 불변 리포트 |
| `GET projects/{pid}/repository-scans/{sid}/components?parent=&cursor=` | 루트 또는 자식 keyset 페이지, 최대 100개 |
| `POST projects/{pid}/repository-scans/{sid}/deep-analysis` | 원본 기준 심층 요청, profile·선택 manifest/run_command·idempotency key |
| `POST projects/{pid}/repository-scans/{sid}/cancel` | 대기/실행 중 작업 취소 |
| `GET/POST admin/repository-analysis/settings` | 관리자 OpenRouter 상태 / 암호화 키 등록 |

별도 paths/SBOM 업로드 API는 이번 구현에 포함하지 않는다. 저장소 내부 CycloneDX를 읽고 유입 경로는 지연 조회 트리로 제공한다.

정적 지원: requirements 파일명 변형·코드의 pip `-r` 참조·재귀 `-r`/`-c`, PEP 621/Poetry TOML, uv/Poetry lock, Pipfile.lock, setup.cfg, npm package/lock, CycloneDX JSON. setup.py는 실행하지 않는다. Yarn/pnpm/Maven/Gradle/Go/Cargo 등 미지원 형식은 미확인이다. Python 선택 의존성·마커와 모든 설치 시나리오의 완전 복원은 보증하지 않는다.

심층 지원: Python 설치 메타데이터·관계, Node 설치 후 SBOM, Docker 베이스/최종/최대 3개 named stage 및 실행 후 SBOM. 공개 Docker Hub linux/amd64 digest 고정을 지원한다. digest/플랫폼 미확인 베이스는 빌드하지 않는다. private registry 인증, 다른 플랫폼, 외부 저장소 빌드 입력, LFS/submodule, 숨겨진 모든 경로의 자동 실행, 웹훅은 아직 지원하지 않는다.

리포트는 불변 기록이다. 취소/시간 초과 시 가능한 checkpoint를 회수해 중단 증거를 보존하며 회수 실패 시 1차 리포트·보관 디스크를 유지한다. 부분 분석으로 인벤토리를 비우지 않는다. 이전 항목은 `retained:` 출처와 재확인 상태를 표시한다. 과거 버전도 보존하므로 소스 관찰만으로 기존 영향을 자동 해결하지 않는다.

저장소 보관본·키·리포트·작업 디스크는 자동 삭제하지 않는다. 디스크 합계 할당량 32GiB 초과 또는 여유 공간 8GiB 미만이면 새 VM을 거부한다. 기존 ZIP 최신 10개 정책과 별개이며 정리는 소유·사용·백업과 승인 범위를 확인한 뒤 수행한다.

2026-10-28 서버 KVM fixture에서 Python idna 설치 후 숨겨진 charset-normalizer 추가와 호스트 API 접근 차단, Alpine 베이스/curl 빌드/jq 런타임 SBOM 분리를 확인했다. OpenRouter는 실제 키 등록 전까지 모의 응답으로 모델·요청 형식·근거 검증만 시험한다.

배포 전 DB 일관 백업과 사용자/세션 보존을 검증한다. migration 022는 테이블·인덱스를 추가하며 기존 데이터를 지우지 않는다. 장애 시 새 워커 중지 후 이전 API commit/서비스 설정으로 복구한다. 추가 스키마는 남겨 새 분석 기록을 보존한다. DB 복원은 이후 신규 데이터 손실 가능성이 있어 자동 실행하지 않는다. 암호화 데이터 복구에는 DB와 대응 키 백업이 모두 필요하다.
