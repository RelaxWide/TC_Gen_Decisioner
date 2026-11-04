# SSD 평가 모니터링 / TC 자동생성 시스템

상세 설계 배경은 `C:\Users\gangho.yoon\.claude\plans\snazzy-humming-sky.md` 참고.

## 1. 이 프로젝트가 하는 일

목표는 두 가지다.

1. **로그 기반 1차 불량 판단** — QST(테스트 플랫폼), PULSEFZ(퍼저), TC 자동 실행 결과, 이 세 소스의 실패 로그를 보고 "실제 펌웨어 결함 / 테스트 환경 이슈 / 엔지니어 추가 확인 필요"를 1차로 분류하고 근거를 제시한다.
2. **Spec 기반 TC 자동생성 + 실행 + 판정** — NVMe Spec 커버리지 인덱스를 기반으로 시나리오를 만들고, 실제 SSD(192.168.137.9)에 명령을 보내 실행하고, Expectation/Fail Criteria로 판정하고, Spec 대비 커버리지 %를 추적한다. (현재는 안전장치로 실행이 막혀있음 — 4번 참고)

두 파이프라인의 판정 결과는 하나의 정적 HTML 리포트(`report/output/report_latest.html`)로 합쳐진다.

## 2. 폴더 구조

```
QST/, PULSEFZ/          실제 로그 원본 (건드리지 않음)
rag/                     실제 SRAG 코드/검색 인덱스. srag_llm_guide.py 에 자격증명을 직접 채움
shared/                  RAG/LLM 클라이언트(둘 다 실연동 완료), 공용 유틸
log_judge/               로그 파싱 + 1차 판정 파이프라인
tc_system/               TC 생성/실행/판정 + 커버리지
report/                  HTML 리포트 생성
specs/                   TC 시스템이 쓰는 커버리지 인덱스(seed)
data/                    파이프라인 산출물(FailureContext, Verdict, TC, 커버리지) — 재생성 가능
tests/                   테스트 코드 전부 — 유닛 테스트(장비·SSH·LLM 호출 없음) + 감사 재현 스크립트
docs/                    스펙 검증 설계 문서, 리뷰 기록
config.py                경로/설정 중앙 관리
secrets.local.json       SSH 타겟 자격증명 (git에 올리지 말 것)
run_ingest.py / run_judge.py / run_tc_pipeline.py / run_report.py   CLI 진입점
```

## 3. 세팅 방법

### 3-1. Python 패키지
`requests`, `openai`, `numpy`, `python-dotenv` 설치되어 있어야 함(이미 설치 확인됨). 표준 라이브러리 외 추가 의존성 없음 — HTML 리포트도 Jinja2 없이 stdlib로 생성.

### 3-2. SSH 타겟 (TC 실행용)
`secrets.local.example.json`을 `secrets.local.json`으로 복사해서 실제 값 채우기:
```json
{ "ssh_host": "192.168.137.9", "ssh_user": "ssd", "ssh_password": "changeme",
  "nvme_ctrl": "/dev/nvme0", "nvme_ns": "/dev/nvme0n1" }
```
타겟 쪽 요구사항(이미 확인됨): `nvme-cli`, `sudoers`에 `(root) NOPASSWD: /usr/sbin/nvme` 규칙(패스워드 없이 `sudo nvme` 가능). `dmesg`는 비밀번호가 필요해서 `-S`로 stdin 전달.

### 3-3. 권한 설정 (`.claude/settings.local.json`)
이미 세팅되어 있음: `Bash(plink:*)`, `Bash(python run_tc_pipeline.py:*)`, `Edit(**)` — plink 호출, TC 파이프라인 실행, 이 프로젝트 안 파일 쓰기가 승인 없이 진행됨.

### 3-4. RAG — 이미 동작함 (크레덴셜 불필요)
`rag/index/current` → `rag/index/v20260922_172200/chunks.jsonl`에 실제 검색 인덱스가 있음: NVMe Base/Command Set/MI/TCG 4개 스펙, 969개 청크, 105개 실제 커맨드명 태깅. API 호출이나 자격증명 없이 지금 바로 동작한다.

### 3-5. LLM 완성 호출 — 실연동 완료

자격증명은 `rag/srag_llm_guide.py` 상단 상수에 직접 채워 넣는 방식이다 — 이 파일은 `.gitignore` 대상이라 리포에는 빈 템플릿 `rag/srag_llm_guide.example.py`만 있다. 템플릿을 `rag/srag_llm_guide.py`로 복사해서 채울 것(`.env`/`dotenv` 안 씀 — 원래 있던 `.env` 덮어쓰기 부트스트랩은 외부 파일을 훼손해서 삭제했다). 채워야 할 것: `OPENAI_API_KEY`, `credential_key`, `api_base_url`, `model`, `rag_api_key`, `rag_credential_key`, `index_name`, `search_url`. (`user_pw`는 코드에서 안 쓴다.)

`shared/llm_client.py`가 이 모듈의 **이미 인증된 `client` 객체만 재사용**한다 — 자격증명 값을 읽거나 로그에 남기지 않는다. 모듈의 `generate_rag_response()`는 쓰지 않는데, 시스템 프롬프트가 고정이고 자체 RAG 검색을 또 돌려서 우리 용도에 안 맞기 때문이다. 대신 우리 시스템 프롬프트 + JSON 스키마 지시를 붙여 호출하고 응답을 파싱한다(코드펜스/산문 감싸기 모두 처리). **재시도는 "JSON 파싱 실패"와 "유효한 JSON인데 스키마 키가 빠짐" 둘 다 1회씩이 아니라 둘이 합쳐서 1회**다 — 파싱 재시도가 이미 발생했으면 키 누락에서 또 재시도하지 않는다(실측: `fail_criteria` 키 하나가 빠진 응답이 재시도 없이 바로 에러를 올려서 `--count 20` 배치 전체가 죽은 적이 있었음).

실패 시 `LLMCallError`를 올리고 **가짜 판정을 만들지 않는다** — `run_judge.py`가 해당 항목을 건너뛰고(미판정 유지) 다음 실행에서 재시도하며, 종료코드 1과 함께 몇 건이 미판정인지 알려준다. `run_tc_pipeline.py`는 다르게 처리한다 — `generate_scenario`가 1회 재시도 끝에도 실패하면(`LLMCallError`) 그 타겟 하나만 `skipped`로 건너뛰고 나머지 배치는 계속 돈다(장비에 아무것도 안 나갔으므로 다음 실행에 다시 타겟으로 제시됨).

**응답 언어**: `description`/`rationale`/`guidance`/`role`/`chain_summary`/`field_breakdown` 같은 자연어 필드는 시스템 프롬프트에서 한국어로 쓰라고 명시한다. `classification`/`opcode_name`/`phase`/`direction` 같은 고정 식별자·열거값, 그리고 `shared_facts`의 키(예: `lba`, `nlb`)는 검증 로직이 정확한 문자열로 매칭하므로 번역하지 말라고 같이 명시한다.

## 4. 사용법

### 4-1. 로그 판단 루프 (완전히 동작함 — 실제 LLM 판정)
```
python run_ingest.py --source all      # QST/PULSEFZ 로그 -> FailureContext
python run_judge.py  --source all      # FailureContext -> Verdict (실제 RAG 근거 + 실제 LLM 판정)
python run_report.py                   # report/output/report_latest.html 생성
```
이미 처리된 로그/판정은 재실행 시 건너뜀(매니페스트·verdict id 기반). `--force`로 강제 재처리.

`run_judge.py`는 건당 LLM을 호출하므로 8건에 수 분 걸릴 수 있다. LLM 오류로 건너뛴 항목이 있으면 종료코드 1.

### 4-2. TC 자동생성 루프 (동작함 — 실제 장비에 명령 전송)
```
python build_spec_index.py             # 최초 1회(또는 RAG 인덱스 갱신 시): 커버리지 인덱스 생성
python run_tc_pipeline.py --count 12   # 미커버 조항 선정 -> 인자 생성 -> 실제 실행 -> 판정 -> 커버리지 갱신
```
**파괴적 커맨드가 기본 포함됩니다** (대상 드라이브 데이터는 소모품 전제). 내용이 중요한 드라이브에 돌릴 때만 `--no-destructive`. 배치 안에서는 비파괴적 커맨드가 먼저 실행되도록 정렬되어, Sanitize/Format 같은 장시간·전면삭제 커맨드가 앞서 나오지 않습니다.

TC 1건당 LLM 호출이 2~3회(시나리오 + 인자 + 거부 시 재생성) 일어나므로 12건에 수 분 걸립니다.

**인자가 끝내 placeholder로 떨어진 TC, LLM 응답이 일시적으로 망가진 타겟(1회 재시도 후에도 복구 안 됨), `--no-destructive` 중 모델이 직접 고른 커맨드가 파괴적이었던 TC — 이 셋 다 그 타겟 하나만 `skipped`로 건너뛰고 배치는 계속됩니다**(장비에 아무것도 안 나감, 다음 실행에 다시 타겟으로 제시됨). 건너뛸 때마다 터미널에 `[i/total] ... — 건너뜀, 다음 타겟으로 진행`과 사유가 바로 찍히고(`on_skip` 콜백), 최종 요약 줄의 `skipped=N`으로 몇 건이 건너뛰어졌는지 다시 확인할 수 있습니다. (예전에는 placeholder 인자가 `exit 2`로, `--no-destructive`에 걸린 파괴적 커맨드가 `exit 3`으로 **배치 전체를 멈췄습니다** — 실측으로 `--count 10` 중 4번째 타겟에서 걸려 나머지 6개가 전부 날아간 사례가 있어서, 세 경우 다 "그 타겟만 건너뛰기"로 통일했습니다. `--allow-placeholder-args`를 주면 placeholder 인자라도 그대로 실행하되 그 TC는 커버리지에서 제외됩니다 — 이 플래그의 의미 자체는 바뀌지 않았습니다.)

판정(`judge_failure_context`) 호출이 같은 이유로 실패해도 배치는 안 멈춥니다 — FAIL/ERROR라는 장비 쪽 결과는 그대로 저장되고, LLM 분류(`verdict_id`)만 비워진 채로 남습니다. 다만 로그 판단 쪽(`run_judge.py`)과 달리 TC 실행 쪽은 미판정 건을 다음 실행에서 자동으로 다시 판정하는 스윕이 없어서, 같은 조항이 다시 타겟으로 뽑혀 새 FAIL/ERROR가 나야 그제서야 다시 판정됩니다.

**커버리지와 판정 증거는 실행마다 쌓입니다** — 기존 실행 이력으로 조항을 영구 완료 처리하지 않으며 판정 기록도 보존합니다. 그런데 `tc_store.json`에는 "이 결과가 어떤 물리 디바이스에서 나왔는지"가 전혀 안 적혀 있어서, **테스트 대상 드라이브를 바꾸면 새 드라이브가 이전 드라이브의 누적 결과를 그대로 물려받습니다** — 특히 UNSUPPORTED는 드라이브(모델)마다 다를 수 있는데도 그대로 남습니다. 드라이브를 바꿨으면:
```
python run_tc_pipeline.py --count 12 --reset-coverage
```
`tc_store.json`/`coverage_state.json`을 지우기 **전에** `data/coverage_backups/<UTC타임스탬프>/`로 복사해두므로, 잘못 눌러도 이전 커버리지 기록이 영구히 사라지지 않습니다. 같은 드라이브를 계속 쓰는 일반적인 반복 실행에서는 이 플래그를 주면 안 됩니다 — 그동안 쌓은 커버리지가 매번 날아갑니다.

### 4-3. 결과 확인
`report/output/report_latest.html`을 브라우저로 열면 커버리지 대시보드 + TC 현황 + 3소스 판정 결과를 한 화면에서 볼 수 있다.

## 5. 동작 방식 (데이터 흐름)

### 5-1. 로그 판단
- **QST**: `[ <N> TC_name START ... FAILED ]` 괄호로 TC 단위 윈도우를 나누고, 그 안에서 `SYSTEM ERROR`/`CMD` 블록/데이터 miscompare를 추출. FAILED 이후 teardown 중 에러(장비가 벤더 커맨드에 응답을 멈춘 것 같은 증거)도 별도 캡처. dmesg는 로그에 적힌 덤프 경로 문자열로 매칭.
- **PULSEFZ**: 스트리밍으로 `[ERROR][TIMEOUT CRASH]` 이벤트들을 추적하다가, `[ARTIFACT]`로 실제 수집 확정된 크래시만 "종단"으로 보고 그 크래시 타임스탬프와 일치하는 `dmesg_<ts>.txt`를 찾음. 재현용 커맨드 페이로드(`FAIL CMD` 블록)도 캡처.
- **판정**: opcode/커맨드명을 뽑아 실제 RAG 인덱스에서 관련 스펙 조각을 찾고, 그걸 포함해 실제 LLM에 분류를 요청 → `firmware_defect`/`test_env_issue`/`needs_engineer_review` + 근거 + 가이드. 어휘 검색이라 커맨드명이 질의에 있어야 잘 맞으므로(실측: 이름 ~22-47점 vs hex만 ~2점), hex opcode와 사람이 읽을 수 있는 커맨드명을 함께 질의한다.

### 5-2. TC 생성/실행
1. 아직 안 덮인 (Spec 섹션, opcode) 타겟을 커버리지 인덱스에서 선정 — 이게 그 TC의 **action 스텝**(아래 참고)이 됨
2. 시나리오 생성(RAG+LLM) → 실행 스텝 작성(opcode, cdw, direction, destructive 여부)
3. 전체 체인 검증 후 SSH로 단계를 순차 실행하고 사전조건을 확인합니다. 명령 상태와 근거·검증식 기반 PASS/FAIL/UNVERIFIED를 별도로 기록합니다.
4. FAIL이면 로그 판단과 동일한 `judge` 모듈로 라우팅 → 커버리지 갱신

### 5-2a. 복합(멀티스텝) TC — Write→Read 같은 시퀀스

TC는 커맨드 1개가 아니라 **여러 커맨드를 순서대로 엮은 체인**일 수 있습니다(`scenario_generator.py`의 `steps_plan`). LLM에게 조항 선정 타겟 1개(`opcode_entry`)와 **같은 command_set 제한 없이 전체 60개 opcode 이름 목록**(ADMIN/NVM 섞는 조합도 허용)을 주고, `{opcode_name, role, phase}` 객체 배열을 받습니다. `phase`는 `setup`(action 전에 실행, 사전조건 — Write 후 Read처럼) / `action`(지금 커버리지가 노리는 그 타겟, 정확히 1개) / `verify`(action 후 확인). 사전조건이나 확인이 여러 개 필요하면(PM 상태 전환 등) `setup`/`verify`를 여러 개 써도 되고, 스텝 수에 고정 캡은 없습니다 — 스텝 1개(`action`만)가 흔하고 정상입니다.

받은 `steps_plan`은 action의 유일성·타겟 일치·실존 명령·단계 순서와 스펙 인용·검증식·고정 필드를 함께 검증합니다. 실패하면 이유를 전달해 1회 재생성하고, 다시 실패하면 해당 타겟을 건너뜁니다. 원래 요구사항을 단일 명령으로 축소하는 폴백은 하지 않습니다. 전체 명령 체인의 실행 전 검증과 기존 destructive 게이트를 적용합니다.

**스텝 간 값 공유(`shared_facts`)**: 각 스텝의 `author_args` 호출이 LBA/NLB/Feature ID처럼 "다음 스텝이 재사용해야 할 의미있는 값"을 명시적으로 돌려주고(`{"lba": "0x5", "nlb": "0"}` 식), 이후 스텝들은 **이전 스텝 전체의 기록**(평평하게 병합한 dict가 아니라 스텝별 리스트 — PM 상태 A→B 전환처럼 같은 키가 여러 번 바뀌는 과정이 안 사라지게)을 프롬프트로 받아 "다른 값을 요구하지 않는 한 그대로 재사용하라"는 지시를 받습니다. 이게 없으면 Write가 LBA 5에 쓰고 Read가 LBA 9를 읽는 식으로, 체인이 서로 무관한 명령 두 개가 되어 버립니다. (바이트 자체가 실제로 일치하는지 비교하는 건 아직 안 함 — 다음 단계로 보류.)

**스텝 중 하나가 깨졌을 때**: 거부(인자 문제, 고치면 될 수 있음)면 `tc_writer.reauthor_steps`가 **그 스텝부터 끝까지**(앞은 그대로) 다시 짓습니다 — 뒤 스텝이 거부된 스텝의 바뀌기 전 `shared_facts`를 참조하고 있을 수 있어서, 그 스텝 하나만 고치면 뒤가 낡은 값을 참조하게 됩니다. 미지원(`INVALID_OPCODE`, 인자를 고쳐도 소용없음)이고 그게 action이 아닌 스텝이면 `generate_scenario`에 "이 커맨드는 이 드라이브에 없다"를 피드백해서 **전체 재계획**(1회)을 시도합니다. action 스텝 자체가 미지원이면(타겟 자체가 없음) 재계획해도 못 바뀌니 시도 안 하고 그대로 받아들입니다. 어느 경로든, **이미 파괴적 스텝이 실행된 뒤**라면 재시도/재계획을 전부 생략합니다 — SSH 배치가 부분 재실행이 안 돼서, 재시도는 그 파괴적 스텝도 다시 쏘게 되기 때문입니다.

재시도/재계획이 일어나면 `tc["retried"]`(`{"kind": "args_rejected"|"replanned", "step_index", "step_name", "reason"}`)에 기록되고, 터미널/로그에 "⚠ 재시도" 줄로 표시됩니다 — 이게 없으면 `_print_start`가 찍는 "실행할 명령"(재시도 전 값)과 `_print_result`가 찍는 결과(재시도 후 cdw10/data_len)가 서로 다른데도 아무 설명이 없어서, 처음 보면 버그처럼 보입니다(실측: `logs/ssh_commands.jsonl`을 따로 대조해야 재시도였다는 걸 알 수 있었던 사례).

**action 스텝의 section은 `pick_next_targets`가 원래 고른 그 section을 그대로 씁니다** — opcode 테이블의 대표 `section_ref`로 다시 조회하지 않습니다(`pipeline._resolve_steps_plan`). opcode의 `section_ref`는 그 커맨드의 "대표" 조항(예: Migration Send → `base:5.2.17`)일 뿐이고, 같은 opcode를 공유하는 더 구체적인 형제/하위 조항(`base:5.2.17.1` "Migration Send Management Operations" 등)도 `pick_next_targets`가 독립적인 타겟으로 고릅니다 — 실측으로 103개 reachable 조항 중 43개가 이런 관계였습니다. action 스텝의 section을 `section_ref`로 재조회하면(예전 버그) 커버리지가 항상 대표 조항으로만 기록되어, 원래 고른 세부 조항은 구조적으로 영원히 커버될 수 없고 다음 실행에서도 똑같은 커맨드를 다른 타겟 이름으로 영원히 재시험하게 됩니다(실측: 같은 배치 안에서 "TC_MigrationSend_base_5_2_17"이 두 번 찍혀 중복처럼 보였던 사례). setup/verify 스텝은 사전 할당된 타겟이 없어서 여전히 `section_ref`로 조회합니다.

**스텝별 실행 이력과 요구사항 검증은 별도 집계**합니다. 선행조건이 실패한 체인은 action 성공만으로 스펙 PASS가 되지 않습니다. TC 이름은 action 기준이며 전체 계획은 `chain_summary`로 확인합니다.

**"조항이 제대로 커버됐는가"의 최종 판단은 여전히 기계적 규칙만 씁니다** — LLM에게 이 판단 자체를 맡기지 않습니다(커버리지 %의 재현성을 지키기 위함). LLM의 홀리스틱 의견을 보조 신호로 추가하는 건 아직 미정입니다.

**터미널/로그 표시**: opcode/nsid/mode 같은 레지스터 값을 먼저 보여주던 예전 방식 대신, **시나리오 → 어떤 커맨드들의 조합인지 → 각 스텝이 실제로 보낼 CLI 명령 → 나머지(Expectation/Fail 기준)** 순서로 보여줍니다:
```
[2/10] TC_CreateI/OSubmissionQueue_base_5_3_2
  시나리오: Create I/O Submission Queue 커맨드가 물리적으로 연속된 큐를 올바르게 생성하는지 확인...
  체인 요약: I/O Completion Queue를 만들고 Submission Queue를 만든 뒤 삭제해서 순서 규칙을 확인.
  명령 조합: Create I/O Completion Queue → Create I/O Submission Queue → Delete I/O Submission Queue
  실행할 명령:
    [0] (사전조건) Create I/O Completion Queue — 유효한 연속 큐 생성
        $ sudo nvme admin-passthru /dev/nvme0 --opcode=0x05 --namespace-id=0 --cdw10=... --cdw11=... --cdw12=...
    [1] (본동작) Create I/O Submission Queue — CDW11.PC=1로 생성
        $ sudo nvme admin-passthru /dev/nvme0 --opcode=0x01 --namespace-id=0 --cdw10=... --cdw11=... --cdw12=...
    [2] (확인) Delete I/O Submission Queue — 생성됐는지 확인 후 삭제
        $ sudo nvme admin-passthru /dev/nvme0 --opcode=0x00 --namespace-id=0 --cdw10=... --cdw11=... --cdw12=...
  Expectation: ...
  Fail 기준: ...
```
각 스텝의 `$ sudo nvme ...` 줄은 `ssh_runner.passthru_cmd(step)`로 **실제로 전송될 명령을 그대로 미리 보여주는 것**입니다(실행 전에 계산 가능 — 인자가 이미 다 지어진 뒤라서). 스텝 1개짜리 TC도 같은 형식으로 보이되 `[i]`/단계 태그/"명령 조합" 줄은 생략됩니다.

**분모 = 1,292개 조항** — `build_spec_index.py`가 RAG 인덱스의 실제 스펙 본문에서 조항 헤딩(`4.1.7 Sanitize command` 같은 정식 번호)을 추출해 생성합니다. Base 2.3 + NVM Command Set 1.2 + MI 2.1. **TCG(1,241개)는 제외** — nvme-cli passthru로 닿지 않는 영역이라 포함하면 커버리지가 영구히 0 근처에 묶입니다. 그중 opcode가 연결되어 실제 타겟이 될 수 있는 조항은 258개(아래 "커맨드별 세부 값 단위 커버리지" 참고 — 그중 165개는 LID/FID/CNS 같은 세부 값 단위).

**커맨드별 세부 값(LID/FID/CNS/...) 단위 커버리지**: Get Log Page(0x02) 하나만 봐도 스펙엔 LID별로 42개의 별도 조항("Error Information (Log Page Identifier 01h)" 등)이 있는데, 예전엔 그중 단 하나도 opcode에 연결돼 있지 않았습니다 — LID=0x02로 한 번 PASS 받으면 Get Log Page 전체가 "커버됨"으로 기록되고 나머지 41개 LID는 영원히 다시 타겟으로 안 나왔습니다. `build_spec_index.py`에 4번째 연결 패스(`link_field_values`)를 추가해서, `"(Log Page Identifier 02h)"` 같은 제목의 조항을 찾아 **opcode가 연결된 가장 가까운 조상 조항까지 거슬러 올라가며**(중간에 "Common Log Specific Information" 같은 빈 그룹 조항이 끼어 있어도 건너뛰고 계속 올라감) opcode를 상속시킵니다. Event Type처럼 그 밑에 또 중첩된 경우(Persistent Event Log의 특정 LID 밑에 Event Type별 조항이 또 있음)도 고정점(fixed-point) 루프로 자동 해결되어, `field_values`에 `[{LID=0x0D}, {EventType=0x02}]` 식으로 체인 전체가 쌓입니다. 실측: 1,292개 조항 중 **165개**가 이 패턴이었고 전부 opcode가 없었습니다(Feature Identifier 다수, Log Page Identifier 42개, CNS 다수, Event Type, Management Operation 등).

`author_args`가 이 세부 값(`required_field_value`)을 받으면 **CDW10 bits 7:0에 그 값이 실제로 들어갔는지 결정론적으로 검증**합니다(LLM의 자기 서술이 아니라 direction/nsid 검증과 같은 방식) — 단, 이 검증이 가능한 필드는 호스트가 **요청 시 직접 쓰는** 필드로 확인된 것들(`Log Page Identifier`/`Feature Identifier`/`CNS`/`Management Operation`/`Directive Operation`/`Directive Type`/`Configuration Identifier`)뿐입니다. **Event Type은 의도적으로 제외**했습니다 — 이건 호스트가 요청 시 고르는 값이 아니라 컨트롤러가 이미 기록해둔 로그를 읽어서 파싱해야만 알 수 있는 분류값이라, CDW에 넣을 방법이 스펙에 없습니다(opcode는 연결되어 리포트에 뜨지만 "검증됨" 표시는 안 받습니다). **Action Type도 제외**했습니다 — 호스트가 쓰는 값이긴 하지만 Get LBA Status의 CDW10이 아니라 **CDW13 bits 31:24**에 들어가는 필드이고, 이 하네스는 CDW10~12만 보냅니다. 검증된 필드가 거부되면(`field_value_verified=True`인 스텝의 `INVALID_*` 응답) **우리 버그(ERROR)가 아니라 미지원(UNSUPPORTED)으로 집계**됩니다 — CDW에 올바른 값이 들어갔다는 걸 이미 확인했으므로, 거부는 "이 드라이브가 그 값을 안 지원한다"는 유효한 결론입니다.

**섹션→opcode 연결의 함정**: "X.Y.1 Command Completion" 같은 서브조항은 거의 모든 커맨드 조항 아래 반복되는 보일러플레이트 제목이라, 스펙 전체에 59번 등장합니다. RAG 청크 하나가 여러 조항(예: Abort의 꼬리 서브조항과 그다음 AER 조항 전체)을 함께 담는 경우가 있는데, 청크 단위 `covers_commands` 태그를 거기서 추출된 모든 헤딩에 그대로 물려버리면 AER 자신의 조항(`base:5.2.2`)이 Abort의 opcode(0x08)에도 연결되는 식으로 커맨드가 샙니다(실측: 샘플 20건 중 8건에서 발생 — TC명은 Abort인데 와이어로 나간 건 Abort, 판정 기준은 AER 내용). 그래서 지금은 두 가지로 막습니다: ① covers_commands로 연결을 넓힐 때 그 조항이 실제로 해당 커맨드 자신의 조항(opcode 표의 `section_ref`) 아래 **중첩된 번호**일 때만 허용하고, ② "Command Completion" 제목의 서브조항은 설령 올바르게 중첩되어 있어도 **애초에 opcode를 연결하지 않습니다** — 그 보일러플레이트 본문이 실제로는 다른 커맨드의 예시를 인용하는 경우가 많아서, 올바르게 연결해도 시나리오가 엉뚱한 커맨드 내용으로 생성되는 걸 막을 수 없기 때문입니다. 이 두 조건을 추가하면서 테스트 가능 조항이 160→103으로 줄었는데, 그 차이(57개)가 전부 "출처가 불확실했던" 가짜 타겟입니다.

**opcode 60개**도 스펙의 opcode 표에서 파싱합니다(기억이 아니라). 파괴적 커맨드가 자동 실행되는 만큼 매핑이 틀리면 의도와 다른 명령이 나가므로, 파싱 시 M/O/P 플래그 열 + 조항 제목 교차검증을 요구하고, 알려진 값 16건 spot-check와 opcode 키 충돌 검사를 통과하지 못하면 **인덱스를 생성하지 않고 중단**합니다. (실제로 느슨한 정규식이 `Firmware Commit`을 `0Dh`로, Feature ID 표를 opcode로 잘못 읽는 것을 이 검증이 잡았습니다.)

**집계 기준** — 명령 실행 이력과 스펙 요구사항 검증을 분리합니다. 인용 근거·검증식·관측값이 있어야 요구사항 PASS/FAIL을 집계하며, 단순 명령 성공이나 INVALID_OPCODE는 스펙 준수의 증거가 아닙니다. 기존 PASS 기록도 검증 계약이 없으면 `UNVERIFIED`로 표시합니다. 생성된 요구사항 수가 검증 통계의 분모이며 전체 스펙 대비 준수율이 아닙니다.

**자기교정** — 거부된 인자를 한 번 재생성하되 시나리오의 FID/SEL·주소 등 고정 필드를 유지합니다. 기대한 음성 응답은 재시도하지 않습니다. 최초 실행과 재시도 결과를 모두 보존합니다. [검증 계약과 지원 범위](docs/spec_verification.md)를 참고하세요.

**방향 비트 검증** (`tc_system/generation/args_author.py`): opcode 바이트의 비트 1:0이 그 커맨드 자신의 전송방향(00=데이터 없음, 01=host→device, 10=device→host)을 인코딩합니다. 실측에서 opcode 0x2A(bits=10, "read")에 `direction="write"`로 인자를 지었다가 nvme-cli가 경고(`write flag set but write direction bit is not set in the opcode`)만 찍고 그대로 전송 — 컨트롤러가 응답을 안 해서 SSH 배치 타임아웃(~125초)까지 그대로 날린 사례가 4건 있었습니다. 이제 `author_args`가 LLM이 고른 `direction`을 opcode 자신의 비트와 맞춰보고, `direction="none"`이 아니면서 불일치하면 **장비에 보내기 전에** 거부합니다(수 ms 안에 실패). `direction="none"`은 Get Features 같은 데이터 버퍼 없는 명령에 사용할 수 있습니다. Identify/Get Log Page 등은 별도 길이 검증을 통과해야 합니다 — 실제로 PASS했던 사례라서.

이 불일치는 장비로 나가기 전에 로컬에서 잡힌 LLM 자신의 실수이므로(컨트롤러가 거부한 게 아니라, 애초에 보내지도 않음), 컨트롤러 거부 피드백 루프와 같은 방식으로 **그 틀린 이유를 LLM에게 알려주고 그 TC 1건만 1회 재시도**합니다 — 재시도까지 또 틀리면 그제서야 placeholder 폴백으로 떨어져 그 타겟만 건너뛰어집니다(배치 전체는 안 멈춤). (실측: opcode 0x1D에서 같은 유형의 실수가 재발 — `direction="read"`로 지었다가 bits가 "write"를 요구 — 1회 재시도로 복구되는지 확인이 핵심입니다. 한 번의 LLM 실수가 나머지 19건의 실행까지 막는 걸 막기 위함.)

**nsid도 하드코딩하지 않고 author_args가 결정**: `tc_writer.py`가 예전에는 admin-passthru 스텝의 `nsid`를 항상 0으로, io-passthru는 항상 1로 박아놨습니다. 실측에서 Identify CNS=0("Identify Namespace", 특정 네임스페이스를 요구)에 nsid=0을 보냈다가 `INVALID_NS`로 떨어졌는데, `nsid`는 `author_args`가 건드릴 수 있는 필드가 아니어서 cdw10을 몇 번을 재시도해도 구조적으로 못 고쳤습니다. 그런데 거꾸로 "그럼 LLM이 nsid도 알아서 고르게 하자"도 위험합니다 — 실제로 존재하는 네임스페이스가 아닌 값을 지어내면 또 다른 이유로 거부되기 때문입니다(멀티 네임스페이스 드라이브거나, 반대로 어떤 커맨드는 nsid=0을 요구하거나 `FFFFFFFFh`(전체 네임스페이스)를 요구할 수도 있음 — 하나로 고정할 수 없는 문제). 그래서:
- 파이프라인이 타겟의 `nvme_ns` 설정값(`/dev/nvme0n1` 같은 실제 경로)에서 이 하네스가 테스트 중인 **진짜 네임스페이스 id**(`active_nsid`)를 한 번 뽑아서(`tc_writer.namespace_id_from_device_path`), 매 TC마다 `author_args`에 넘겨줍니다.
- `author_args`는 `cdw10/cdw11/cdw12/direction`과 똑같이 `nsid`도 LLM에게 스펙 본문 근거로 고르게 하되, 그 값이 **`0`(네임스페이스 비특정) / `active_nsid`(이 타겟의 실제 네임스페이스) / `0xFFFFFFFF`(전체 네임스페이스, 스펙이 명시적으로 허용할 때만)** 셋 중 하나가 아니면 거부합니다. 만들어낸 다른 네임스페이스 id는 이 타겟에 존재하지 않으므로 받아들이지 않습니다.
- 이 검증도 opcode 방향비트와 똑같이, 장비에 보내기 전에 로컬에서 거부되면 1회 재시도(피드백 포함) 후에만 placeholder로 폴백합니다.

**Write 스텝이 섞인 배치가 몇 분씩 걸리던 버그**: `sudo nvme ... --write`는 `--input-file`을 안 주면 쓸 데이터를 **stdin에서** 읽습니다(nvme-cli 자신의 `--help`: "write/send file (default stdin)"). `execute_tc_steps`가 배치를 보낼 때 stdin을 명시적으로 안 채워주면, 로컬 프로세스(터미널에 붙어 인터랙티브하게 돌리는 경우)의 stdin이 plink를 통해 그대로 원격 `nvme io-passthru --write`로 흘러가는데 아무도 입력을 안 주니, **그 Write 스텝이 영원히 블로킹**합니다 — 실측: Write가 섞인 4단계 체인이 재시도까지 두 번 다 정확히 `SECONDS_PER_STEP * len(steps)`(120초)를 꽉 채우고서야 타임아웃났습니다(정상 스텝은 몇 초면 끝남). 지금은 `execute_tc_steps`가 배치의 "batch" plink 호출에 **Write 스텝들의 `data_len`만큼 0으로 채운 버퍼를 이어붙여 stdin으로 명시적으로** 넘깁니다(쓰기 스텝이 없는 배치도 빈 문자열 `""`을 넘겨서 stdin이 열린 채로 남지 않게 함). 터미널에 직접 붙여서 돌릴 때만 재현되고 파이프/리다이렉트로 돌리면 재현이 안 돼서 놓치기 쉬운 버그였습니다.

**TC 사이에 남는 상태 변화 — Sanitize/Namespace Management/Lockdown**: TC 하나의 멀티스텝 체인 안에서는 `shared_facts`로 상태를 넘기지만, **배치 안의 TC와 TC 사이**는 아무것도 추적하지 않았습니다. Sanitize/Format/Namespace Management처럼 `/dev/nvme0n1` 자체를 한동안 없애버리는 커맨드도 있고, Lockdown/Security Send처럼 디바이스 노드는 그대로인데 이후 admin 커맨드가 전부 거부되게 만드는 커맨드도 있습니다 — 실측으로 한 TC의 Write/Read가 "`/dev/nvme0n1: No such file or directory`"로 떨어졌는데, 이게 펌웨어 결함이 아니라 **바로 앞 TC의 상태 변경 커맨드 때문**이었던 사례가 있었습니다. 그래서 `destructive`/`firmware_state`/`lockout_risk` 스텝이 하나라도 섞인 TC가 끝나면, 다음 타겟으로 넘어가기 전에 `ssh_runner.device_responsive`(가벼운 `nvme id-ctrl` 1회 왕복)로 **디바이스가 여전히 명령에 응답하는지** 확인합니다. 응답이 없으면(디바이스 노드가 없거나 타임아웃이거나 거부당하거나) 남은 타겟을 전부 `skipped`로 건너뛰고 배치를 끝냅니다 — 똑같이 떨어질 게 뻔한 나머지 타겟들을 굳이 다 돌리지 않습니다. 파일 존재 여부만 보는 게 아니라 실제 커맨드를 보내서 응답을 확인하므로, 디바이스 노드가 사라지는 경우와 Lockdown처럼 노드는 있는데 커맨드만 거부되는 경우를 **둘 다** 잡습니다. (어떤 커맨드가 정확히 뭘 망가뜨리는지까지 의미적으로 모델링하지는 않습니다 — 범용적인 "죽었나 살았나" 확인으로 충분하다고 판단했습니다.)

**Firmware Download/Commit**: CA는 CDW10 bits 5:3, FS는 bits 2:0입니다. 성공한 0 바이트 더미 다운로드 증거가 있는 CA=1/3 활성화 성공을 검출합니다. CA=2의 기존 이미지 활성화를 더미 활성화로 단정하지 않습니다. 자세한 판정과 실행 범위는 [검증 문서](docs/spec_verification.md)를 참고하세요.

**디바이스 역량 사전 조회 — UNSUPPORTED/INVALID_FIELD 낭비 줄이기**: 실측(`data/tc_store.json`)에서 TC 103건 중 **UNSUPPORTED가 54건(약 52%)으로 가장 큰 비중**이었습니다. 지금까지 `generate_scenario`/`author_args`는 이 드라이브가 실제로 뭘 지원하는지 전혀 모른 채 스펙 표만 보고 커맨드/값을 고르고, 미지원이든 범위 밖 값이든 **매번 LLM 호출 + SSH 왕복을 거쳐서야** 알아냈습니다. 그래서 `run_pipeline`이 시작할 때 **딱 1회** `nvme id-ctrl`/`id-ns`/`effects-log`를 실제 장비에 던져서(`tc_system/execution/ssh_runner.py`의 `probe_device_capabilities`) OACS/ONCS/SANICAP 비트, NPSS, NSZE, 현재 LBA 포맷 섹터 크기, (버전이 지원하면) Commands Supported and Effects 로그를 읽고, 이를 한국어 힌트 문단으로 포맷해(`tc_system/generation/device_capabilities.py`의 `summarize_device_capabilities`) 매 TC의 시나리오/인자 생성 프롬프트에 `device_facts=` 블록으로 끼워넣습니다.

- **런당 1회**만 장비에 묻고, 파싱된 결과를 메모리에 들고 있다가 그 실행의 모든 LLM 호출 프롬프트에 재사용합니다 — LLM 호출은 서버 쪽에 대화 기록이 없는 완전한 stateless 호출(`shared/llm_client.py`의 `_complete`가 매번 `messages`를 새로 만듦)이라, 한 번 알려준 사실을 LLM이 "기억"해주지 않으므로 매 프롬프트에 다시 넣어야 하지만, 장비에 다시 묻는 비용은 없습니다.
- `generate_scenario`(시나리오/`steps_plan`)에는 "이 드라이브가 실제로 지원한다고 확인된 커맨드를 setup/verify로 우선 고르라"는 힌트로, `author_args`(값 생성)에는 "LBA는 NSZE 범위 안으로, Power State는 NPSS 범위 안으로, Sanitize는 SANICAP이 허용하는 방식만"이라는 값-검증 힌트로 씁니다.
- **타겟 선정 순서(`pick_next_targets`)는 건드리지 않습니다** — 미지원으로 예상되는 조항도 여전히 타겟으로 제시되고 실제로 1회 실행해서 실측으로 확인합니다. CLAUDE.md의 "UNSUPPORTED도 드라이브에 대한 유효한 결론"이라는 원칙과 충돌하지 않도록, 이 정보는 **순수 프롬프트 힌트**로만 쓰고 실행 자체를 건너뛰지 않습니다.
- 조회가 실패하거나(장비 연결 안 됨) nvme-cli 버전이 `effects-log` 서브커맨드를 모르면, `summarize_device_capabilities`는 파싱 가능한 부분만 담아 빈 문자열까지 떨어질 수 있고, `run_pipeline`은 이 전체를 `try/except`로 감싸 실패 시 `device_facts=None`으로 그냥 진행합니다 — 이 조회는 "있으면 속도가 빨라지는" 보조 수단일 뿐, 실행 자체의 전제조건이 아닙니다.

## 5-4. 디테일 로그 — 전체 로그 / LLM 프롬프트·응답 확인

**실행 전체 기록** — `run_tc_pipeline.py`를 실행하면 터미널에 찍히는 모든 줄(TC별 시나리오/Expectation, 실행 결과, 최종 커버리지 요약)이 `logs/tc_pipeline_<UTC타임스탬프>.log`에도 동시에 저장됩니다(`shared/run_log.py`의 `capture_to_file`). 실행 시작 시 맨 처음 줄에 그 실행의 로그 파일 경로가 `[전체 로그] ...`로 찍히므로, 터미널을 닫았거나 스크롤을 놓쳤어도 그 경로를 열면 그 실행에서 무슨 일이 있었는지 전부 다시 볼 수 있습니다. UTF-8로 저장되어 한글이 깨지지 않습니다(콘솔 코드페이지 때문에 화면 표시가 깨지더라도 파일 쪽은 항상 정상).

**모든 줄 앞에 `[YYYY-MM-DD HH:MM:SS.mmm]`가 찍힙니다**(콘솔/파일 둘 다) — "`-> 실행 중...`"만 보고는 지금 걸린 게 정상적인 대기인지 실제로 SSH가 멈춘 건지 알 수가 없어서, `logs/ssh_commands.jsonl`/`logs/llm_calls.jsonl`의 타임스탬프와 수동으로 대조해야 했습니다. 이제 그 자리에서 바로 "몇 분째 멈춰 있는지" 보입니다.



터미널 화면은 `textwrap.shorten`으로 한 줄씩 줄여서 보여주지만, **파일에는 시나리오/Expectation/Fail 기준/체인 요약/스텝 역할/실패 사유/위반 상세가 전부 원문 그대로** 남습니다 — 다만 짧은 줄과 전체 줄을 **따로 두 번 찍지 않습니다**. 한 줄을 두 목적지(콘솔/파일)에 **다른 내용으로** 쓰는 `sys.stdout.dual_write()`를 통해, 콘솔엔 줄인 버전 한 줄, 파일엔 원문 한 줄만 남도록 합니다(`run_tc_pipeline.py`의 `_dual_line`/`_dual_label`). 처음엔 짧은 줄 하나 + `[라벨 전체]` 전체 줄 하나를 따로 찍는 식으로 만들었는데, 그러면 파일에 같은 내용이 줄여진 버전/전체 버전 두 줄로 중복 남는 게 불필요해서(사용자 피드백) 한 줄짜리 설계로 바꿨습니다. `dual_write`는 `capture_to_file`이 이미 열어둔 파일 핸들에 직접 쓰는 방식입니다 — 같은 경로를 두 번째 핸들로 또 열면(`open(path, "a")`) 서로 다른 버퍼 위치 때문에 파일이 깨져서(실측: 줄이 사라지거나 다른 줄 중간에 섞여 들어감), 반드시 이 경로로 써야 합니다.

이 파일 쪽 원문도 **표시 직전까지 온전했던 텍스트만** 복원합니다 — 그 전에 데이터 자체가 이미 잘려 있었다면(과거 버그) 복원할 원본이 없습니다. 실측으로 `expectation_checker.py`의 `controller returned an error status` 등 세 함수가 상태 텍스트를 200~300자로 하드컷해서, 실제 NVMe 상태 설명이 문장 중간("...currently in u")에서 끊긴 채로 criteria_results/판정/로그 전부에 그대로 남는 버그가 있었다. 지금은 그 컷을 없애고 "그 상태 텍스트가 들어있는 한 줄 전체"만 가져오므로(여러 줄 전체를 다 가져오는 게 아니라 한 줄 단위로는 여전히 자연스럽게 bound됨), 콘솔/로그 레이어에서 다시 줄이는 것과 무관하게 데이터 자체는 원문을 보존합니다.

**LLM 프롬프트/응답** — `logs/llm_calls.jsonl`: judge/scenario_generator/args_author가 호출한 **모든** LLM 요청이 한 줄씩(JSON) 쌓입니다. 성공/실패 둘 다 남습니다(실패해도 몰래 버려지지 않음).

필드: `timestamp`, `caller`(어느 모듈이 불렀는지), `system`, `prompt`(전체, RAG로 붙인 스펙 본문 포함), `response_schema_keys`, `raw_response`(LLM이 실제로 뭐라고 답했는지, 가공 전), `retry_prompt`/`retry_raw_response`(JSON 파싱 실패해서 재시도한 경우), `structured`(파싱된 최종 결과), `error`(실패 사유), `elapsed_sec`.

```python
import json
lines = [json.loads(l) for l in open("logs/llm_calls.jsonl", encoding="utf-8")]
lines[-1]["prompt"]          # 가장 최근 호출의 전체 프롬프트
lines[-1]["raw_response"]    # 그 응답 원문
```

git에는 안 올라감(`.gitignore`). TC 1건당 보통 2~3줄(시나리오 생성 → 인자 생성 → [FAIL/ERROR일 때만] 판정) 쌓입니다.

**실제 SSH로 나간 명령 + 단계별 타이밍** — `logs/ssh_commands.jsonl`: `tc_system/execution/ssh_runner.py`가 매 TC 배치마다 한 줄씩 남깁니다. 필드: `timestamp`, `n_steps`, `step_commands`(실제로 만들어진 `sudo nvme admin-passthru/io-passthru ...` 명령 전체 텍스트, 비밀번호는 stdin으로만 전달되므로 여기 안 남음), `stages`(순서대로 `dmesg_clear` → `batch` → `dmesg_dump`, 각각 `elapsed_sec`/`exit_code`/`timed_out`). 배치가 타임아웃으로 멈춰도 `finally`에서 항상 기록되므로, "어느 단계에서 몇 초 동안 멈췄는지 + 그때 보낸 명령이 정확히 뭐였는지"를 사후에 재구성할 수 있습니다.

`batch` 단계의 타임아웃은 고정값이 아니라 **스텝 1개당 30초**(`ssh_runner.SECONDS_PER_STEP`)로, `30 * len(steps)`초입니다. 실측해보니 정상 완료는 전부 3~12초, 실제로 장비가 먹통인 경우는 전부 125~143초(옛 고정 120초 타임아웃 + plink 강제종료 오버헤드)였고 그 사이가 텅 비어 있었습니다 — 그래서 정확한 임계값 자체는 정상/행 구분에 거의 영향이 없고, "행 1건당 얼마나 낭비하는지"만 좌우합니다. 스텝 1개짜리 TC는 30초(옛 120초보다 훨씬 짧게 끊음), 스텝 4개짜리 체인은 120초까지 여유를 줍니다.

```python
import json
lines = [json.loads(l) for l in open("logs/ssh_commands.jsonl", encoding="utf-8")]
lines[-1]["step_commands"]                      # 마지막 배치가 실제로 보낸 명령
[(s["stage"], s["elapsed_sec"]) for s in lines[-1]["stages"]]   # 단계별 소요시간
```

**정리**: 지금까지 확인 가능한 곳은 5군데입니다 — ① `logs/tc_pipeline_*.log`(그 실행의 터미널 전체 기록), ② `logs/llm_calls.jsonl`(LLM 프롬프트/응답), ③ `logs/ssh_commands.jsonl`(실제 전송된 nvme-cli 명령 + 단계별 타이밍), ④ `data/tc_store.json`(TC별 최종 상태), ⑤ `data/verdicts/tc_exec.json`(FAIL/ERROR 판정 결과). ①이 가장 먼저 볼 곳이고, 명령 자체나 타이밍이 궁금하면 ③, 더 깊이 볼 때 ②/④/⑤로 내려가면 됩니다.

**터미널의 판정 결과를 `data/verdicts/`·`data/failure_contexts/`의 실제 파일과 매칭하기**: FAIL이든 ERROR든(둘 다 판정 대상이면) 결과 줄 바로 아래에
```
     -> LLM 판정 완료 (verdict_id=verdict-xxxx, data/verdicts/tc_exec.json 참고)
        failure_context_id=fc-tc_exec-yyyy (data/failure_contexts/tc_exec/fc-tc_exec-yyyy.json 참고)
```
가 그대로 찍힙니다 — `verdict_id`로 `data/verdicts/tc_exec.json`에서 판정(classification/confidence/rationale)을, `failure_context_id`로 `data/failure_contexts/tc_exec/<id>.json`에서 원본 증거(로그 발췌, dmesg, 위반 기준)를 바로 찾을 수 있습니다. (예전에는 `verdict_id`만 FAIL일 때만 찍혀서, ERROR로 판정된 건이나 FailureContext 파일 자체를 찾으려면 `data/verdicts/tc_exec.json`을 열어 `failure_context_id` 필드를 수동으로 봐야 했습니다.)

**판정과 FailureContext는 실행 간 보존합니다.** judge 호출 전에 FailureContext를 먼저 저장하여 LLM 실패 후에도 재판정할 수 있습니다. 재시도마다 명령과 원시 실행 결과를 `attempts`에 기록합니다.

## 6. 테스트

```
python -m unittest discover -s tests -v
```
기존 파서·생성·판정·SSH·커버리지 회귀 테스트와 스펙 검증 계약 테스트를 실행합니다. 실제 로그 기반 사례 및 분기별 합성 응답을 사용하며 장비·SSH·LLM 호출은 모킹합니다. 검증 범위는 [스펙 검증 문서](docs/spec_verification.md)를 참고하세요.

테스트는 **네트워크를 타지 않는다** — LLM 클라이언트는 순수 함수(JSON 추출, confidence 정규화)만 테스트하고, 실제 LLM 경로는 `run_judge.py`를 돌려서 확인한다.
