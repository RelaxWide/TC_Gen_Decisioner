# 스펙 기반 TC 생성·실행·판정 검토

검토일: 2026-11-04 (Asia/Seoul)

## 결론

현재 커버리지 수치는 **관련 opcode를 실행하고 특정 상태로 분류한 조항 수**에 가깝다. 생성된 시나리오의 요구사항을 실제로 자극하고, 결과를 관측하여 검증한 비율로 해석할 수 없다. 시나리오와 명령 인자가 어긋난 실제 PASS 사례가 있고, 스펙별 실패 조건은 평가하지 않은 상태에서도 PASS가 된다.

LLM 프롬프트 문구만 개선해서 해결할 문제는 아니다. 스펙 근거 → 테스트 의도 → 명령 인자 → 관측 데이터 → 검증식 → 커버리지의 연결 정보가 여러 단계에서 빠진다. 기존의 재시도·placeholder 차단·장비 헬스체크는 유용하지만 이 연결을 보장하지 않는다.

## 검토 범위와 재현

- 로컬 `origin`: `https://github.com/RelaxWide/TC_Gen_Decisioner.git`; 로컬 HEAD: `1ca30dd`.
- GitHub 최신 원격 브랜치를 fetch하거나 push하지 않았다. 분석 대상은 이 작업 폴더의 코드와 로컬 산출물이다.
- 검토 시작 시 변경 표시된 10개 기존 파일은 `git diff --ignore-space-at-eol --stat`에서 내용 차이가 없었다. 기존 파일은 수정하지 않았다.
- 현재 `data/tc_store.json` 12건, `logs/llm_calls.jsonl` 465건 중 현재 TC에 연결되는 생성·인자 프롬프트, 과거 judge 응답, 로컬 스펙 원문 청크, 판정·커버리지·리포트 코드를 대조했다.
- 실제 SSH·LLM 호출이나 장비 실행은 하지 않았다. 아래의 반례는 명시적으로 합성한 응답을 **현재 판정 함수**에 넣는 오프라인 재현이다. 실제 드라이브 동작으로 오인하면 안 된다.

재현 명령:

```bash
python3 tests/reproduce_spec_coverage_audit.py
python3 tests/reproduce_spec_coverage_audit.py --scan-retrieval
python3 -m unittest discover -s tests -q
```

첫 두 명령은 JSON을 stdout으로 출력한다. 저장된 TC가 없는 새 체크아웃에서는 합성 반례는 실행하고 실제 TC 통계는 생략한다. SSH/LLM 및 자격증명 파일을 사용하지 않고, 상태 파일도 쓰지 않는다.

현재 저장 상태:

| 항목 | 확인값 |
|---|---:|
| TC | 12 |
| 전체 TC 상태 | PASS 3 / ERROR 2 / UNSUPPORTED 7 |
| LLM이 작성한 산문 실패 기준 | 41개, 전부 unevaluated |
| 현재 커버된 조항 | 12 / opcode 연결 조항 258 |
| 전체 스펙 조항 / opcode | 1,292 / 60 |
| 현재 TC 실행의 LLM verdict | 0건 |

## 1. 시나리오의 의도가 인자 생성기에 전달되지 않는다 — 높음

`tc_system/generation/tc_writer.py:73`은 `author_args`에 section/opcode, 이전 스텝의 shared_facts, 장비 힌트만 보낸다. 시나리오 본문·preconditions·fail_criteria와 **현재 스텝의 role/phase**는 인자 생성 프롬프트에 전달하지 않는다. `args_author.py:299`에서 만드는 프롬프트에도 이 정보가 없다.

인자 생성기의 시스템 지시는 `args_author.py:108`에서 “컨트롤러가 받아들일 가장 단순한 변형”을 고르게 한다. 따라서 시나리오가 약속한 특정 동작보다 성공하기 쉬운 다른 변형을 고를 수 있다. 거부 후 재시도도 `args_author.py:321`에서 다른 필드 값을 고르라고만 요구하여 테스트 목적의 변경을 허용한다.

**실제 저장 사례:**

| TC / 단계 | 생성된 의도 | 실제 인자 / 결과 |
|---|---|---|
| `tc-3abc86f1ab` Get Features | Host Metadata FID=7Dh, SEL=3; Saveable/Changeable 확인 | 최종 CDW10=`0x00000002`: FID=02h, SEL=0. 다른 기능을 조회하고 PASS |
| `tc-3105679f40` setup | Identify Controller로 LPOS/전송 상한 확인 | CNS=0, NSID=1로 Identify Namespace 실행 |
| 같은 TC verify | Supported Log Pages LID=00h 조회 | LID=02h를 다시 조회하고 PASS |
| `tc-e15b994c0c` action | Identify Controller CNS=01h 조회 | 재시도 후 CNS=0, NSID=0; INVALID_NS / ERROR |
| `tc-5088877af0` setup | Keep Alive Timer FID=0Fh 확인 | FID=7Dh, SEL=3 조회 |

증거: `data/tc_store.json`의 각 TC, `logs/llm_calls.jsonl` 424~433행, 435행. Get Features는 424행 시나리오 → 425행 초기 인자 FID=7Fh → 426행 거부 피드백 후 FID=02h로 바뀐다. **명령은 바뀌는데 원래 시나리오는 그대로 저장된다.**

개선 방향: 현재 스텝의 목적·고정 필드·기대 결과를 구조화하여 인자 생성에 넘기고, 인코딩 결과가 그 목적과 일치하는지 검증한다. 재시도가 고정 필드나 테스트 목적을 변경하면 같은 TC의 성공으로 대체하지 않는다.

## 2. 스펙별 결과를 검사하는 실행 가능한 검증식이 없다 — 높음

`expectation_checker.py:231`은 고정된 5개 규칙을 검사하고 그 밖의 선언된 기준을 모두 `unevaluated`로 만든다. `check_expectation`은 `unevaluated`를 PASS 차단 조건으로 사용하지 않는다. 시나리오 생성 스키마도 실패 조건을 문자열 배열로만 요구한다.

따라서 다음은 검사되지 않는다.

- 반환된 CQE Dword 0의 특정 비트가 요구값인지.
- Read 데이터가 앞선 Write 내용과 같은지.
- Get Features 결과가 Set Features 값과 같은지.
- 로그/Identify 데이터 구조의 필드 값, reserved 비트, 길이가 올바른지.
- 요구한 이벤트가 실제로 발생했는지, 상태 전환이 완료됐는지.

현재 PASS 3건도 각각 세부 조건 4개가 미평가다. Get Features 응답을 `result: 0xFFFFFFFF`로 바꿔 Saveable=0 조건을 위반하게 해도 현재 판정은 PASS다. Get Log Page가 읽을 데이터 길이 512를 선언했으나 출력에 payload가 전혀 없는 합성 응답도 PASS다. 이는 실제 드라이브가 잘못된 데이터를 반환했다는 주장이 아니라 **검증기가 차이를 검출하지 못한다는 재현**이다.

정상적으로 에러를 반환해야 하는 negative test도 표현할 수 없다. 실제 `tc-fdc9bb6be6` 시나리오는 INVALID_FIELD 거부를 기대하지만 기본 expectation은 성공을 요구한다. 기대한 INVALID_* 응답을 넣으면 ERROR 또는 UNSUPPORTED로 빠지고 PASS assertion으로 평가되지 않는다.

**LLM judge가 이 빈틈을 메우지 않는다.** `pipeline.py:409` 이후 judge는 일부 FAIL/ERROR의 원인 분류에만 호출되고 PASS의 스펙 준수 여부를 검사하지 않는다. 현재 12건에는 판정 호출 결과가 없다. `pipeline.py:24`가 judge용 FailureContext를 만들 때도 실제 CDW·NSID·payload와 시나리오 본문·preconditions를 전용 필드로 전달하지 않는다. 실패 기준 문자열은 criteria_results에 있지만 어떤 명령을 의도대로 구성했는지 확인할 입력이 부족하다. `judge.py:86`의 signals JSON은 4,000자로 잘려 긴 출력에 뒤쪽 증거가 밀릴 수도 있다.

개선 방향: expected completion status, CQE/버퍼 필드 비교, 이전 단계와 값 비교 등 허용된 검증식을 정의하고 측정 증거와 함께 평가한다. 미평가 필수 조건이 남으면 “요구사항 검증 완료”로 집계하지 않는다. LLM은 요구사항 추출과 불확실한 원인 설명을 담당하고, 결정 가능한 비교는 코드가 수행한다.

## 3. 조항의 정확한 본문을 확보하지 않고 프롬프트를 만든다 — 높음

`scenario_generator.py:108`은 제목/명령명 검색 top 3, `args_author.py:293`은 일반적인 명령 필드 검색 top 4를 쓴다. 인덱스에 이미 있는 section.chunk_ids를 직접 따라가지 않는다. `shared/spec_chunks.py:85`는 선택된 청크의 **처음 2,000자**만 반환한다. section_id라는 반환 필드도 실제 스펙 조항 ID가 아니라 chunk ID다.

현재 258개 opcode 연결 조항에 시나리오 검색 질의를 동일하게 재실행한 결과:

| 진단 | 조항 수 |
|---|---:|
| 선택된 전체 청크에 해당 조항 제목이 있음 | 96 |
| 2,000자 절단 후에도 해당 조항 제목이 보임 | 40 |
| 청크 선택에는 성공했지만 절단으로 제목이 사라짐 | 56 |
| 해당 제목을 포함한 청크 자체가 top 3에 없음 | 162 |

이 수치는 **제목 추적성 진단**이다. 제목이 없다는 사실만으로 그 컨텍스트 전체가 무관하다고 단정하거나, 218건 모두가 잘못된 TC라는 뜻으로 사용하면 안 된다. 다만 정확한 목표 조항을 반드시 제공하는 보장이 없다는 점은 명확하다.

직접 확인한 예:

- Get Features `base:5.2.11` 본문은 소속 청크의 문자 offset 3,905부터 시작한다. 청크가 검색되어도 2,000자 제한에 잘린다. 실제 시나리오 프롬프트 424행과 인자 프롬프트 425~426행 spec_context에는 조항 제목이 하나도 없다.
- Identify `base:5.2.13`은 offset 2,998부터 시작한다. 대신 앞 조항인 Pull Model DDC Request Log Page 내용이 전달된다. 실제 431행 시나리오, 432~433행 인자 프롬프트에서도 확인된다.
- NVMe-MI Send 목표 `base:5.2.19`의 실제 본문은 **MI 스펙 참조**다. 그러나 검색을 Base 문서로 제한하여 MI 상세 스펙을 받지 못하고, 다른 명령인 Manage Exported Port Delete 조항으로 시나리오가 이동했다(`tc-fdc9bb6be6`).

개선 방향: section/chunk 연결로 정확한 조항과 표를 추출하고 다음 청크의 연속 내용 및 명시적 교차 참조를 연결한다. 요구사항마다 문서·조항·근거 구간을 보존한다. 근거가 없거나 실행 불가능하면 생성 단계에서 이를 명시한다.

## 4. 현재 커버리지와 다음 타겟 선정이 검증 누락을 고착시킨다 — 높음

`coverage_state.py:16`은 placeholder가 아니면서 스텝 상태가 PASS/FAIL/UNSUPPORTED이면 조항을 covered로 만든다. requirement/assertion의 존재나 실제 평가 여부를 보지 않는다. `pick_next_targets`는 이 조항을 다음 대상에서 제외하며 조항당 첫 연결 opcode만 고른다.

따라서 단순 setup 조회나 목적이 바뀐 명령도 전체 명령 조항을 커버할 수 있다. 하나의 정상 전송으로 같은 조항의 다른 조건, 경계값, 오류 처리까지 검증된 것은 아니다. 현재 258개 분모도 “opcode에 연결된 조항 수”이지 실행기와 검증기가 실제로 검증할 수 있다고 확인된 조항 수가 아니다.

오프라인 반례에서 `/dev/nvme0n1: No such file or directory`를 반환한 명령은 FAIL이 되고 실제 조항 1개가 covered로 집계된다. 장비 명령이 실행되지 않은 호스트 오류다. usage의 `--timeout` 문자열도 timeout 위반으로 오인한다. 현재 AER TC의 verify 단계 역시 `Resource temporarily unavailable` + usage 출력인데 FAIL이다. ERROR인 TC 안에서도 이 스텝은 커버리지에 반영된다.

FAIL과 UNSUPPORTED를 **실행/지원 조사 이력**에 포함하는 정책 자체를 없앨 필요는 없다. 대신 requirement coverage와 구분해야 한다. 미지원 판단에는 mandatory/optional 및 장비가 광고한 지원 여부도 필요하다. 유효한 미지원 결론을 남기는 것과 해당 기능의 정상 동작을 검증했다는 것은 서로 다른 결과다.

개선 방향: 실행 도달/지원 조사, 요구사항 검증 시도, 준수 결과를 별도 집계한다. 다음 타겟 선정은 opcode 이름이나 명령 조항의 방문 여부가 아니라 아직 검증하지 못한 요구사항/케이스를 기준으로 한다.

## 5. 생성기가 실행기에 없는 능력을 가정한다 — 높음

`ssh_runner.py:253`은 모든 명령을 동기적으로 순서대로 실행한다. 이전 명령이 끝나야 다음 명령을 시작하고, setup 실패 후에도 나머지 명령을 보낸다. 모든 인자는 실행 전에 생성되며 실제 setup 반환값을 파싱해서 후속 인자에 반영하지 않는다. shared_facts는 모델이 미리 선택한 값이지 측정된 상태가 아니다.

실제 사례와 기능 차이:

- Abort 시나리오는 진행 중인 명령의 SQID/CID를 취소한다고 하지만, 앞선 Get Log Page가 완료된 뒤 Abort를 실행한다. 취소 대상 명령을 비동기로 유지하거나 실제 CID를 수집하는 경로가 없다. 반환 `result=1`은 스펙상 immediate abort가 수행되지 않았음을 뜻하지만 검증하지 않고 PASS다. 이는 Abort 명령 자체의 정상 완료일 수 있으나 시나리오의 목표가 달성됐다는 증거는 아니다.
- AER 시나리오는 이벤트 설정과 발생을 가정한다. 실제 setup은 FID=0Bh 대신 FID=81h를 쓰고, 이벤트를 발생시키는 동작 없이 AER을 동기 실행한다. 현재 실패만으로 기대 동작/펌웨어 결함을 결론낼 수 없다.
- 쓰기 payload는 `ssh_runner.py:273`에서 무조건 0으로 채운다. MI Delete의 EPID/SUBNQN, 다른 관리 명령의 구조화된 입력, 특정 패턴 데이터 등을 시나리오에 기술해도 payload로 인코딩되지 않는다.
- `passthru_cmd`는 CDW10~12만 보낸다. CDW13~15가 필요한 테스트, 반환 데이터를 바탕으로 분기하는 테스트, 비동기 이벤트·정밀 타이밍 테스트의 실행 능력을 생성기에 알리지 않는다.

개선 방향: 실행기가 지원하는 동작/관측/검증 능력을 생성 입력에 명시하고 실행 가능한 계획인지 검사한다. 지원하지 않는 테스트를 단순 opcode 명령으로 축소해 원래 설명과 함께 PASS 처리하지 않는다.

## 6. 필드 하나의 일치가 명령 전체의 유효성으로 확대된다 — 높음

`args_author.py:69`의 field_value_verified는 일부 selector가 CDW10 하위 8비트에 들어갔는지만 확인한다. 하지만 `expectation_checker.py:175`와 스텝 판정은 이 값이 True이면 INVALID_OPCODE 이외의 **모든 INVALID_***를 UNSUPPORTED로 처리한다.

오프라인 재현: LID=02h가 올바르게 인코딩됐다는 확인을 붙인 뒤 응답을 INVALID_NS로 주면 UNSUPPORTED가 된다. LID가 맞아도 NSID, 전송 길이, 다른 필드, 사전 상태는 틀릴 수 있으므로 “이 로그 페이지가 미지원”이라는 결론은 성립하지 않는다. 현재 저장된 12건에서 이 반례를 실측했다고 주장하는 것은 아니다.

필드 배치 표도 일반화가 과도하다. REQUEST_SELECTABLE_FIELDS는 Directive Operation/Directive Type까지 CDW10[7:0]으로 가정한다. 로컬 스펙 Figure 181은 DOPER=CDW11[7:0], DTYPE=CDW11[15:8]을 정의한다. 현재 인덱스에는 해당 이름으로 field_values가 연결된 조항이 없어 이 경로는 잠재 오류지만, 새 조항을 추가하면 잘못된 검증을 강제한다.

개선 방향: command_set/opcode/selector에 맞는 필드 정의로 검증하고, 어떤 필드까지 검증됐는지를 기록한다. 단일 bool을 명령 전체의 정상 인코딩이나 미지원 증거로 확장하지 않는다.

## 7. 실제 전송 길이 불일치를 프롬프트 지시만으로 막고 있다 — 높음

Get Log Page의 NUMDL/NUMDU는 0-based dword 수이며 `bytes = (NUMD + 1) * 4`다. 로컬 스펙 Figure 201에도 명시되어 있다. 프롬프트는 이 규칙을 말하지만 인자 검증은 범위·형식만 검사하여 일치 여부를 강제하지 않는다.

현재 저장 결과에 두 건의 불일치가 있다.

| TC / step | CDW10 | 명령이 요청한 길이 | 할당 길이 |
|---|---|---:|---:|
| `tc-4522b684eb` / 0 | `0x00800001` | 516 B | 512 B |
| `tc-3105679f40` / 2 | `0x007F0002` | 512 B | 508 B |

둘 다 저장된 결과는 PASS다. 실제 손상 여부는 이 자료만으로 판단하지 않는다. 그러나 전송 길이가 일치하지 않는 명령이 유효한 스펙 검증으로 통과했다는 점은 확인된다. 두 번째 인자 응답(`llm_calls.jsonl:430`)은 NUMD=127을 127×4=508로 해석하고 있으며, 0-based 보정을 놓쳤다.

개선 방향: 길이와 필드 간 관계를 코드로 검증하고, 가능한 경우 하나의 구조화된 요청에서 CDW와 버퍼 길이를 함께 산출한다.

## 8. Firmware Commit 규칙과 프롬프트가 스펙의 비트 위치를 잘못 사용한다 — 높음

로컬 NVMe Base 스펙 Firmware Commit CDW10 표:

- **CA = bits 5:3**
- **FS = bits 2:0**

하지만 `expectation_checker.py:101`은 `cdw10 & 0b111`을 CA로 읽는다. `args_author.py:144`의 프롬프트와 CLAUDE.md/README 설명, `tests/test_expectation_checker.py`의 관련 테스트도 같은 오류를 공유한다.

오프라인 성공 응답 재현:

| CDW10 | 스펙 CA / FS | 현재 전체 판정 | 현재 스텝 판정 |
|---|---|---|---|
| `0x01` | CA=0 / FS=1 | FAIL: 활성화했다고 오인 | PASS |
| `0x08` | CA=1 / FS=0 | PASS: 활성화 규칙 누락 | PASS |
| `0x09` | CA=1 / FS=1 | FAIL | PASS |

별도로 스텝 판정 함수에는 이 firmware 규칙이 없어 전체 FAIL과 커버리지용 PASS가 충돌한다. 또한 CA=2는 기존 슬롯 이미지를 활성화하는 동작이므로 성공만으로 더미 이미지를 활성화했다고 단정할 수 없다. 규칙은 선행 download의 실제 payload·성공 여부·슬롯과 연결된 증거도 필요하다. CA=6은 Boot Partition 교체, CA=7은 활성 지정이므로 전부 같은 활성화 동작으로 설명하는 프롬프트도 부정확하다.

이 문제는 “CA를 0으로 강제할 것인가”라는 기존 정책 선택과 별개다. 어떤 CA를 테스트하든 먼저 정확히 인코딩·해석하고 그 동작의 기대 결과를 검사해야 한다. 이번 검토에서는 실행 정책이나 코드를 수정하지 않았다.

스펙 근거 청크: `rag/index/v20260922_172200/chunks.jsonl` 안 doc_id가 `833824_7150992_0a034b43-1925-4733-b953-cd717bea9765#13`인 항목. Directive 표는 같은 접두사의 `#12`, Get Log Page NUMDL 표는 `#21`, Abort 결과 비트는 `#0`에 있다.

## 화면과 로그가 문제를 드러내지 못하는 이유

`report/html_report.py:37`의 TC 표에는 이름·상태·조항/opcode·시간만 있다. 계획한 동작과 실제 필드, 반환값, 평가한 조건과 미평가 조건을 나란히 보여주지 않는다. `:20`은 PASS 커버리지를 “정상 동작 확인됨”으로 표시하여 현재 보장 범위보다 강한 의미를 전달한다.

`tc_store`에는 시나리오의 llm_response_id만 연결되고 각 args 생성 호출의 ID는 없다. SSH 로그에도 tc_id/attempt_id가 없어 시간·순서·명령문을 수동 대조해야 한다. 재시도 전 결과는 최종 TC에서 교체되며, TC 판정/FailureContext는 다음 실행에 초기화된다. 따라서 상세 로그의 양을 늘리는 것만으로는 사후 검증이 쉬워지지 않는다.

권장 검토 화면은 각 requirement에 대해 다음 열을 갖는다:

| 스펙 근거 | 검증할 요구사항 | 계획한 자극 | 실제 명령/입력 | 관측 결과 | 검증식과 평가 | 커버리지 반영 이유 |
|---|---|---|---|---|---|---|
| 문서/조항/근거 구간 | 검증 가능한 한 문장 | FID=7Dh, SEL=3 | FID=02h, SEL=0 | CQE=4 | 대상 불일치, 미검증 | 요구사항 커버 제외 |

전체 조항을 먼저 자동화하기보다 Get Features 한 사례에서 이 연결을 끝까지 검증한 뒤 확대하는 편이 적절하다.

## 수정 우선순위

1. **잘못된 신뢰 표시부터 분리:** 현재 실행 이력/미지원 이력을 보존하면서 “스펙 검증 완료”와 구분한다. 필수 기준 미평가·대상 불일치·호스트 오류가 requirement coverage에 들어가지 않게 한다.
2. **스펙 근거와 테스트 목적 연결:** 정확한 조항/표 확보 → 요구사항 ID → 스텝 의도와 고정 필드 → 인코딩 일치 검증. 재시도가 테스트 목적을 바꾸지 못하게 한다.
3. **실행 가능한 검증 추가:** 예상 오류 응답도 정답으로 표현하고 CQE·버퍼·전후 상태 비교를 구현한다. 생성기에는 실행기의 지원 능력을 알려준다.
4. **구체적 판정 오류 수정:** Firmware CA/FS, selector 배치, NUMD/버퍼 길이, INVALID_*의 근거 없는 미지원 분류, usage timeout 오탐, 전체/스텝 판정 불일치.
5. **근거를 한 화면에 연결:** TC/attempt/LLM/SSH/requirement ID를 연결하고 미평가 조건과 재시도 전후 차이를 보존한다.

기존 253개 테스트가 통과해도 위 반례가 존재한다. 특히 Firmware 테스트는 구현과 같은 잘못된 비트 해석을 기대값으로 사용한다. 향후 테스트에는 **원문 표에서 독립적으로 유도한 벡터**, 잘못된 CQE/데이터를 넣었을 때의 검출, 올바른 negative response의 PASS, 시나리오와 실제 인자의 일치가 포함되어야 한다.
