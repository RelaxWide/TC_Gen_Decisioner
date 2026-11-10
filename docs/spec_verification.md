# 스펙 검증과 실행 이력

2026-11-04 수정부터 명령 성공과 스펙 검증을 분리한다. `execution_status`는 명령 실행 결과이고, `verification.status`는 인용 근거와 검증식 평가 결과다. 정상 실행이어도 검증 근거가 없으면 TC는 `UNVERIFIED`다. 기존 저장 기록은 수정하지 않으며 리포트가 검증 상태를 다시 계산한다.

## 생성 → 실행 → 판정

1. `shared/spec_evidence.py`가 문서 순서대로 청크를 복원해 정확한 조항과 하위 조항, 명시적인 참조 조항을 가져온다. NVMe-MI 명령은 MI 문서도 연결한다. 프롬프트가 약 10K 토큰을 넘지 않도록 문자 예산(시나리오 20,000 / 인자 16,000 / 판정 14,000)을 둔다. 표는 `| 셀 |` 행으로 압축한다. 예산 초과 블록은 전체를 제외하고 누락을 표시하며, 대상 조항과 커맨드 레이아웃 조항만 앞쪽 줄 단위로 잘라 `truncated`로 표시한다. 인자 생성에는 커맨드 본 조항의 Command Dword 정의를 먼저 넣는다.
2. 시나리오는 원문 인용, 근거 ID, 요구사항별 검증식, 단계별 기대 상태와 고정 필드를 선언한다. Identify Controller/Namespace와 Supported Log Pages·Commands Supported and Effects·FID Supported and Effects 로그의 필드는 **이름으로** 쓴다(`{"field": "OACS.NMS", "value": 1}`, `{"field": "LSUPP", "index": "16h", "value": 1}`). 오프셋·마스크는 하네스가 스펙 표(`tc_system/spec_fields.py`, 로컬 스펙과 대조하는 테스트 있음)에서 정한다. 오프셋으로 쓴 검사식도 그 구조의 필드 경계와 설명이 말하는 필드·비트·0/1 조건과 대조한다(설명은 NMS인데 Self-test 비트를 읽음, "257:256"을 offset 257로 읽음, "1이어야"를 `ne`로 씀). 설명이 필드·비트 하나를 분명히 가리키면 하네스가 검사식을 그 필드로 **고쳐 쓰고** 계약의 `check_repairs`와 터미널 `검사식 보정`에 남긴다(지난 실행 응답 기준 문제 110건 중 87건). 여러 필드를 말하거나 다른 구조의 필드를 말하면 고치지 않고 재시도로 돌려보낸다. 스텝 역할에 FID/LID/CNS가 하나 적혀 있으면 그 값으로 고정하고, 고정값과 다르면 거부한다. 항상 참인 검사(`le mask`, `ge 0`)는 거부하고, 요청 길이를 비교하는 `data_length`는 장비 관측이 아니라 빼며 그것만 남으면 거부한다. 전체 바이트 비교는 `data_all`(캡처가 요청한 버퍼 전체가 아니면 평가하지 않음). 인용에는 SHALL/SHOULD/MAY 강도가 기록된다. 인용이 실제 제공 근거에 있는지 검사한다(글자·숫자 기준으로 같은 단어가 같은 순서인지 — 표 구분자·수식 흔적·따옴표 차이는 허용, 번역·의역은 거부). 사전조건은 action 이전 단계의 관측 검증식으로만 측정한다. 측정할 단계가 없는 사전조건은 시나리오를 거부하지 않고 실행하되 "사전조건 미측정"으로 기록하며, 그 TC의 요구사항은 PASS/FAIL로 판정하지 않는다(미검증). 유효한 계약 생성에 두 번 실패하면 해당 타겟을 건너뛴다.
3. 인자 생성 프롬프트에 시나리오, 역할, 검증식, 고정 필드와 이전 단계의 실제 인코딩을 전달한다. 재시도에서도 FID/SEL, CNS, LID, 주소 등 테스트 의도를 바꿀 수 없다. CDW10~15를 전송하며 opcode별 선택자 위치와 Get Log Page 등의 전송 길이를 검사한다.
4. 하네스가 체인에 원복 단계를 붙인다: Set Features 앞에 같은 FID의 현재값(SV=1이면 저장값) 읽기, 체인 끝에 그 값으로 되돌리기(인스턴스 선택 비트 TMPSEL/IV/NVMSETID 유지, 버퍼 기능은 읽은 버퍼 그대로), Write Uncorrectable 뒤 같은 범위 Write Zeroes. `cleanup` 단계는 체인이 멈춰도 마지막에 항상 실행되고(장비 무응답 제외) 판정에는 넣지 않는다. 원복 방법은 FID별 표(`spec_fields.FEATURE_CODECS`: 값 레지스터 비트·인스턴스·네임스페이스·버퍼·Set reserved 바이트·되돌릴 수 없는 값)로 정하고, 표에 없는 FID를 성공으로 바꾸는 Set은 보내지 않는다. 쓰기 보호 WPS 2/3처럼 되돌릴 수 없는 값은 아예 보내지 않는다. 원래 값은 DW0과 버퍼 전체가 캡처됐을 때만 확보된 것으로 보고, 원복 후 다시 읽어 같은지 확인한다. SV=1이면 저장값과 현재값을 둘 다 되돌린다. 원복은 예외·Ctrl+C에서도 실행된다. 원복 대상은 (FID, SV, NSID, 인스턴스 선택 비트)마다 따로이고 재시도에서 바뀌지 않는다(센서·벡터가 다르면 각각). 원복은 변경이 반영됐거나 반영됐을 수 있을 때(성공, 응답 없이 중단, Internal Error 같은 처리 중 실패·모르는 상태) 하고, 처리 전에 인자를 거부한 상태(Invalid Field 등 `spec_fields.REJECTED_BEFORE_EFFECT`)에는 하지 않는다. Host Identifier는 Set으로 되돌릴 수 없어 성공을 기대하는 변경을 보내지 않는다. 원래 값을 읽지 못했거나 형식을 몰라 되돌릴 수 없으면, 그 값을 성공으로 바꾸려는 스텝부터 보내지 않는다(부정 테스트는 보내되, 장비가 받아들이면 원복 생략이 "꼭 확인"). 바꾸는 스텝이 실행되지 않았으면 원복도 하지 않는다. 원복 생략·실패는 검토 요청 "꼭 확인"이다. 전체 명령 체인을 로컬 검증한 뒤 한 단계씩 실행한다(dmesg는 TC당 한 번 clear, 한 번 dump). 이전 단계의 기대 완료나 사전조건 검증이 실패하면 이후 단계는 실행하지 않는다. 실행하지 않은 단계는 TC 상태 집계에서 빠지므로 action의 FAIL이 ERROR로 바뀌지 않는다. 커널이 취소한 커맨드(EINTR/EIO)는 타임아웃과 같은 FAIL이다. 쓰기 데이터는 `data_len`을 나누어떨어지게 채우는 `payload_hex`면 반복 패턴, 아니면 구조체로 보고 나머지를 0으로 채운다(구조체를 반복하면 reserved 영역에 쓰레기가 들어감). 없으면 0 바이트다. NVM Read/Write/Compare의 버퍼는 실행 전에 NLB×측정한 LBA 크기와 방향으로 검사한다.
5. 완료 상태는 nvme-cli 토큰 이름이 아니라 **(SCT, SC) 숫자**로 비교한다(`(0x2285)`의 More/DNR 비트 제외 — COMPARE_FAILURE=COMPARE_FAILED, UNRECOVERED_READ_ERROR=READ_ERROR, INVALID_QUEUE_IDENTIFIER=QID_INVALID). `verification_contract.version=2`에 저장된 유한 검증식으로 결과를 판정한다. LLM이 만든 코드나 표현식을 실행하지 않는다. 실제 NVMe 완료 상태, CQE Dword 0 비트, 응답 길이, little-endian 데이터 필드, 단계 간 데이터/쓰기 페이로드 비교를 지원한다. 비교는 같은 장치·네임스페이스이고 LBA 범위가 상대 범위 안에 있을 때만 하며(계획과 실행 후 모두 검사), 쓰기 비교에는 0이 아닌 패턴이 필요하다. 단순 exit 0이나 임의의 성공 문자열은 스펙 검증 증거가 아니다.
6. 명령 단계에서 기대와 다른 완료가 나와도, 그 규정의 사전조건이 측정되지 않았거나 전제가 반증됐으면 FAIL이 아니라 UNVERIFIED다. 리셋 전후 상태 문장은 상태를 호스트 스텝 앞에서 만들거나 기록해야 하고, 그 뒤 검사 전까지 상태를 바꾸는 명령이 없어야 한다. 기대한 음성 응답(예: INVALID_FIELD)은 해당 검증식의 정상 결과이며 재저작하지 않는다. "지원하지 않으면 거부해야 한다" 규정에서 장비가 SUCCESS로 답하면 지원한다는 뜻이라 위반이 아니다(UNVERIFIED, "전제가 반증됨") — 스펙이 Reserved로 둔 값(코드 변형)은 예외로 FAIL이다. setup 스텝이 거부되면 action은 관측되지 않았으므로 FAIL이 아니라 ERROR(원인 "사전 상태")다. 실행 시작 조회가 미지원이라고 확인한 FID/LID의 거부(INVALID_FIELD/INVALID_LOG_PAGE)는 "우리 인자 오류"가 아니라 기능 단위 UNSUPPORTED이며 재시도하지 않는다. 재생성한 인자가 거부된 것과 같으면 다시 보내지 않는다. 올바른 LID 하나만으로 다른 INVALID_* 응답을 미지원이라고 단정하지 않는다. 호스트 오류, 미관측 데이터, 사전조건 실패는 요구사항 검증 완료로 집계하지 않는다.

검증식 예:

```json
{"kind": "result_bits", "step": 0, "mask": "0x7", "value": "0x5", "operator": "eq"}
```

이는 CQE Dword 0의 하위 세 비트가 5인지 비교한다. 실제 응답에 CQE 결과가 없으면 `unevaluated`다. 검증식은 인용된 요구사항과 함께 저장해야 한다. 인용 존재 검사는 출처를 보장할 뿐, LLM의 의미 해석까지 증명하지 않는다.

## 검토 요청 (꼭 확인 / 확인 권장 / 참고)

기계 판정(PASS/FAIL/...)과 별도로 TC마다 `tc["review"]`에 "그 판정을 얼마나 믿을지"를 남긴다(`tc_system/review.py`). 리포트 맨 위 "꼭 봐야 할 결과"와 터미널 `⚑` 줄에 사유와 함께 나온다. 최종 판단은 사람이 한다.

- **꼭 확인**: 모든 FAIL, 호스트 크래시, 원복 생략·실패 또는 원복 없이 상태를 바꾼 스텝, PASS/FAIL이 걸린 검사식이 설명과 다른 필드를 읽음, 역할의 FID와 실제 CDW10 불일치, 상태 이름만 다르고 코드가 같은 위반, 요청 길이 자기비교 위반, 설정한 값과 모순되는 기대값, 진행 중 상태를 한 번만 읽은 FAIL, 판정 LLM의 결함/검토 판정 또는 FAIL에 대한 "테스트 문제" 의견.
- **확인 권장**: 미지원 응답만 본 PASS, 설정 왕복만 본 PASS(인용이 동작을 말할 때), 지원 여부 미측정 부정 테스트 PASS, 전체 데이터 주장인데 일부 바이트만 검사, 요구 문장이 아닌 인용 조각, 다른 컨트롤러 유형을 주체로 한 인용, 잘못된 필드로 막혔을 수 있는 사전조건, 버퍼 크기를 모르는 FID.
- **LLM 감사**: PASS/FAIL TC는 같은 LLM이 감사 역할로 코드가 디코딩한 사실(어느 필드를 읽는지, 상태 코드)만 보고 이의를 낸다(`config.REVIEW_AUDIT_WITH_LLM`). 이의는 판정을 바꾸지 않고 사유로만 추가된다.
- 판정 LLM이 firmware_defect라고 해도 코드가 계약 문제를 찾았으면 needs_engineer_review로 보류한다. 판정 프롬프트는 스텝별 예산(action과 검사 대상 스텝 우선), 디코딩된 필드, 숫자 상태 코드, `harness_findings`를 받는다.

오프라인 재평가: `python -m tc_system.replay <tc_store.json 또는 실행 폴더>` — 저장된 원시 응답으로 현재 코드의 상태·요구사항·검토 사유를 다시 계산한다(장비·LLM 없음, 입력 수정 없음).

판정 LLM의 응답은 정해진 분류값과 그 표기 변형만 받고(나머지는 needs_engineer_review), 신뢰도는 유한한 0~1 값만 받는다. 나중에 `run_judge --source tc_exec`로 판정해도 최초 판정과 같은 경로로 TC에 연결되고 보류 규칙이 적용된다.

## 커버리지와 리포트

- 명령 실행·지원 조사 이력: 기존 조항/opcode 통계다. 스펙 준수율이 아니다.
- 요구사항 검증: 근거와 검증식이 있는 항목의 PASS/FAIL/MIXED/UNVERIFIED다. 분모는 **생성된 요구사항 수**이며 전체 스펙 요구사항 수가 아니다. 한 항목 통과로 조항 전체를 완료 처리하지 않는다.
- 타겟은 검증 기록과 시도 횟수에 따라 우선순위를 정한다. 예전 PASS/UNSUPPORTED만으로 영구 제외하지 않는다. 장비에 보내기 전에 건너뛴 타겟도 `data/target_skips.json`에 남겨 시도 횟수로 세고, Abort/AER는 후보에서 뺀다. 검증된 요구사항, action INVALID_OPCODE, 3회 이상 시도 중 하나가 있는 타겟은 답이 없는 타겟 뒤로 보내고, 한 배치에 한 조항은 한 번만 뽑는다. 이전에 검증한 인용은 다음 생성 프롬프트에 제공한다.
- 요구사항 PASS는 커버리지로 세되, 무엇을 관측했는지(데이터 비교 / 필드 관측 / 설정 왕복 / 거부 응답 확인 / 미지원 응답 확인 / 완료 상태만)를 요구사항마다 `scope`로 남기고 리포트·터미널에 PASS 수를 그 종류별로 나눠 보여준다(`requirements_passed_by_scope`).
- 진행 상황은 "시도"와 분리해 보여준다: TC 수, 본동작(action) 전송 수, 본동작 전 중단 수, 건너뜀 수. 현재 TC에 연결되지 않은 이전 실행 판정은 별도 섹션(보존 기록)으로 둔다. 실행마다 `data/run_manifests/<run_id>.json`에 코드 해시(git 커밋), 커버리지 인덱스·RAG 버전, 프롬프트 해시, nvme-cli/커널 버전, 장비 모델·펌웨어를 남긴다.
- 리포트의 TC 상세에서 스펙 원문, 검증식의 관측값/기대값, 시나리오, 고정 필드와 실제 CDW, 원시 응답, 재시도별 명령·실행 결과, LLM 응답 ID를 확인한다.
- 판정 및 FailureContext는 실행 간 보존한다. judge가 실패해도 먼저 저장된 FailureContext로 다시 판정할 수 있다. 드라이브 교체 시 기존 `--reset-coverage` 백업 경로를 사용한다.

## 타겟 구성

- **요구사항 타겟(LLM):** 타겟 조항의 "shall" 문장 965개 + 거부 규칙 251개("abort ... with a status code of X" — 기대 상태 고정 부정 테스트) + 문장이 없는 조항 49개 = 1,265개(하위 조항 문장은 가장 가까운 타겟 조상 하나에만 붙음). 시나리오는 그 문장을 인용하는 요구사항을 action에서 확인해야 한다.
- **코드 변형(LLM 없음):** LBA 경계 23개(장비 NSZE 필요), Reserved FID × Get/Set Features 280개, Reserved LID 86개 = 389개. 판정 기준은 해당 스펙 문장 인용이다.
- **호스트 스텝:** 컨트롤러 리셋, PMU 전원 사이클(설정 시)을 setup/verify로 써서 리셋·전원 손실 전후 상태 요구사항을 테스트한다. "across/after/on/at the next … power cycle/reset", "… Reset occurs"처럼 **사건 전후 상태를 말하는 문장 14개**는 호스트 스텝이 강제된다(`host_actions.required_host_actions`): 체인에 그 스텝이 있고 타겟 문장을 인용한 요구사항이 그 스텝 **뒤** 스텝을 확인해야 한다. 단어만 나오는 문장("Power Loss Signaling 미지원이면 abort", "shall be saveable", "Write Protect Until Power Cycle 상태")은 해당하지 않는다. 지금 14개는 전부 리셋으로도 충족되는 문장이라 PMU 없이도 "Controller Reset"으로 테스트된다.

## 건너뛰는 경우 (장비에 아무것도 보내지 않음)

건너뛴 타겟은 `data/target_skips.json`에 남아 시도 횟수로 세며, 3회가 쌓이면 후순위로 밀린다. 아래가 전부다.

타겟으로 아예 뽑지 않는 것: Abort/AER(순차 실행기로 만들 수 없음), Event Type 조항 22개(가변 길이 이벤트 레코드를 찾아야 검증되며 고정 오프셋 검증식으로는 불가). Fabrics 전용(base:5.4.x)은 뒤로 미루고, 한 배치 안에서는 커맨드를 돌아가며 뽑는다.

0. **LLM 호출 전**: 같은 실행에서 그 커맨드가 이미 미지원으로 확인됨(`opcode_unsupported_in_run` — action이 INVALID_OPCODE였거나, 사전조건이 그 커맨드 자신의 지원 비트(OACS/ONCS의 해당 비트, CSE CSUPP)를 0으로 읽어 action을 보내지 않은 경우. 다음 실행부터는 답이 있는 타겟으로 뒤로 밀림). 리셋/전원 사이클 전후 문장인데 이 실행에서 쓸 수 있는 호스트 스텝이 없음(전원 사이클만 되는 문장 + PMU 미설정 또는 `--no-destructive`, `host_step_unavailable`).
1. **시나리오 생성** (`scenario contract invalid: ...`, 오류 문구를 주고 1회 재시도)
   - LLM 응답 실패: 호출 실패, 빈 응답, JSON 파싱 실패, 스키마 키 누락.
   - 체인 구조: 스텝 없음/객체 아님, action이 2개 이상, 타겟 커맨드가 체인에 없음(있으면 그 스텝을 action으로 고침), 목록에 없는 커맨드, 잘못된 phase, setup이 action 뒤·verify가 action 앞.
   - 실행기 한계: 어느 스텝이든 Abort/AER. I/O 큐 Create/Delete를 성공으로 기대하거나 QID가 0도 0x8000 이상도 아님(드라이버가 쓰는 큐·PRP 없음). Set Features로 HMB(FID 0Dh) 변경.
   - 필드 검사: 이름 모르는 필드, 구조(CNS/LID)를 알 수 없는 스텝의 이름 검사(offset/width/mask/value가 다 있으면 이름은 라벨로 보고 통과), 설명과 다른 필드·비트·0/1 조건, 필드 경계를 어긋난 오프셋, 역할의 FID/LID/CNS와 다른 고정값, 항상 참인 검사, `data_length`만 있는 요구사항, cleanup 스텝을 확인하는 요구사항.
   - 지원 전제(실행 시작 조회가 있을 때): 지원한다고 확인된 LID에 INVALID_LOG_PAGE 기대, 미지원 FID로 다른 필드의 INVALID_FIELD를 시험. 지원 여부를 모르면 실행하되 "사전조건 미측정"으로 기록.
   - **action 스텝**: 기대 완료 상태 누락, 선택자/주소 필드(FID/SEL, LID, CNS, Directive, Commit, SLBA/NLB) 미고정.
   - 기대 완료 상태가 (SCT, SC) 코드로 풀리지 않는 이름(어느 스텝이든 SUCCESS가 아니면): 이름으로만 비교하면 같은 코드의 다른 철자가 "위반"이 된다(2026-11-06: READ_ERROR 2/81h vs UNRECOVERED_ERROR). 오류에 가까운 상태 이름을 제안한다.
   - 고정 필드·`payload_hex` 형식 오류(필드 이름, mask/value 모순, hex 아님).
   - 요구사항: 없음, 설명/검증식 없음, 인용이 근거에 없음(번역·의역·의미 반전), action을 확인하는 요구사항이 하나도 없음, 검증식 형식 오류.
   - 타겟 요구사항: 그 문장을 인용하는 요구사항이 없음, 거부 규칙인데 action의 기대 상태가 그 상태가 아님, 리셋/전원 사이클 전후 문장인데 호스트 스텝이 없거나 요구사항이 그 스텝 뒤를 확인하지 않음. **그 문장을 관측하지 않음**(`verification._target_unobserved`, 실행 후 판정과 같은 규칙): 거부를 말하지 않는 문장인데 action을 거부되도록 계획함(미지원이면 SUCCESS를 기대하고 보내야 UNSUPPORTED로 남음), 또는 완료 상태만 확인함 — 완료 확인은 action 자신의 것이고 문장이 완료 자체를 말할 때("complete successfully", "post a completion queue entry", "shall be ignored", "shall not return this status", "shall succeed/be supported")만 관측으로 친다. 값을 말하는 문장(DSLBA, STC, FB 등)은 action이나 그 뒤 스텝의 data_field/result_bits/data_* 검사가 있어야 한다. 2026-11-06 시나리오 응답 재검증 기준 최종 통과 218 → 184/329(줄어든 34개는 PASS여도 그 문장의 판정이 아니었음).
   - 데이터 비교: 쓰기 비교인데 상대가 쓰기가 아님/0이 아닌 패턴 없음, 읽는 LBA가 쓴 범위 밖, LBA와 비-LBA 비교, 스스로 바뀌는 로그(LID 02h/03h) 전체 비교.
   - 반환 레이아웃: Get Features 완료 DW0의 정의되지 않은(예약) 비트 검사, SEL=011b 결과에서 bits 2:0 밖 검사.
   - 사전조건/메모가 배열이 아님, 사전조건 검증식 형식 오류.
2. **인자 생성** (`placeholder command arguments`, 스텝마다 1회 재시도, 어느 스텝이든 실패하면 TC 전체): LLM 실패, 스텝 역할의 `NAME=값`(DEAC, NSZ, CA, SEL 등)과 실제 인코딩 불일치, 성공을 기대하는 Set Features의 CDW11 예약 비트, cdw 형식, direction 값이 read/write/none이 아님, 허용 밖 nsid(관리 명령은 기대 상태가 INVALID_NS일 때만 다른 NSID 허용, I/O 명령은 활성 NSID만 — 커널이 다른 값을 장치에 보내기 전에 버림), 위험한 큐 명령, HMB Set Features, data_len 범위, 버퍼 크기를 계산할 수 없는 커맨드의 빈 전송(방향은 있는데 data_len=0)·버퍼 없는 커맨드에 data_len, 선택자 레지스터 위치 불일치, 고정 필드 위반, 시나리오가 길이 필드와 data_len을 둘 다 고정했는데 서로 어긋남, payload가 data_len보다 김. 길이 필드(NUMD/NLB)↔data_len 불일치, opcode 방향 비트 모순, Get/Set Features의 FID별 버퍼 크기(HMB 4096B, Timestamp 8B, APST 256B, Host Behavior·PLM 512B, LBA Range Type 4096B, SEL=011b·값이 DW0인 FID는 0), 조항 선택자(LID/FID/CNS) 값은 거부하지 않고 하네스가 계산해 쓴다(`derive_transfer`, 터미널 `하네스 계산값 적용`/`시나리오 고정값 적용`). Identify Controller/Namespace setup·verify 스텝은 LLM 없이 코드가 만든다.
3. **전송 직전**: `--no-destructive`에서 파괴적/펌웨어 스텝, 스텝 형식 검증 실패, I/O 명령 nsid가 네임스페이스 장치와 다름, 위험한 큐 명령, HMB Set Features. 이미지를 바꾸거나 활성화하는 Firmware Commit(CA 000b/001b/011b)을 SUCCESS로 기대하는데 체인 앞에 실제 이미지 전체 다운로드("Firmware Image Download (full image)", `secrets.local.json` `firmware.image`)가 없거나 그 뒤 일부 다운로드가 있음(`pipeline._firmware_commit_problem`).
4. **헬스체크 실패**: 앞 TC 뒤 장비 무응답이면 남은 타겟 전체(시도 횟수에 넣지 않음).
5. **생성 시간 초과**: 미리 생성한 TC가 `config.TC_PREPARE_WAIT_SEC`(1200초) 안에 끝나지 않음(`generation_timeout`, LLM 호출 하나는 300초 제한).

거부하지 않고 하네스가 고쳐 쓰는 형식 실수(`check_repairs`, 터미널 `검사식 보정`): offset/width가 있는 검사의 종류 이름(`offset`/`data` → `data_field`), mask 없는 `data_field`(폭 전체), 이름에 적은 오프셋(`GENCTR@0+8`), mask 없는 고정 필드(필드 전체), mask 0인 고정 필드(제거), `cdw1`(NSID)·`cdw010` 같은 필드 철자.

거부하지 않고 메모(`out_of_scope`)나 기본값으로 처리하는 것: 범위 메모, 측정하지 못한 사전조건("사전조건 미측정" — 실행은 하되 요구사항은 미검증), 목록 밖 실행기 역량 이름, setup/verify의 기대 상태 누락(SUCCESS), 고정 필드 키 누락(없음), setup/verify의 선택자 미고정(첫 인자 생성 값으로 고정), 잘못 붙은 근거 ID, setup만 보는 요구사항(사전조건으로 이동), 스펙식 hex 표기(`84h`), 스펙식 상태 이름(`INVALID_COMMAND_OPCODE`), 역할에 적힌 FID/LID/CNS(고정되지 않았으면 그 값으로 고정), `data_length` 검사(빠지고 메모).

## Firmware Commit

CA는 CDW10 **bits 5:3**, FS는 **bits 2:0**이다. 앞선 성공한 Firmware Image Download에서 0 바이트 더미가 전달된 증거가 있고, 이를 교체·활성화하는 CA=1/3이 성공했을 때 기존 더미 활성화 규칙을 적용한다. CA=2의 기존 슬롯 활성화 또는 다운로드 이력이 없는 Commit을 동일한 증거로 결함이라고 단정하지 않는다. 기존 destructive/firmware 실행 게이트는 유지한다.

## 지원 범위와 검증

현재 실행기는 순차 passthru다. 생성(LLM)은 다음 타겟들을 미리 병렬로 만들지만(`config.TC_GENERATION_WORKERS`) 장비 실행은 항상 하나씩 순서대로다. I/O 큐 생명주기(드라이버 소유)와 인터럽트·이벤트·원자성 같은 동작은 이 방식으로 관측할 수 없으며, 설정 왕복 PASS는 그 동작의 검증이 아니다. Abort/AER, 동시 outstanding command 제어, 이벤트 주입, 동적 런타임 값 주입이나 타이밍 측정이 필요한 시나리오는 지원하지 않는다. 리셋은 컨트롤러 리셋과 PMU 전원 사이클(설정 시)만 호스트 스텝으로 지원하며, FLR·hot reset·NSSR·PERST#·CLKREQ#는 아직 넣지 않았다. 요구사항이 의존하는 조건은 `preconditions`로 선언하고 action 이전의 검증식으로 확인한다. 확인할 단계가 없으면 "사전조건 미측정"으로 기록되고 그 TC의 요구사항은 미검증으로 남는다. 이 TC가 일부러 검증하지 않는 관련 동작은 `out_of_scope`에 메모로 남기며(터미널·리포트에 표시), 이것만으로 시나리오를 거부하지 않는다. 모든 스펙 조항의 요구사항을 완전하게 추출했다는 주장은 하지 않는다.

오프라인 검증: `python3 -m unittest discover -s tests`. 기존 회귀 테스트와 함께 실제 nvme-cli 형식을 모사한 응답으로 정상/비정상/미관측 결과, 고정 필드, NUMD 길이, Firmware CA, 선행조건 차단, HTML 이스케이프, 실제 로컬 스펙 조항/MI 연결을 검사한다. 실제 SSD·SSH·LLM을 호출하지 않는다. 장비와 실제 LLM 조합에서의 생성 품질 및 동작은 별도 통합 검증이 필요하다.
