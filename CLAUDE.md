# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

프로젝트 개요·세팅·사용법은 `README.md`(한국어)에 있다. 설계 배경은 `C:\Users\gangho.yoon\.claude\plans\snazzy-humming-sky.md`(실제 동작 PC 기준 경로).
이 문서는 그 위에서 "코드를 고칠 때 알아야 하는 것"만 담는다.

## 명령

```bash
python -m unittest discover -s tests -v        # 전체 (253개)
python -m unittest tests.test_qst_parser -v    # 모듈 단위
python -m unittest tests.test_qst_parser.TestQstParser.test_name -v   # 단일 테스트

python run_ingest.py --source all   # 로그 -> data/failure_contexts/<source>/
python run_judge.py  --source all   # FailureContext -> data/verdicts/<source>.json
python run_report.py                # -> report/output/report_latest.html
python run_tc_pipeline.py --count 5 # 생성+실행+판정 — 실제 장비(192.168.137.9)에 명령이 나간다
#   --no-destructive          Format/Sanitize/Write/DSM/Firmware 계열 opcode 제외
#   --allow-placeholder-args  placeholder 인자 TC도 실행(커버리지에선 제외)
#   --reset-coverage          드라이브 교체 시 tc_store/coverage_state 백업 후 초기화
#   --quiet                   TC별 진행 출력 생략
python build_spec_index.py          # RAG 청크 -> specs/spec_coverage_index.json 재생성
```

`run_tc_pipeline.py`의 실패는 전부 "그 타겟만 건너뛰기"라 배치가 멈추지 않는다(아래 불변조건 참고). 비정상 종료코드는 `DestructiveStepBlocked` 방어용 exit 3뿐이다.
매 실행의 전체 콘솔 출력은 `logs/tc_pipeline_<타임스탬프>.log`에 타임스탬프와 함께 남는다(`shared/run_log.capture_to_file`).

`--force`로 매니페스트(`data/ingest_state_*.json`, mtime+size 기준)를 무시하고 재처리.
빌드/린트 단계 없음. 의존성은 stdlib + `requests`/`openai`/`numpy`/`python-dotenv`(현재 import 경로는 stdlib만 씀).
Python 3.10+ 필요(`dict | None`, `list[dict]` 같은 타입 힌트 사용). 구버전 인터프리터는 import 시점에 `TypeError`로 바로 죽는다.

## 구조

두 파이프라인이 `log_judge.judge`와 `report`를 공유한다.

```
QST/, PULSEFZ/ (원본 로그, 수정 금지)
  └ log_judge/ingest/*_ingestor.py  ─ 매니페스트로 중복 스킵
      └ log_judge/parsers/*.py       ─ FailureContext(dict) 생성
          └ log_judge/judge.py       ─ RAG 검색 + LLM 분류 -> Verdict
              └ log_judge/classify.py ─ post-rule 보정
specs/spec_coverage_index.json (build_spec_index.py 산출, 없으면 seed_coverage_index.json으로 폴백 — config.active_coverage_index_path)
  └ tc_system/pipeline.py            ─ 타겟선정 -> 시나리오 -> TC -> SSH 실행 -> 판정 -> 커버리지
      └ 실패 시 같은 judge.py로 라우팅 (source_type="TC_EXEC")
data/ (산출물, gitignore, 전부 재생성 가능) -> report/aggregator.py -> report/html_report.py
```

- `config.py`가 모든 경로의 단일 출처이고 import 시점에 `data/` 하위를 `mkdir`한다. 경로 리터럴을 새로 쓰지 말고 여기에 상수를 추가할 것.
- FailureContext / Verdict / TCRecord는 dataclass가 아니라 **고정 shape의 dict**다 (`log_judge/models.py`, `tc_system/models.py`의 팩토리 함수로만 생성). 파서가 regex 매치에서 점진적으로 채워 그대로 JSON으로 저장하기 때문.
- 영속화는 `shared/file_store.save_json_atomic`(tmp + `os.replace`)만 사용. ID는 `shared/ids.stable_id(prefix, *parts)`.

## 깨뜨리기 쉬운 불변조건

**placeholder 인자 게이트.** `tc_system/generation/args_author.py`가 스펙 근거로 실제 opcode별 인자를 만든다(`args_source="authored"`). 생성에 실패하면(`ArgsAuthoringError`) `tc_writer._command_step`이 `cdw10=0` 등 placeholder로 폴백하고 `args_source="placeholder"`를 박는다 — 실측 결과 그 값은 대부분 reserved라 INVALID_FIELD로 떨어지고, NVM Read 0x02는 exit 0이면서 아무 데이터도 옮기지 않는다. 그게 PASS로 기록되면 거짓 커버리지가 된다. 그래서:
- 이 fallback이 하나라도 섞인 TC는 기본적으로 **그 타겟 하나만 건너뛴다**(`skipped` 카운트, `on_skip` 콜백) — 장비에 아무것도 안 나갔으므로 다음 실행에 다시 타겟으로 제시된다. `--allow-placeholder-args`를 주면 그래도 실행하되 그 TC는 커버리지에서 제외된다. (예전엔 `PlaceholderArgsGuard`를 던져서 `--count N` 배치 전체를 exit 2로 멈췄다 — 실측: 10개 중 4번째 타겟에서 걸려 나머지 6개가 전부 날아간 사례. 이걸 다시 배치 전체를 멈추는 방향으로 고치지 말 것 — `PlaceholderArgsGuard` 클래스 자체를 삭제했다.)
- `coverage_state._counts_toward_coverage`는 **opt-in**이다: `uses_placeholder_args`가 명시적으로 False여야 집계된다(필드가 없으면 제외).
- 게이트를 우회하는 방향으로 고치지 말 것 — `author_args`가 실패하는 이유(스펙 근거 부족, direction/opcode 비트 불일치 등)를 고칠 것.

**실제 장비에 쏘는 코드.** `tc_system/execution/ssh_runner.py`는 `plink`로 192.168.137.9에 실제 NVMe 커맨드를 보낸다.
- 파괴적 opcode 차단은 `execute_tc_steps` 안, 와이어 직전 마지막 게이트에 있다(`DestructiveStepBlocked`). 기록만 하고 검사하지 않던 버그가 있었던 자리다. `pipeline.run_pipeline`이 최초 실행에서 이걸 잡으면 **그 타겟 하나만 건너뛰고**, replan 후 재실행에서 잡으면 **이미 장비에서 실행된 원래 결과로 돌아간다**(replan의 LLM 실패와 같은 처리 — 건너뛰면 실제로 나간 실행 결과와 헬스체크가 같이 버려졌었다) — LLM이 자유롭게 고른 setup/verify 커맨드나 action 자체가 `--no-destructive`에 걸리는 건 이 TC만의 문제라 배치 전체를 멈출 이유가 없다(실측: `PlaceholderArgsGuard`와 같은 종류의 배치 전체 정지 문제였음). `run_tc_pipeline.py`의 `except DestructiveStepBlocked`(exit 3)는 이제 이론상 못 터지는 방어용 최후 보루로만 남아있다 — 파괴적 명령이라는 위험도를 감안해 코드 자체는 지우지 않았다.
- step 필드는 쉘에 보간되기 전 `_validate_step`으로 전부 검증한다(hex/device 정규식, bool 거부). LLM이 인자를 쓰게 되면 이게 유일한 방어선이다.
- nvme-cli는 진단 출력을 전부 stderr로 보내므로 배치 스크립트가 `2>&1`로 각 step의 stdout 블록에 접는다. **이걸 떼면 `expectation_checker`의 출력 스캔 규칙 전부가 조용히 무력화된다.**
- `dmesg -c`(사전 clear)는 sudo 패스워드가 필요해서 실패할 수 있다. 실패하면 `dmesg_captured_scoped=False`이고, 그때의 dmesg 덤프는 부팅 이후 전체 히스토리이므로 "이 TC가 유발했다"고 읽으면 안 된다.
- **`sudo nvme ... --write`는 `--input-file`이 없으면 stdin에서 쓸 데이터를 읽는다**(nvme-cli 자신의 `--help`: "write/send file (default stdin)"). `execute_tc_steps`가 "batch" plink 호출에 stdin을 명시적으로 안 주면, 로컬 프로세스의 stdin(터미널에 붙어 있으면 그게 그대로 plink를 통해 포워딩됨)이 거기로 흘러가는데 아무도 입력을 안 주니 **그 Write 스텝이 영원히 블로킹**한다 — 실측: Write 스텝이 섞인 4단계 체인이 매 시도마다 정확히 `SECONDS_PER_STEP * len(steps)`(이 경우 120초)를 꽉 채우고서야 타임아웃. 그래서 `execute_tc_steps`가 스텝 목록에서 `direction=="write"`인 스텝들의 `data_len` 바이트만큼 0으로 채운 버퍼를 이어붙여 "batch" 호출의 stdin으로 명시적으로 넘긴다(쓰기 스텝이 없으면 빈 문자열 `""`을 넘겨서, 그 경우도 stdin이 터미널에 그대로 열려있지 않고 즉시 EOF가 되게 한다). 다시 `stdin=None`(기본값)으로 되돌리는 방향으로 고치지 말 것 — 터미널에 연결해서 돌릴 때만 재현되고 파이프/리다이렉트로 돌리면 재현 안 돼서 놓치기 쉬운 버그다.
- **TC 사이의 상태 변화는 `pipeline.run_pipeline`이 "건강검진"으로만 다룬다, 커맨드별 의미 모델링은 안 한다.** `shared_facts`는 한 TC의 멀티스텝 체인 **안**에서만 상태를 넘긴다 — 배치 안의 TC와 TC **사이**(한 TC의 Sanitize/Namespace Management가 다음 TC에 영향)는 따로 추적하지 않는다. 그래서 `tc["steps"]`에 `destructive`/`firmware_state`/`lockout_risk`(opcode 테이블에서 그대로 복사, `tc_writer._command_step`)가 하나라도 있으면, 그 TC의 `on_progress` 호출 직후 `ssh_runner.device_responsive`(가벼운 `nvme id-ctrl` 1회, 파일 존재 여부가 아니라 실제 커맨드 응답을 확인 — Sanitize/Namespace Management처럼 디바이스 노드가 사라지는 경우와 Lockdown처럼 노드는 있는데 커맨드만 거부되는 경우를 **둘 다** 잡기 위함)를 돌린다. 응답이 없으면 남은 타겟 전체를 `skipped`로 기록하고(`on_skip` 호출) `break` — 실측으로 한 TC의 Write/Read가 "`/dev/nvme0n1: No such file or directory`"로 떨어진 게 사실은 바로 앞 TC의 상태 변경 때문이었던 사례가 있다. `lockout_risk`는 `build_spec_index.py`가 이미 `risk_class` 계산에 쓰고 있었지만(`LOCKOUT_COMMANDS = {Security Send, Security Receive, Lockdown}`) 런타임에서 읽는 곳이 하나도 없었다 — 이게 그 첫 소비처다. 커맨드마다 "정확히 뭘 망가뜨리는지" 모델링하는 방향으로 확장하지 말 것 — 범위가 commandSet 전체로 터진다. 테스트에서 `PipelineTestCase`가 `pipeline.device_responsive`를 기본 `(True, "")`로 패치해둔 걸 건드리지 말 것 — 안 그러면 파괴적 스텝이 섞인 기존 테스트 전부가 진짜 `plink`를 띄워서 실제로 네트워크를 탄다(실측: 패치 빠뜨렸을 때 테스트 스위트가 0.5초에서 29초로 늘어남).
- **Firmware Commit(0x10)의 Commit Action(CDW10 bits 2:0)에 안전 제약을 걸지 않았다 — 의도적 결정.** Firmware Image Download(0x11)는 `direction="write"`라 위 stdin 수정이 0-버퍼를 자동으로 채워주지만, 그 버퍼는 서명된 진짜 이미지가 아니다. CA=0(스테이징만, 활성화 안 함)으로 강제하는 안전한 설계를 제안했으나, 사용자가 "펌웨어가 더미 이미지를 알아서 거부하는 게 정상 동작이니 그냥 LLM이 고르게 둬라"로 명시적으로 결정했다 — 그래서 `author_args`에 CA 검증/강제가 **없다**. 대신 `expectation_checker.BUILTIN_RULES`에 `firmware commit activated an unvalidated dummy image`를 추가해서, CA가 활성화 액션(1/2/3/6/7)인 Firmware Commit이 **성공(exit 0)**하면 위반으로 잡는다 — 거부 문구 내용은 안 보고 "성공했는지"만 본다(정확한 상태 텍스트는 nvme-cli/펌웨어 버전마다 다를 수 있어서 string-matching에 걸지 않음). CA=0으로 성공하는 건 위반 아님(활성화 안 되므로 더미 내용이어도 무해). 이 판정 규칙을 없애거나 CA=0 강제로 되돌리는(사용자가 명시적으로 거부한 방향) 수정 둘 다 하지 말 것. 바로 위의 디바이스 헬스체크가 firmware_state 스텝 이후 자동으로 돌기 때문에, 활성화가 실제로 성공해버리는 최악의 경우에도 다음 타겟으로 넘어가기 전에 디바이스 생존 여부를 확인하는 안전망이 걸린다.
- opcode 바이트의 비트 1:0이 그 커맨드 자신의 전송방향(00=없음/01=host→device/10=device→host)을 인코딩한다. `args_author.author_args`가 LLM이 고른 `direction`을 이 비트와 맞춰보고 `direction != "none"`인데 불일치하면 와이어로 보내기 전에 거부한다 — 실측에서 이걸 놓쳐서 malformed 커맨드가 그대로 나가 SSH 배치 타임아웃(~125초)을 그대로 날린 적이 있다(opcode 0x2A, direction="write" vs 실제 bits="read"). 이 불일치는 장비에 아무것도 보내지 않은 채 로컬에서 잡힌 LLM 자신의 실수라서, 컨트롤러 거부 피드백과 같은 패턴으로 그 TC 1건만 1회 재시도한다(`_author_once` 내부 재시도) — 재시도도 틀려야 그제서야 placeholder 폴백으로 떨어진다. 그 타겟만 건너뛰는 placeholder 폴백은 "재시도까지 실패"했을 때만 트리거되게 바뀐 것이니, 이 재시도 루프를 없애는 방향으로 고치지 말 것(실측에서 opcode 0x1D가 재발 사례).
- 매 TC 배치마다 `execute_tc_steps`가 `logs/ssh_commands.jsonl`에 실제 전송된 명령 전체 텍스트 + 단계별(`dmesg_clear`/`batch`/`dmesg_dump`) 타이밍을 남긴다(`finally`라 타임아웃 중에도 기록됨). 비밀번호는 stdin으로만 전달되고 이 로그에는 안 남는다.
- 배치 타임아웃(`ssh_runner.SECONDS_PER_STEP`, 현재 30)은 **스텝 1개당** 초 단위이고 `timeout = SECONDS_PER_STEP * len(steps)`로 계산된다 — 고정값이 아니다. 실측(정상 완료 3~12초, 실제 행 125~143초— 그 사이가 없음)으로 "정확한 값"은 정상/행 구분에 거의 영향 없고, "행 1건당 얼마나 낭비하는지"만 좌우한다는 걸 확인했다. 스텝 수가 늘어나는 방향(멀티스텝 TC)으로 가면서 고정 120초를 그대로 두면 짧은 TC도 똑같이 오래 기다리게 되는 걸 막기 위해 스텝당 예산으로 바꿨다.
- `nsid`는 `tc_writer.py`가 하드코딩하지 않는다. `pipeline.run_pipeline`이 타겟의 `nvme_ns` 경로에서 `active_nsid`를 한 번 뽑아(`tc_writer.namespace_id_from_device_path`) `author_args`에 매번 넘기고, `author_args`는 LLM이 고른 `nsid`가 `0`/`active_nsid`/`0xFFFFFFFF` 셋 중 하나가 아니면 거부한다(1회 재시도 후 placeholder 폴백). `nsid=0` 고정이던 시절 Identify CNS=0(네임스페이스 특정) 변형이 전부 `INVALID_NS`로 떨어졌었다 — `cdw10`만 재시도해도 `nsid`를 못 바꾸니 구조적으로 못 고쳤던 자리. 반대로 LLM이 지어낸 임의 nsid를 그냥 믿는 방향으로 고치지 말 것 — 이 타겟에 실재하지 않는 네임스페이스는 또 다른 이유로 거부된다.
- **디바이스 역량 사전 조회는 순수 프롬프트 힌트고, `pick_next_targets`(타겟 선정 순서)는 건드리지 않는다.** `pipeline.run_pipeline`이 시작 시 `ssh_runner.probe_device_capabilities`로 `nvme id-ctrl`/`id-ns`/`effects-log`를 **런당 1회만** 실제 장비에 보내고, `device_capabilities.summarize_device_capabilities`로 OACS/ONCS/SANICAP/NPSS/NSZE/LBA 섹터 크기/Commands Supported and Effects를 한국어 힌트 문단으로 만들어 그 실행의 모든 `generate_scenario`/`author_args` 호출(초기+재계획+재시도 전부)에 `device_facts=`로 넘긴다. 실측(`data/tc_store.json`)에서 TC의 52%가 UNSUPPORTED였던 걸 줄이려는 목적. LLM 호출은 서버에 대화 기록이 없는 완전한 stateless 호출(`shared/llm_client.py`의 `_complete`가 매 호출마다 `messages`를 새로 만듦)이라 한 번 알려준 사실을 LLM이 기억하지 않으므로, 장비 조회는 1회만 하되 그 결과를 매 프롬프트에 재사용하는 식으로 짰다. CLAUDE.md의 "UNSUPPORTED도 드라이브에 대한 유효한 결론"이라는 원칙과 충돌하지 않도록 **미지원으로 예상되는 조항도 타겟 선정 순서를 바꾸지 않고 여전히 1회 실제 실행해서 확인한다** — 이걸 "미리 알았으니 건너뛴다"는 방향으로 넓히지 말 것. 조회 자체는 `try/except`로 전부 감싸여 있어 실패(장비 불가, nvme-cli 버전에 `effects-log` 없음)해도 `device_facts=None`으로 그냥 진행된다 — 이 조회가 실행의 전제조건이 되는 방향으로 고치지 말 것.

**멀티스텝 TC (`steps_plan`).** TC는 커맨드 1개가 아니라 체인일 수 있다. `scenario_generator.generate_scenario`가 `phase`(`setup`/`action`/`verify`) 태그가 붙은 순서 리스트를 받고, `tc_system/pipeline.py`가 이름→opcode_entry로 풀어 `tc_writer.build_tc`에 넘긴다.
- `action`은 정확히 1개, 항상 `pick_next_targets`가 고른 그 타겟이다. 이름/Expectation의 "주 커맨드"는 항상 action 기준(`TC_<ActionName>_<조항>`) — 체인 길이와 무관하게 오늘까지의 단일스텝 포맷과 동일. 체인 전체 설명은 별도 `tc["chain_summary"]`.
- `steps_plan` 검증에 risk_class 체크를 **의도적으로 넣지 않았다** — "Write를 setup으로 써서 Read action을 검증"이 이 기능의 핵심 예시인데, Write(risk_class 2)가 Read(risk_class 0)보다 위험해서 그런 체크를 넣으면 그 예시부터 막힌다(실제로 구현 중 테스트로 확인). 진짜 안전 경계는 `DestructiveStepBlocked`.
- `author_args`가 각 스텝마다 `shared_facts`(LBA/NLB/Feature ID 등 다음 스텝이 재사용할 값)를 명시적으로 반환하고, 뒤 스텝은 **스텝별 리스트**(`prior_steps`, 평평한 dict 병합 아님 — PM 상태 전환처럼 같은 키가 여러 번 바뀌는 과정이 안 사라지게)로 그 기록을 전부 받는다. 이게 없으면 Write와 Read가 서로 다른 LBA를 가리키는, 체인이라고 부를 수 없는 두 개의 무관한 명령이 된다.
- 스텝이 거부되면(`rejected_arguments`가 `(step_index, reason)` 반환) `tc_writer.reauthor_steps`가 **그 스텝부터 끝까지** 다시 짓는다(앞은 그대로) — 그 스텝 하나만 고치면 뒤 스텝들이 "바뀌기 전" 값을 전제로 낡아있게 된다. 마지막 스텝이 거부된 경우는 자연히 그 스텝 하나만 재생성되는 것과 같아져서, 오늘까지의 단일스텝 재시도와 동일한 코드 경로다.
- 스텝이 **미지원**(`INVALID_OPCODE`)이고 **action이 아니면** `generate_scenario`에 피드백해서 전체 재계획을 1회 시도한다(값을 바꿔서 고칠 수 있는 문제가 아니라서). action 자체가 미지원이면 재계획해도 못 바뀌므로 시도하지 않는다 — 기존 "INVALID_OPCODE는 재시도 안 한다" 원칙과 동일.
- 재시도/재계획 둘 다, **이미 깨진 스텝 앞에 destructive/firmware_state 스텝이 실행됐으면 생략**한다 — SSH 배치는 부분 재실행이 안 돼서, 재시도는 그 파괴적 스텝도 다시 쏘게 된다.
- `tc["step_section_ids"]`/`tc["step_opcodes"]`/`tc["step_statuses"]`는 **중복 제거하지 않는** 스텝 개수만큼의 병렬 리스트다(`source_section_ids`/`source_opcodes`는 여전히 중복 제거+순서유지 롤업). `coverage_state._covering_entries`가 이 셋을 인덱스로 짝지어, 스텝별로 독립적인 status로 커버리지를 매긴다.
- 각 step dict는 `name`/`phase`/`role`도 갖고 있다(`tc_writer._command_step`). `name`/`role`은 **순수 표시용**이다. `phase`는 예외로 두 곳에서 읽는다: `check_expectation`이 action 스텝을 찾을 때(아래 PASS/FAIL 참고), `pipeline._build_tc_exec_failure_context`가 judge에 넘길 `signals["cmd_name"]`/`["opcode"]`를 action 스텝으로 정할 때(예전엔 judge가 `source_opcodes[0]` = 첫 setup 스텝으로 스펙을 검색해서 Write→Read TC를 Write 기준으로 판정했다) — `run_tc_pipeline.py`가 opcode/nsid 레지스터 값 대신 커맨드 이름·역할·phase를 보여주기 위해 추가됨. `ssh_runner.passthru_cmd`(예전엔 `_passthru_cmd`, 모듈 밖에서도 쓰이게 되면서 이름에서 밑줄 뗌)가 스텝 dict로부터 실제 전송될 `sudo nvme ...` 명령 전체를 만들어내므로, `run_tc_pipeline.py`가 실행 **전에** 이걸 호출해서 실제 CLI 명령을 미리 보여준다.
- `pipeline._resolve_steps_plan`에서 **action 스텝의 section은 항상 `pick_next_targets`가 고른 그 section(`fallback_section`)을 그대로 쓴다** — opcode 테이블의 `section_ref`로 다시 조회하지 않는다. opcode의 `section_ref`는 그 커맨드의 "대표" 조항(예: Migration Send → `base:5.2.17`)일 뿐이고, `pick_next_targets`는 같은 opcode를 공유하는 더 구체적인 형제/하위 조항(`base:5.2.17.1` "Migration Send Management Operations", `base:5.2.17.1.1` "Suspend")도 독립적인 타겟으로 고른다 — 실측: 103개 reachable 조항 중 43개가 자기 opcode의 `section_ref`와 다른 section_id를 가짐. action 스텝의 section을 `section_ref`로 재조회하면(예전 버그) `tc["step_section_ids"]`가 항상 대표 조항으로 기록되어, 원래 고른 세부 조항은 **구조적으로 영원히 커버될 수 없고** 다음 실행에서도 똑같은 커맨드를 다른 타겟 이름으로 영원히 재시험하게 된다(실측: 같은 배치 안에서 "TC_MigrationSend_base_5_2_17"이 두 번 찍혀 중복처럼 보였던 사례). setup/verify 스텝은 애초에 LLM이 자유롭게 고른 것이라 사전 할당된 타겟이 없으므로, 그 스텝들만 `section_ref`로 조회한다. 이 구분을 없애고 전부 `section_ref`로 되돌리지 말 것.
- 스텝이 거부/재계획으로 재시도되면 `tc["retried"]`(`{"kind": "args_rejected"|"replanned", "step_index", "step_name", "reason"}`)가 기록된다 — `run_tc_pipeline.py`의 `on_start`는 재시도 **전** 스텝으로 "실행할 명령"을 찍고 `on_progress`는 재시도 **후** 스텝의 cdw10/data_len으로 결과를 찍으므로, 이 마커가 없으면 둘이 서로 다른 값을 보여주면서도 그 이유를 알려주는 게 전혀 없다(실측: 처음 보면 버그로 보임 — `logs/ssh_commands.jsonl`을 따로 대조해야 재시도였다는 걸 알 수 있었다). `_print_result`가 이 마커를 보고 "⚠ 재시도" 줄을 찍는다.

**PASS/FAIL/ERROR 구분** (`tc_system/execution/expectation_checker.py`, `coverage_state.py`):
- PASS와 FAIL 모두 "covered"로 집계한다(FAIL도 그 경로를 탄 정보). 단 outcome을 `passing`/`failing`/`mixed`로 구분해 리포트한다.
- ERROR는 집계 제외 + 다음 실행에서 타겟으로 재제시(`pick_next_targets`). 타임아웃은 ERROR가 아니라 **FAIL**이다 — 먹통 장비가 이 도구가 찾으려는 바로 그 결과이므로. 그래서 `check_expectation`은 타임아웃을 **맨 먼저** 본다(UNSUPPORTED/ERROR 판정보다 앞), `pipeline`은 타임아웃 난 TC를 **재시도/재계획하지 않고**(재시도가 행을 덮어쓰게 됨) 파괴적 스텝이 없어도 **헬스체크를 돈다**.
- 단, 스텝별로는 **행 걸린 스텝만 FAIL**이고 그 뒤에 아예 시작도 못 한 스텝은 **ERROR**다. `_parse_batch_output`이 스텝마다 `started`(그 스텝의 구분자가 echo됐는지)를 남기고, `check_step_expectations`가 `started=False`를 ERROR로 매긴다 — 예전엔 둘 다 FAIL이라 장비에 나가지도 않은 조항이 커버리지에 잡혔다.
- **전체 스칼라 status는 action 스텝 기준이다.** setup/verify 스텝만 UNSUPPORTED(INVALID_OPCODE 또는 검증된 세부 값 거부)면 그 스텝은 스칼라 판정에서 빼고 나머지로 판정한다(그 스텝의 non-zero exit도 FAIL로 치지 않음). action 스텝 자체가 UNSUPPORTED일 때만 TC가 UNSUPPORTED다. 예전엔 아무 스텝이나 INVALID_OPCODE면 TC 전체가 UNSUPPORTED여서, 미지원 setup 하나가 action의 진짜 FAIL/행을 가리고 judge도 안 탔다. `phase` 태그가 없는 레코드(레거시/테스트 fake)는 모든 스텝을 action으로 취급해 예전 동작과 같다.
- 산문(prose) fail criteria는 `unevaluated`로 보고한다. 아무도 검사하지 않은 기준을 만족으로 처리하지 않는다.
- `tc["status"]`(전체 스칼라, `check_expectation` — 라우팅/judge 호출/placeholder 게이트용)와 `tc["step_statuses"]`(스텝별, `check_step_expectations` — 커버리지 집계용)는 **별개**다. 체인에서 한 스텝이 ERROR여도 다른 스텝이 PASS였다는 증거를 버리지 않기 위해 둘로 나눘다. 커버리지 집계 코드가 전체 스칼라를 다시 보게 고치지 말 것.
- `_controller_error_status`/`unsupported_opcode`/`rejected_arguments`는 **상태 텍스트를 글자 수로 자르지 않는다**(예전엔 각각 `[:200]`/`[:300]`). 실측에서 실제 NVMe 상태 설명이 문장 중간("...currently in u")에서 끊긴 채로 `criteria_results`/판정/터미널 로그 전부에 그대로 남는 걸 확인했다 — 표시 레이어(`run_tc_pipeline.py`의 `_one_line`/`_dual_line`/`_dual_label`, `shared/run_log.py`의 `_Tee.dual_write`)가 아무리 "전체를 로그 파일에 남기게" 돼 있어도, 그 입력 데이터 자체가 여기서 이미 잘려 있으면 복원할 원본이 없다. 지금은 "그 상태 텍스트가 들어있는 한 줄"만 가져오는 식으로 바뀌어서(`splitlines()`로 자연히 bound됨) 글자수 제한이 없다. 다시 글자 수로 자르는 방향으로 고치지 말 것 — 자르려면 표시 레이어에서 하고 데이터 자체는 원문을 유지해야 한다. 참고로 이 표시 레이어 자체도 한 번 바뀌었다: 처음엔 콘솔용 짧은 줄과 파일용 전체 줄을 `print()`+`_log_full()`로 **따로 두 번** 찍었는데(파일에 같은 내용이 중복 남는 불필요한 설계였음), 지금은 `_Tee.dual_write(console_data, file_data)`로 **한 줄을 두 목적지에 다른 내용으로** 쓴다 — 콘솔/파일에 중복 줄을 남기는 방향으로 되돌리지 말 것.
- `_Tee`는 콘솔/파일 양쪽에 쓰는 **모든 줄 앞에 `[HH:MM:SS]`를 붙인다**("-> 실행 중..." 같은 줄만 보고는 지금 걸린 게 정상 대기인지 실제 SSH 행인지 알 길이 없어서, `ssh_commands.jsonl`의 타임스탬프와 수동으로 대조해야 했다). `print()`가 줄 내용과 줄바꿈(`"\n"`)을 **별도의 두 `write()` 호출**로 나눠 보내므로, `_Tee`가 "지금 새 줄 시작 지점인지"를 호출 간에 상태로 들고 있어야 한다(`_at_line_start`) — 한 번의 `write()` 호출을 한 줄로 가정하면 안 된다. `dual_write`도 콘솔/파일 각각에 같은 시각으로 스탬프를 찍는다. 빈 줄(`print(f"\n[1/10] ...")`의 선행 개행처럼)은 스탬프 없이 진짜 빈 줄로 남아야 한다 — 스탬프만 찍힌 내용 없는 줄을 만들지 말 것.

**판정 보정.** `classify.apply_post_rules`가 confidence < 0.5를 `needs_engineer_review`로 강등한다. 더미/실제 LLM 무엇이든 거쳐야 하는 안전망.

**LLM 응답이 스키마 키를 빠뜨렸을 때.** `shared/llm_client.py`의 "JSON 파싱 실패" 재시도와 "필수 키 누락" 재시도는 **같은 1회 예산을 공유**한다 — JSON 파싱 재시도가 이미 소비됐으면 키 누락에서 또 재시도하지 않는다(실측 사례는 없지만 설계상 의도). 실측: `generate_scenario` 응답이 `fail_criteria` 키 하나를 빠뜨렸는데, 그 호출이 `pipeline.run_pipeline` 안에서 try/except 없이 맨몸으로 있어서 `LLMCallError`가 그대로 전파돼 `--count 20` 배치 전체가 죽었다(이미 완료된 TC들은 매 TC 저장이라 안전했지만, 남은 타겟은 전부 날아감). 그래서: ① `generate_llm_response`가 키 누락에도 1회 재시도하게 추가했고, ② `pipeline.py`가 `generate_scenario`/`_resolve_steps_plan`/`build_tc` 묶음을 `try/except _LLM_REPLY_ERRORS`(`LLMCallError`/`ValueError`/`KeyError`/`TypeError` — `run_judge.py`가 judge 호출에서 잡는 것과 같은 집합. replan·judge 지점도 같은 집합을 쓴다)로 감싸서, 그 타겟 하나만 건너뛰고(`skipped` 카운트) 배치는 계속 돈다. **이 try/except를 없애는 방향으로 고치지 말 것** — 장비에 아무것도 안 나간 생성 단계 실패가 무관한 나머지 타겟들까지 끌고 내려가면 안 된다는 게 핵심.

같은 이유로, **배치 전체를 멈출 수 있는 지점은 전부 "그 타겟만 건너뛰기"로 맞춰져 있다** — 최초 생성뿐 아니라: ① replan의 `generate_scenario`(비-action 스텝이 UNSUPPORTED일 때)가 `LLMCallError`를 던지면 `replanned_tc=None`으로 두고 **원래(이미 실행된) 결과를 그대로** 쓴다("재계획은 되면 좋고 안 되면 원래대로"라는 기존 설계와 동일한 결) — 아래로 전파시켜 배치를 죽이지 말 것. ② `judge_failure_context(fc)`가 `LLMCallError`를 던지면 `verdict=None`으로 두고 TC는 FAIL/ERROR 상태 그대로 `tc_store`에 저장하되 `verdict_id`/`failure_context_id`는 비워둔다 — 장비 쪽 결과(FAIL/ERROR)는 이미 실재하는 사실이라 판정 실패가 그걸 지우면 안 된다. 단, `run_judge.py`의 로그 기반 파이프라인과 달리 **TC_EXEC 쪽은 미판정 TC를 다음 실행에서 자동으로 다시 판정하는 스윕이 없다** — 같은 (section, opcode)가 다시 타겟으로 뽑혀 새 FAIL/ERROR가 나야 그제서야 다시 판정 시도가 된다. 세 지점 모두 `run_pipeline`이 `on_skip(index, total, section, opcode_entry, reason)` 콜백으로 "이 타겟은 건너뛴다"를 알려주므로(`run_tc_pipeline.py`의 `_print_skip`), 터미널에서 아무 설명 없이 멈춘 것처럼 보이는 일이 없다.

**`data/verdicts/tc_exec.json`은 실행마다 리셋된다.** `pipeline.run_pipeline`이 맨 처음에 `_reset_tc_exec_judgments()`를 불러서 그 파일과 `data/failure_contexts/tc_exec/*.json`을 비우고, `tc_store.json`의 TC들 중 거기(이제 사라진 파일)를 가리키던 `verdict_id`/`failure_context_id`도 같이 지운다(죽은 참조 방지). `tc_store.json`/`coverage_state.json`은 안 건드린다 — 커버리지는 실행마다 누적되는 게 맞고, 판정 기록만 매 실행 새로 쌓이게 바뀐 것. 이 리셋을 `tc_store`/`coverage_state`까지 건드리는 방향으로 넓히지 말 것.

**`tc_store.json`/`coverage_state.json`을 지우는 건 `--reset-coverage`일 때만, 완전히 별개의 opt-in 경로다.** 둘 다 같은 "리셋"이라는 단어를 쓰지만 목적이 다르다 — `_reset_tc_exec_judgments`는 **항상** 돌고 판정 기록만 지우는 반면, `_reset_coverage`는 **플래그가 있을 때만** 돌고 커버리지 자체를 지운다. 커버리지가 실행마다 누적되는 건 "같은 물리 드라이브를 계속 테스트한다"는 가정 위에서만 맞는데, `tc_store.json`의 TC 레코드엔 "이게 어떤 드라이브에서 나온 결과인지"가 전혀 안 적혀 있다(디바이스 식별/시리얼 넘버 트래킹 없음) — 그래서 드라이브를 바꾸면 새 드라이브가 이전 드라이브의 누적 커버리지(드라이브별로 다를 수 있는 UNSUPPORTED 포함)를 그대로 물려받고, `pick_next_targets`는 새 드라이브를 사실상 전혀 안 건드린 채로 "이미 다 커버됨"이라고 결론 낸다(실측: `--count 10`을 새 드라이브에 돌렸는데 `generated=0`으로 즉시 끝남 — 103/103 reachable이 이미 이전 드라이브 기준으로 채워져 있었음). `_reset_coverage`는 지우기 **전에** `<tc_store 폴더>/coverage_backups/<UTC타임스탬프>/`로 복사해두므로 되돌릴 수 있다 — 백업 없이 바로 지우는 방향으로 고치지 말 것. 디바이스 식별 기반 자동 분리(시리얼 넘버로 커버리지를 드라이브별로 자동 나누는 것)는 사용자가 명시적으로 범위 밖으로 결정했다 — 지금은 수동 플래그만 제공한다.

## LLM / RAG 현재 상태

- `shared/llm_client.py`는 **실제로 동작한다**(`IS_DUMMY = False`) — `rag/srag_llm_guide.py`의 이미 인증된 `client`를 재사용한다. 모든 호출(성공/실패 불문, 재시도 포함)이 `logs/llm_calls.jsonl`에 한 줄씩 남는다(`caller`로 호출 모듈 구분). 호출자는 반환 dict의 shape에만 의존한다.
- `shared/rag_client.py` + `shared/spec_chunks.py`는 **실제로 동작한다** — `rag/index/current` → `v20260922_172200/chunks.jsonl`(969 청크, NVMe Base/Command Set/MI/TCG). 네트워크·크레덴셜 불필요. 단 임베딩 서버에 닿을 수 없어 **lexical 검색**(`covers_commands` 매치 +10점)이다.
- 그래서 RAG 질의는 hex opcode가 아니라 **커맨드 이름**으로 만들어야 한다. `judge._opcode_name_lookup`이 커버리지 인덱스로 opcode→이름을 역변환하는 이유 (실측: "0x09" ~2점 vs "Dataset Management" ~22점).
- `rag/srag_llm_guide.py`, `rag/srag_llm_service.py`는 실제 LLM에 붙이기 위한 코드다. 이 파일들의 크레덴셜 값은 읽거나 출력하지 말 것. SSH 자격증명이 든 `secrets.local.json`(`config.load_secrets`가 읽음, 템플릿은 `secrets.local.example.json`)도 마찬가지. 리포는 **public**이다 — `rag/srag_llm_guide.py`와 `secrets.local.json`은 `.gitignore` 대상이고 리포에는 빈 템플릿(`rag/srag_llm_guide.example.py`, `secrets.local.example.json`)만 있다. 원본 로그 `QST/`·`PULSEFZ/`도 커밋하지 않는다(103MB 파일이 GitHub 100MB 제한 초과, 테스트는 안 읽음).
- 세 시스템 프롬프트(judge/scenario_generator/args_author)는 **자연어 필드(description/rationale/guidance/role/chain_summary/field_breakdown)는 한국어로, 고정 식별자·열거값(classification/opcode_name/phase/direction, `shared_facts`의 키)은 원문 그대로** 쓰라고 명시한다. 후자를 번역하면 검증 로직(정확한 문자열 매칭)이 깨진다 — 새 자연어 필드를 추가할 때 이 구분을 지킬 것.

## 그 외 주의

- `opcode`(커버리지 인덱스의 식별자)와 `raw_opcode`(와이어로 보내는 값)는 다르다. Admin/NVM 커맨드셋이 같은 숫자를 재사용하기 때문(0x02 = Get Log Page vs Read). 혼용하면 조용히 틀린다.
- `build_spec_index.py`의 섹션→opcode 링크는 opcode 표의 `section_ref`(권위있는 1차 링크) 외에 `covers_commands` 태그로 recall을 넓히는데, 이 태그는 **청크 단위**라 한 청크가 여러 조항(예: 어떤 커맨드의 꼬리 서브조항 + 다음 커맨드의 조항 전체)을 담고 있으면 그 청크의 태그가 엉뚱한 조항에도 붙는다. 그래서 ① 그 조항이 태그가 가리키는 커맨드 자신의 `section_ref` 아래 중첩된 번호일 때만 covers_commands 링크를 허용하고, ② "Command Completion"(스펙 전체에 59번 반복되는 보일러플레이트 제목)은 올바르게 중첩되어 있어도 애초에 opcode를 연결하지 않는다 — 그 본문이 실제로는 다른 커맨드를 예시로 드는 경우가 많아서다. 새 조항 유형을 추가할 때 이 가드를 느슨하게 풀지 말 것(실측: 샘플 20건 중 8건이 이 경로로 엉뚱한 커맨드를 테스트했었다).
- **커맨드별 세부 값(LID/FID/CNS/...) 조항은 4번째 연결 패스(`link_field_values`)로, 위 3개 패스가 다 끝난 뒤에만 추가로 돈다.** `"(Log Page Identifier 02h)"` 같은 제목의 조항은 opcode 표의 `section_ref`가 직접 가리키는 조항이 아니라 — 흔히 2단계 중첩(`base:5.2.12` Get Log Page → `base:5.2.12.1` "Common Log Specific Information", opcode 없음 → `base:5.2.12.1.2` LID별 리프)이라, **바로 위 부모만 보면 전부 놓친다**. `_ancestor_chain`이 "opcode가 이미 연결된 가장 가까운 조상"을 찾을 때까지 계속 올라가고(중간의 빈 그룹 조항은 건너뜀), `FIELD_VALUE_RE`는 `findall` + "매치가 정확히 1개일 때만" 인정한다 — 끝 앵커(`\s*$`)를 쓰면 "10h and 11h"처럼 값이 여러 개인 제목에서 숫자를 허용한 필드명 글자 클래스가 "Action Type 10h and"를 필드명으로 잘못 삼키고, "Host Metadata (FID 7Dh), (FID 7Eh), (FID 7Fh)"처럼 자식 3개를 한 줄에 나열한 부모 제목을 끝의 FID 하나로 잘못 연결한다(둘 다 실측으로 확인된 버그) — `findall` + 유일성 체크로 둘 다 자동으로 걸러진다. 고정점(fixed-point) 루프로 전체를 반복 실행하는 이유는 Event Type처럼 특정 LID 리프 밑에 또 중첩된 2단계 복합 케이스를 처리하기 위함 — 그 LID 리프가 먼저(이전 반복에서) opcode를 얻어야 Event Type 리프가 "가장 가까운 연결된 조상"으로 그 LID 리프를 찾아 `field_values`에 `[LID, EventType]` 체인으로 이어붙일 수 있다. 실측: 1,292개 조항 중 165개가 이 패턴이었고 전부 opcode가 없었다(테스트 가능 조항이 103→258로 늘어남).
- **`args_author`가 `required_field_values`를 CDW10 bits 7:0로 결정론적으로 검증하는 필드는 `REQUEST_SELECTABLE_FIELDS`뿐이다** — Log Page Identifier/Feature Identifier/CNS/Management Operation/Directive Operation/Directive Type/Configuration Identifier. **Event Type은 의도적으로 뺐다** — 호스트가 요청 시 CDW에 쓰는 필드가 아니라 컨트롤러가 이미 기록한 로그를 읽어서 파싱해야만 아는 분류값이라, "이 값만 달라"는 CDW 인코딩이 스펙에 없다. **Action Type도 뺐다** — 호스트가 쓰는 필드는 맞지만 CDW10이 아니라 Get LBA Status의 **CDW13 bits 31:24**다(스펙 청크로 확인, CDW10은 SLBA 하위). CDW10[7:0]으로 검증하면 LLM이 SLBA를 ATYPE 값으로 덮어쓰게 강제했었다. 이 하네스는 CDW10~12만 보내므로(`passthru_cmd`) 검증할 CDW13 자체가 없다. 이 집합을 늘리기 전에 그 필드가 정말 "호스트가 요청 시 쓰는" 필드인지 실측으로 확인할 것 — direction 비트/nsid 허용 목록과 같은 종류의 하드코딩이라 틀리면 조용히 틀린다.
- **세부 값이 검증된 스텝(`field_value_verified=True`)의 `INVALID_*`(INVALID_OPCODE 제외) 거부는 ERROR가 아니라 UNSUPPORTED다.** CDW10에 올바른 값이 들어갔다는 걸 이미 확인했으므로, 거부는 "이 드라이브가 그 특정 값을 안 지원한다"는 유효한 결론이지 인자 저작 실수가 아니다 — `rejected_arguments(execution_result, tc_record=None)`가 이 스텝들을 건너뛰고(`tc_record` 없이 호출하면 기존 동작과 완전히 동일 — 하위 호환), `field_value_unsupported`가 대신 UNSUPPORTED로 분류한다. 체인 안에서 한 스텝이 이렇게 UNSUPPORTED로 빠져도 다른 스텝의 진짜 ERROR를 가리면 안 된다(`check_step_expectations`가 스텝별로 독립 판단하므로 이미 보장됨).
- `judge_failure_context(fc)`는 `fc["spec_grounding"]`을 **in place로 채운다**. 호출자는 판정 *후에* FailureContext를 저장해야 한다(`run_judge.judge_source`, `pipeline.run_pipeline`의 judge 호출 직후).
- `run_judge.judge_source`는 FailureContext가 사라진 고아 verdict를 삭제한다. 리포트에 근거 없는 분류 행이 남는 것을 막기 위한 것.
- `tc_system/pipeline.py`가 TC가 판정됐을 때 `tc["verdict_id"]`뿐 아니라 `tc["failure_context_id"]`도 저장한다(`Verdict`는 애초에 `failure_context_id` 필드를 갖고 있지만, 터미널에서 바로 보이게 TC에도 복제). `run_tc_pipeline.py`의 판정 완료 출력은 `status`가 FAIL이든 ERROR든(둘 다 judge 대상이면) 항상 뜨게 되어 있다 — 예전엔 `elif status == "FAIL":` 블록 안에만 있어서 ERROR로 판정된 건은 verdict_id조차 안 보였다. 이 출력을 다시 FAIL 전용으로 좁히지 말 것.
- HTML 리포트는 Jinja2 없이 stdlib 문자열 조립이다(`report/components.py`). 값 삽입은 반드시 `components.esc()`를 통과시킬 것 — 로그 원문이 그대로 들어간다.
- 테스트는 전부 실제 로그 샘플/실측 수치 기반이다. 가짜 데이터로 통과시키지 말고, 파서 엣지케이스(윈도우 겹침, 다중 크래시 중 종단 판별)를 깨지 않았는지 확인할 것.
- 실제 동작 PC의 `.claude/settings.local.json`에서 `Bash(plink:*)`, `Bash(python run_tc_pipeline.py:*)`, `Edit(**)`가 승인 없이 실행된다 — 즉 실제 장비 접근이 승인 프롬프트 없이 나갈 수 있다. (리포에는 이 파일이 없다 — 체크아웃한 다른 PC에서 승인 동작을 가정하지 말 것.)
