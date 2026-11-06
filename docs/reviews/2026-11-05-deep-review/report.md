# 현재 작업 코드의 추가 종합 리뷰 — 2026-11-05

## 결론과 범위

개별 예외를 보완해도 같은 계열의 결함이 다시 생기는 이유는 세 계약이 분산돼 있기 때문이다.

1. **복구 계약:** 어떤 대상을 바꿀지, 어떤 값을 온전히 백업해야 하는지, 실제 원복이 가능한지, 어떤 레지스터·버퍼로 원복할지를 함께 검증하지 않는다.
2. **판정 계약:** `verify_tc`의 검증 불가 사유가 상위 FAIL 및 LLM 펌웨어 결함 판정을 일관되게 제한하지 않는다.
3. **이력 계약:** 최초 판정, 재판정, TC 연결, 리포트가 서로 다른 갱신 경로를 사용한다.

이번 추가 점검에서는 아래 **11개 문제군의 반례 18개**를 장비·SSH·LLM 호출 없이 재현했다. 앞선 리뷰의 4건과 6건은 아래 별도 표에 남겼으며, 새 발견 수에 다시 넣지 않았다. R03은 이전의 “snapshot 실패 시 차단” 수정이 SUCCESS 응답의 실제 백업 내용까지 확인하지 않는다는 후속 결함이다. R06·R09·R11은 이번 변경에서 새로 생긴 회귀라고 주장하는 것이 아니라 현행 코드에 남은 기존 결함이다.

- 검토 기준: HEAD `ae3306f` 위의 사용자가 수정한 작업 트리. HEAD만 리뷰한 것이 아니다.
- 기존 전체 테스트: **476개 통과**, 17.250초. [출력](tests.txt).
- 추가 반례: **18/18 재현**. [재현 스크립트](reproduce.py), [현재 관측값](counterexamples.json).
- 이전 `--all` 기록: **191 TC를 현재 판정기로 오프라인 재평가**. [요약](replay-summary.json).
- 검토 도중 기준 소스·테스트·문서 73개 파일의 변경은 없었다. [파일별 해시](source-snapshot.json).
- 제품 코드와 기존 테스트는 수정하지 않았다. 이 폴더에는 검토 문서와 재현 자료만 추가했다.

## R01 — P1: 영구 쓰기 보호도 일반적인 “원복 가능 Set Features”로 취급한다

**위치:** `tc_system/generation/tc_writer.py:278`, `tc_system/execution/tc_executor.py:139`, `tc_system/pipeline.py:225`.

Set Features의 opcode 메타데이터는 `destructive=False`, `firmware_state=False`, `lockout_risk=False`다. FID 84h는 버퍼가 없다는 이유로 `restorable=True`가 된다. 값 2(Write Protect Until Power Cycle)나 3(Permanent Write Protect)의 상태 전환 가능성을 검사하지 않는다.

반례 R01에서는 해당 전환을 지원하는 모의 장비를 사용했다. `allow_destructive=False` 사전 검증을 통과하고, WPS=3으로 변경된 뒤 cleanup이 `FEATURE_NOT_CHANGEABLE`로 거부됐다. **원래 WPS=0으로 돌아오지 않았는데 TC는 PASS였다.** 실제 SSD가 이 상태 전환을 지원한다거나 이번 검토에서 실제로 보호 상태가 변경됐다는 뜻은 아니다.

로컬 스펙 `base:5.2.26.1.35`는 WPS=2/3 상태에서 Set Features로 변경을 시도하면 Feature Not Changeable로 거부하도록 명시한다. 버퍼를 읽고 쓸 수 있다는 사실과 상태를 원복할 수 있다는 사실은 다르다.

**수정:** 값에 따른 비가역·전원 복구 필요 상태를 전송 전에 구분해야 한다. 일반 cleanup으로 복구 가능한 설정으로 표시해서는 안 된다. `--no-destructive` 경계도 이 값의 의미를 반영해야 한다.

## R02 — P1: FID별 수신 형식과 복원 형식을 동일하게 가정한다

**위치:** `tc_system/execution/tc_executor.py:174`, `tc_system/execution/tc_executor.py:179`.

현재는 CQE DW0을 항상 Set Features CDW11로 옮기고, Get Features 데이터는 그대로 Set Features payload로 사용한다.

| 반례 | 로컬 스펙 | 올바른 복원 위치·형식 | 실제 결과 |
|---|---|---|---|
| R02a: FID 13h PLM Config | `base:5.2.26.1.12` | LPE는 CDW12 bit 0 | 기존 1이 테스트 후 0으로 남음. cleanup 자체는 SUCCESS |
| R02b: FID 14h PLM Window | `base:5.2.26.1.13` | WSEL은 CDW12 bits 2:0 | cleanup이 WSEL=0(Reserved)을 전송, INVALID_FIELD, 테스트값 잔류 |
| R02c: FID 12h Read Recovery Level | `base:5.2.26.1.11` | RRL은 CDW12 bits 3:0 | 원래 7을 CDW11에 쓰고 CDW12는 0이 되어 원복 실패 |
| R02d: FID 0Eh Timestamp | `base:5.2.26.1.7` | Set 데이터 bytes 7:6은 Reserved | Get의 Origin 속성 `0200`을 Reserved 영역에 그대로 송신 |

R02c의 모의 장비는 스펙이 허용하는 NVM Set 미지원/서브시스템 단위 경우로, CDW11의 NVMSETID를 무시한다. R02d는 잘못된 송신 필드가 만들어졌다는 재현이며, 모든 실제 컨트롤러가 그 필드를 반드시 거부한다는 주장은 아니다.

**수정:** FID별 복구 인코더를 두고, 응답→Set 레지스터/버퍼 변환과 원복 가능성을 명시해야 한다. 그 변환을 모르는 FID는 복구 가능하다고 단정하지 않아야 한다.

## R03 — P1: SUCCESS snapshot이어도 백업할 값이 없거나 불완전할 수 있다

**위치:** `tc_system/execution/tc_executor.py:150`, `tc_system/execution/tc_executor.py:170`.

`_unrestorable`은 snapshot의 완료 상태가 SUCCESS인지만 확인한다.

- R03a: SUCCESS 문구는 있지만 CQE DW0이 캡처되지 않은 경우에도 Set을 전송했다. cleanup에서는 값 파싱 실패를 오류로 처리하지 않아 **0으로 복원**했다.
- R03b: APST 원래 버퍼가 256바이트 중 1바이트만 캡처돼도 Set을 전송했다. cleanup 단계에서야 버퍼가 부족한 것을 알고 원복을 생략했다.

이는 “Get Features가 에러로 끝났을 때 차단”하는 기존 수정과 다른 경계다. SUCCESS라는 문구만으로 복원에 필요한 값을 확보했다는 보장이 되지 않는다.

**수정:** 상태 변경 전에 필요한 CQE 값·payload 전체·FID별 변환 가능성을 모두 확인해야 한다. 없는 원래 값을 0으로 대체해서는 안 된다.

## R04 — P1: 재시도가 복구 대상의 NSID/SV를 바꿀 수 있다

**위치:** `tc_system/generation/tc_writer.py:175`, `tc_system/generation/tc_writer.py:338`.

CDW11의 일부 인스턴스 비트는 고정하지만, 원복 정체성을 구성하는 NSID와 SV는 고정하지 않는다. `reauthor_steps`는 기존 snapshot/cleanup을 그대로 유지한다.

- R04a: 원래 NSID=1인 Set을 재생성하면서 NSID=FFFFFFFFh로 바꾸면 모의 장비의 두 namespace가 변경되지만 cleanup은 NSID=1만 복원한다. namespace 2는 200→300으로 남았다.
- R04b: 원래 SV=0인 명령을 SV=1로 바꾸면 저장값까지 변경되지만 cleanup은 SV=0이다. 저장값은 150→300으로 남았다.

관리 명령의 FFFFFFFFh NSID는 현재 인자 검증기가 허용한다. 반례에서 재생성 자체는 mock했지만, 만들어진 인자는 제품의 실제 사전 검증과 실행기 검증을 통과했다.

**수정:** FID·NSID·SV·인스턴스 등 복구 대상의 정체성을 재시도 동안 불변으로 유지하거나, 정체성이 바뀌는 경우 백업·cleanup·검증식까지 한 단위로 다시 구성해야 한다.

## R05 — P2: 첫 단계가 host action이면 dmesg 범위가 틀리고 로그가 사라진다

**위치:** `tc_system/execution/tc_executor.py:49`, `tc_system/execution/tc_executor.py:93`.

- R05: 첫 Reset이 실패해 뒤 NVMe 명령이 차단되면 dmesg clear를 한 번도 하지 않는다. 그런데 반환값은 `dmesg_captured_scoped=True`다. 부팅 이후 로그를 이번 TC 범위의 로그로 표시한다.
- R05b: 첫 Reset이 성공하면 그 다음 NVMe 명령을 보내기 직전에 clear한다. 모의 실행 순서는 `reset → clear dmesg → action`이었고, reset 중 발생한 경고가 최종 캡처에서 사라졌다.

**수정:** TC의 첫 host/NVMe 동작 전에 로그 경계를 설정해야 한다. clear 실패·미실행 여부는 실제 캡처 범위에 반영해야 한다.

## R06 — P2: LLM 응답 보정이 부정 표현과 NaN을 잘못 확정한다

**위치:** `log_judge/judge.py:145`, `log_judge/judge.py:178`.

`_as_classification("not a firmware defect")`가 `firmware_defect`가 된다. 정확한 enum이나 알려진 표기 변형인지 확인하는 대신 `firmware`/`defect`라는 단어 포함 여부로 결정하기 때문이다.

또한 `_as_confidence("NaN")`은 0이나 오류가 아니라 **1.0**이 된다. 이 값은 confidence<0.5 강등 규칙도 통과한다. 두 입력 모두 기존 응답 스키마가 요구하는 정상 값은 아니지만, 현행 코드가 잘못된 응답을 안전하게 거부하지 않고 오히려 결론을 강화한다.

**수정:** enum은 알려진 동치 표기만 허용하고 나머지는 검토 대상으로 둔다. confidence는 `isfinite`와 범위를 검증해야 한다.

## R07 — P1: 전제 미측정의 UNVERIFIED가 펌웨어 결함 판정을 막지 못한다

**위치:** `tc_system/execution/expectation_checker.py:393`, `tc_system/review.py:383`.

Discovery controller라는 전제가 측정되지 않은 부정 테스트를 구성했다. 기대 INVALID_FIELD 대신 SUCCESS를 관측하면:

1. `verify_tc`는 전제 미측정을 이유로 **UNVERIFIED**다.
2. `check_expectation`은 raw 실행 결과의 **FAIL**을 그대로 반환한다.
3. 그 결과로 들어온 `firmware_defect` 판정을 `downgrade_verdict`도 그대로 유지한다. 전제 미측정 사유가 blocking 목록에 없고, actor 확인 이유도 PASS에서만 생성되기 때문이다.

반례 R07은 LLM이 실제로 이 결론을 냈다는 주장이 아니라, 그런 결론이 들어왔을 때 코드의 보류 장치가 작동하지 않는다는 재현이다.

**수정:** 원시 실행 실패와 조항 위반을 구분해야 한다. 조항 적용 전제가 측정되지 않았다면 조항 위반을 근거로 펌웨어 결함을 확정하지 않도록 공통 판정 경로에서 제한해야 한다. 별도의 장비 장애 근거가 있다면 그 근거는 독립적으로 다룰 수 있다.

## R08 — P1: 중첩 입력 형식 오류가 전제 삭제 또는 배치 중단으로 이어진다

**위치:** `tc_system/verification.py:593`, `tc_system/verification.py:849`.

- R08a: `precondition_checks=["some condition"]`인 잘못된 LLM 응답과 지원 probe 결과를 넣으면 `_support_premises`가 문자열의 `.get()`을 호출해 AttributeError가 난다. 생성 재시도와 pipeline의 `_LLM_REPLY_ERRORS`에 포함되지 않아 타겟 하나의 실패로 정리되지 않는다.
- R08b: `preconditions=[{"condition": "controller must be a Discovery controller"}]`는 거부되지 않고 목록에서 사라진다. `unmeasured_preconditions`도 비어 최종 **PASS**가 된다.

**수정:** 보정·지원 전제 처리보다 먼저 중첩 객체/배열/문자열의 형식을 검증해야 한다. 이해하지 못한 전제를 조용히 없애서는 안 된다. 선언을 보존해 미측정으로 남기거나 생성 응답을 거부해야 한다.

## R09 — P2: 나중에 판정한 TC_EXEC 결과가 원래 TC에 연결되지 않는다

**위치:** `run_judge.py:40`, `report/html_report.py:320`.

최초 judge 실패 후 저장된 TC의 `failure_context_id`는 있고 `verdict_id`는 없는 상황을 재현했다. `judge_source("tc_exec")`는 판정 파일을 생성하지만 TC의 `verdict_id`를 갱신하지 않는다. 저장된 판정 1개 중 현재 TC에 연결된 판정은 **0개**였다.

리포트는 `tc.verdict_id`만으로 현재/과거 판정을 구분하므로, 이 복구 결과는 “현재 TC와 연결 안 된 이전 실행”으로 분리된다. 최초 pipeline 경로에서 적용하는 `downgrade_verdict`도 재판정 경로에는 없으므로 판정 보정 책임을 함께 정리할 필요가 있다. 추가 반례는 연결 누락을 직접 검증한다.

**수정:** TC_EXEC 재판정 시 FailureContext ID로 TC를 연결하고, 최초 판정과 동일한 보정·저장·review 갱신 경로를 사용해야 한다.

## R10 — P2: FID 미지원을 커맨드 자체의 INVALID_OPCODE로 설명한다

**위치:** `tc_system/execution/expectation_checker.py:481`.

probe에서 미지원으로 확인된 FID 11h의 Get Features가 INVALID_FIELD로 거부되면 `feature_unsupported`에 의해 UNSUPPORTED가 된다. 그러나 설명은 **“드라이브가 이 커맨드를 구현하지 않음(INVALID_OPCODE)”**이다.

실제 wire 응답은 INVALID_FIELD이고 Get Features 전체가 미지원이라는 증거는 없다. opcode 미지원 캐시 자체는 별도로 INVALID_OPCODE를 검사하므로, 이 반례는 다른 Get Features를 실행하지 못하게 만드는 캐시 오류라는 뜻은 아니다.

**수정:** opcode 미지원과 FID/LID 선택자 미지원을 상태 설명에서 구분하고 실제 상태 코드를 유지해야 한다.

## R11 — P2: 다른 LLM 응답이 같은 response_id를 가질 수 있다

**위치:** `shared/llm_client.py:199`.

ID에 전체 응답 대신 `text[:200]`만 넣는다. 같은 프롬프트에 앞 200자가 같고 그 뒤가 다른 두 JSON 응답을 넣자, 구조와 내용은 다른데 response_id는 같았다.

저장된 TC·인자 생성·감사 결과에서 이 ID로 로그를 추적하면 어느 원문 응답을 가리키는지 모호해진다.

**수정:** 전체 응답의 해시나 실제 completion/call 식별자를 사용해야 한다. 긴 원문을 ID에 직접 보관할 필요는 없다.

## 앞선 리뷰 지적과의 관계

아래 10건은 앞선 두 응답에서 이미 재현·보고한 내용이며, 이번 추가 문제군에 다시 세지 않았다. 해당 코드 경로는 현재도 유지돼 있다.

| 기존 지적 | 현재 코드 경로 |
|---|---|
| SV=1에서 저장값만 원복해 현재값도 저장값으로 바뀜 | `plan_state_restore`: SEL=2 snapshot 한 건, SV=1 cleanup 한 건 |
| Reset→Set→Get도 상태 보존 검증으로 인정 | `_require_host_event`: 관측이 host step 뒤인지 여부만 확인 |
| 별도 측정으로 미지원이 확인돼도 SUCCESS를 전제 반증으로 처리 | `_premise_refuted`: 측정 결과를 확인하지 않음 |
| 예외/Ctrl+C에서 cleanup 미실행 | `_execute_contract`: cleanup을 보장하는 예외 종료 경로 없음 |
| Write Uncorrectable 미전송 시에도 Write Zeroes 전송 | `plan_state_restore`: WU cleanup에 실행 guard 없음 |
| 짧게 캡처된 두 데이터의 data_equal이 통과 | `evaluate_check`: 양쪽 전체 캡처 길이 검증 없음 |
| 경계 내 Read/Verify의 정상 DULBE도 FAIL | `_LBA_CASES`: 기록 상태/DULBE 조건 없이 SUCCESS 고정 |
| 128비트 Host ID의 EXHID가 복구 단계에서 누락 | `_FEATURE_INSTANCE_CDW11`: FID 81h 없음 |
| 요구사항별 관측 scope 과대 집계 | `requirement_coverage`: TC 단위 claim_scope 재사용 |
| 최신 실행의 skip 수에 과거 기록 합산 | `_progress_section`: TC만 run_id 필터, skip은 전체 len |

더 이전에 지적한 build_tc 하네스 raw_opcode 누락, PMU OFF 실패 무시, 에러 완료 snapshot 뒤 변경 전송, feature snapshot의 NSID/인스턴스 중복 제거, data_all 전체 캡처 길이 누락은 현재 코드에 대응 수정이 있다. 다만 snapshot의 SUCCESS 내용을 검사하지 않는 R03은 별도로 남아 있다. “관련 수정이 있다”는 표현은 이 계열 전체가 해결됐다는 뜻이 아니다.

## 점검표와 검증의 한계

| 경계 | 이번 확인 | 남은 한계 |
|---|---|---|
| 정상/오류 완료, 상태 코드 alias, field mask, 전송 길이 | 전체 476 테스트, 현재 검증기 코드 확인 | 실제 nvme-cli 버전별 출력 통합 검증 없음 |
| snapshot/원복 | 완료 실패·내용 누락·짧은 데이터·비가역 값·FID별 레지스터/버퍼·재시도 정체성 | 모든 FID·컨트롤러 조합을 시험한 것은 아님 |
| host action | 첫 host 실패 및 성공 후 dmesg 경계, 기존 PMU 테스트 | 실제 PMU·컨트롤러 리셋은 호출하지 않음 |
| 생성 입력 | 중첩 형식 오류, 전제 보존/차단, 기존 scenario/args 테스트 | 실제 LLM의 생성 품질·응답 분포는 측정하지 않음 |
| 판정·보정 | 부정 분류값, NaN, 미측정 전제와 FAIL/firmware verdict의 연결 | 모든 스펙 문장의 의미와 검증식의 동치를 증명하지 않음 |
| 저장·재판정·출처 | judge 실패 후 TC 연결, response ID 충돌, 코드 파일 해시 | 프로세스 강제 종료/디스크 장애 시나리오는 이번에 새로 주입하지 않음 |
| 커버리지·리포트·기록 | 이전 scope/skip 문제 확인, 191 TC 재평가 | 과거 실행을 새 생성기로 다시 실행한 것은 아님 |
| 병렬 생성 | daemon pool, 공유 로그 lock, 순차 장비 실행 경로 정적 확인 및 기존 테스트 | 실제 LLM 부하·경합/네트워크 중단 부하 시험 없음 |

이전 실행 재평가 결과: 기존 FAIL 14개는 FAIL 2 / ERROR 2 / UNVERIFIED 10으로 바뀌었다. 기존 PASS 34개는 PASS 28 / UNVERIFIED 6이다. 이는 **저장된 명령과 원시 응답의 재판정**이며, 현재 생성기와 하네스가 실제 장비에서 올바르게 동작한다는 통합 검증은 아니다.

“남은 결함이 없다”는 결론은 내리지 않는다. 이번 산출물은 확인된 재현 조건, 실제/기대 결과, 점검한 범위, 미검증 범위를 고정해 다음 수정의 검증 기준으로 쓰기 위한 것이다.

## 재현

프로젝트 루트에서:

```bash
python3 docs/reviews/2026-11-05-deep-review/reproduce.py
python3 -m unittest discover -s tests -q
```

재현 스크립트는 모의 장비 상태와 임시 폴더만 사용한다. 실제 SSH를 거부하는 guard를 추가로 적용한다. `reproduced=true`는 현재 코드가 기대 불변조건을 위반했다는 뜻이다. 수정 후에는 해당 항목이 `false`가 되는지 확인하고 실제 회귀 테스트로 옮길 수 있다. 이 스크립트 자체는 장비 상태 전이 전체를 구현한 NVMe 적합성 시험기가 아니다.
