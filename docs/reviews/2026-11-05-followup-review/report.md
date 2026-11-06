# 계약 수정 후 재리뷰 — 2026-11-05

현재 작업 트리를 검토했다. 이전 심층 리뷰의 소스 해시와 비교해 원복·판정·형식 검사·재판정 연결·scope·리포트 변경을 확인했다. 제품 코드는 수정하지 않았다.

- 기존 전체 테스트 **504개 통과**(23.012초). 심층 리뷰 회귀 테스트 28개가 추가됐다.
- 추가 모의 반례 **5/5 재현**: [스크립트](reproduce.py), [관측 결과](counterexamples.json).
- 실제 장비·SSH·LLM·PMU를 호출하지 않았다. 모의 장비의 조건을 실제 SSD에서 관측했다는 주장은 아니다.

## F01 / P1 — 변경 명령 도중 중단되면 finally에서도 원복을 건너뛴다

위치: `tc_system/execution/tc_executor.py:88`, `:125`.

`send()`가 반환한 다음에야 `results.append(current)`를 실행한다. 컨트롤러가 Set Features를 처리했지만 SSH 호출이 Ctrl+C/예외로 끝나면 해당 스텝의 결과가 없다. finally의 cleanup guard는 이를 “변경 스텝 미실행”으로 취급한다.

원래 온도 임계값 360에서 Set이 300으로 반영된 직후 KeyboardInterrupt를 발생시켰다. 호출은 snapshot Get → action Set에서 끝났고 cleanup Set은 없었다. 최종값은 **300**이었다. 새 회귀 테스트는 변경 명령 다음 단계에서의 중단을 검증하므로 이 경우를 놓친다.

수정: 전송 중인 변경을 별도로 기록해 결과 미수신과 미전송을 구분해야 한다. 처리 여부가 불확실하면 백업을 이용한 원복을 시도하고, 시도 여부와 결과를 남겨야 한다.

## F02 / P1 — 다른 항목의 지원 측정을 테스트 대상의 미지원 측정으로 인정한다

위치: `tc_system/verification.py:1096`, `:1135`.

`_support_measured`는 지원 테이블에서 만족한 data_field 검사가 하나라도 있으면 True를 반환한다. 대상 identifier, 테이블 종류, 기대 비트값을 연결하지 않는다.

반례는 LID 00h의 LSUPP=1만 사전조건으로 확인하고, 지원 여부가 측정되지 않은 LID 7Eh에 “미지원이면 INVALID_LOG_PAGE”를 시험한다. 7Eh가 SUCCESS일 때 현재 계획은 미측정 전제를 남기지 않고, 판정도 **FAIL**이다. LID 00h가 지원된다는 사실은 LID 7Eh가 미지원이라는 근거가 아니다.

수정: 해당 action의 FID/LID/opcode와 지원 테이블의 identifier·명령 집합·지원 비트·극성을 정확히 연결해야 한다. 관계없는 측정은 미지원 전제를 입증하지 않는다.

## F03 / P1 — Host Identifier를 Set Features만으로 원복 가능한 기능으로 등록한다

위치: `tc_system/spec_fields.py:487`.

로컬 스펙 `base:5.2.26.1.32`의 Host Identifier 데이터 구조 규정은 현재 ID가 0이면 설정하고, 이미 nonzero이면 Command Sequence Error로 거부하도록 명시한다.

초기 Host ID가 0인 모의 장비에서 8바이트 `AB` 패턴을 설정한 뒤 cleanup으로 0을 설정했다. cleanup은 **CMD_SEQ_ERROR**, ID는 **ABABABABABABABAB**로 남았고 TC는 PASS였다. EXHID의 버퍼 크기·인스턴스 보존 수정은 유효하지만, 이 기능의 상태 전이 제약까지 해결한 것은 아니다.

수정: Set만으로 되돌릴 수 없는 전환을 일반 복구 가능 codec으로 허용하지 않아야 한다. 필요한 reset/연결 재설정까지 포함하는 복구 경로가 없다면 그 상태 변경을 차단해야 한다.

## F04 / P2 — 원복 재조회 실패가 확인 필요 목록에 나타나지 않을 수 있다

위치: `tc_system/review.py:176`.

cleanup이 SUCCESS여도 재조회가 INTERNAL/통신 예외/누락된 CQE로 실패하면 `restore_verified=None`이다. 현재는 시간값의 근사 원복과 구분 없이 `cleanup_unverified`를 **info**로 분류한다.

모의 실행에서 재조회 INTERNAL, TC PASS, 코드 검토 level=info를 확인했다. 리포트의 검토 목록은 info 레벨을 제외하므로, 별도 LLM 감사가 이의를 제기하지 않는 한 원복 확인 실패가 검토 요청으로 드러나지 않는다.

수정: Timestamp의 의도된 근사 비교와 재조회 실패를 구분해야 한다. 재조회 실패는 최소한 확인 권장 대상으로 표시하고 원시 응답을 연결해야 한다. 요구사항 자체의 PASS를 곧바로 FAIL로 바꾸라는 뜻은 아니다.

## F05 / P2 — 최신 실행에 TC가 없으면 이전 실행을 최신으로 선택한다

위치: `report/aggregator.py:42`, `report/html_report.py:224`.

skip에는 run_id가 생겼지만 최신 실행 ID는 여전히 TC 기록만으로 선택한다. 실행 A에 TC 1개가 있고, 뒤의 실행 B가 생성 실패로 전부 skip되면 B의 manifest·skip 기록이 있어도 report.run_id는 A다. skip 필터는 B의 기록을 제거한다.

재현 결과: 실제 최신 B는 **TC 0 / skip 1**인데, 진행 상황은 이전 A의 **TC 1 / skip 0**이었다. run_id 선택만 B로 바꾸더라도 `_progress_section`의 `or tc_records`가 빈 B의 TC 목록을 이전 전체 목록으로 대체하므로 두 경로를 함께 고쳐야 한다.

수정: TC 유무와 독립적인 실행 기록을 기준으로 최신 실행을 선택하고, 명시된 실행 ID의 TC가 0개이면 0개로 표시해야 한다.

## 기존 수정에 대한 확인과 한계

기존 반례에 대응하는 FEATURE_CODECS, snapshot 내용 검사, NSID/SV 고정, SV=1의 saved/current 복구, 원복 재조회, dmesg 시작 경계, nested shape 검사, 판정 enum/유한 confidence, TC 재판정 연결, 응답 전체 기반 ID, 요구사항별 scope가 추가돼 있다. 해당 회귀 테스트는 모두 통과했다.

FID 12h/13h/14h는 올바른 복구 인코더를 구현한 것이 아니라, codec 미지원으로 성공을 기대하는 Set을 차단하는 방식이다. 이 동작은 안전하게 미지원 범위를 표시하지만 해당 기능의 적합성 시험을 완료했다는 뜻은 아니다.

이 리뷰는 로컬 스펙과 오프라인 모의 실행에 기반한다. 실제 SSD의 Host ID 지원·상태 전이와 실제 SSH 중단 동작, LLM 생성 품질은 통합 검증하지 않았다.

```bash
python3 docs/reviews/2026-11-05-followup-review/reproduce.py
python3 -m unittest discover -s tests -q
```
