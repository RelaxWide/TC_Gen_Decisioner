# 수정본 리뷰 — 2026-11-06

검토 대상은 사용자가 수정한 현재 작업 트리다. HEAD에 커밋되지 않은 변경도 포함했다. 제품 코드와 기존 테스트를 수정하지 않았으며 실제 SSD·SSH·LLM·PMU는 호출하지 않았다.

- 전체 테스트: **514개 통과**, 21.473초.
- 직전 후속 리뷰의 F01~F05: 기존 반례 스크립트 재실행 결과 모두 `reproduced=false`. 새 회귀 테스트도 통과했다.
- 이번 추가 경계: **3개 반례 재현**. [재현 코드](reproduce.py), [실제 관측 결과](counterexamples.json).

## N01 / P1 — 처리 중 오류도 “변경 없음”으로 단정해 원복을 생략한다

위치: `tc_system/execution/tc_executor.py`, `_may_have_changed`의 `return status is None or status == "SUCCESS"`와 cleanup guard.

정상적인 인자 거부에서 불필요한 원복을 생략하려는 수정이 모든 오류 완료 상태로 확대됐다. INTERNAL 등 처리 도중 발생한 오류는 명령 전송 자체가 거부됐다는 증거도, 상태 변경이 원자적으로 롤백됐다는 증거도 아니다.

모의 장비에 “온도 임계값을 360→300으로 반영한 뒤 INTERNAL을 반환”하는 장애를 주입했다. 결과는 TC FAIL이지만 cleanup은 `cleanup_not_needed`이며, 사유도 “장비가 거부해 바뀐 것이 없음”이다. 원복 Set은 한 번도 보내지 않았고 값은 **300**으로 남았다.

이것은 실제 SSD가 그런 장애를 보였다는 주장이나 정상 인자 거부가 값을 변경한다는 주장이 아니다. firmware QA 하네스가 처리 실패 응답만으로 무변경을 단정하는 경계를 확인한 장애 주입이다. `_may_have_changed`라는 함수의 목적상 실패 후 효과를 알 수 없는 상태도 처리해야 한다.

수정: 확실한 사전 검증 거부와 처리 중 실패를 구분해야 한다. 효과가 불확실한 실패는 원래 값을 재조회하거나 백업으로 원복을 시도하고, 확인 결과를 기록해야 한다. 단순히 정상 거부된 모든 부정 테스트를 다시 원복 대상으로 만들 필요는 없다.

## N02 / P1 — FID 미지원을 직접 측정해도 생성 단계가 “미측정”으로 남긴다

위치: `tc_system/verification.py`, `_support_premises`의 Get/Set Features 분기 끝 `if known is None:`.

LID 분기는 사전조건의 동일 엔트리/극성을 확인하지만 FID 분기는 probe 사전에 해당 FID가 없으면 항상 미측정 메모를 추가한다. 실행 단계에 추가된 정확한 `_support_measured`도 이 메모를 제거하지 못한다.

반례의 조건:

1. 실행 시작 probe에는 FID 01h 결과만 있고 대상 FID 7Fh 결과는 없다. 부분 probe 실패/미확정 결과에 해당한다.
2. TC setup은 FID Supported and Effects 로그 LID 12h에서 **FID 7Fh의 FSUPP=0**을 직접 확인한다.
3. action Get Features FID 7Fh는 기대 INVALID_FIELD 대신 SUCCESS다.

실제 결과: 사전조건 **satisfied**, 요구사항 검사 **violated**, 최종 상태 **UNVERIFIED**. 생성 단계가 추가한 “FID 7Fh 지원 여부가 측정되지 않음”이 위반 판정을 막는다.

수정: FID 분기에서도 같은 FID의 지원 비트와 극성이 측정되는지 확인해 `unmeasured_preconditions`를 정해야 한다. probe 결과가 없다는 것과 TC에서 측정하지 않았다는 것을 구분해야 한다.

## N03 / P2 — `unsupported`를 지원됨으로 읽어 검사값을 반전한다

위치: `tc_system/verification.py`, `_bit_polarity` 및 `_resolve_structure_checks`의 자동 보정.

`supported\b` 정규식에 단어 시작 경계가 없어 `unsupported` 끝부분까지 매칭한다. 반대로 clear 패턴에는 영어 `unsupported`가 없다. 따라서 `FID 7Fh is unsupported`는 극성 `set`으로 해석된다.

올바른 `FSUPP=0` named check와 이 설명을 넣으면 보정기가 검사값을 **1**로 바꾸고 `repaired=True`로 기록한다. 실제 미지원 비트가 0인 장비에서는 올바른 사전조건이 실패해 본동작이 차단된다. 이 자동 보정 결함은 이번 변경으로 새로 생겼다고 단정하지 않으며, 수정 경로를 점검하면서 추가 확인한 현행 결함이다.

수정: 단어 경계와 부정 표현을 구분해야 한다. 설명의 극성이 모호할 때 명시적인 검사값을 반전시키면 안 된다.

## 기존 수정 확인 및 한계

직전 5건의 반례에서 다음을 확인했다: 명령 호출 중 interrupt의 pending 기록, 대상 엔트리와 극성을 연결한 LID 측정, Host Identifier의 성공 변경 차단, 원복 재조회 실패의 확인 권장 분류, TC가 없는 최신 실행의 보고.

FID/Host ID 기능을 차단하는 수정은 해당 적합성 시험을 구현했다는 뜻이 아니다. 또한 모든 오류 상태의 복구 의미나 모든 영어/Korean 설명을 검증한 것은 아니다. 실제 장비의 실패 동작 및 실제 LLM 생성 품질은 별도 통합 검증이 남아 있다.

```bash
python3 docs/reviews/2026-11-06-review/reproduce.py
python3 -m unittest discover -s tests -q
```
