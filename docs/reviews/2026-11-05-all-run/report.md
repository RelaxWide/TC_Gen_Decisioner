# 2026-11-05 `--all` 실행 로그·리포트 감사

## 결론

이번 실행은 232개 타겟을 모두 **시도**했지만, 스펙 내용을 모두 검증한 실행은 아니다. 본동작을 실제 전송한 타겟은 115개(49.6%)이며, 76개는 사전 단계에서 중단되고 41개는 생성/인자 검증 단계에서 건너뛰었다. 저장된 PASS 34건도 범위별 재해석이 필요하다. 특히 사전조건의 잘못된 바이트·비트와 인용의 의미 불일치가 PASS와 중단 양쪽에 영향을 준다.

**펌웨어 결함으로 확정할 수 있는 사례를 이 기록에서 찾지 못했다.** `firmware_defect` 2건 중 Self-test는 최신 정상 완료 결과를 놓친 오판정이며, Controller Data Queue는 FID 지원 여부를 모른 채 오류 원인을 단정했다. 이것이 장비에 결함이 없다는 증명은 아니다. 현재 실패 기록의 다수가 테스트 정의·실행 제약·판정의 문제라는 뜻이다.

동시에 실제 호스트 오류도 발생했다. HMB FID 0Dh Get Features에 4바이트 버퍼를 주어 `nvme-cli`가 malloc assertion/exit 134로 종료됐다. 상태 이름 불일치로 Write Uncorrectable의 복구 Write가 실행되지 않아, 기록상 8개 LBA 중 7개에 대한 후속 복구 쓰기가 없다. 다음 장비 실행 전에 버퍼 크기 보호와 실패 후 정리를 우선 보완해야 한다.

## 범위와 재현

- 입력: `TC_Gen_Decisioner-main/`의 콘솔 로그 10개, LLM 호출 1,230줄, SSH 호출 712줄, TC 191건, skip 41건, verdict 28건, FailureContext 28건, 최신/보관 HTML.
- 주 분석 실행: **2026-11-05 10:05:53~14:59:33 KST**, `logs/tc_pipeline_20261105_010553.log`. 파일명은 UTC, 본문은 KST다.
- 실행 처음에 `--reset-coverage` 사용. 이전 TC 34건/skip 22건은 `data/coverage_backups/20261105T010553Z/`로 이동했다. 판정은 보존되어 예전 verdict 5건이 현재 report에도 함께 나온다.
- 최신 HTML은 15:06:34 KST 생성이며 실행 종료 직후 리포트와 보관본도 있다. 복사된 report 소스는 `b889a17`/`ae3306f` 모두와 일치하므로 이것만으로 실행 코드 SHA를 유일하게 확정할 수 없다. 다만 TC 기록에 미측정 사전조건 게이트가 있어 그 수정이 동작 중이었음은 확인된다.
- 분석 중 SSD/SSH/LLM을 호출하지 않았다. 원본 로그·JSON·HTML은 수정하지 않았다. 입력 SHA256은 [audit.json](audit.json)에 저장했다.
- 모든 TC 191건의 상태·단계·계약을 검사하고, FAIL 14건 및 PASS 34건을 개별 검토했다. 미지원/생성 실패를 실제 장비 결함으로 단정하지 않았다. 원본 PDF 대신 저장된 로컬 스펙 텍스트/표를 사용했으며 OCR·버전 차이는 추가 원문 확인 대상이다.

재현:

```bash
python3 docs/reviews/2026-11-05-all-run/analyze.py
```

산출물:

- [audit.json](audit.json): 수치, 근거 체크, 21개 문제군, TC별 요구사항/관측 요약, 입력 해시.
- [cases.csv](cases.csv): **실행 TC 191건 전부**. 원본 콘솔/TC JSON/LLM JSONL의 행 번호 포함. CSV는 Excel용 UTF-8 BOM.
- [skips.csv](skips.csv): **건너뛴 41건 전부**, 원문 사유와 분류.
- [counterexamples.json](counterexamples.json): 기존 검증기에 대한 메모리 내 반례 및 저장 상태 재생 결과. `ae3306f`의 검증기로 191건의 verification 상태를 다시 계산했으며 원본과 불일치는 0건이었다. 이 일치는 의미상 정확도를 증명하지 않으며, 같은 잘못된 판정을 재현한 것이다.
- 아래 표: FAIL/PASS 전체의 사람이 검토한 결론.

## 실제 수치

| 항목 | 결과 | 해석 |
|---|---:|---|
| 선정 타겟 | 232 | 실제 실행 가능한 전체 스펙 요구사항 수와 같지 않음 |
| 생성·실행 TC | 191 | 460개 계획 스텝 중 149개는 미실행 |
| 본동작 전송 | 115 | 232개 중 49.6%; 이 중 상당수는 미지원/정상 음성 응답 |
| 사전 단계 중단 | 76 | 생성됐지만 본동작은 장비에 보내지 않음 |
| 생성/인자 실패 | 41 | placeholder 22, 시나리오/JSON/계약 실패 19 |
| 저장 상태 | PASS 34 / FAIL 14 / ERROR 41 / UNVERIFIED 61 / UNSUPPORTED 41 | 상태 자체가 장비 결함 확정 여부는 아님 |
| 요구사항 집계 | 337개 중 평가 78, PASS 66 / FAIL 12 / 미검증 259 | 분모는 생성된 인용 항목. 아래의 의미/전제 오류가 포함되어 정정 필요 |
| PASS 중 음성 테스트 | 20/34 | 정상 거부 검증은 가치가 있으나 특정 원인·지원 전제가 확인되어야 함 |
| 실제 호스트 크래시 | 1 | HMB Get Features, exit 134 |
| SSH timeout / EINTR/EIO | 0 / 0 | 이 실행을 장치 hang 사례로 해석할 근거 없음 |
| 현 실행 판정 | 23 | 환경 11 / 검토필요 10 / 펌웨어 2 |
| 리포트 전체 판정 | 28 | 예전 실행 5건 추가: 환경 14 / 검토필요 12 / 펌웨어 2 |

## 문제군과 수정 순서

각 ID는 CSV/JSON의 `issues`와 연결된다. `P1`은 다음 장비 실행 전에 해결할 항목, `P2`는 정확도·효율·가시성 개선 항목이다. 항목은 서로 겹치므로 건수를 합산하면 안 된다.

### 1. 실행과 장치 상태 보호 — F02/F09/F10/F11

**F02 — HMB 버퍼 길이 오류가 실제 host crash로 이어짐 (P1).**

`tc-2fea8a412d`는 Host Memory Buffer(FID 0Dh)가 비활성화됐다는 조건을 검사하려고 Get Features를 실행했다. 최초에는 버퍼 없이 INVALID_FIELD, 재시도에서는 `data_len=4 --read`로 바뀌었다. 이후 SUCCESS DW0=1 뒤 malloc assertion/exit 134가 발생했다. 로컬 스펙 `base:5.2.26.2.4`, Figure 484의 HMB Attributes는 bytes 0~4095 구조(0~15 필드, 16~4095 reserved)다. 현재 Get Log Page/Identify/NVM 길이 검증으로는 Get Features의 FID별 크기를 보호하지 못한다. 제어기는 HMB가 **활성화**됐다고도 보고했으므로, 비활성화를 무작정 실행하면 Linux 드라이버가 관리하는 HMB를 건드릴 위험도 있다. 실제 overwrite 경로의 세부 원인은 도구/커널 추가 분석 대상이나, 4B 요청이 사양 구조와 맞지 않고 호스트 프로세스가 죽은 사실은 확정이다.

개선: FID/SEL/EXHID별 최소·정확 버퍼/방향 테이블, 호스트 소유 기능의 운영 backend 구분, 전송 전 검사. 단순 `direction` 비트나 NUMD 계산 추가로 해결되지 않는다.

**F09 — OS가 관리하는 큐의 positive 테스트를 passthru만으로 구성 (P1).**

`tc-71051853d9`(Delete CQ)와 `tc-7db5dade5a`(Interrupt Vector Configuration)는 setup Create CQ(QID 2/1)에서 QID_INVALID로 끝났고 action은 한 번도 실행되지 않았다. Linux가 이미 사용하는 QID일 가능성이 있으며, 큐용 DMA 메모리/PRP/할당·해제 및 드라이버 상태 동기화도 관리하지 않는다. 정확한 QID 거부 원인은 기록만으로 확정하지 않는다. 다만 이 setup 실패를 Delete CQ/FID09의 결함으로 집계하는 것은 잘못이다.

개선: 전용 QEMU/SPDK/테스트 드라이버 등으로 큐 생명주기를 소유하거나, 해당 backend가 없으면 positive queue 테스트를 명시적으로 비실행 처리. 임의의 빈 QID를 추측하여 재시도하지 말 것.

**F10 — 실패 시 cleanup이 실행되지 않고 설정이 남음 (P1).**

`tc-72e4c056d0`의 Write Uncorrectable은 LBA `0x1000..0x1007`에 성공했다. 정상 READ_ERROR를 잘못 매칭해 뒤의 복구 Write/Read가 차단됐다. 이후 `tc-65c641579d`가 LBA 0x1000 하나에 성공한 Write를 보냈지만, **0x1001..0x1007은 제공된 기록에서 복구 Write가 없다.** 이는 현재 실장비 상태를 확인한 결론은 아니다.

온도 threshold=300K(`tc-249e4a0c7a`), Timestamp 약 17분 값(`tc-ff1a706bb9`), AEC/Interrupt Coalescing/Write Atomicity/Arbitration 설정도 원래 값으로 복구하는 단계가 없다. 다음 TC가 이전 TC의 상태에 의존하게 된다. 예를 들어 Timestamp 초기 조회는 실제 시각과 유사한 큰 값인데 Set 이후 작은 값으로 바뀌었다.

개선: setup/action/verify와 독립된 `finally/cleanup`, 원상태 snapshot/restore, cleanup 실패를 별도 결과로 보존, TC별 독립 LBA/패턴 사용. 기본 id-ctrl health check는 설정/미디어 복구를 증명하지 않는다.

**F11 — I/O device 경로와 NSID 모순 (P1).**

`tc-a4d578c08b`, `tc-24ca0373ae`, `tc-1afe54d404`에서 `/dev/nvme0n1`에 NSID=0을 사용해 커널이 `nsid (0) in cmd does not match nsid (1) of namespace`를 기록했다. 이 명령들은 해당 컨트롤러 동작의 증거가 아니다. opcode/명령 스코프에 맞는 controller/namespace 노드 선택과 NSID 검사를 전송 전에 수행해야 한다.

### 2. FAIL 오판정과 잘못된 전제 — F01/F03/F04/F05/F06

**F01 — Self-test의 완료 상태를 고장으로 해석 (P1).**

`tc-3af95784f5`: setup 로그 처음 8바이트 `00 00 00 00 27 07 03 00`, verify `00 00 00 00 10 00 00 00`. 스펙 Figure 215에서 byte0=0은 현재 자가진단이 진행 중이지 않음이다. Figure 216에 따라 새 RDS1 byte4=`0x10`은 **Short self-test / completed without error**다. 약 0.86초 뒤 읽은 로그에서 이미 완료됐을 수 있는데, 생성된 체크는 byte0 !=0을 강제하고 최신 결과를 무시했다. LLM은 이를 firmware_defect 0.75로 잘못 확정했다. 진행 중과 정상 완료를 모두 인정하고, 이전/이후 결과 및 poll 시점을 함께 검사해야 한다.

**F03 — 정상 음성 응답 4개 TC를 이름 불일치로 FAIL (P1).**

- COMPARE_FAILURE ↔ COMPARE_FAILED (`tc-8c504b8303`, 0x2285)
- INVALID_QUEUE_IDENTIFIER ↔ QID_INVALID (`tc-d7ddb15e56`, `tc-4a9f0c0cd9`, 0x101)
- UNRECOVERED_READ_ERROR ↔ READ_ERROR (`tc-72e4c056d0`, 0x6281)

특히 judge는 0x6281의 상위 플래그를 vendor-specific 가능성으로 해석했다. nvme-cli의 상태 표현에서 SC/SCT와 MORE/DNR 등의 플래그를 분리해야 한다. 단순 이름 alias 추가에 더해 숫자 상태·플래그를 저장하고, 규격상 허용되는 상태 집합으로 비교해야 한다. 매핑을 고쳐도 별도 미측정 사전조건이 있는 TC를 자동 PASS로 올리면 안 된다.

**F04 — 검증식과 전송 내용의 정적 모순 (P1).**

12개 TC에 15개의 `data_length` 불일치가 있다. 예: 68B 요청/64B 기대, 4100B 요청/4096B 기대, 260B 요청/256B 기대. NUMD는 0-based다. 버퍼 길이가 와이어 NUMD와 같도록 맞추는 것만으로는 충분하지 않으며, 스펙 인용·시나리오·검증식의 크기까지 일치해야 한다.

별도 확정 사례:

- Timestamp에 `00 00 10 00 00 00`(little endian 1,048,576ms)을 쓰고 4,194,304ms 이상을 기대. 실제 1,049,486ms는 약 910ms 경과를 더한 정상 값.
- CNS07/NSID=1 목록이 비어 있으면 실패하도록 했지만 활성 NSID는 1 하나뿐이다. `>1` 목록은 비는 것이 정상.
- Cancel TC는 Identify 4096B 응답에 대해 data_length=256 조건을 달아 action 전에 중단.

검증식 생성도 코드와 독립된 제3의 진실로 두지 말고, 길이/주소/배열 경계/정수 상수/페이로드의 정적 일관성을 검사해야 한다.

**F05 — “지원 불명/선택사항”을 “미지원”으로 바꾸는 오류 (P1).**

`tc-cc6cb9f6b0`은 LID09 지원 여부를 모르는데 INVALID_LOG_PAGE를 기대했고, 실제 성공을 실패로 기록했다. `tc-63fd69acd4`는 NMS 미지원이면 CNS10도 반드시 미지원이라고 단정했지만 실제 활성 NSID 목록이 정상 반환됐다. 선택 기능을 구현할 의무가 없다는 사실은 구현하지 않았다는 사실과 다르다.

음성 테스트에서도 FID 자체가 미지원이어서 나온 INVALID_FIELD와 잘못된 ENDGID/CDQID/NSID 때문에 나온 INVALID_FIELD를 구분하지 않는다. `tc-f41a83f6af`를 firmware_defect로 분류한 것은 이 구분을 하지 않은 결과다. 지원 여부는 지원/미지원/불명의 세 상태로 유지하고, 특정 인자의 음성 테스트는 그 외 조건과 기능 지원을 독립 확인해야 한다.

**F06 — 잘못된 오프셋·마스크·선택자로 사전조건이 거짓 통과/중단 (P1).**

실패한 사전조건에서만 명백하게 word 시작을 잘못 잡은 체크가 **19개/17 TC**다. 이것은 전체 오류의 하한이며 bit 위치·반대 operator 오류는 별도다.

| 필드/기능 | 실제 위치 | 실행에서 나타난 잘못된 검사 |
|---|---|---|
| OACS | bytes256~257, little endian | offset257을 word 시작처럼 사용 |
| ONCS | bytes520~521 | offset521에서 하위 비트 마스크 검사 |
| CTRATT | bytes96~99 | offset99에서 4바이트 검사 |
| SANICAP | bytes328~331 | offset331에서 4바이트 검사 |
| NMS | OACS bit3 | bit4(Self-test), bit15, 상위 바이트 bit3 |
| Directives | OACS bit5 | bit4(Self-test) |
| HMLMS | OACS bit11 | bit14/15, 관계없는 상위 바이트 전체 비교 |
| Format NVM | OACS bit1 | ONCS bit1 |
| NPSS | byte263 | byte254 |
| HCTMA | bytes322~323 | byte255 |
| DPS | Identify Namespace byte29 | byte26(FLBAS), byte462 |
| VWC | byte525 | byte527 |
| Supported Logs LID16 | 4B entry 시작 offset88 | offset5 mask0C |
| PLM Config FID13h | CDW10 low8=13h | **CDW10=20Dh → HMB FID0Dh, SEL2** |

또한 `tc-20f142d32b`는 “Save/Select 지원 bit4=1”이라고 적고 `(value & 0x10) != 0x10`으로 반대 조건을 만들었다. `tc-5bc0d67e1d`는 NMS를 Self-test bit4로 확인해 실제 NMS가 없는 장치에서도 전제가 통과했다.

원시 Identify의 실제 초기값은 OACS=0x0017, ONCS=0x00DF, SANICAP=0x60000002, NN=1, NPSS=4, CNTRLTYPE=1이다. 이 프로파일에는 Format/Firmware/Self-test/Compare/Verify 등이 지원되어 있다. 모델의 잘못된 비트 읽기 때문에 일부 지원 명령도 실행되지 못했다. typed field registry/decoder를 만들고 LLM에는 필드 이름/값만 선택하게 해야 한다.

### 3. PASS 의미와 검증 강도 — F07/F08

**F07 — 실행 가능한 체크가 있어도 요구사항 전체를 증명하지 못함 (P1).**

전체 계약에서 `(x & mask) <= mask` 또는 `unsigned >=0` 등 항상 참인 체크 **20개**를 발견했다. 이 개수에는 요구사항과 사전조건의 중복된 체크도 포함된다. Firmware Slot의 `(AFI & 0x70) <= 0x70`이 대표적이다.

Write Zeroes는 512B 중 offset0/248/504에서 각8B, 총24B만 읽고 “모든 바이트가 zero”를 PASS했다. 실제 원시 응답 512B는 전부 zero여서 이 장비 관측 자체는 정상이다. 다만 메모리 안에서 byte100 하나를 FF로 바꾼 반례도 기존 검증기는 여전히 PASS했다([counterexamples.json](counterexamples.json)). 이 반례는 실제 장비가 FF를 반환했다는 뜻이 아니다. Interrupt Coalescing은 TIME/THR 저장/조회를 했을 뿐 실제 interrupt 시간/개수를 측정하지 않았다. AEC는 설정값을 확인했을 뿐 이벤트 주입/수신을 하지 않았다. DN=1 설정의 왕복은 atomic write/power-fail 보장을 시험한 것이 아니다.

개선: 항상 참인 체크 거부, 완전한 배열·버퍼 비교 지원, 샘플링 시 주장도 샘플 범위로 축소, configuration roundtrip/behavioral test 구분.

**F08 — 인용문이 존재하는 것과 논리적으로 요구사항을 뒷받침하는 것은 다름 (P1).**

- Namespace Management 미지원 응답을 Namespace Attachment도 지원해야 한다는 조건부 문장으로 정당화.
- Migration Receive는 단순 목록 조각 `the Migration Receive command (refer to section 5.2.16);`로 요구사항 PASS.
- “Exported NVM Subsystem에서 지원하면 안 됨”을 “일반 PCIe I/O 컨트롤러에서 지원하면 안 됨”으로 대상 주체를 변경.
- 미지원 Manage Exported NVM Subsystem의 INVALID_OPCODE만 확인하고 관리 동작/데이터 포인터 구조까지 PASS.
- FDP Placement Handle/Reclaim Group 선택은 일반 Write/Read 성공만으로 확인할 수 없음.
- SHOULD 권고(Number of Queues)를 SHALL과 같은 강제 합격/불합격 규칙으로 설명.

개선: `actor / applicability / condition / action / expected observable / normative strength`를 구조화하고, 특정 타겟 인용과 실제 테스트의 논리적 연결을 검사해야 한다. 현재 추가 중인 target requirement/variant 바인딩은 인용 범위 변경을 막는 데 도움이 되지만, 바이트·관측 의미까지 보장하지는 않는다.

### 4. LLM 판정의 근거·효율 — F12/F13/F14/F15/F16

**F12 — 중요한 응답이 잘리고 잘못된 디코딩을 높은 확신으로 설명 (P1).**

이번 judge 호출23건 중 **12건은 프롬프트의 raw excerpt에 action 응답 블록이 없다.** 실패 요약/검증 결과는 일부 전달되므로 모든 증거가 사라진 것은 아니지만, 앞선 Identify 4096B dump가 8,000자 예산을 독점해 뒤의 근거 bytes가 빠졌다. Self-test는 setup Identify만 raw로 전달되고 최신 RDS1은 없었다. judge가 잘못된 검증식의 observed=0만 재해석한 배경이다.

`tc-7db5dade5a`의 judge는 Identify의 bytes196~197를 큐 개수로 해석했다. 해당 위치는 그런 필드가 아니며 Number of Queues는 Get Features FID07 결과다. 실제 다른 TC의 FID07 DW0=0x001f001f는 32/32 큐를 보고한다. ONCS 값도 잘못 디코딩했다. “0x6281 상위 비트가 vendor-specific” 등도 근거 없는 설명이다. 원문 인용을 늘리는 것보다 관심 필드와 해당 bytes/decoder 결과를 명시적으로 제공하고 미측정 필수 전제에 대한 verdict gate를 두어야 한다.

**F13 — payload 비교 결과가 중복되어 프롬프트 비대화 (P2).**

CNS07 판정 프롬프트는 **95,847자**다. `data_equal`의 observed/expected/detail 전체 hex가 verification과 criteria_results 등에 중복된다. 프롬프트 예산 테스트가 synthetic 짧은 응답만 다루면 실제 이 문제를 놓친다. 비교 결과는 길이/hash/최초 불일치/관심 slice로 제한하고 실제 로그 fixture로 예산을 검사해야 한다.

**F14 — 34개 실행 후 재시도의 최종 PASS=0 (P2).**

최종 ERROR31, UNSUPPORTED2, UNVERIFIED1. 선택자를 유지해야 하는 상황에서 NSID0↔1만 바꾸거나 미지원 FID에 같은 요청을 재전송하는 경우가 반복된다. 이것은 “재시도 코드를 없애라”는 결론이 아니라, 고칠 수 있는 전송 오류와 기능 미지원/필수 전제 불충족을 구분해야 한다는 근거다.

**F15 — 41개 skip의 세부 원인 (P2).**

8개 payload, 7개 인용, 6개 NUMD/길이, 5개 NSID, 5개 검증식 필드 누락, 4개 selector/고정 필드, 2개 JSON, 2개 action 누락, 1개 비교 LBA, 1개 mask/value. 잘못된 정의를 장비로 보내지 않은 동작 자체는 맞다. 다만 형식/산술은 모델 재호출보다 schema/코드 builder로 처리하고, payload는 반복 패턴과 실제 구조체를 구분해야 한다. 구조체의 reserved 영역은 zero-padding할 수 있으나 임의 반복으로 채우면 안 된다.

NSID0/active/FFFFFFFF만 허용하는 규칙은 실제 잘못된 네임스페이스를 막는 데 유효하지만 invalid-NSID 음성 테스트까지 무조건 막는다. 추가로 로컬 추출 스펙에 FFFFFh/FFFFFFh 같은 가변 폭 표기가 있으므로 원문과 비트 폭을 확인해야 한다. 검증기를 단순 완화해서 통과시키면 안 된다.

**F16 — 미측정 gate는 유지하고 전제 정의를 고칠 것 (P2).**

61개 UNVERIFIED 중52개는 본동작 미실행,9개는 명령 완료 후 미측정 전제 때문에 보류됐다. 70개 TC에 적어도 하나의 violated precondition이 있다(ERROR 등에 포함). 예전 미측정 전제를 삭제하던 문제는 이미 ae3306f 계열 코드에서 고쳐졌고 이 실행에도 게이트가 작동했다. “장비가 요청에 정상 응답함”, “probe에서 이미 알려진 사실” 같은 과도/중복 전제를 분리하되, 의미상 필수 조건을 PASS를 얻기 위해 버리는 방식으로 해결하면 안 된다.

### 5. 진행률·이력·재현성 — F17/F18/F19/F20

**F17 — 시도 진행률과 유효 검증 진행률을 함께 보여야 함 (P2).**

현재 HTML의 232/232는 정확히 “시도”라고 표기하므로 숫자 자체가 거짓은 아니다. 다만 41개 skip·76개 setup 중단·115개 action 전송을 함께 보지 않으면 완료처럼 보인다. 78/337도 생성된 인용 항목의 평가 비율이며 전체 스펙 준수율이 아니다. 중복 인용/부모·자식 조항의 같은 테스트 및 위의 잘못된 PASS/FAIL 때문에 현재66/12를 최종 준수/위반으로 사용할 수 없다.

**F18 — 현재 실행과 과거 판정이 혼재 (P2).**

reset-coverage는 TC/skip을 백업하고 비웠지만 verdict/FailureContext는 보존했다. 이번 판정23건과 이전5건이 함께 리포트에28건으로 나온다. 보존은 맞는 동작이며 삭제하면 안 된다. 대신 run/device/기간 필터와 “현재 TC에 연결되지 않은 역사 판정” 표시가 필요하다.

또한 기계 상태가 FAIL인데 judge는 test_env_issue로 설명하는 사례에서도 일반 결과 문구는 여전히 “장비 결함 후보”다. 기계 상태·요구사항 상태·원인 분류를 보존하면서, 최종 안내는 “테스트 정의 수정 후 재평가”처럼 두 근거를 함께 반영해야 한다. LLM 답으로 원본을 자동 덮어쓰라는 뜻은 아니다. CSV에는 현재 TC별 판정 연결을 분리했다.

**F19 — 실행 manifest와 applicability/version 정보 (P2).**

Git SHA/dirty 상태, spec 버전/hash, 모델·reasoning/schema/prompt 버전, nvme-cli/kernel/firmware/namespace format을 명시적으로 저장하지 않아 “이 변경 직전”을 코드와 정확히 연결하기 어렵다. 원시 Identify 덤프에서 일부를 복구할 수 있지만, NVMe 최신 스펙의 선택적 기능을 이전 버전 장치의 필수 요구처럼 시험하지 않도록 device applicability가 필요하다. 문서 내 참조 조항·스캔/추출 오류·숫자 폭도 검증 대상이다.

**F20 — 실제 실패의 작은 fixture로 회귀 검증 (P2).**

권장 고정 fixture: Self-test `byte0=0,RDS1=0x10`; COMPARE_FAILED/READ_ERROR/QID_INVALID; HMB4B 사전 차단; NSID 끝에서 빈 목록; 68/64,4100/4096,260/256; Timestamp little endian; PLM FID13h 대 HMB0Dh; OACS/ONCS 각 word 시작; missing action raw prompt; cleanup이 verify 실패 후에도 실행되는 경우. 장비/LLM을 호출할 필요가 없다.

### 6. 데이터 관계 추상화 — F21

**F21 — 잘못된 readback 방지용 주소 검사가 정상 Copy 검증까지 거부 (P2).**

`nvm:3.3.2` Copy 타겟은 소스 LBA100~107을 목적지500~507로 복사하고 양쪽 Read 데이터를 비교하려 했다. 첫 시나리오(LLM JSONL383행)는 `data_matches_write`, 재생성(384행)은 소스 Read(step3)와 목적지 Read(step4)의 `data_equal`을 제안했다. 둘 다 “범위가 같은 소스 LBA 안에 있지 않음”으로 거부됐다. Copy는 원래 주소가 다른 곳으로 데이터를 전달하므로, 현재의 same-range 관계만으로는 정상 검증을 구성할 수 없다. 이 DUT는 ONCS.Copy=0이어서 실제 positive Copy는 별도 미지원 처리될 수 있지만, 그 사실과 검증 언어가 Copy를 표현하지 못한다는 문제는 구분해야 한다.

개선: 일반 Write→Read에는 같은 namespace/range 검사를 유지하고, Copy descriptor의 source/destination 매핑을 증명하는 별도 비교/provenance 관계를 추가한다. 단순히 주소 검사를 삭제하면 이전의 “다른 LBA인데 둘 다 zero라 PASS” 문제를 다시 만든다. 지원 불가 backend/검증식은 테스트 대상 분모에도 명시해야 한다.

## 성능

- 총 약4시간53분40초 중 LLM elapsed 합 **16,475.09초(4시간34분35초, 약93.5%)**.
- scenario_generator302회/9,415.2초, args_author674회/6,741.4초, judge23회/318.4초: 총999회.
- SSH605회, stage elapsed 합680.36초(약11분20초), timeout0.
- 남은 시간은 생성/저장/리포트/로컬 처리 및 합산의 경계 차이다. elapsed는 호출 단위 합이며 정확한 wall-time 프로파일러는 아니다.
- 가장 큰 개선 여지는 stage batching보다 잘못된 시나리오/인자 재생성 감소, typed decoder, 지원 프로파일 재사용, unsupported 계열의 반복 child 타겟 축소, 코드 계산이다. 동시 명령 실행은 상태 변경 TC 간 간섭 때문에 무작정 적용하면 안 된다.

## 현재 작업 코드와 구분

이번 입력은 실행 당시 결과다. 현재 작업 폴더에는 `derive_transfer`, variant/target requirement 바인딩, host action/reset/power 관련 **미커밋 변경**이 이미 있다. 이 감사는 이를 덮어쓰지 않았다.

- NUMD/Identify/NVM 길이·방향 계산 자동화는 일부 생성 실패를 줄일 수 있다.
- 그러나 잘못된 precondition offset/mask/FID, Get Features FID별 버퍼, 검증식 크기/상수, Self-test 완료 race, 상태 코드 alias, cleanup, judge의 필드 디코딩은 별도로 검증해야 한다.
- target requirement 바인딩은 명령 성공을 다른 조항의 근거로 바꾸는 문제를 줄이지만, 일반 readback으로 placement/IRQ/atomicity 동작까지 증명할 수 있게 만들지는 않는다.
- host action 지원은 이벤트가 필요한 시험 범위를 넓힐 수 있지만, 이 실행에서 그 기능은 사용되지 않았다. 추가된 코드의 존재를 장비 검증 완료로 취급하지 않았다.

## 권장 실행 순서

1. HMB 등 버퍼 보호, namespace routing, 큐 backend, cleanup을 먼저 수정·오프라인 검증.
2. 모든 Identity/로그 필드와 selector를 typed registry에 연결하고 전제 검사 자동화.
3. 상태/길이/상수/배열/항상 참인 체크를 정적으로 검증.
4. 지원 여부와 음성 응답의 인과관계, 인용→행위자→관측 연결 보강.
5. 판정 prompt를 raw full dump 대신 실제 필드/관심 bytes 중심으로 재작성.
6. 기존 기록을 **새 결과 필드/별도 리포트**로 오프라인 재평가. 원본 상태는 보존. 그 뒤 실제 재실행이 필요한 타겟만 선정.

원래 FAIL14건을 alias만 바꿔 모두 PASS로 전환하거나, PASS34건을 전부 무효로 지우는 것은 둘 다 적절하지 않다. 아래 개별 판정을 바탕으로 증거가 있는 좁은 범위를 유지하고 잘못된 주장과 전제만 분리해야 한다.

## FAIL 14건 전수 재분류

실패로 저장됐다는 사실은 유지한다. 아래는 **감사 해석**이며 원본 TC의 상태를 변경하지 않았다.

| TC / 조항 | 원인 | 감사 결론 | 원본 콘솔 행 |
|---|---|---|---:|
| `tc-8c504b8303` / nvm:3.3.1 | F03, F16 | 정상 Compare 불일치 응답 COMPARE_FAILED를 COMPARE_FAILURE와 다르게 취급. 사전조건 미측정은 별도로 보류해야 함. | 532 |
| `tc-3af95784f5` / base:5.2.5 | F01, F12 | 자가진단 완료 후 current operation=0은 정상. 새 RDS1=0x10(Short test, completed without error)을 무시한 false FAIL/firmware_defect. | 807 |
| `tc-d7ddb15e56` / base:5.3.1 | F03, F16 | QID_INVALID(0x101)는 기대 Invalid Queue Identifier와 같은 상태. 문자열 매핑 오류. | 879 |
| `tc-4a9f0c0cd9` / base:5.3.2 | F03, F07, F16 | QID_INVALID(0x101)는 기대 Invalid Queue Identifier와 같은 상태. 문자열 매핑 오류. | 904 |
| `tc-71051853d9` / base:5.3.3 | F09, F16 | Create CQ(QID=2) setup 거부로 Delete CQ action 미실행. Linux 큐 소유/PRP/사용 중 QID 문제 조사. 타겟 결함 증거 없음. | 939 |
| `tc-72e4c056d0` / nvm:3.3.7 | F03, F10 | READ_ERROR(0x6281)와 UNRECOVERED_READ_ERROR 표기 불일치로 정상 음성 응답을 FAIL. 이후 복구 Write가 미실행. | 1283 |
| `tc-cc6cb9f6b0` / base:5.2.12.1.10 | F05, F07, F12 | 지원 여부 불명 LID09를 미지원으로 단정. 정상 SUCCESS를 FAIL. LPA>=0 사전조건은 미지원을 입증하지 않음. | 2284 |
| `tc-aabba0b28e` / base:5.2.12.1.2 | F04, F07, F12 | NUMDL=16으로 68B를 요청하고 64B를 기대. LPVER=1은 정상. 길이 계약 모순. | 3703 |
| `tc-06f29a6cbd` / base:5.2.13.2.7 | F04, F12, F13 | 활성 NSID가 1 하나인데 NSID=1보다 큰 목록에 nonzero 첫 항목을 기대. 빈 목록은 정상. | 4003 |
| `tc-63fd69acd4` / base:5.2.13.2.9 | F05, F06, F12 | 선택 기능의 지원 의무 없음과 미지원을 혼동. CNS10이 실제 NSID1 목록을 성공 반환. NMS 비트 설명도 틀림. | 4231 |
| `tc-3753251032` / base:5.2.12.1.6 | F04, F12 | Commands Supported/Effects 로그를 4100B 요청하고 4096B로 검사. 요청/검증식 불일치. | 5278 |
| `tc-ff1a706bb9` / base:5.2.26.1.7 | F04, F10 | 설정 payload=1048576ms인데 4194304ms 이상을 요구. 관측1049486ms는 설정값+약910ms로 정상. | 5472 |
| `tc-7db5dade5a` / base:5.2.26.2.3 | F09, F12, F16 | Create CQ(QID=1) setup 거부로 FID09 action 미실행. judge가 Identify reserved bytes를 큐 개수로 오해. | 5809 |
| `tc-dde1721c6e` / nvm:4.1.4.1 | F04, F07, F12 | Error Information 260B 요청/256B 기대. NUMDL=64는 65 DWORD=260B. judge의 256B 산식도 틀림. | 6065 |

## PASS 34건 전수 범위 검토

“좁은 범위 유효”도 조항 전체 준수 완료를 의미하지 않는다. 잘못된 전제 검사가 있는 경우 실제 raw 값을 올바른 decoder로 재해석해 일부 관측을 살릴 수 있지만, 원본 checker의 정확성과는 별개다.

| TC / 조항 | 감사 분류 | 확인·보완할 내용 | 원본 콘솔 행 |
|---|---|---|---:|
| `tc-4824f61bb9` / base:5.2.11 | 정의 일부 수정 | CHANG=1 및 reserved bits=0 관측은 유효. capabilities !=7만으로 역량 비트의 의미/타당성을 검증하지 못함. 개별 비트 규정으로 검사해야 함. | 4 |
| `tc-a9a7159b7c` / nvm:3.3.4 | 좁은 범위 유효 | 동일 NSID/SLBA에 대한 비영 패턴 Write→Read 일치 및 NSZE 사전확인. 이 한 범위의 I/O 검증. | 573 |
| `tc-1a6c33a855` / base:5.2.21 | 전제·근거 수정 | NMS를 OACS 상위 바이트 bit3에서 검사(실제 전체 word bit3). 인용은 Namespace Attachment 지원의 조건부 규정이며 실제 검증과 다름. | 1111 |
| `tc-0c6b790bdd` / nvm:3.3.6 | 좁은 범위 유효 | 단일 LBA 비영 패턴 Write→Read 일치. 복구/원상태 보존은 별도. | 1251 |
| `tc-de15664d98` / nvm:3.3.8 | 샘플 검증으로 축소 | 512B 중 24B만 zero 검사. PI 비활성 사전조건 offset462는 DPS29가 아님. 원시 512B 전체 zero는 오프라인 재검사 가능. | 1333 |
| `tc-4830baf8c2` / base:5.4.2 | 근거 수정 | Exported NVM Subsystem에서 미지원이라는 규정을 일반 PCIe I/O 컨트롤러에 적용. CNTRLTYPE=1만으로 Exported 역할을 증명 못함. | 1528 |
| `tc-a265ef2c68` / base:5.2.13.1 | 좁은 범위 유효 | CNS21 거부 및 CNS01 4096B 성공 경로. 현재 관측 범위의 규칙만 인정. | 1710 |
| `tc-c2f99b95d0` / base:5.2.16.1 | 근거·역할 수정 | 인용이 명령 이름 목록 조각뿐. HMLMS=0만으로 Migratable Controller 역할을 단정. | 1744 |
| `tc-7d17668322` / base:8.1.11.3 | 일반 I/O로 축소 | Write/Read 성공은 FDP Placement Handle/Reclaim Group 선택을 관측하지 않음. FDP 활성 조건 미확인. | 2128 |
| `tc-514bf16fe1` / nvm:5.3.2.1 | 전제 수정 | DPS를 offset26에서 확인(실제29;26은 FLBAS). NSZE 확인도 완료 상태뿐. PI 처리를 수행하지 않았다는 내부 동작까지 증명 못함. | 2629 |
| `tc-546c3abd91` / base:5.2.17.1.2 | 전제·역할 수정 | HMLMS bit11 대신 mask0x4000(bit14). Migratable/MMC 역할도 미확인. | 2791 |
| `tc-5bc0d67e1d` / base:5.2.13.2.12 | 전제 수정 | NMS를 OACS bit4(Self-test)로 오인. 실제 NMS=0. Controller List 성공 관측은 별도로 유효. | 3169 |
| `tc-3574f2e15f` / base:5.2.26.1.13 | PASS 보류 필요 | PLM Config FID13h를 조회한다고 했으나 실제 setup CDW10=0x20D(FID0D HMB, SEL2). unrelated INVALID_FIELD가 전제 통과. | 3201 |
| `tc-5a470edacc` / base:5.4.9.1.4 | 미지원 관측으로 축소 | INVALID_OPCODE만으로 SEL04 기능, Subsystem Management payload 구조까지 세 요구사항 PASS 처리. | 3235 |
| `tc-9cc5084d94` / base:5.2.26.1.16 | 전제 보강 | FID18 지원과 ENDGID 부재를 독립 확인하지 않아 일반 INVALID_FIELD와 특정 ENDGID 거부를 구분 못함. | 3486 |
| `tc-fd2c56f6a8` / base:5.2.26.1.2 | 전제 수정 | NPSS263 대신254 검사. 별도 원시 Identify의 실제 NPSS4와 PS6 거부는 정상 재해석 가능. | 3770 |
| `tc-f879ba29e0` / base:5.2.26.1.21 | 지원 여부 보강 | FID1E 미지원과 NSID FFFFFFFF 거부 원인 구분 미흡. 잘못된 NSID 거부만으로 기능별 규정 입증 부족. | 3811 |
| `tc-bcb316ee06` / base:5.2.12.1.22 | PASS 보류 필요 | LID16 지원 비트 대신 Supported Logs offset5 mask0C 검사. LID16의 4B entry 시작은88. reserved bits=0으로 전제 통과. | 3889 |
| `tc-8d316c6938` / base:5.2.13.3.2 | 전제 수정 | Virtualization 지원 bit7 대신bit15 검사. 선택 사항이라는 사실을 미지원으로 단정. | 4404 |
| `tc-249e4a0c7a` / base:5.2.26.1.3 | 설정 왕복 유효 | 온도 threshold300K 저장/조회는 관측. 원래 threshold 원복이 없음. | 4467 |
| `tc-c0676ca7ea` / base:5.2.13.4.2 | 거부 관측으로 축소 | CNS1E의 INVALID_FIELD 관측은 유효. optional 규정 자체를 입증한 것으로 확대하지 말 것. | 4506 |
| `tc-d2a4fc92d8` / base:5.2.12.1.4 | 정의 일부 수정 | Firmware Slot 길이/CAFS 확인은 유효. (value&0x70)<=0x70은 항상 참. | 5131 |
| `tc-cfb622ca1c` / nvm:4.1.5.9 | 전제 수정 | NMS를 offset257 bit3로 오인. CNS1B 미지원 전제가 잘못된 필드를 사용. | 5161 |
| `tc-a2c38cd3a3` / base:5.2.26.1.36 | 좁은 범위 유효 | FID85의 reserved state 거부와 읽기값0x12 유지 관측. full field 마스크로 초기상태 확인 보강 권장. | 5194 |
| `tc-cba9433d26` / base:5.2.26.1.5 | 설정 왕복으로 축소 | AEC bit 저장/조회만 관측. 실제 비동기 이벤트 발생/전달은 미검증; 원복 없음. | 5316 |
| `tc-26dbd7cdbd` / base:5.2.26.1.9 | 전제·불변성 보강 | HCTMA322 대신255 검사. 잘못된 설정 미반영을 before/after 동일성 대신 일부 비트!=300으로 검사. | 5624 |
| `tc-a170569303` / base:5.2.26.2.1 | 권고 규정으로 표시 | 인용은 should abort. 응답은 정상이나 MUST 준수율로 취급하면 안 됨. | 5689 |
| `tc-338e53ed93` / base:5.2.12.3.3 | 좁은 범위 유효 | I/O 컨트롤러에서 Discovery LID70의 정상 거부를 관측. | 5708 |
| `tc-a3b1b3fb31` / base:5.2.26.2.2 | 설정 왕복으로 축소 | TIME/THR 저장/조회는 관측. 실제 IRQ 지연/aggregation count를 측정하지 않음; 원복 없음. | 5736 |
| `tc-b6be524147` / base:5.2.12.3.4 | 좁은 범위 유효 | CNTRLTYPE와 NN 확인 후 Host Discovery LID71 거부 관측. | 5778 |
| `tc-086f58c9f7` / base:5.2.12.3.6 | 미지원 관측으로 축소 | LID73 INVALID_LOG_PAGE로 ORI 형식까지 PASS 처리. 실제 반환 구조를 읽지 않음. | 5934 |
| `tc-ff9873791e` / base:5.2.26.3.1 | 설정 왕복으로 축소 | AEC 설정값 조회만 관측. Fabrics-independent 범위와 이벤트 기능 전체를 입증하지 않음. | 5963 |
| `tc-0b51141ff7` / nvm:4.1.3 | 설정 왕복으로 축소 | DN=1 저장/조회는 관측. AWUN/AWUPF 실제 atomic write 보장은 미시험. | 6030 |
| `tc-311a1e650d` / nvm:4.1.3.3 | 설정 왕복으로 축소 | 같은 DN=1 왕복을 별도 조항으로 반복. 원자성 동작 전체 및 상태 원복은 미검증. | 6182 |

## Skip 41건 분류

건너뛰기는 잘못된 명령이 장비에 전달되는 것을 막은 정상 보호 동작이다. 원인은 [skips.csv](skips.csv)에 전부 보존했다.

| 원인 | 개수 |
|---|---:|
| 페이로드 길이/형식 | 8 |
| 인용 불일치 | 7 |
| 전송 길이/NUMD | 6 |
| NSID 정책/값 | 5 |
| 검증식 필드 누락 | 5 |
| 선택자/고정 필드 | 4 |
| JSON 형식 | 2 |
| action 누락 | 2 |
| 비교 주소 관계 | 1 |
| 마스크/값 | 1 |

## 문제군 색인과 현재 수정 상태

현재 수정 상태는 감사 시점 작업 트리의 **정적 확인**이며 실제 장비 검증 완료 표시가 아니다.

| ID | 우선순위 | 문제군 | 현재 코드 확인 |
|---|---|---|---|
| F01 | P1 | Self-test 정상 완료를 펌웨어 결함으로 분류 | 미해결 |
| F02 | P1 | Get Features의 FID별 버퍼 검증 부재와 HMB 호스트 크래시 | 일반 NUMD 계산 추가됨; FID별 보호는 미해결 |
| F03 | P1 | 정상 음성 상태의 이름 불일치와 상위 상태 비트 오해 | 미해결 |
| F04 | P1 | 요청값·버퍼·검증식의 내부 모순 | 전송 산술 derive 추가됨; 검증식까지의 일관성은 미해결 |
| F05 | P1 | 미확인 지원 여부를 미지원으로 단정 / 일반 거부 원인을 오인 | 미해결 |
| F06 | P1 | 지원 비트·오프셋·FID 선택자 오류로 전제 거짓 통과/중단 | 미해결 |
| F07 | P1 | 항상 참인 비교, 일부 바이트/설정값으로 전체 동작을 PASS | 요구사항 바인딩 추가 작업 중; 검증식 의미 보장은 별도 |
| F08 | P1 | 인용의 존재와 요구사항 의미를 혼동 | variant/target requirement 바인딩 추가 작업 중; 의미 검증 미완 |
| F09 | P1 | Linux 드라이버가 관리하는 I/O 큐를 일반 passthru로 생성 | 미해결 |
| F10 | P1 | 체인 중단 시 복구 미실행과 전역 설정 잔류 | host action 지원 추가 작업 중; cleanup 보장은 별도 |
| F11 | P1 | namespace 노드와 NSID 불일치로 컨트롤러 도달 전 거부 | 미해결 |
| F12 | P1 | judge에 필요한 실제 응답 누락 및 근거 없는 디코딩/확신 | 미해결 |
| F13 | P2 | 큰 data_equal 비교 결과가 judge 프롬프트를 비대화 | 미해결 |
| F14 | P2 | 반복 재시도의 낮은 효율과 LLM 산술 의존 | derive_transfer 일부 해결; 재시도 정책은 별도 |
| F15 | P2 | 41개 생성/인자 실패의 유형별 복구 경로 부족 | 길이·방향 계산은 일부 해결; 나머지는 재검증 필요 |
| F16 | P2 | 잘못되거나 과도한 사전조건으로 실질 테스트 정체 | 미측정 게이트 복원은 이미 ae3306f에 반영/실행 기록에서도 동작 |
| F17 | P2 | 232/232 시도와 실제 본동작·요구사항 검증 사이의 간극 | 리포트가 시도로 표기하는 점은 맞음; 추가 분해 필요 |
| F18 | P2 | 현재 실행과 이전 실행의 판정 혼재 | 미해결 |
| F19 | P2 | 스펙·도구·코드·장치 버전 추적 미흡 | 일부 기초 정보는 raw Identify로 복구 가능; 명시적 manifest 부재 |
| F20 | P2 | 새 인자/검증기에 대한 실제 로그 회귀 테스트 필요 | 이전 단위테스트 통과는 본 실행 의미 정확도 보장이 아님 |

| F21 | P2 | 같은 LBA만 허용하는 데이터 비교가 Copy 검증까지 금지 | Copy source/destination을 증명하는 관계가 필요; 미해결 |

## 근거 파일 찾는 법

- 콘솔 행: `TC_Gen_Decisioner-main/logs/tc_pipeline_20261105_010553.log`의 해당 줄부터 TC 블록 전체.
- TC JSON 행: `TC_Gen_Decisioner-main/data/tc_store.json`의 `cases.csv.tc_store_line`.
- 시나리오/판정 LLM 행: `TC_Gen_Decisioner-main/logs/llm_calls.jsonl`의 `scenario_llm_line`/`judge_llm_line`.
- 이전 실행을 포함한 전체 원본 파일은 그대로이며, 분석 CSV/JSON은 입력 해시를 남겨 대조 가능하다.
- source 행 번호는 제공된 파일에 대한 번호다. 원본을 다시 pretty-print하거나 JSONL 줄을 지우면 달라진다.


## 11월 4일 보조 로그와 현재 실행 구분

이전 콘솔 로그9개도 종료 요약·중단·호출 이력의 맥락을 확인했다. 이들은 11월5일232개 실행의 집계에 더하지 않았다.

| 파일 시각(UTC) | 종료 요약(생성/실행/FAIL/우리쪽/미지원/skip) | 비고 |
|---|---|---|
| 053107 | 2/2/0/1/0/1 | 이전 인자 오류 및 skip |
| 055454 | 5/5/0/1/4/0 | 미지원 명령 비중 높음 |
| 060014 | 4/4/0/0/4/1 | 미지원 반복 |
| 060920 | 6/6/1/0/3/4 | 일부 오류가 현재 보존 verdict에 남음 |
| 063232 | 종료 요약 없음 | 마지막은 `blocked step Write`; 수동 중단/예외 원인을 이 파일만으로 단정하지 않음 |
| 064214 | 종료 요약 없음 | 마지막은 `blocked step Write` |
| 064345 | 종료 요약 없음 | 마지막은 placeholder 인자 skip |
| 064957 | 2/2/1/1/0/8 | 낮은 실제 실행률, 필드 생성 실패 |
| 075602 | 10/10/3/1/3/0 | 이전 판정5건 및 backup 데이터와 구분 필요 |

이전의 “보내지 않을 TC도 실행 중이라고 출력”, placeholder/파괴적 차단 사유 표시 등의 문제는 후속 코드에서 이미 바뀐 부분이 있다. 과거 로그의 문구를 현재 구현의 새 결함으로 중복 보고하지 않았다. 최신11월5일실행에는 종료 요약·리포트 생성이 정상적으로 기록되어 있다.
