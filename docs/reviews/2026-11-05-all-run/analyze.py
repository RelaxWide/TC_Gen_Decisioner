"""Read-only audit of the supplied 2026-11-05 --all run. Stdlib; no device/LLM.

Run from the project root:
  python3 docs/reviews/2026-11-05-all-run/analyze.py
Inputs are never rewritten. Outputs live beside this script.
"""
import argparse
import collections
import csv
import hashlib
import json
import re
from pathlib import Path

FAIL_REVIEW = {
 'tc-8c504b8303': ('F03', '정상 Compare 불일치 응답 COMPARE_FAILED를 COMPARE_FAILURE와 다르게 취급. 사전조건 미측정은 별도로 보류해야 함.'),
 'tc-3af95784f5': ('F01', '자가진단 완료 후 current operation=0은 정상. 새 RDS1=0x10(Short test, completed without error)을 무시한 false FAIL/firmware_defect.'),
 'tc-d7ddb15e56': ('F03', 'QID_INVALID(0x101)는 기대 Invalid Queue Identifier와 같은 상태. 문자열 매핑 오류.'),
 'tc-4a9f0c0cd9': ('F03', 'QID_INVALID(0x101)는 기대 Invalid Queue Identifier와 같은 상태. 문자열 매핑 오류.'),
 'tc-71051853d9': ('F09', 'Create CQ(QID=2) setup 거부로 Delete CQ action 미실행. Linux 큐 소유/PRP/사용 중 QID 문제 조사. 타겟 결함 증거 없음.'),
 'tc-72e4c056d0': ('F03,F10', 'READ_ERROR(0x6281)와 UNRECOVERED_READ_ERROR 표기 불일치로 정상 음성 응답을 FAIL. 이후 복구 Write가 미실행.'),
 'tc-cc6cb9f6b0': ('F05', '지원 여부 불명 LID09를 미지원으로 단정. 정상 SUCCESS를 FAIL. LPA>=0 사전조건은 미지원을 입증하지 않음.'),
 'tc-aabba0b28e': ('F04', 'NUMDL=16으로 68B를 요청하고 64B를 기대. LPVER=1은 정상. 길이 계약 모순.'),
 'tc-06f29a6cbd': ('F04', '활성 NSID가 1 하나인데 NSID=1보다 큰 목록에 nonzero 첫 항목을 기대. 빈 목록은 정상.'),
 'tc-63fd69acd4': ('F05,F06', '선택 기능의 지원 의무 없음과 미지원을 혼동. CNS10이 실제 NSID1 목록을 성공 반환. NMS 비트 설명도 틀림.'),
 'tc-3753251032': ('F04', 'Commands Supported/Effects 로그를 4100B 요청하고 4096B로 검사. 요청/검증식 불일치.'),
 'tc-ff1a706bb9': ('F04', '설정 payload=1048576ms인데 4194304ms 이상을 요구. 관측1049486ms는 설정값+약910ms로 정상.'),
 'tc-7db5dade5a': ('F09,F12', 'Create CQ(QID=1) setup 거부로 FID09 action 미실행. judge가 Identify reserved bytes를 큐 개수로 오해.'),
 'tc-dde1721c6e': ('F04', 'Error Information 260B 요청/256B 기대. NUMDL=64는 65 DWORD=260B. judge의 256B 산식도 틀림.'),
}
PASS_REVIEW = {
 'tc-4824f61bb9': ('정의 일부 수정', 'F07', 'CHANG=1 및 reserved bits=0 관측은 유효. capabilities !=7만으로 역량 비트의 의미/타당성을 검증하지 못함. 개별 비트 규정으로 검사해야 함.'),
 'tc-a9a7159b7c': ('좁은 범위 유효', '', '동일 NSID/SLBA에 대한 비영 패턴 Write→Read 일치 및 NSZE 사전확인. 이 한 범위의 I/O 검증.'),
 'tc-1a6c33a855': ('전제·근거 수정', 'F06,F08', 'NMS를 OACS 상위 바이트 bit3에서 검사(실제 전체 word bit3). 인용은 Namespace Attachment 지원의 조건부 규정이며 실제 검증과 다름.'),
 'tc-0c6b790bdd': ('좁은 범위 유효', 'F10', '단일 LBA 비영 패턴 Write→Read 일치. 복구/원상태 보존은 별도.'),
 'tc-de15664d98': ('샘플 검증으로 축소', 'F06,F07', '512B 중 24B만 zero 검사. PI 비활성 사전조건 offset462는 DPS29가 아님. 원시 512B 전체 zero는 오프라인 재검사 가능.'),
 'tc-4830baf8c2': ('근거 수정', 'F08', 'Exported NVM Subsystem에서 미지원이라는 규정을 일반 PCIe I/O 컨트롤러에 적용. CNTRLTYPE=1만으로 Exported 역할을 증명 못함.'),
 'tc-a265ef2c68': ('좁은 범위 유효', '', 'CNS21 거부 및 CNS01 4096B 성공 경로. 현재 관측 범위의 규칙만 인정.'),
 'tc-c2f99b95d0': ('근거·역할 수정', 'F08', '인용이 명령 이름 목록 조각뿐. HMLMS=0만으로 Migratable Controller 역할을 단정.'),
 'tc-7d17668322': ('일반 I/O로 축소', 'F08', 'Write/Read 성공은 FDP Placement Handle/Reclaim Group 선택을 관측하지 않음. FDP 활성 조건 미확인.'),
 'tc-514bf16fe1': ('전제 수정', 'F06,F08', 'DPS를 offset26에서 확인(실제29;26은 FLBAS). NSZE 확인도 완료 상태뿐. PI 처리를 수행하지 않았다는 내부 동작까지 증명 못함.'),
 'tc-546c3abd91': ('전제·역할 수정', 'F06,F08', 'HMLMS bit11 대신 mask0x4000(bit14). Migratable/MMC 역할도 미확인.'),
 'tc-5bc0d67e1d': ('전제 수정', 'F06', 'NMS를 OACS bit4(Self-test)로 오인. 실제 NMS=0. Controller List 성공 관측은 별도로 유효.'),
 'tc-3574f2e15f': ('PASS 보류 필요', 'F06,F08', 'PLM Config FID13h를 조회한다고 했으나 실제 setup CDW10=0x20D(FID0D HMB, SEL2). unrelated INVALID_FIELD가 전제 통과.'),
 'tc-5a470edacc': ('미지원 관측으로 축소', 'F08', 'INVALID_OPCODE만으로 SEL04 기능, Subsystem Management payload 구조까지 세 요구사항 PASS 처리.'),
 'tc-9cc5084d94': ('전제 보강', 'F05,F08', 'FID18 지원과 ENDGID 부재를 독립 확인하지 않아 일반 INVALID_FIELD와 특정 ENDGID 거부를 구분 못함.'),
 'tc-fd2c56f6a8': ('전제 수정', 'F06', 'NPSS263 대신254 검사. 별도 원시 Identify의 실제 NPSS4와 PS6 거부는 정상 재해석 가능.'),
 'tc-f879ba29e0': ('지원 여부 보강', 'F05', 'FID1E 미지원과 NSID FFFFFFFF 거부 원인 구분 미흡. 잘못된 NSID 거부만으로 기능별 규정 입증 부족.'),
 'tc-bcb316ee06': ('PASS 보류 필요', 'F06,F07', 'LID16 지원 비트 대신 Supported Logs offset5 mask0C 검사. LID16의 4B entry 시작은88. reserved bits=0으로 전제 통과.'),
 'tc-8d316c6938': ('전제 수정', 'F06,F05', 'Virtualization 지원 bit7 대신bit15 검사. 선택 사항이라는 사실을 미지원으로 단정.'),
 'tc-249e4a0c7a': ('설정 왕복 유효', 'F10', '온도 threshold300K 저장/조회는 관측. 원래 threshold 원복이 없음.'),
 'tc-c0676ca7ea': ('거부 관측으로 축소', 'F05', 'CNS1E의 INVALID_FIELD 관측은 유효. optional 규정 자체를 입증한 것으로 확대하지 말 것.'),
 'tc-d2a4fc92d8': ('정의 일부 수정', 'F07', 'Firmware Slot 길이/CAFS 확인은 유효. (value&0x70)<=0x70은 항상 참.'),
 'tc-cfb622ca1c': ('전제 수정', 'F06,F05', 'NMS를 offset257 bit3로 오인. CNS1B 미지원 전제가 잘못된 필드를 사용.'),
 'tc-a2c38cd3a3': ('좁은 범위 유효', '', 'FID85의 reserved state 거부와 읽기값0x12 유지 관측. full field 마스크로 초기상태 확인 보강 권장.'),
 'tc-cba9433d26': ('설정 왕복으로 축소', 'F07,F10', 'AEC bit 저장/조회만 관측. 실제 비동기 이벤트 발생/전달은 미검증; 원복 없음.'),
 'tc-26dbd7cdbd': ('전제·불변성 보강', 'F06,F07', 'HCTMA322 대신255 검사. 잘못된 설정 미반영을 before/after 동일성 대신 일부 비트!=300으로 검사.'),
 'tc-a170569303': ('권고 규정으로 표시', 'F08', '인용은 should abort. 응답은 정상이나 MUST 준수율로 취급하면 안 됨.'),
 'tc-338e53ed93': ('좁은 범위 유효', '', 'I/O 컨트롤러에서 Discovery LID70의 정상 거부를 관측.'),
 'tc-a3b1b3fb31': ('설정 왕복으로 축소', 'F07,F10', 'TIME/THR 저장/조회는 관측. 실제 IRQ 지연/aggregation count를 측정하지 않음; 원복 없음.'),
 'tc-b6be524147': ('좁은 범위 유효', '', 'CNTRLTYPE와 NN 확인 후 Host Discovery LID71 거부 관측.'),
 'tc-086f58c9f7': ('미지원 관측으로 축소', 'F05,F08', 'LID73 INVALID_LOG_PAGE로 ORI 형식까지 PASS 처리. 실제 반환 구조를 읽지 않음.'),
 'tc-ff9873791e': ('설정 왕복으로 축소', 'F07,F10', 'AEC 설정값 조회만 관측. Fabrics-independent 범위와 이벤트 기능 전체를 입증하지 않음.'),
 'tc-0b51141ff7': ('설정 왕복으로 축소', 'F07,F10', 'DN=1 저장/조회는 관측. AWUN/AWUPF 실제 atomic write 보장은 미시험.'),
 'tc-311a1e650d': ('설정 왕복으로 축소', 'F07,F10', '같은 DN=1 왕복을 별도 조항으로 반복. 원자성 동작 전체 및 상태 원복은 미검증.'),
}

ISSUES = [
 ('F01','P1','확정','Self-test 정상 완료를 펌웨어 결함으로 분류','tc-3af95784f5','실행 중 byte0만 요구하지 말고 진행/완료/중단 상태와 최신 RDS1을 함께 검증.','미해결'),
 ('F02','P1','확정','Get Features의 FID별 버퍼 검증 부재와 HMB 호스트 크래시','tc-2fea8a412d','FID/SEL/EXHID별 레이아웃·버퍼 검증. HMB Figure484는4096B 구조.4B 요청 차단.','일반 NUMD 계산 추가됨; FID별 보호는 미해결'),
 ('F03','P1','확정','정상 음성 상태의 이름 불일치와 상위 상태 비트 오해','tc-8c504b8303,tc-d7ddb15e56,tc-4a9f0c0cd9,tc-72e4c056d0','SC/SCT와 MORE/DNR 분리, canonical alias 및 규격상 동등 상태 집합.','미해결'),
 ('F04','P1','확정','요청값·버퍼·검증식의 내부 모순','tc-aabba0b28e,tc-3753251032,tc-dde1721c6e,tc-ff1a706bb9,tc-06f29a6cbd','계약 정적 검사: bytes,NUMD,배열 끝,write payload 상수와 기대값 일치.','전송 산술 derive 추가됨; 검증식까지의 일관성은 미해결'),
 ('F05','P1','확정','미확인 지원 여부를 미지원으로 단정 / 일반 거부 원인을 오인','tc-cc6cb9f6b0,tc-63fd69acd4,tc-f41a83f6af','지원됨/미지원/불명 삼상태. 선택 사항!=미지원. 음성 테스트의 다른 필드를 유효하게 만들기.','미해결'),
 ('F06','P1','확정','지원 비트·오프셋·FID 선택자 오류로 전제 거짓 통과/중단','tc-81b2f4413c,tc-20f142d32b,tc-3574f2e15f,tc-bcb316ee06','Identify/Logs typed decoder와 field registry. 문구·필드·실제 인코딩을 동일키에 연결.','미해결'),
 ('F07','P1','확정','항상 참인 비교, 일부 바이트/설정값으로 전체 동작을 PASS','tc-de15664d98,tc-d2a4fc92d8,tc-a3b1b3fb31,tc-cba9433d26','tautology 거부, all-zero/all-byte 검사, 설정 왕복과 이벤트/타이밍/원자성 관측 분리.','요구사항 바인딩 추가 작업 중; 검증식 의미 보장은 별도'),
 ('F08','P1','확정','인용의 존재와 요구사항 의미를 혼동','tc-4830baf8c2,tc-c2f99b95d0,tc-5a470edacc,tc-7d17668322','행위자/조건/규범 강도/관측 대상을 정형화. 목록 조각/무관한 일반 문장으로 특정 기능 PASS 금지.','variant/target requirement 바인딩 추가 작업 중; 의미 검증 미완'),
 ('F09','P1','확정/원인추정','Linux 드라이버가 관리하는 I/O 큐를 일반 passthru로 생성','tc-71051853d9,tc-7db5dade5a','QID 소유·PRP 메모리·정리까지 관리하는 전용 backend. 현재 Linux 큐 명령의 positive path는 제외.','미해결'),
 ('F10','P1','확정','체인 중단 시 복구 미실행과 전역 설정 잔류','tc-72e4c056d0,tc-249e4a0c7a,tc-ff1a706bb9','finally/cleanup 단계, 실패 후에도 복구 시도·결과 저장. 설정 snapshot/restore와 매 TC 고유 데이터 범위.','host action 지원 추가 작업 중; cleanup 보장은 별도'),
 ('F11','P1','확정','namespace 노드와 NSID 불일치로 컨트롤러 도달 전 거부','tc-a4d578c08b,tc-24ca0373ae,tc-1afe54d404','I/O command scope에 맞는 device 경로와 NSID 조합을 전송 전에 검증.','미해결'),
 ('F12','P1','확정','judge에 필요한 실제 응답 누락 및 근거 없는 디코딩/확신','tc-3af95784f5,tc-7db5dade5a,tc-f41a83f6af','단계별 완료상태/파싱필드/해당 bytes를 우선 제공. 미검증 전제면 firmware_defect 상한 제한.','미해결'),
 ('F13','P2','확정','큰 data_equal 비교 결과가 judge 프롬프트를 비대화','tc-06f29a6cbd','byte dump 대신 길이·hash·최초 불일치·관심 범위. 실제 프롬프트 예산 검증.','미해결'),
 ('F14','P2','확정','반복 재시도의 낮은 효율과 LLM 산술 의존','tc-53cf1a5d17,tc-619cffa9a1,tc-2fea8a412d','동일 요청 재전송 차단, 지원 프로파일 캐시, 산술 계산을 코드로 이동.','derive_transfer 일부 해결; 재시도 정책은 별도'),
 ('F15','P2','확정','41개 생성/인자 실패의 유형별 복구 경로 부족','','schema constrained output, field별 재작성, invalid NSID 음성 케이스 정책, 구조체 builder.','길이·방향 계산은 일부 해결; 나머지는 재검증 필요'),
 ('F16','P2','확정','잘못되거나 과도한 사전조건으로 실질 테스트 정체','','필수 인과 조건과 단순 환경 설명 분리. 미측정 게이트는 유지하며 모델의 잘못된 전제를 고칠 것.','미측정 게이트 복원은 이미 ae3306f에 반영/실행 기록에서도 동작'),
 ('F17','P2','확정','232/232 시도와 실제 본동작·요구사항 검증 사이의 간극','','attempt/action sent/observation complete/requirement evaluated 네 분모를 표시.','리포트가 시도로 표기하는 점은 맞음; 추가 분해 필요'),
 ('F18','P2','확정','현재 실행과 이전 실행의 판정 혼재','','run_id/device_id/기간 필터. 과거 판정은 삭제하지 말고 역사로 구분.','미해결'),
 ('F19','P2','확정','스펙·도구·코드·장치 버전 추적 미흡','','실행 manifest: git SHA,dirty,모델,프롬프트/schema/spec hash,nvme-cli/kernel,firmware/NS format.','일부 기초 정보는 raw Identify로 복구 가능; 명시적 manifest 부재'),
 ('F20','P2','개선','새 인자/검증기에 대한 실제 로그 회귀 테스트 필요','','본 실행의 false FAIL/PASS/host crash/미실행/cleanup 사례를 오프라인 fixture로 고정.','이전 단위테스트 통과는 본 실행 의미 정확도 보장이 아님'),
]
ISSUES.append(('F21','P2','확정','같은 LBA만 허용하는 데이터 비교가 Copy 검증까지 금지','','Copy descriptor의 source/destination 매핑을 검증하는 별도 provenance 관계/비교식. 주소 검사를 무조건 제거하지 말 것.','미해결'))


def integer(x):
 if isinstance(x,int):return x
 s=str(x).strip();return int(s[:-1],16) if s.lower().endswith('h') else int(s,16 if s.lower().startswith('0x') else 10)

def skip_group(s):
 r=s['reason']
 for needles,name in [(['NUMD','NUMDL'],'전송 길이/NUMD'),(['payload_hex'],'페이로드 길이/형식'),(['nsid='],'NSID 정책/값'),(['clause requires','test intent mismatch','field_constraints must fix'],'선택자/고정 필드'),(['quote was not found'],'인용 불일치'),(['parseable JSON'],'JSON 형식'),(['target command'],'action 누락'),(['integer required'],'검증식 필드 누락'),(['LBAs '],'비교 주소 관계'),(['constraint mask/value'],'마스크/값')]:
  if any(n in r for n in needles):return name
 return '기타'

def brief(x,n=200):
 return x if not isinstance(x,str) or len(x)<=n else x[:n]+'…'

def decode_hex_rows(result):
    data = bytearray()
    for line in result.get("stdout", "").splitlines():
        m = re.match(r"^\s*([0-9a-fA-F]+):\s+(.*)$", line)
        if not m:
            continue
        if int(m[1], 16) != len(data):
            raise ValueError("noncontiguous hexdump")
        for token in m[2].split()[:16]:
            if not re.fullmatch(r"[0-9a-fA-F]{2}", token):
                break
            data.append(int(token, 16))
    return bytes(data)


def main():
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('--input',type=Path,default=Path('TC_Gen_Decisioner-main'))
 parser.add_argument('--output',type=Path,default=Path(__file__).resolve().parent)
 args=parser.parse_args();root=args.input.resolve();out=args.output;out.mkdir(parents=True,exist_ok=True)
 def read(p):return json.loads((root/p).read_text(encoding='utf-8-sig'))
 def jsonl(p):return [(i,json.loads(s)) for i,s in enumerate((root/p).read_text(encoding='utf-8-sig').splitlines(),1) if s.strip()]
 ts=read('data/tc_store.json');skips=read('data/target_skips.json');vs=read('data/verdicts/tc_exec.json');cov=read('data/coverage_state.json')
 ll=jsonl('logs/llm_calls.jsonl');ssh=jsonl('logs/ssh_commands.jsonl');ld={r['response_id']:(i,r) for i,r in ll};vd={v['verdict_id']:v for v in vs}
 run_ll=[(i,l) for i,l in ll if '2026-11-05T01:05:53'<=l['timestamp']<'2026-11-05T06:00']
 run_ssh=[(i,l) for i,l in ssh if '2026-11-05T01:05:53'<=l['timestamp']<'2026-11-05T06:00']
 log_path=Path('logs/tc_pipeline_20261105_010553.log');log=(root/log_path).read_text(encoding='utf-8-sig').splitlines();starts={}
 for n,line in enumerate(log,1):
  m=re.search(r'\[\d+/232\] (TC_\S+)',line)
  if m:starts[m[1]]=n
 tc_lines={}
 for n,line in enumerate((root/'data/tc_store.json').read_text(encoding='utf-8-sig').splitlines(),1):
  m=re.match(r'    "tc_id": "([^"]+)"',line)
  if m:tc_lines[m[1]]=n
 length_conflicts=[];tautologies=[];shifted=[];case_rows=[];judge_missing=[]
 for t in ts:
  tid=t['tc_id'];contract=t['verification_contract'];steps=t['steps'];i=next(i for i,s in enumerate(steps) if s.get('phase')=='action');action=steps[i]
  result=next((r for r in t['execution']['step_results'] if r['step_index']==i),{});sent=bool(result) and result.get('started',True)
  flags=[]
  for origin,items in [('requirement',contract['requirements']),('precondition',contract.get('precondition_checks',[]))]:
   for item in items:
    for c in item.get('checks',[]):
     if c.get('kind')=='data_length':
      j=integer(c['step']);expect=integer(c['bytes']);actual=steps[j]['data_len']
      if expect!=actual:length_conflicts.append(dict(tc_id=tid,kind=origin,step=j,buffer_bytes=actual,expected_bytes=expect));flags.append('F04')
     if c.get('kind') in {'data_field','result_bits'} and ((c.get('operator')=='ge' and integer(c['value'])==0) or (c.get('operator')=='le' and integer(c['value'])==integer(c['mask']))):
      tautologies.append(dict(tc_id=tid,kind=origin,check=c));flags.append('F07')
  for p in t['verification'].get('preconditions',[]):
   for c in p.get('results',[]):
    x=c['check'];d=p['description']
    if c['result']=='violated' and x.get('kind')=='data_field' and ((('OACS' in d or 'ONCS' in d) and x.get('offset') in (257,521)) or ('SANICAP' in d and x.get('offset')==331) or ('CTRATT' in d and x.get('offset')==99)):
     shifted.append(dict(tc_id=tid,description=d,check=x,observed=c.get('observed')));flags.append('F06')
  if not sent:flags.append('F16')
  if contract.get('unmeasured_preconditions'):flags.append('F16')
  if t['status']=='UNSUPPORTED':flags.append('F14')
  if len(t.get('attempts',[]))>1:flags.append('F14')
  v=vd.get(t.get('verdict_id'));l=ld.get(v.get('llm_response_id')) if v else None
  if l and f'step {i}: exit_code' not in l[1]['prompt']:judge_missing.append(dict(tc_id=tid,llm_line=l[0],action_step=i));flags.append('F12')
  if t.get('execution',{}).get('host_tool_crash'):flags.append('F02')
  review='저장 결과를 참고하되 본동작·전제·검증 범위를 분리해서 해석'
  assessment={'PASS':'아래 개별 검토 참조','FAIL':'아래 개별 검토 참조','ERROR':'인자/환경/지원 여부 조사','UNVERIFIED':'필수 전제 또는 관측 미충족','UNSUPPORTED':'명령 미지원 응답 관측'}[t['status']]
  if tid in FAIL_REVIEW:
   f,review=FAIL_REVIEW[tid];flags+=f.split(',');assessment='장비 결함 확정 근거 아님'
  if tid in PASS_REVIEW:
   assessment,f,review=PASS_REVIEW[tid];flags+=f.split(',') if f else []
  for code,_,_,_,ids,_,_ in ISSUES:
   if tid in ids.split(','):flags.append(code)
  cases_requirements=[]
  for rq in t['verification']['requirements']:
   cases_requirements.append({'requirement_id':rq['requirement_id'],'status':rq['status'],'description':rq['description'],'quote':rq['quote'],'checks':[dict(check=c['check'],result=c['result'],observed=brief(c.get('observed'),100),expected=brief(c.get('expected'),100),detail=brief(c.get('detail'),140)) for c in rq.get('results',[])]})
  case_rows.append(dict(tc_id=tid,name=t['name'],target=contract.get('target_section_id'),status=t['status'],execution_status=t.get('execution_status'),action_sent=sent,action_command=action['name'],action_expected=action.get('expected_status'),attempts=len(t.get('attempts',[])),issues=sorted(set(flags)),assessment=assessment,review=review,log_line=starts.get(t['name']),tc_store_line=tc_lines.get(tid),scenario_llm_line=ld.get(t['generated_from']['llm_response_id'],(None,))[0],judge_llm_line=l[0] if l else None,judge_classification=v['classification'] if v else None,requirements=cases_requirements))
 used={t.get('verdict_id') for t in ts};old=[v['verdict_id'] for v in vs if v['verdict_id'] not in used]
 metrics=dict(targets=232,tc_records=len(ts),skipped=len(skips),statuses=dict(collections.Counter(t['status'] for t in ts)),execution_statuses=dict(collections.Counter(t['execution_status'] for t in ts)),action_sent=sum(c['action_sent'] for c in case_rows),action_not_sent=sum(not c['action_sent'] for c in case_rows),steps=sum(len(t['steps']) for t in ts),steps_not_sent=sum(not r.get('started',True) for t in ts for r in t['execution']['step_results']),skip_types=dict(collections.Counter(s['kind'] for s in skips)),skip_causes=dict(collections.Counter(skip_group(s) for s in skips)),llm_calls=len(run_ll),llm_callers=dict(collections.Counter(l['caller'] for _,l in run_ll)),llm_elapsed_sec=round(sum(l.get('elapsed_sec',0) for _,l in run_ll),2),ssh_calls=len(run_ssh),ssh_elapsed_sec=round(sum(s.get('elapsed_sec',0) for _,h in run_ssh for s in h['stages']),2),ssh_timeouts=sum(s.get('timed_out',False) for _,h in run_ssh for s in h['stages']),retry_tcs=sum(len(t.get('attempts',[]))>1 for t in ts),retry_final_status=dict(collections.Counter(t['status'] for t in ts if len(t.get('attempts',[]))>1)),judge_this_run=sum(t.get('verdict_id') is not None for t in ts),old_unlinked_verdicts=old,judge_missing_action_raw=len(judge_missing),judge_prompt_max_chars=max(len(l['prompt']) for _,l in run_ll if l['caller']=='judge'),length_conflict_checks=len(length_conflicts),length_conflict_tcs=len({c['tc_id'] for c in length_conflicts}),tautology_checks=len(tautologies),shifted_failed_register_checks=len(shifted),shifted_failed_register_tcs=len({c['tc_id'] for c in shifted}),negative_action_passes=sum(c['status']=='PASS' and c['action_expected']!='SUCCESS' for c in case_rows),stored_coverage_summary=cov['summary'])
 observations = {}
 self_test = next(t for t in ts if t['tc_id'] == 'tc-3af95784f5')
 before = decode_hex_rows(self_test['execution']['step_results'][1])
 after = decode_hex_rows(self_test['execution']['step_results'][3])
 observations['self_test'] = dict(tc_id=self_test['tc_id'], before_first32=before[:32].hex(' '), after_first32=after[:32].hex(' '), current_operation=after[0]&15, newest_result_code=after[4]&15, newest_test_code=after[4]>>4)
 identify = next(decode_hex_rows(r) for t in ts for j, step in enumerate(t['steps']) if step['name']=='Identify' and integer(step['cdw10'])&255==1 for r in t['execution']['step_results'] if r['step_index']==j and r.get('exit_code')==0)
 observations['identify_fields']={key:dict(offset=off, width=width, value=int.from_bytes(identify[off:off+width], 'little')) for key,off,width in [('CNTRLTYPE',111,1),('OACS',256,2),('ONCS',520,2),('CTRATT',96,4),('SANICAP',328,4),('NN',516,4),('NPSS',263,1),('HCTMA',322,2),('VWC',525,1),('HMPRE',272,4)]}
 observations['dmesg_nonempty_tcs']=[t['tc_id'] for t in ts if t['execution'].get('dmesg_text','').strip()]
 observations['host_crash_tcs']=[t['tc_id'] for t in ts if t['execution'].get('host_tool_crash')]
 wu=next(t for t in ts if t['tc_id']=='tc-72e4c056d0')
 invalid=set(range(0x1000,0x1008));repairs=[]
 for t in ts:
  if t['created_at']<=wu['created_at']:continue
  for r in t['execution']['step_results']:
   step=t['steps'][r['step_index']]
   if step.get('mode')=='io-passthru' and step.get('opcode') in ('0x01','0x08') and r.get('started',True) and r.get('exit_code')==0:
    slba=integer(step['cdw10'])+(integer(step['cdw11'])<<32);n=(integer(step['cdw12'])&65535)+1
    overlap={v for v in invalid if slba<=v<slba+n}
    if overlap:repairs.append(dict(tc_id=t['tc_id'],overlap_lbas=sorted(overlap)));invalid-=overlap
 observations['write_uncorrectable_cleanup']={'invalidated_lbas':list(range(0x1000,0x1008)), 'later_overlapping_writes':repairs,'lbas_without_recorded_repair':sorted(invalid),'note':'제공된 기록 범위의 추적'}
 observations['write_uncorrectable_cleanup']['note']='제공된 실행 기록의 추적이며 현재 장치 상태를 확인한 것이 아님'
 inputs={str(p.relative_to(root)):dict(bytes=p.stat().st_size,sha256=hashlib.sha256(p.read_bytes()).hexdigest()) for p in [root/'data/tc_store.json',root/'data/coverage_state.json',root/'data/target_skips.json',root/'data/verdicts/tc_exec.json',root/log_path,root/'logs/llm_calls.jsonl',root/'logs/ssh_commands.jsonl', *sorted((root/'logs').glob('tc_pipeline_*.log'))]}
 result=dict(scope='2026-11-05 10:05:53–14:59:33 Asia/Seoul; original records unchanged',input_hashes=inputs,metrics=metrics,observations=observations,issues=[dict(zip(('id','priority','certainty','title','example_tc_ids','improvement','current_code_status'),v)) for v in ISSUES],length_conflicts=length_conflicts,tautologies=tautologies,shifted_failed_register_checks=shifted,judge_missing_action_raw=judge_missing,cases=case_rows,skips=[dict(s,category=skip_group(s)) for s in skips])
 (out/'audit.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
 fields=['tc_id','target','name','status','execution_status','action_sent','action_expected','attempts','issues','assessment','review','log_line','tc_store_line','scenario_llm_line','judge_llm_line','judge_classification']
 with (out/'cases.csv').open('w',encoding='utf-8-sig',newline='') as f:
  w=csv.DictWriter(f,fieldnames=fields);w.writeheader()
  for row in case_rows:w.writerow({k:';'.join(row[k]) if k=='issues' else row.get(k) for k in fields})
 with (out/'skips.csv').open('w',encoding='utf-8-sig',newline='') as f:
  w=csv.DictWriter(f,fieldnames=['section_id','opcode','kind','category','at','reason']);w.writeheader()
  for s in skips:w.writerow(dict(s,category=skip_group(s)))
 print(json.dumps({k:v for k,v in metrics.items() if k!='stored_coverage_summary'},ensure_ascii=False,indent=2))

if __name__=='__main__':main()
