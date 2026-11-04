#!/usr/bin/env python3
"""■ 배치: **온라인 LLM PC** — 리포 밖. `srag_llm_guide.py`(실제 LLM 호출 코드)와 **같은 폴더**에 둔다.
   같은 폴더의 guide 를 import 하므로 둘이 떨어지면 뜨지 않는다.
   BRIDGE_DIR 은 오프라인 퍼징 PC 의 `PC_Sampling/rag/bridge` 와 **같은 물리 폴더**를
   가리켜야 한다(Samba 공유). 짝이 되는 오프라인 쪽 파일 = rag_bridge_client.py.

온라인 PC 용 RAG 브리지 서비스 — Samba 공유 drop-box 를 폴링해 실제 LLM 을 처리한다.

오프라인 fuzzer 의 rag_bridge_client.py 가 _BRIDGE/requests/ 에 쓴 요청을 읽어 실제 LLM
함수(generate_rag_response)를 호출하고 _BRIDGE/responses/ 에 답을 쓴다. 온라인 PC 에서
계속 띄워둔다. 요청/응답 파일은 처리 후 삭제(stateless — 서비스 재시작해도 남은 요청부터).

실행 (인자 불필요 — 같은 폴더에 srag_llm_guide.py 두고):
  python3 srag_llm_service.py

설정은 아래 상수만 필요시 수정(환경변수로도 override 가능).
"""
import importlib
import json
import os
import string
import sys
import threading
import time
import traceback
from pathlib import Path

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))   # 같은 폴더의 srag_llm_guide.py 를 import 가능하게

# ═══════════════ 설정 — 필요시 이 값만 수정 (실행 인자 불필요) ═══════════════
LLM_MODULE = "srag_llm_guide"          # 같은 폴더의 srag_llm_guide.py (실제 LLM 함수 보유)
LLM_FUNC   = "generate_rag_response"   # 그 안의 함수명. generate_rag_response(user)->str
# Samba 공유 drop-box — 오프라인 PC 의 PC_Sampling/rag/bridge 와 **같은 물리 폴더**여야 한다.
# 찾는 순서: ① 환경변수 RAG_BRIDGE_DIR → ② 이 스크립트 옆의 bridge/ (공유 안에서 돌 때)
#            → ③ (Windows) 드라이브 문자를 훑어 BRIDGE_SUBPATH 가 있는 드라이브
# ③ 은 네트워크 드라이브 문자가 연결할 때마다 바뀌는 경우용이다. 경로 구조는 그대로고
# 문자만 바뀌므로, 이 파일을 매번 고치는 대신 찾아서 쓴다.
BRIDGE_SUBPATH   = Path("pc_sample") / "rag" / "bridge"   # 드라이브 루트 아래 상대경로
BRIDGE_PREFERRED = "ZYX"               # 먼저 볼 드라이브 문자(보통 이 선에서 끝난다)
_BRIDGE_SRC = "?"                      # 어느 규칙으로 골랐는지(시작 배너에 표시)
# ══════════════════════════════════════════════════════════════════════════


def _win_live_drives():
    """존재하는 드라이브 문자만 **선호순**으로 돌려준다.

    GetLogicalDrives 는 비트마스크라 I/O 가 없다 — 끊긴 네트워크 드라이브를 stat 하다
    수 초씩 멈추는 것을 피하려고 후보를 먼저 이걸로 좁힌다.
    """
    import ctypes
    mask = ctypes.windll.kernel32.GetLogicalDrives()
    live = [c for i, c in enumerate(string.ascii_uppercase) if mask >> i & 1]
    pref = [c for c in BRIDGE_PREFERRED if c in live]
    return pref + [c for c in live if c not in pref]


def _probe_bridge_dir():
    """**실재하는** bridge 폴더를 (경로, 출처, 찾아본 경로들) 로 돌려준다. 없으면 (None, "", ...).

    시작 시점과 실행 중 재탐색이 같은 규칙을 쓰도록 분리했다 — 이쪽은 비치명이라
    실패해도 종료하지 않는다.

    ⚠ Windows 에서는 **드라이브 탐색을 먼저** 한다. 스크립트 옆 bridge/ 를 먼저 보면,
    예전 버전이 만들어 둔 빈 bridge/ 가 남아 있을 때 네트워크 드라이브를 아예 찾지
    않고 그 빈 폴더를 폴링한다 — 요청을 영영 못 받고 로그도 조용하다(실측).
    """
    local = _HERE / "bridge"
    tried = []
    if os.name == "nt":
        for d in _win_live_drives():
            cand = Path(f"{d}:\\") / BRIDGE_SUBPATH
            tried.append(str(cand))
            try:
                if cand.is_dir():
                    return cand, "드라이브 탐색", tried
            except OSError:
                continue                # 권한/끊김 — 다음 문자로
    tried.append(str(local))
    if local.is_dir():
        return local, "스크립트 옆", tried
    return None, "", tried


def _find_bridge_dir():
    """시작 시 BRIDGE_DIR 확정. 못 찾으면 찾아본 경로를 보여주고 종료한다.

    (조용히 기본값으로 떨어지면 서비스가 뜬 채로 영영 요청을 못 받는다 — 그 실패는
     _IDLE_WARN_SEC 가 지나야 드러나므로, 시작 시점에 끊는 편이 낫다.)
    """
    global _BRIDGE_SRC
    found, src, tried = _probe_bridge_dir()
    if found is not None:
        _BRIDGE_SRC = src
        return found
    if os.name != "nt":
        _BRIDGE_SRC = "스크립트 옆(신규 생성)"
        return _HERE / "bridge"         # 리눅스/오프라인 쪽 기존 동작(없으면 아래에서 생성)
    sys.exit("[RAG service] bridge 폴더를 찾지 못했습니다. 네트워크 드라이브 연결을 "
             "확인하거나 RAG_BRIDGE_DIR 로 직접 지정하세요.\n  찾아본 경로:\n    "
             + "\n    ".join(tried))


def _rebind_bridge(newdir: Path, src: str = "재탐색"):
    """실행 중 bridge 위치 변경을 반영한다(네트워크 드라이브 문자 변경 등)."""
    global BRIDGE_DIR, _REQ, _RESP, _BRIDGE_SRC
    _BRIDGE_SRC = src
    BRIDGE_DIR = newdir
    _REQ = newdir / "requests"
    _RESP = newdir / "responses"
    for _d in (_REQ, _RESP):
        try:
            _d.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass


# (선택) 환경변수 override — 없으면 위 기본값/자동탐색 사용
LLM_MODULE = os.environ.get("RAG_LLM_MODULE", LLM_MODULE)
LLM_FUNC = os.environ.get("RAG_LLM_FUNC", LLM_FUNC)
_env_bridge = os.environ.get("RAG_BRIDGE_DIR")
_BRIDGE_PINNED = _env_bridge is not None   # 사용자가 못박음 → 실행 중 재탐색하지 않는다
if _env_bridge:
    BRIDGE_DIR, _BRIDGE_SRC = Path(_env_bridge), "RAG_BRIDGE_DIR"
else:
    BRIDGE_DIR = _find_bridge_dir()

_REQ = BRIDGE_DIR / "requests"
_RESP = BRIDGE_DIR / "responses"
_POLL = 0.5
# 접근 불가가 이어질 때 bridge 위치를 다시 찾아보는 간격(초). 드라이브 문자가 바뀌는
# 경우를 잡는 용도라 폴링(_POLL)보다 성기게 둔다.
_REDETECT_SEC = 5.0
# 유휴 경고 간격(초). 퍼저는 request_cadence(기본 5000 exec) 마다만 요청하므로 수 분 공백은
# 정상이다 → 기본 15분. 공유가 조용히 끊긴 경우를 잡는 게 목적.
_IDLE_WARN_SEC = float(os.environ.get("RAG_IDLE_WARN_SEC", "900"))

try:
    _llm_mod = importlib.import_module(LLM_MODULE)
    _llm_call = getattr(_llm_mod, LLM_FUNC)
except Exception as e:
    sys.exit(f"[RAG service] LLM 로드 실패: {LLM_MODULE}.{LLM_FUNC} — {e}\n"
             f"  → 같은 폴더에 {LLM_MODULE}.py 가 있고 {LLM_FUNC}() 가 정의됐는지 확인하세요.")

# LLM 호출 상한(초). 오프라인 클라이언트 타임아웃(RAG_BRIDGE_TIMEOUT, 기본 180s)보다 짧게
# 잡아야, 매달린 호출을 포기하고 **오류 응답이라도** 제때 돌려줄 수 있다.
_CALL_TIMEOUT = float(os.environ.get("RAG_CALL_TIMEOUT", "150"))

_REQ.mkdir(parents=True, exist_ok=True)
_RESP.mkdir(parents=True, exist_ok=True)


def _reload_llm():
    """LLM 모듈을 다시 import 해 모듈 레벨 세션/클라이언트를 새로 만든다(= 재연결).

    유휴 TCP 연결이 방화벽/NAT 에 조용히 끊기면, 모듈 레벨에 살아 있는 requests.Session
    이나 LLM 클라이언트가 죽은 소켓을 계속 재사용해 응답 없이 매달린다. 모듈을 reload
    하면 그 객체들이 새로 생성돼 연결이 다시 맺힌다 — guide 파일 내용을 몰라도 통한다.
    """
    global _llm_mod, _llm_call
    _llm_mod = importlib.reload(_llm_mod)
    _llm_call = getattr(_llm_mod, LLM_FUNC)


def _call_once(prompt: str, timeout: float) -> str:
    """별도 스레드로 호출해 timeout 안에 안 끝나면 포기.

    파이썬은 스레드를 강제 종료할 수 없어 매달린 스레드는 daemon 으로 남는다(프로세스
    종료 시 정리). 대신 **서비스 루프가 통째로 멈추는 것**을 막는다 — 이게 핵심이다.
    """
    box = {}

    def _run():
        try:
            box['ok'] = _llm_call(prompt)
        except Exception as exc:
            box['err'] = exc

    th = threading.Thread(target=_run, daemon=True)
    th.start()
    th.join(timeout)
    if th.is_alive():
        raise TimeoutError(f"LLM 호출이 {timeout:.0f}초 안에 끝나지 않음(응답 없음)")
    if 'err' in box:
        raise box['err']
    return box.get('ok', '')


def _log_call_error(label, exc):
    """Keep the exception type and guide frame; str(KeyError) alone is just 'hits'."""
    summary = f"{type(exc).__name__}: {exc}"
    frames = traceback.extract_tb(exc.__traceback__)
    if frames:
        leaf = frames[-1]
        summary += f" ({leaf.filename}:{leaf.lineno} in {leaf.name})"
    _log(f"⚠ {label}: {summary}")
    # Standard traceback excludes locals and request/response payload dumps.
    for line in traceback.format_exception(type(exc), exc, exc.__traceback__):
        _log(line.rstrip())
    return summary


def _call_llm_resilient(prompt: str):
    """호출 → 실패 시 모듈 reload(재연결) → 1회 재시도. (text, error) 반환."""
    try:
        return _call_once(prompt, _CALL_TIMEOUT), None
    except Exception as e1:
        detail = _log_call_error("LLM 호출 실패", e1)
        if getattr(e1, "retryable", None) is False:
            return "", detail
        _log("⚠   모듈을 다시 로드해 1회 재시도합니다. 연결 문제 여부는 위 traceback으로 확인하세요.")
        try:
            _reload_llm()
        except Exception as e_rl:
            _log_call_error("모듈 reload 실패(기존 함수로 재시도)", e_rl)
        try:
            _text = _call_once(prompt, _CALL_TIMEOUT)
            _log("✓ 모듈 reload 후 재시도 성공")
            return _text, None
        except Exception as e2:
            detail = _log_call_error("재시도도 실패", e2)
            return "", f"{detail} (모듈 reload 후 재시도도 실패)"


def _atomic_write(path: Path, text: str):
    tmp = path.parent / (path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def _unlink(path: Path):
    try:
        path.unlink()
    except OSError:
        pass


def _log(msg: str):
    # 타임스탬프 필수 — 요청 간 공백/처리 지연을 사후에 읽으려면 시각이 있어야 한다.
    print(f"{time.strftime('%Y-%m-%d %H:%M:%S')} [RAG service] {msg}", flush=True)


# 대조용 환경변수 후보. 값은 찍지 않는다 — 자격증명이 섞일 수 있어 **키 이름만** 본다.
_ENV_HINTS = ("PROXY", "ELASTIC", "ES_", "_ES", "OPENSEARCH", "RAG",
              "SSL", "CERT", "TOKEN", "API_KEY", "AUTH", "CONDA", "VIRTUAL_ENV")


def _log_environment():
    """서비스와 (노트북 등) 직접 실행의 환경 차이를 한 줄씩 대조하기 위한 시작 진단.

    같은 함수·같은 입력이 한쪽에서만 실패하면 원인은 입력이 아니라 이 값들 중 하나다.
    특히 `guide` — 서비스는 sys.path 에 스크립트 폴더를 넣으므로, 사본이 둘이면
    노트북과 **다른 파일**을 import 하고 있을 수 있다.
    """
    import getpass, platform
    def _safe(fn, default="?"):
        try:
            return fn()
        except Exception:
            return default
    for k, v in (("python", sys.executable),
                 ("version", sys.version.split()[0]),
                 ("cwd", os.getcwd()),
                 ("script", str(_HERE)),
                 ("guide", getattr(_llm_mod, "__file__", "?")),
                 ("user", _safe(getpass.getuser)),
                 ("host", _safe(platform.node))):
        _log(f"[env] {k:<8}= {v}")
    keys = sorted(k for k in os.environ
                  if any(t in k.upper() for t in _ENV_HINTS))
    _log(f"[env] related env keys ({len(keys)}): {', '.join(keys) or '(없음)'}")


def main():
    _log(f"watching {_REQ}  [{_BRIDGE_SRC}]  (LLM={LLM_MODULE}.{LLM_FUNC})")
    _log_environment()
    _log(f"유휴 경고 간격 {_IDLE_WARN_SEC:.0f}초 (RAG_IDLE_WARN_SEC 로 조정)")
    last_ok = time.monotonic()     # 마지막으로 요청을 처리한(또는 폴더가 멀쩡했던) 시각
    _unreadable = {}               # 파일명 -> 연속 읽기 실패 횟수(권한 문제 조기 발견)
    last_warn = 0.0
    broken = False                 # 감시 폴더 접근 불가 상태인지
    last_redetect = 0.0            # 마지막으로 bridge 위치를 다시 찾아본 시각
    while True:
        now = time.monotonic()

        # ── 감시 폴더 건강 확인 ──────────────────────────────────────────────
        # 중요: Path.glob() 은 폴더가 없어도 예외 없이 **빈 목록**을 돌려준다. 즉 공유가
        #   끊기거나 마운트가 사라져도 서비스는 "요청이 없다" 와 구분하지 못해 조용히 멈춘
        #   것처럼 보인다(실제로 그렇게 놓친 사례가 있었다). 그래서 is_dir() 로 명시 확인한다.
        try:
            alive = _REQ.is_dir()
            reqs = sorted(_REQ.glob("req_*.json")) if alive else []
            err = None
        except OSError as e:        # 끊긴 네트워크 드라이브 등
            alive, reqs, err = False, [], e

        if not alive:
            if not broken or (now - last_warn) >= _IDLE_WARN_SEC:
                _log(f"⚠ 감시 폴더에 접근할 수 없습니다: {_REQ}")
                if err:
                    _log(f"⚠   {err}")
                _log("⚠   공유 연결이 끊겼거나 경로가 사라졌습니다. "
                     "드라이브 매핑/네트워크를 확인하세요.")
                last_warn = now
            broken = True
            # 드라이브 문자가 바뀌었을 수 있다 — 접근 불가가 이어지는 동안 다시 찾는다.
            # 찾으면 경로만 갈아끼우고, 정상 판정/복구 로그는 다음 라운드에 맡긴다.
            if not _BRIDGE_PINNED and (now - last_redetect) >= _REDETECT_SEC:
                last_redetect = now
                _found, _src, _ = _probe_bridge_dir()
                if _found is not None and _found != BRIDGE_DIR:
                    _log(f"✓ bridge 위치 변경 감지: {BRIDGE_DIR} → {_found} ({_src})")
                    _rebind_bridge(_found, _src)
                    continue
            time.sleep(_POLL)
            continue
        if broken:
            _log(f"✓ 감시 폴더 접근 복구됨: {_REQ}")
            broken = False
            last_ok = now

        # ── 요청 처리 ────────────────────────────────────────────────────────
        for req in reqs:
            try:
                data = json.loads(req.read_text(encoding="utf-8"))
            except (ValueError, OSError) as _re:
                # 대개는 '아직 쓰는 중' 이라 다음 라운드에 성공한다. 하지만 권한 때문에
                #   영영 못 읽는 경우(퍼저가 root 로 만든 0600 파일 등)에도 같은 경로를 타서,
                #   예전엔 로그 한 줄 없이 무한히 건너뛰었다 — 서비스가 요청을 '인지조차
                #   못 하는' 것처럼 보이는 원인. 반복 실패는 알린다.
                _n = _unreadable.get(req.name, 0) + 1
                _unreadable[req.name] = _n
                if _n in (10, 100) or _n % 600 == 0:   # ≈5초 / 50초 / 이후 5분 간격
                    _log(f"⚠ 요청 파일을 {_n}회 읽지 못했습니다: {req.name}")
                    _log(f"⚠   {_re}")
                    _log("⚠   권한 문제일 수 있습니다 — 퍼징 PC 에서: "
                         "sudo chmod -R 777 <bridge 폴더>")
                continue
            _unreadable.pop(req.name, None)
            rid = data.get("id", "?")
            _prompt = data.get("user_prompt") or ""
            # 처리 '시작' 을 먼저 찍는다. 이 서비스는 단일 스레드 동기 루프라 _llm_call 하나가
            #   오래 걸리면 그동안 폴링이 통째로 멈추고, 그 사이 들어온 요청은 오프라인 쪽이
            #   180초 뒤 스스로 지워버려 흔적조차 남지 않는다. 완료 시에만 로그하면 '물려 있는
            #   중' 을 알 방법이 없다.
            _log(f"→ processing {rid} (task 프롬프트 {len(_prompt):,}자)")
            _t0 = time.monotonic()
            _text, _err = _call_llm_resilient(_prompt)
            out = {"id": rid, "text": _text}
            if _err:                 # LLM 오류는 응답에 실어 오프라인 쪽이 알게
                out["error"] = _err
            _el = time.monotonic() - _t0
            _atomic_write(_RESP / f"resp_{rid}.json",
                          json.dumps(out, ensure_ascii=False))
            _unlink(req)
            _log(f"handled {rid} ({_el:.1f}s, 응답 {len(out.get('text') or ''):,}자)"
                 f"{' (error)' if out.get('error') else ''}")
            # 오프라인 클라이언트 타임아웃(RAG_BRIDGE_TIMEOUT, 기본 180s)을 넘겼으면 이미
            #   버려진 응답이다 — 다음 요청들도 줄줄이 타임아웃 날 신호이므로 크게 알린다.
            if _el >= 180:
                _log(f"⚠ 처리에 {_el:.0f}초 소요 — 오프라인 기본 타임아웃(180s) 초과. "
                     f"이 응답은 폐기됐을 가능성이 높습니다.")
                _log("⚠   프롬프트가 커졌거나 LLM 이 느려졌습니다. "
                     "RAG_BRIDGE_TIMEOUT 을 올리거나 원인을 확인하세요.")
            last_ok = time.monotonic()
            last_warn = 0.0

        # ── 유휴 경고 ────────────────────────────────────────────────────────
        # 폴더는 멀쩡한데 오래 요청이 없는 경우. 퍼저가 안 돌거나, 퍼저 쪽 경로가 여기와
        # 다른 폴더를 보고 있을 수 있다(양쪽이 서로 다른 물리 폴더면 둘 다 조용하다).
        now = time.monotonic()
        if (now - last_ok) >= _IDLE_WARN_SEC and (now - last_warn) >= _IDLE_WARN_SEC:
            _log(f"⚠ {int((now - last_ok) / 60)}분간 요청 없음 — watching {_REQ}")
            _log("⚠   퍼저가 안 돌고 있거나, 퍼저 쪽이 다른 폴더를 보고 있을 수 있습니다.")
            last_warn = now

        time.sleep(_POLL)


if __name__ == "__main__":
    main()
