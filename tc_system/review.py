"""Which results a person must look at, and why.

A TC's status says what the machine concluded; this says how far to trust
it. Every reason is computed by code from the stored TC (so it also works on
old records: `python -m tc_system.review <tc_store.json>`), plus optional
objections from the same LLM in an auditor role that sees decoded facts, not
the generator's reasoning. LLM objections never change a status; they only
put the TC on the list.

Levels: "must" (꼭 확인) - a FAIL, a host crash, state left changed, a contract
contradiction under a PASS/FAIL, a firmware-defect verdict; "recommend" (확인
권장) - a PASS whose observation is narrower than its claim, a test stopped by
a check that reads the wrong field; "info" (참고) - everything else.

Origin (2026-11-05 --all run audit): all 14 FAILs were our own errors or
unproven premises, several PASSes claimed more than they observed, and the
judge LLM's own "test_env_issue" notes never reached the reader.
"""
import json
import re

from tc_system import spec_fields
from tc_system.verification import (FIRMWARE_PENDING_NOTE, canonical_status, completion_status, expected_status, integer, payload_for_step,
                                    plain_text, selector_in_text, validate_check, _UNSUPPORTED_PREMISE_RE)

LEVELS = ("info", "recommend", "must")
LEVEL_LABELS = {"must": "꼭 확인", "recommend": "확인 권장", "info": "참고"}
_BEHAVIOR_RE = re.compile(r"interrupt|event|atomic|power[- ]fail|power loss|thermal|temperature|throttl|"
                          r"keep alive|timer|latency|placement|reclaim", re.I)
_ALL_RE = re.compile(r"\ball\b.*\b(?:zero|cleared|0h)\b|\bzero[- ]filled\b|\bcleared to 0h\b|모든 바이트|전부 0", re.I)
_ACTOR_RE = re.compile(r"Discovery controller|Administrative controller|Exported NVM Subsystem|over Fabrics|"
                       r"Fabrics|Migratable Controller|Migration Management Controller|secondary controller", re.I)
_NORMATIVE_VERB_RE = re.compile(r"\b(?:shall|should|may|must|is|are|returns?|indicates?|specifies|contains?|"
                                r"reports?|sets?|clears?)\b", re.I)


def _reason(reasons, level, code, text, source="code"):
    reasons.append({"level": level, "code": code, "text": text, "source": source})


def _results(tc):
    return {r["step_index"]: r for r in (tc.get("execution") or {}).get("step_results", [])}


def _raw_op(step):
    try:
        return integer(step.get("opcode", "0x0"))
    except (TypeError, ValueError):
        return None


def step_structure(step):
    """The data structure a stored step returned, from its actual fields."""
    if step.get("mode") != "admin-passthru":
        return None
    raw = _raw_op(step)
    if raw is None:
        return None
    return spec_fields.structure_of({"command_set": "ADMIN", "raw_opcode": f"0x{raw:02X}"},
                                    {k: step.get(k, "0x0") for k in ("cdw10", "cdw11", "cdw12", "cdw13")})


def _contract_groups(tc):
    contract = tc.get("verification_contract") or {}
    groups = [("요구사항", r) for r in contract.get("requirements") or []]
    groups += [("사전조건", p) for p in contract.get("precondition_checks") or []]
    return groups


def claim_scope(tc):
    """What the PASS actually observed, in a few words."""
    steps = tc.get("steps") or []
    action = next((s for s in steps if s.get("phase") == "action"), None)
    if action is None:
        return None
    exp = expected_status(action)
    if exp == "INVALID_OPCODE":
        return "미지원 응답 확인"
    kinds = {c.get("kind") for _, g in _contract_groups(tc) for c in g.get("checks") or [] if isinstance(c, dict)}
    if exp != "SUCCESS":
        return "거부 응답 확인"
    names = [s.get("name") for s in steps if not s.get("harness") and s.get("phase") != "cleanup"]
    if "Set Features" in names and "Get Features" in names and not kinds & {"data_equal", "data_matches_write", "data_all"}:
        return "설정 왕복(저장된 값만 확인)"
    if kinds & {"data_equal", "data_matches_write", "data_all"}:
        return "데이터 비교"
    if kinds & {"data_field", "result_bits"}:
        return "필드 관측"
    return "완료 상태만 확인"


def requirement_scope(tc, req):
    """What one requirement's PASS observed, from its own checks (review: a
    TC-wide label overstated requirements that only checked a completion)."""
    steps = tc.get("steps") or []
    checks = [c for c in req.get("checks") or [] if isinstance(c, dict)]
    kinds = {c.get("kind") for c in checks}
    if kinds & {"data_equal", "data_matches_write", "data_all"}:
        return "데이터 비교"
    if kinds & {"data_field", "result_bits"}:
        read = [steps[c["step"]] for c in checks if c.get("kind") in ("data_field", "result_bits")
                and isinstance(c.get("step"), int) and c["step"] < len(steps)]
        set_fids = {integer(s.get("cdw10", "0x0")) & 0xFF for s in steps
                    if s.get("mode") == "admin-passthru" and _raw_op(s) == 0x09 and not s.get("harness")}
        if read and all(s.get("mode") == "admin-passthru" and _raw_op(s) == 0x0A
                        and integer(s.get("cdw10", "0x0")) & 0xFF in set_fids for s in read):
            return "설정 왕복(저장된 값만 확인)"
        return "필드 관측"
    expected = {expected_status(steps[c["step"]]) for c in checks if c.get("kind") == "completion"
                and isinstance(c.get("step"), int) and c["step"] < len(steps)}
    if "INVALID_OPCODE" in expected:
        return "미지원 응답 확인"
    if any(e != "SUCCESS" for e in expected):
        return "거부 응답 확인"
    return "완료 상태만 확인"


def code_review(tc, verdict=None):
    reasons = []
    status = tc.get("status")
    steps = tc.get("steps") or []
    results = _results(tc)
    execution = tc.get("execution") or {}
    verification = tc.get("verification") or {}

    if status == "FAIL":
        _reason(reasons, "must", "fail", "기계 판정 FAIL — 아래 사유와 원시 응답으로 장비 결함인지 확인")
    if execution.get("host_tool_crash"):
        _reason(reasons, "must", "host_crash", f"호스트 도구(nvme-cli) 비정상 종료: {execution['host_tool_crash']}")

    # Completion compared by name while the numeric code agrees (old records).
    for req in verification.get("requirements") or []:
        for outcome in req.get("results") or []:
            check = outcome.get("check") or {}
            if check.get("kind") == "completion" and outcome.get("result") == "violated":
                i = check.get("step")
                r = results.get(i) if isinstance(i, int) else None
                code = spec_fields.status_code_in_output((r or {}).get("stdout", ""))
                want = spec_fields.status_code_of_name(outcome.get("expected"))
                if code and want and code == want:
                    _reason(reasons, "must", "status_alias",
                            f"스텝 {i}: 기대 {outcome.get('expected')}와 실제 {outcome.get('observed')}는 같은 상태 코드"
                            f"(SCT {code[0]}, SC {code[1]:02X}h) — 이름만 달라 위반으로 기록됨")
            if check.get("kind") == "data_length":
                _reason(reasons, "must" if outcome.get("result") == "violated" else "recommend", "self_length",
                        "data_length 검사는 우리가 요청한 버퍼 길이를 비교할 뿐 장비 관측이 아님"
                        + (f" — 위반({outcome.get('detail')})은 요청 길이(0-based NUMD) 실수" if outcome.get("result") == "violated" else ""))
    for issue in verification.get("issues") or []:
        if "전제가 장비 응답으로 반증" in issue:
            _reason(reasons, "recommend", "premise_refuted", issue)
        if "사전조건 미측정" in issue:
            _reason(reasons, "must" if status == "FAIL" else "recommend", "premise_unmeasured", issue)
        if FIRMWARE_PENDING_NOTE in issue:
            # Someone has to reset the drive; every later TC runs in this state.
            _reason(reasons, "must", "fw_activation_pending", issue)

    # Setup step refused: the action never ran in the intended state.
    action_idx = next((i for i, s in enumerate(steps) if s.get("phase") == "action"), len(steps))
    statuses = tc.get("step_statuses") or []
    for i in range(min(action_idx, len(statuses))):
        if statuses[i] == "FAIL" and not steps[i].get("harness"):
            _reason(reasons, "must" if status == "FAIL" else "recommend", "setup_failed",
                    f"setup 스텝 {i} {steps[i].get('name')}가 거부/실패 — action은 의도한 상태에서 실행되지 않음")

    # State left changed.
    restore_steps = [i for i, s in enumerate(steps) if s.get("phase") == "cleanup"]
    for i in restore_steps:
        r = results.get(i) or {}
        if r.get("cleanup_not_needed"):
            continue
        if r.get("cleanup_skipped"):
            _reason(reasons, "must", "cleanup_skipped", f"원복 스텝 {i} {steps[i].get('name')} 생략: {r['cleanup_skipped']}")
        elif r and completion_status(r) == "INVALID_OPCODE":
            # The restore command itself is not implemented: the same command
            # cannot have changed anything either (2026-11-06: a Capacity
            # Management cleanup after an unsupported action was "꼭 확인").
            _reason(reasons, "recommend", "cleanup_failed",
                    f"원복 스텝 {i} {steps[i].get('name')}가 INVALID_OPCODE — 이 커맨드는 미지원이라 바꾼 상태도 없을 것"
                    " (다른 변경 스텝이 성공했는지 확인)")
        elif r and completion_status(r) != "SUCCESS":
            _reason(reasons, "must", "cleanup_failed",
                    f"원복 스텝 {i} {steps[i].get('name')}가 성공하지 않음: {completion_status(r) or r.get('stdout', '')[:120]}")
        elif r.get("restore_verified") is False:
            _reason(reasons, "must", "cleanup_failed",
                    f"원복 스텝 {i} {steps[i].get('name')}는 성공했지만 다시 읽은 값이 원래와 다름: {r.get('restore_check')}")
        elif r.get("restore_verified") is None and r.get("restore_check"):
            # A read-back that failed is not the same as a value that cannot be
            # exact (Timestamp): the restore is unconfirmed (review F04).
            approximate = str(r["restore_check"]).startswith("근사")
            _reason(reasons, "info" if approximate else "recommend", "cleanup_unverified",
                    f"원복 스텝 {i}: {r['restore_check']}")
    changed = [i for i, s in enumerate(steps) if not s.get("harness") and s.get("mode") != "host"
               and ((s.get("mode") == "admin-passthru" and _raw_op(s) == 0x09)
                    or (s.get("mode") == "io-passthru" and _raw_op(s) == 0x04))
               and completion_status(results.get(i)) == "SUCCESS"]
    if changed and not restore_steps:
        names = ", ".join(f"{i} {steps[i].get('name')}" for i in changed)
        _reason(reasons, "must", "state_left_changed",
                f"상태를 바꾼 스텝({names})이 성공했는데 원복 단계가 없음 — 이후 TC가 바뀐 상태에서 실행됐을 수 있음")

    # Contract consistency on the real fields.
    blocked_by = next((r.get("blocked_reason") for r in results.values() if r.get("blocked_reason")), "") or ""
    for label, group in _contract_groups(tc):
        for check in group.get("checks") or []:
            if not isinstance(check, dict):
                continue
            try:
                validate_check(check, len(steps))
            except ValueError as exc:
                if "always true" in str(exc):
                    _reason(reasons, "recommend" if status == "PASS" else "info", "always_true",
                            f"{label} '{group.get('description', '')[:60]}': 항상 참인 검사 — {exc}")
            except (KeyError, TypeError):
                pass
            if check.get("kind") != "data_field":
                continue
            try:
                k = integer(check["step"])
            except (KeyError, TypeError, ValueError):
                continue
            if not 0 <= k < len(steps):
                continue
            structure = step_structure(steps[k])
            if not structure:
                continue
            siblings = {i["field"] for c in group.get("checks") or [] if c is not check and isinstance(c, dict)
                        and c.get("kind") == "data_field" and c.get("step") == check.get("step")
                        for i in [spec_fields.interpret_check(c, structure)] if i and i.get("field")}
            problem = spec_fields.check_matches_description(check, structure, group.get("description"), siblings)
            read = spec_fields.interpret_check(check, structure) or {}
            if not problem and "정의되지 않은 비트" in str(read.get("label")):
                # 2026-11-06: "VERS" premises read SANICAP bit 4 / bit 9.
                _reason(reasons, "recommend", "undefined_bit",
                        f"{label} '{group.get('description', '')[:70]}'의 검사식이 {read['label']}를 읽음 — "
                        "설명한 필드인지 확인할 수 없음")
            if problem:
                gating = label == "사전조건" and group.get("description", "") and group["description"] in blocked_by
                level = "must" if status in ("PASS", "FAIL") else "recommend"
                _reason(reasons, level, "wrong_field",
                        f"{label} '{group.get('description', '')[:70]}'의 검사식: {problem}"
                        + (" — 이 사전조건 때문에 체인이 멈춤(잘못된 필드로 막혔을 수 있음)" if gating else ""))

    # The role names a different selector than the one sent.
    for i, s in enumerate(steps):
        if s.get("harness") or s.get("mode") != "admin-passthru":
            continue
        raw = _raw_op(s)
        named = selector_in_text({"command_set": "ADMIN", "raw_opcode": f"0x{raw:02X}"}, s.get("role"))
        if named and integer(s.get("cdw10", "0x0")) & 0xFF != named[1]:
            _reason(reasons, "must" if status in ("PASS", "FAIL") else "recommend", "role_selector",
                    f"스텝 {i} {s.get('name')}: 역할 설명은 {named[0]} {named[1]:02X}h인데 실제 CDW10={s.get('cdw10')}"
                    f"({named[0]} {integer(s['cdw10']) & 0xFF:02X}h)")
        if raw in (0x09, 0x0A) and s.get("data_len"):
            c10 = integer(s["cdw10"])
            if spec_fields.feature_buffer(c10 & 0xFF, raw == 0x09, (c10 >> 8) & 7, integer(s.get("cdw11", "0x0"))) is None:
                _reason(reasons, "recommend", "unknown_buffer",
                        f"스텝 {i}: FID {c10 & 0xFF:02X}h의 버퍼 크기를 하네스가 모름({s['data_len']}B 요청)")

    _roundtrip_expectations(tc, reasons)

    if status == "PASS":
        scope = claim_scope(tc)
        quotes = " ".join(plain_text(r.get("quote", "")) for r in (tc.get("verification_contract") or {}).get("requirements") or [])
        action = steps[action_idx] if action_idx < len(steps) else {}
        if scope == "미지원 응답 확인":
            _reason(reasons, "recommend", "unsupported_only",
                    "PASS지만 관측은 INVALID_OPCODE(미지원) 응답뿐 — 인용한 규정의 동작을 시험한 것이 아님")
        if scope and scope.startswith("설정 왕복") and _BEHAVIOR_RE.search(quotes):
            _reason(reasons, "recommend", "roundtrip_only",
                    "설정값 저장/조회만 관측 — 인용이 말하는 동작(인터럽트/이벤트/원자성/전원 등)은 시험하지 않음")
        if expected_status(action).startswith("INVALID") and action.get("selector_support") is None \
                and action.get("mode") == "admin-passthru" and _raw_op(action) in (0x02, 0x09, 0x0A):
            if tc.get("variant_id"):
                # A code variant of a value the spec table reserves, every
                # other field 0: the oracle is the table, not a device claim
                # (2026-11-06: 63 reserved-FID PASSes all "확인 권장").
                _reason(reasons, "info", "support_unknown",
                        "예약값 변형: 이 FID/LID는 시작 조회 범위 밖이라 장비 지원 여부는 측정하지 않음 — "
                        "근거는 스펙 표의 Reserved(다른 필드는 전부 0)")
            else:
                _reason(reasons, "recommend", "support_unknown",
                        "부정 테스트 PASS인데 그 FID/LID의 지원 여부가 측정되지 않음 — 거부 원인이 의도한 필드인지 불확실")
        for req in verification.get("requirements") or []:
            if req.get("unobserved"):
                _reason(reasons, "recommend", "target_unobserved", f"'{req.get('description', '')[:60]}': {req['unobserved']}")
            kinds = {c.get("kind") for c in req.get("checks") or []}
            text = f"{req.get('quote', '')} {req.get('description', '')}"
            if _ALL_RE.search(text) and "data_field" in kinds and not kinds & {"data_all", "data_equal", "data_matches_write"}:
                _reason(reasons, "recommend", "sampled",
                        f"'{req.get('description', '')[:60]}': 전체 데이터에 대한 주장인데 일부 바이트만 검사")
            strength = req.get("strength")
            if strength in ("SHOULD", "MAY"):
                _reason(reasons, "info", "advisory", f"'{req.get('description', '')[:60]}': 인용이 {strength} 권고 규정")
            quote = plain_text(req.get("quote", ""))
            if len(quote) < 60 and not _NORMATIVE_VERB_RE.search(quote) or "refer to section" in quote.lower() and len(quote) < 90:
                _reason(reasons, "recommend", "fragment_quote", f"인용이 요구 문장이 아닌 조각: {quote[:80]!r}")
            if _ACTOR_RE.search(quote):
                _reason(reasons, "recommend", "actor",
                        f"인용의 주체({_ACTOR_RE.search(quote).group(0)})가 시험한 컨트롤러 유형과 같은지 확인")

    for i, s in enumerate(steps):
        if s.get("mode") == "admin-passthru" and _raw_op(s) == 0x02 and integer(s.get("cdw10", "0x0")) & 0xFF in (0x06, 0x81):
            for _, g in _contract_groups(tc):
                for c in g.get("checks") or []:
                    if isinstance(c, dict) and c.get("kind") == "data_field" and c.get("step") == i \
                            and integer(c.get("offset", 99)) == 0 and c.get("operator", "eq") in ("eq", "ne"):
                        _reason(reasons, "must" if tc.get("status") == "FAIL" else "recommend", "in_progress_once",
                                f"스텝 {i}: 진행 중 상태(현재 동작 바이트)를 한 번만 읽음 — 이미 끝났을 수 있음, "
                                "최신 결과 엔트리를 함께 봐야 함")

    if verdict:
        cls = verdict.get("classification")
        if cls == "firmware_defect":
            _reason(reasons, "must", "verdict_defect", f"판정 LLM: 펌웨어 결함 의심({verdict.get('confidence')})")
        elif cls == "needs_engineer_review":
            # Only a FAIL is a defect candidate; on ERROR the harness already
            # holds the verdict (2026-11-06: 7 of 8 "꼭 확인" ERRORs were this).
            _reason(reasons, "must" if status == "FAIL" else "recommend", "verdict_review", "판정 LLM: 엔지니어 검토 필요")
        elif cls == "test_env_issue" and status == "FAIL":
            _reason(reasons, "must", "verdict_conflict",
                    "기계 판정은 FAIL인데 판정 LLM은 테스트/환경 문제로 봄 — 테스트 정의를 고친 뒤 재평가 대상")
    return reasons


def _roundtrip_expectations(tc, reasons):
    """A Get after a Set must expect what was set (measured: Timestamp
    payload 1,048,576 ms, check required >= 4,194,304 ms)."""
    steps = tc.get("steps") or []
    sets = {}
    for i, s in enumerate(steps):
        if s.get("mode") != "admin-passthru" or s.get("harness"):
            continue
        raw, fid = _raw_op(s), integer(s.get("cdw10", "0x0")) & 0xFF
        if raw == 0x09 and s.get("direction") == "write":
            try:
                sets[fid] = payload_for_step(s)
            except (ValueError, KeyError):
                pass
        if raw != 0x0A or fid not in sets:
            continue
        for label, group in _contract_groups(tc):
            for c in group.get("checks") or []:
                if not isinstance(c, dict) or c.get("kind") != "data_field" or c.get("step") != i:
                    continue
                try:
                    off, width, mask, value = (integer(c[k]) for k in ("offset", "width", "mask", "value"))
                except (KeyError, TypeError, ValueError):
                    continue
                written = int.from_bytes(sets[fid][off:off + width], "little") & mask
                op = c.get("operator", "eq")
                if (op == "eq" and value != written) or (op == "ge" and value > written) or (op == "le" and value < written):
                    _reason(reasons, "must" if tc.get("status") == "FAIL" else "recommend", "roundtrip_expectation",
                            f"스텝 {i} Get Features FID {fid:02X}h: 설정한 값은 {written}(little endian)인데 검사식은 "
                            f"{op} {value}를 요구")


AUDIT_SCHEMA = {
    "objections": 'array of {"level": "must" | "recommend", "text": Korean string, "evidence": string}',
    "summary": "Korean string, one sentence",
}
AUDIT_SYSTEM_PROMPT = (
    "You audit one automated NVMe test result for a human reviewer. You did not write the test. Your job is to "
    "find reasons the stated result does NOT mean what it claims: a check reading a different field or bit than "
    "its description, an expected value that contradicts what an earlier step set, a quote that does not state "
    "the requirement (a fragment, a condition about another controller type, a SHOULD), a PASS that observed "
    "only a configuration round trip or an unsupported-command response, a FAIL whose premise (e.g. 'this value "
    "is unsupported') was never measured, a state the test changed and did not restore. decoded_checks are "
    "computed by code from the spec tables and are authoritative about which field a check reads; likewise "
    "steps[].decoded gives each command's register fields decoded by code from the spec's command layouts and "
    "steps[].cdw*/data_len are the values actually sent - never re-decode cdw values yourself. Only raise "
    "an objection you can point to in the given data (cite step index, field, value). level \"must\" means the "
    "result is likely wrong and you can point to a decoded field, a sent value or an observed status that "
    "shows it; \"recommend\" means it is narrower than claimed. An empty list is a valid answer. "
    "Write text, evidence and summary in Korean (한국어)."
)


def decode_command(step, sent=None):
    """{field: value} for the registers this step sent, by the spec layout
    (`command_fields.REGISTER_LAYOUTS`). 2026-11-06: the auditor LLM decoded
    CDW10 itself and raised "꼭 확인" on LID 7Fh (it was NUMDL; LID 00h),
    Firmware Commit CA=000b (0x19 is CA=011b FS=1) and QID 1 (0x00018000 is
    QID 8000h)."""
    from tc_system.command_fields import decode_fields
    command_set = {"admin-passthru": "ADMIN", "io-passthru": "NVM"}.get(step.get("mode"))
    raw = _raw_op(step)
    if command_set is None or raw is None:
        return None
    return decode_fields(command_set, raw, dict(step, **(sent or {})))


def _audit_prompt(tc, reasons):
    steps = tc.get("steps") or []
    results = _results(tc)
    view = []
    for i, s in enumerate(steps):
        r = results.get(i) or {}
        code = spec_fields.status_code_in_output(r.get("stdout", ""))
        # What went on the wire: a restore step's value is filled in at run
        # time (the plan's CDW11=0 was read as "restored to a fixed 0").
        sent = {k: v for k, v in (r.get("sent") or {}).items() if v is not None}
        view.append({"index": i, "name": s.get("name"), "phase": s.get("phase"), "role": s.get("role"),
                     "harness": s.get("harness"), "nsid": s.get("nsid"),
                     **{k: sent.get(k, s.get(k)) for k in ("cdw10", "cdw11", "cdw12", "cdw13", "data_len", "direction")},
                     "decoded": decode_command(s, sent),
                     "payload_hex": (s.get("payload_hex") or "")[:64] or None,
                     "expected_status": s.get("expected_status"), "completion": completion_status(r),
                     "status_code": code and {"sct": code[0], "sc": f"{code[1]:02X}h"},
                     "not_sent": r.get("blocked_reason") or r.get("cleanup_skipped")})
    decoded = []
    for label, group in _contract_groups(tc):
        for c in group.get("checks") or []:
            if isinstance(c, dict) and c.get("kind") == "data_field" and isinstance(c.get("step"), int) \
                    and c["step"] < len(steps):
                structure = step_structure(steps[c["step"]])
                interp = spec_fields.interpret_check(c, structure) if structure else None
                decoded.append({"group": label, "description": group.get("description"), "check": c,
                                "reads": interp and interp["label"], "problem": interp and interp["error"]})
    verification = tc.get("verification") or {}
    reqs = [{"description": r.get("description"), "quote": r.get("quote"), "strength": r.get("strength"),
             "status": r.get("status"),
             "results": [{"check": x.get("check"), "result": x.get("result"), "detail": x.get("detail")}
                         for x in r.get("results") or []]}
            for r in verification.get("requirements") or []]
    return (f"result={tc.get('status')} tc={tc.get('name')}\n"
            f"scenario={json.dumps((tc.get('scenario') or {}).get('description'), ensure_ascii=False)}\n"
            f"steps={json.dumps(view, ensure_ascii=False)}\n"
            f"requirements={json.dumps(reqs, ensure_ascii=False)}\n"
            f"preconditions={json.dumps(verification.get('preconditions'), ensure_ascii=False)[:4000]}\n"
            f"decoded_checks={json.dumps(decoded, ensure_ascii=False)}\n"
            f"issues={json.dumps(verification.get('issues'), ensure_ascii=False)}\n"
            f"code_findings={json.dumps([r['text'] for r in reasons], ensure_ascii=False)}")


def llm_audit(tc, reasons):
    """Objections from the same LLM in an auditor role. Failure to answer is
    not a finding: returns [] and the code reasons stand alone."""
    from shared.llm_client import LLMCallError, generate_llm_response
    try:
        llm = generate_llm_response(_audit_prompt(tc, reasons), system=AUDIT_SYSTEM_PROMPT,
                                    response_schema=AUDIT_SCHEMA, caller="review_audit")
    except (LLMCallError, ValueError, KeyError, TypeError):
        return [], None
    out = []
    for o in (llm["structured"].get("objections") or [])[:8]:
        if isinstance(o, dict) and str(o.get("text") or "").strip():
            level = o.get("level") if o.get("level") in ("must", "recommend") else "recommend"
            evidence = str(o.get("evidence") or "").strip()
            out.append({"level": level, "code": "llm_audit", "source": "llm",
                        "text": str(o["text"]).strip() + (f" (근거: {evidence})" if evidence else "")})
    return out, llm.get("response_id")


# Code reasons that come from an LLM (the judge) do not corroborate the auditor.
_NOT_INDEPENDENT = {"verdict_defect", "verdict_review", "verdict_conflict", "llm_audit"}


def escalation(tc, code_reasons, objections):
    """The auditor's "must" stands on a FAIL (the engineer looks at it anyway,
    and a doubt about its premise belongs there) or when code independently
    flagged the same TC. Alone it is "recommend": in the 2026-11-06 run, 67 of
    88 "꼭 확인" came from the auditor alone - 41 on code variants, several
    from registers it decoded wrongly. The engineer wants the must list to be
    what must be looked at; nothing is dropped, only the level."""
    corroborated = any(r["level"] in ("recommend", "must") and r["code"] not in _NOT_INDEPENDENT
                       and r.get("source") == "code" for r in code_reasons)
    if tc.get("status") == "FAIL" or corroborated:
        return objections
    return [dict(o, level="recommend", llm_level="must", text="(LLM 단독 의견) " + o["text"])
            if o["level"] == "must" else o for o in objections]


def review_tc(tc, verdict=None, use_llm=False):
    reasons = code_review(tc, verdict)
    audit_id = None
    # A code variant's PASS is one code-built command whose oracle is the spec
    # table: nothing for an auditor to find (2026-11-06: 93 audit calls, and
    # most of their "꼭 확인" objections were "support not measured").
    variant_pass = bool(tc.get("variant_id")) and tc.get("status") == "PASS"
    if use_llm and tc.get("status") in ("PASS", "FAIL") and not variant_pass:
        objections, audit_id = llm_audit(tc, reasons)
        reasons += escalation(tc, reasons, objections)
    level = max((r["level"] for r in reasons), key=LEVELS.index, default="info")
    return {"level": level, "label": LEVEL_LABELS[level], "reasons": reasons,
            "scope": claim_scope(tc) if tc.get("status") == "PASS" else None, "audit_llm_response_id": audit_id}


def downgrade_verdict(verdict, review):
    """A firmware-defect verdict over a contract the code found contradictory
    cannot stand alone (measured: Self-test judged firmware_defect 0.75 on a
    check that ignored the newer, passing self-test result)."""
    blocking = {"status_alias", "self_length", "wrong_field", "role_selector", "roundtrip_expectation",
                "setup_failed", "premise_refuted", "premise_unmeasured", "in_progress_once", "actor",
                "fw_activation_pending"}
    hits = [r["text"] for r in review.get("reasons", []) if r["code"] in blocking and r["source"] == "code"]
    if verdict and verdict.get("classification") == "firmware_defect" and hits:
        verdict = dict(verdict, classification="needs_engineer_review",
                       rationale=verdict.get("rationale", "") + " [하네스: 테스트 정의 문제가 함께 발견되어 결함 단정 보류 — "
                       + "; ".join(hits[:3]) + "]")
    return verdict


def apply_tc_verdict(tc, verdict):
    """The one path a TC_EXEC verdict takes, first judgment or a later
    `run_judge --source tc_exec` (review R09: a re-judged verdict was never
    linked to its TC, skipped the defect hold, and the report filed it as a
    past run's). Holds an unfounded defect verdict, links the TC, refreshes its
    review keeping the auditor LLM's objections. Returns the verdict to store."""
    verdict = downgrade_verdict(verdict, review_tc(tc))
    tc["verdict_id"] = verdict["verdict_id"]
    tc["failure_context_id"] = verdict.get("failure_context_id") or tc.get("failure_context_id")
    old = tc.get("review") or {}
    review = review_tc(tc, verdict=verdict)
    review["reasons"] += [r for r in old.get("reasons", []) if r.get("source") == "llm"]
    review["level"] = max((r["level"] for r in review["reasons"]), key=LEVELS.index, default="info")
    review["label"] = LEVEL_LABELS[review["level"]]
    review["audit_llm_response_id"] = old.get("audit_llm_response_id")
    tc["review"] = review
    return verdict


def summarize(tcs):
    counts = {lvl: 0 for lvl in LEVELS}
    codes = {}
    for tc in tcs:
        review = tc.get("review") or review_tc(tc)
        counts[review["level"]] += 1
        for r in review["reasons"]:
            codes[r["code"]] = codes.get(r["code"], 0) + 1
    return counts, dict(sorted(codes.items(), key=lambda kv: -kv[1]))
