"""Finite, evidence-backed test contracts. Never execute model-supplied code.

Transport completion and specification verification are separate observations.
Missing payloads, missing prerequisites and legacy prose are UNVERIFIED, not a
successful assertion. Citations prove provenance, not the model's interpretation;
the report exposes the quote, encoded request, observation and comparison.
"""
import re

from shared.ids import stable_id
from shared.spec_evidence import plain_text

VERSION = 2
CHECK_KINDS = {"completion", "result_bits", "data_length", "data_field",
               "data_equal", "data_matches_write"}
FIELDS = {"nsid", "data_len", *(f"cdw{i}" for i in range(10, 16))}
CAPABILITIES = {"sequential", "zero_payload", "hex_payload", "completion_status",
                "cqe_bits", "data_bytes"}
# Need concurrent outstanding commands / asynchronous events, which a sequential
# nvme-cli passthru executor cannot produce. Scenario validation rejects them,
# and target selection does not offer them at all.
UNEXECUTABLE_COMMANDS = {"Abort", "Asynchronous Event Request"}
STATUS_RE = re.compile(r"NVMe status:\s*([A-Z][A-Z0-9_]+)", re.I)
HOST_ERROR_RE = re.compile(
    r"No such file or directory|Resource temporarily unavailable|Permission denied|"
    r"Operation not permitted|Connection (?:refused|reset|closed)|"
    r"Network is unreachable|Host key verification failed|FATAL ERROR:|"
    r"command not found|not a block device|Inappropriate ioctl", re.I)
# The kernel gave up on the command: nvme_execute_rq returns -EINTR for a
# request it cancelled after the nvme_core admin/io timeout (measured: AER
# came back as "passthru: Interrupted system call"), and -EIO when the
# controller was reset/disabled under it. That is the device not completing
# the command - a hang caught by the kernel instead of by the SSH timeout
# (nvme_core.io_timeout defaults to 30s, the same as one step's SSH budget).
KERNEL_ABORT_RE = re.compile(r"Interrupted system call|Input/output error", re.I)


def integer(value):
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ValueError(f"integer required: {value!r}")
    if isinstance(value, str):
        return int(value, 16 if value.lower().startswith("0x") else 10)
    return value


def completion_status(result):
    if not result or not result.get("started", True):
        return None
    out = str(result.get("stdout", ""))
    if HOST_ERROR_RE.search(out) or KERNEL_ABORT_RE.search(out):
        return None
    match = STATUS_RE.search(out)
    if match:
        status = match[1].upper()
        return status if (status == "SUCCESS") == (result.get("exit_code") == 0) else None
    if result.get("exit_code") == 0 and re.search(r"\b(?:Admin|IO) Command .+ is Success\b", out, re.I):
        return "SUCCESS"
    return None


def expected_status(step):
    return step.get("expected_status", "SUCCESS")


def matches_expected(step, result):
    actual = completion_status(result)
    return actual is not None and actual == expected_status(step)


def decode_payload(result):
    """Parse nvme-cli hex rows, requiring contiguous offsets and full bytes.

    Diagnostics are not payload. Missing output is not an empty successful read.
    Explicit data_hex is also accepted for executor adapters and offline tests.
    """
    if result is None:
        return None
    if "data_hex" in result:
        try:
            return bytes.fromhex(result["data_hex"])
        except (ValueError, TypeError):
            return None
    output = bytearray()
    found = False
    for line in str(result.get("stdout", "")).splitlines():
        match = re.match(r"^\s*([0-9a-fA-F]+):\s+(.*)$", line)
        if not match:
            continue
        if int(match[1], 16) != len(output):
            return None
        row = []
        for token in match[2].split():
            if not re.fullmatch(r"[0-9a-fA-F]{2}", token) or len(row) == 16:
                break
            row.append(int(token, 16))
        if not row:
            return None
        found = True
        output.extend(row)
    return bytes(output) if found else None


def payload_bytes(raw):
    """payload_hex as bytes; tolerates a 0x prefix and whitespace."""
    text = re.sub(r"\s+", "", str(raw))
    if text.lower().startswith("0x"):
        text = text[2:]
    return bytes.fromhex(text)


def payload_for_step(step):
    """Bytes a write step sends. `payload_hex` is a pattern repeated to fill
    data_len (a 4 KiB block need not be spelled out in the prompt); without
    it the buffer is zero-filled."""
    if step.get("direction") != "write":
        return b""
    raw = step.get("payload_hex")
    if raw is None:
        return bytes(step["data_len"])
    pattern = payload_bytes(raw)
    if not pattern or step["data_len"] % len(pattern):
        raise ValueError(f"payload_hex pattern of {len(pattern)} bytes does not evenly fill "
                         f"data_len={step['data_len']}")
    return pattern * (step["data_len"] // len(pattern))


# NVM Read/Write/Compare: the LBA range a data comparison is about.
NVM_DATA_OPCODES = {0x01: "write", 0x02: "read", 0x05: "write"}


def _lba_range(cdw10, cdw11, cdw12):
    return (integer(cdw11) << 32) | integer(cdw10), (integer(cdw12) & 0xFFFF) + 1


def io_range(step):
    """(SLBA, number of blocks) of an NVM Read/Write/Compare step, else None."""
    if step.get("mode") != "io-passthru" or integer(step.get("opcode", "0x0")) not in NVM_DATA_OPCODES:
        return None
    return _lba_range(step["cdw10"], step["cdw11"], step["cdw12"])


def _check_window(name, rng, source_rng):
    if (rng is None) != (source_rng is None):
        raise ValueError(f"{name}: LBA data can only be compared with LBA data")
    if rng is None:
        return None
    (slba, nlb), (src_slba, src_nlb) = rng, source_rng
    if slba < src_slba or slba + nlb > src_slba + src_nlb:
        raise ValueError(f"{name}: LBAs {slba}..{slba + nlb - 1} are not inside the compared "
                         f"step's LBAs {src_slba}..{src_slba + src_nlb - 1}")
    return slba - src_slba, nlb, src_nlb


def comparison_window(step, source):
    """Which part of `source`'s bytes `step`'s bytes must be compared with.

    A byte comparison proves nothing unless both commands address the same
    data: same device and namespace, and for LBA commands a read range inside
    the written range (measured: write LBA 0, read LBA 8, both zero -> PASS).
    Returns (block offset, blocks, source blocks) for LBA commands, None for a
    whole-buffer comparison; raises ValueError when they address different data.
    """
    if step.get("device") != source.get("device") or integer(step.get("nsid", 0)) != integer(source.get("nsid", 0)):
        raise ValueError("compared steps address different devices or namespaces")
    return _check_window("comparison", io_range(step), io_range(source))


def _compared_slice(data, other, window):
    if window is None:
        return other
    offset, blocks, source_blocks = window
    if len(other) % source_blocks or len(data) != blocks * (len(other) // source_blocks):
        raise ValueError("buffer sizes do not match the compared LBA counts")
    block = len(other) // source_blocks
    return other[offset * block:(offset + blocks) * block]


def validate_check(check, n_steps):
    if not isinstance(check, dict) or check.get("kind") not in CHECK_KINDS:
        raise ValueError("unsupported verification check")
    i = integer(check.get("step"))
    if not 0 <= i < n_steps:
        raise ValueError("check refers to a missing step")
    kind = check["kind"]
    if kind in {"data_equal", "data_matches_write"}:
        other = integer(check.get("other_step"))
        if not 0 <= other < i:
            raise ValueError("comparison source must be an earlier step")
    if kind in {"result_bits", "data_field"}:
        mask, value = integer(check.get("mask")), integer(check.get("value"))
        if mask <= 0 or value < 0 or value & ~mask:
            raise ValueError("invalid comparison mask/value")
        if check.get("operator", "eq") not in {"eq", "ne", "le", "ge"}:
            raise ValueError("unsupported comparison operator")
        if kind == "data_field":
            width, offset = integer(check.get("width")), integer(check.get("offset"))
            if not 1 <= width <= 8 or not 0 <= offset < (1 << 20) or mask >= 1 << (8 * width):
                raise ValueError("invalid payload field range")
        elif mask > 0xFFFFFFFF:
            raise ValueError("CQE Dword 0 is 32 bits")
    if kind == "data_length" and not 0 < integer(check.get("bytes")) <= (1 << 20):
        raise ValueError("invalid expected payload length")


def validate_plan_contract(structured, evidence, section_id, available_opcodes):
    steps = structured["steps_plan"]
    if set(structured.get("required_capabilities", [])) - CAPABILITIES:
        raise ValueError("scenario requires capabilities this executor does not implement")
    if structured.get("unverified_conditions"):
        raise ValueError("scenario has prerequisites/observations that cannot be verified: "
                         + str(structured["unverified_conditions"]))
    action = next(i for i, s in enumerate(steps) if s["phase"] == "action")
    by_name = {o["name"]: o for o in available_opcodes}
    for step in steps:
        if step["opcode_name"] in UNEXECUTABLE_COMMANDS:
            raise ValueError("Abort/AER requires asynchronous command/event control, unavailable in this executor")
        status = step.get("expected_status")
        if not isinstance(status, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]+", status):
            raise ValueError("every step must explicitly declare its expected completion status")
        if step.get("payload_hex") is not None:
            try:
                payload_bytes(step["payload_hex"])
            except (ValueError, TypeError) as exc:
                raise ValueError(f"payload_hex is not a hex byte string: {exc}") from exc
        constraints = step.get("field_constraints")
        if not isinstance(constraints, list):
            raise ValueError("every step must declare field_constraints (possibly empty)")
        masks = {}
        for c in constraints:
            if not isinstance(c, dict):
                raise ValueError("command constraint must be an object")
            if c.get("field") not in FIELDS:
                raise ValueError("invalid constrained command field")
            mask, value = integer(c.get("mask")), integer(c.get("value"))
            if not 0 < mask <= 0xFFFFFFFF or value < 0 or value & ~mask:
                raise ValueError("invalid command constraint mask/value")
            masks[c["field"]] = masks.get(c["field"], 0) | mask
        op = by_name[step["opcode_name"]]
        raw = int(op["raw_opcode"], 16)
        required = {}
        if op["command_set"] == "ADMIN":
            required = {0x0A: {"cdw10": 0x7FF}, 0x09: {"cdw10": 0xFF},
                        0x02: {"cdw10": 0xFF}, 0x06: {"cdw10": 0xFF},
                        0x19: {"cdw11": 0xFFFF}, 0x1A: {"cdw11": 0xFFFF},
                        0x10: {"cdw10": 0x3F}}.get(raw, {})
        elif op["command_set"] == "NVM" and raw in {1, 2, 5}:
            required = {"cdw10": 0xFFFFFFFF, "cdw11": 0xFFFFFFFF, "cdw12": 0xFFFF}
        if any(masks.get(field, 0) & mask != mask for field, mask in required.items()):
            raise ValueError(f"{step['opcode_name']}: scenario must fix its selector/address fields {required}")
    _validate_comparisons(structured, steps, by_name)
    evidence_by_id = {e["evidence_id"]: e for e in evidence if e.get("evidence_id")}
    requirements = structured.get("requirements")
    if not isinstance(requirements, list) or not requirements:
        raise ValueError("a scenario needs at least one cited, executable requirement")
    for req in requirements:
        if not isinstance(req, dict):
            raise ValueError("requirement must be an object")
        block = evidence_by_id.get(req.get("evidence_id"))
        quote = plain_text(req.get("quote", ""))
        if block is None or len(quote) < 20 or quote not in plain_text(block["text"]):
            raise ValueError("requirement quote does not occur in its supplied evidence")
        if not isinstance(req.get("description"), str) or not req["description"].strip():
            raise ValueError("requirement needs a description")
        checks = req.get("checks")
        if not isinstance(checks, list) or not checks:
            raise ValueError("requirement has no executable checks")
        for check in checks:
            validate_check(check, len(steps))
        if not any(integer(c["step"]) >= action for c in checks):
            raise ValueError("a target requirement cannot be verified by setup observations alone")
        req["requirement_id"] = stable_id("req", section_id, block["evidence_id"], quote)
        req["section_id"] = section_id
    covered_conditions = structured.get("precondition_checks", [])
    if not isinstance(covered_conditions, list):
        raise ValueError("precondition_checks must be an array")
    if not all(isinstance(c, dict) and isinstance(c.get("description"), str) for c in covered_conditions):
        raise ValueError("precondition checks need objects with descriptions")
    descriptions = [c.get("description") for c in covered_conditions]
    if sorted(descriptions) != sorted(structured.get("preconditions", [])):
        raise ValueError("every precondition needs observable checks; unstated assumptions are not verified")
    for condition in covered_conditions:
        if not condition.get("checks"):
            raise ValueError("precondition has no executable checks")
        for check in condition["checks"]:
            validate_check(check, len(steps))
            if integer(check["step"]) >= action:
                raise ValueError("preconditions must be observable before the action")


def _planned_range(plan_step, op):
    raw = int(op["raw_opcode"], 16)
    if op["command_set"] != "NVM" or raw not in NVM_DATA_OPCODES:
        return None
    fixed = {}
    for c in plan_step.get("field_constraints", []):
        fixed[c["field"]] = fixed.get(c["field"], 0) | integer(c["value"])
    return _lba_range(fixed.get("cdw10", 0), fixed.get("cdw11", 0), fixed.get("cdw12", 0))


def _validate_comparisons(structured, steps, by_name):
    checks = [c for r in structured.get("requirements") or [] if isinstance(r, dict)
              for c in r.get("checks") or []]
    checks += [c for p in structured.get("precondition_checks") or [] if isinstance(p, dict)
               for c in p.get("checks") or []]
    for check in checks:
        if not isinstance(check, dict) or check.get("kind") not in {"data_equal", "data_matches_write"}:
            continue
        i, j = integer(check.get("step")), integer(check.get("other_step"))
        if not (0 <= j < i < len(steps)):
            continue  # validate_check reports the bad index itself
        op_i, op_j = by_name[steps[i]["opcode_name"]], by_name[steps[j]["opcode_name"]]
        if check["kind"] == "data_matches_write":
            if int(op_j["raw_opcode"], 16) & 0b11 != 0b01:
                raise ValueError(f"data_matches_write: step {j} ({op_j['name']}) does not write data")
            if int(op_i["raw_opcode"], 16) & 0b11 != 0b10:
                raise ValueError(f"data_matches_write: step {i} ({op_i['name']}) does not read data")
            pattern = steps[j].get("payload_hex")
            # Zeros cannot tell "written" from "never written / deallocated".
            if pattern is None or not any(payload_bytes(pattern)):
                raise ValueError(f"data_matches_write: step {j} needs a non-zero payload_hex")
        _check_window(f"step {i} vs step {j}", _planned_range(steps[i], op_i), _planned_range(steps[j], op_j))


def validate_fixed_fields(step, constraints):
    for c in constraints or []:
        if integer(step[c["field"]]) & integer(c["mask"]) != integer(c["value"]):
            raise ValueError(f"test intent mismatch: {c['field']}={step[c['field']]} "
                             f"must satisfy mask={c['mask']} value={c['value']}")


def evaluate_check(check, steps, results):
    observed, expected = None, None
    try:
        validate_check(check, len(steps))
        i = integer(check["step"])
        step, result = steps[i], results.get(i)
        if not result or not result.get("started", True) or result.get("exit_code") is None:
            raise ValueError("step did not complete")
        kind = check["kind"]
        if kind == "completion":
            observed, expected = completion_status(result), expected_status(step)
            if observed is None:
                raise ValueError("no trustworthy controller completion")
        else:
            if completion_status(result) != "SUCCESS":
                raise ValueError("successful completion required for data/CQE checks")
            if kind == "result_bits":
                match = re.search(r"\bresult:\s*(0x[0-9a-fA-F]+)", str(result.get("stdout", "")))
                if not match:
                    raise ValueError("CQE Dword 0 was not captured")
                observed = int(match[1], 16)
            else:
                data = decode_payload(result)
                if data is None:
                    raise ValueError("response bytes were not captured")
                if kind == "data_length":
                    observed, expected = len(data), integer(check["bytes"])
                elif kind == "data_field":
                    offset, width = integer(check["offset"]), integer(check["width"])
                    if len(data) < offset + width:
                        raise ValueError("response too short to observe the requested field")
                    observed = int.from_bytes(data[offset:offset + width], "little")
                else:
                    j = integer(check["other_step"])
                    if not matches_expected(steps[j], results.get(j)):
                        raise ValueError("comparison source did not complete as expected")
                    other = (payload_for_step(steps[j]) if kind == "data_matches_write"
                             else decode_payload(results.get(j)))
                    if other is None or (kind == "data_matches_write" and steps[j].get("direction") != "write"):
                        raise ValueError("comparison source bytes unavailable")
                    if kind == "data_matches_write" and not any(other):
                        raise ValueError("a zero-filled write cannot be told apart from unwritten LBAs")
                    other = _compared_slice(data, other, comparison_window(step, steps[j]))
                    observed, expected = data.hex(), other.hex()
            if kind in {"result_bits", "data_field"}:
                observed &= integer(check["mask"])
                expected = integer(check["value"])
        op = check.get("operator", "eq")
        ok = {"eq": lambda: observed == expected, "ne": lambda: observed != expected,
              "le": lambda: observed <= expected, "ge": lambda: observed >= expected}[op]()
        return {"check": check, "result": "satisfied" if ok else "violated",
                "observed": observed, "expected": expected, "detail": f"{observed!r} {op} {expected!r}"}
    except (ValueError, KeyError, TypeError, IndexError) as exc:
        return {"check": check, "result": "unevaluated", "observed": observed,
                "expected": expected, "detail": str(exc)}


def verify_tc(tc, execution):
    steps = tc.get("steps", [])
    results = {r["step_index"]: r for r in execution.get("step_results", [])}
    contract = tc.get("verification_contract") or {}
    issues = []
    if contract.get("version") != VERSION or not contract.get("requirements"):
        return {"version": VERSION, "status": "UNVERIFIED", "requirements": [],
                "preconditions": [], "issues": ["스펙 인용과 실행 가능한 검증식이 없는 기록"]}
    declared = (tc.get("scenario") or {}).get("preconditions", [])
    checked = [p.get("description") for p in contract.get("precondition_checks", [])]
    if sorted(declared) != sorted(checked):
        issues.append("일부 사전조건에 실행 가능한 검증식이 없음")
    for step in steps:
        try:
            validate_fixed_fields(step, step.get("field_constraints", []))
        except (ValueError, KeyError, TypeError) as exc:
            issues.append(str(exc))
    conditions = []
    for condition in contract.get("precondition_checks", []):
        checks = [evaluate_check(c, steps, results) for c in condition["checks"]]
        conditions.append(dict(condition, results=checks))
    preconditions_ok = (all(c["result"] == "satisfied" for p in conditions for c in p["results"])
                        and all(matches_expected(s, results.get(i)) for i, s in enumerate(steps)
                                if s.get("phase") == "setup"))
    # Every supporting command is a dependency; an unsupported/failed setup
    # cannot be discarded to turn its dependent action into a verified PASS.
    chain_ok = all(matches_expected(s, results.get(i)) for i, s in enumerate(steps))
    evidence = {e.get("evidence_id"): e for e in contract.get("evidence", [])}
    requirements = []
    for req in contract["requirements"]:
        checks = [evaluate_check(c, steps, results) for c in req.get("checks", [])]
        block = evidence.get(req.get("evidence_id"))
        grounded = bool(block and len(plain_text(req.get("quote", ""))) >= 20 and
                        plain_text(req["quote"]) in plain_text(block["text"]))
        if not grounded or issues or not preconditions_ok:
            status = "UNVERIFIED"
        elif any(c["result"] == "violated" for c in checks):
            status = "FAIL"
        elif checks and chain_ok and all(c["result"] == "satisfied" for c in checks):
            status = "PASS"
        else:
            status = "UNVERIFIED"
        requirements.append(dict(req, status=status, results=checks, grounded=grounded))
    statuses = [r["status"] for r in requirements]
    status = "FAIL" if "FAIL" in statuses else "PASS" if statuses and set(statuses) == {"PASS"} else "UNVERIFIED"
    if not preconditions_ok:
        issues.append("필수 사전조건을 확인하지 못함")
    if not chain_ok:
        issues.append("일부 단계의 예상 완료 상태가 확인되지 않음")
    return {"version": VERSION, "status": status, "requirements": requirements,
            "preconditions": conditions, "issues": issues}
