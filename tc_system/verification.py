"""Finite, evidence-backed test contracts. Never execute model-supplied code.

Transport completion and specification verification are separate observations.
Missing payloads, missing prerequisites and legacy prose are UNVERIFIED, not a
successful assertion. Citations prove provenance, not the model's interpretation;
the report exposes the quote, encoded request, observation and comparison.
"""
import re
import unicodedata

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
# Clause values that are found in returned data, not set in the request. An
# Event Type clause (Persistent Event Log, 22 clauses) is verified by locating
# a variable-length event record of that type; the finite checks here only
# read fixed offsets, and several events (thermal excursion, ...) cannot be
# caused from this host. Measured: every one of them was skipped or built a
# contract that tested something else. Not offered until a record check exists.
UNVERIFIABLE_FIELD_VALUES = {"Event Type"}
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


MIN_QUOTE_CHARS = 20   # letters/digits in the whole quote
MIN_SEGMENT_CHARS = 8  # letters/digits in each "..."-separated piece


# One spelling per operator: the evidence has both "≥" and OCR'd LaTeX
# "$ \geq $", and a model may write ">=". Operators carry meaning and are kept.
_LATEX_OPERATORS = [(re.compile(r"\\geq?(?![a-z])"), ">="), (re.compile(r"\\leq?(?![a-z])"), "<="),
                    (re.compile(r"\\neq(?![a-z])"), "!="), (re.compile(r"\\times(?![a-z])"), "*")]
_OPERATOR_CHARS = str.maketrans({"≥": ">=", "⩾": ">=", "≤": "<=", "⩽": "<=", "≠": "!=", "×": "*", "÷": "/",
                                 "−": "-", "–": "-", "—": "-", "‐": "-", "‑": "-", "‒": "-"})


def _quote_key(text):
    """Letters, digits and operators, case-folded.

    The evidence carries table pipes, OCR'd LaTeX ("LBA $ _{s} $"), curly
    quotes and en dashes; a model copying the sentence writes "LBAs", "'" and
    "-". Those differences are dropped. Comparison/arithmetic operators and
    decimal points are kept: "≥ NAWUN" quoted as "≤ NAWUN" is the opposite
    requirement, not a formatting difference. Hyphens inside words
    ("zero-filled") are dropped; a minus next to a number or space is kept.
    """
    text = unicodedata.normalize("NFKC", plain_text(text))
    for pattern, replacement in _LATEX_OPERATORS:
        text = pattern.sub(replacement, text)
    text = text.translate(_OPERATOR_CHARS).casefold()
    text = re.sub(r"(?<=[a-z])-(?=[a-z])", "", text)
    text = re.sub(r"(?<=\d)\.(?=\d)", "#", text)  # 1.5 stays distinct from 15
    return re.sub(r"[^0-9a-z<>=!+\-*/%^#]", "", text)


def quote_in(quote, text):
    """True when `quote` (pieces joined by "..." allowed, in order) occurs in `text`."""
    quote = unicodedata.normalize("NFKC", str(quote or ""))
    pieces = [_quote_key(p) for p in re.split(r"\.\.\.+", quote)]
    pieces = [p for p in pieces if p]
    if sum(map(len, pieces)) < MIN_QUOTE_CHARS or any(len(p) < MIN_SEGMENT_CHARS for p in pieces):
        return False
    haystack, pos = _quote_key(text), 0
    for piece in pieces:
        found = haystack.find(piece, pos)
        if found < 0:
            return False
        pos = found + len(piece)
    return True


def integer(value):
    """int, decimal string, "0x84", or the spec's own "84h" notation."""
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ValueError(f"integer required: {value!r}")
    if isinstance(value, str):
        text = value.strip().replace("_", "")
        if re.fullmatch(r"[0-9a-fA-F]+[hH]", text):
            return int(text[:-1], 16)
        return int(text, 16 if text.lower().startswith("0x") else 10)
    return value


def required_selector_masks(opcode_entry):
    """Request fields that define WHICH test a command performs (FID/SEL, LID,
    CNS, directive type/operation, commit action/slot, LBA range)."""
    raw = int(opcode_entry["raw_opcode"], 16)
    if opcode_entry["command_set"] == "ADMIN":
        return {0x0A: {"cdw10": 0x7FF}, 0x09: {"cdw10": 0xFF},
                0x02: {"cdw10": 0xFF}, 0x06: {"cdw10": 0xFF},
                0x19: {"cdw11": 0xFFFF}, 0x1A: {"cdw11": 0xFFFF},
                0x10: {"cdw10": 0x3F}}.get(raw, {})
    if opcode_entry["command_set"] == "NVM" and raw in {1, 2, 5}:
        return {"cdw10": 0xFFFFFFFF, "cdw11": 0xFFFFFFFF, "cdw12": 0xFFFF}
    return {}


def add_scope_notes(structured, new_notes):
    notes = structured.get("out_of_scope")
    if not isinstance(notes, list):
        notes = list(structured.get("unverified_conditions") or [])
    structured["out_of_scope"] = notes + list(new_notes)


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


# nvme-cli prints its own short tokens ("NVMe status: INVALID_OPCODE: ...",
# confirmed in stored real output), while the spec - and so the model - names
# the same status "Invalid Command Opcode". A scenario that correctly expected
# the drive to reject an unsupported command but wrote INVALID_COMMAND_OPCODE
# never matched, and its intended result was reported as "미지원 응답".
STATUS_ALIASES = {
    "SUCCESSFUL_COMPLETION": "SUCCESS",
    "INVALID_COMMAND_OPCODE": "INVALID_OPCODE",
    "INVALID_FIELD_IN_COMMAND": "INVALID_FIELD",
    "INVALID_NAMESPACE_OR_FORMAT": "INVALID_NS", "INVALID_NAMESPACE": "INVALID_NS",
    "COMMAND_ID_CONFLICT": "CMDID_CONFLICT",
    "DATA_TRANSFER_ERROR": "DATA_XFER_ERROR",
    "COMMANDS_ABORTED_DUE_TO_POWER_LOSS_NOTIFICATION": "POWER_LOSS",
    "INTERNAL_ERROR": "INTERNAL",
    "COMMAND_ABORT_REQUESTED": "ABORT_REQ",
    "COMMAND_SEQUENCE_ERROR": "CMD_SEQ_ERROR",
    "LBA_OUT_OF_RANGE": "LBA_RANGE",
    "CAPACITY_EXCEEDED": "CAP_EXCEEDED",
    "NAMESPACE_NOT_READY": "NS_NOT_READY",
    "INVALID_LOG_PAGE_IDENTIFIER": "INVALID_LOG_PAGE",
    "INVALID_FIRMWARE_SLOT": "FIRMWARE_SLOT",
    "INVALID_FIRMWARE_IMAGE": "FIRMWARE_IMAGE",
    "FEATURE_IDENTIFIER_NOT_SAVEABLE": "FEATURE_NOT_SAVEABLE",
    "FEATURE_NOT_NAMESPACE_SPECIFIC": "FEATURE_NOT_PER_NS",
}
def canonical_status(name):
    """A spec-style status name -> the token nvme-cli prints."""
    token = re.sub(r"[^A-Z0-9]+", "_", str(name or "").upper()).strip("_")
    return STATUS_ALIASES.get(token, token)


def expected_status(step):
    return canonical_status(step.get("expected_status") or "SUCCESS")


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
    capabilities = structured.get("required_capabilities") or []
    capabilities = [capabilities] if isinstance(capabilities, str) else capabilities
    unknown = sorted({str(c) for c in capabilities} - CAPABILITIES) if isinstance(capabilities, list) else []
    # Not a gate: what this executor can actually observe is enforced by the
    # finite check kinds below. Rejecting on a capability *name* the model
    # spelled its own way skipped otherwise executable scenarios.
    # Notes on what this TC deliberately leaves untested are recorded, not
    # rejected (measured: the model listed honest scope limits such as "other
    # LIDs are not covered by this single-action TC", and every target was
    # skipped). What the requirement depends on must be a precondition with a
    # check before the action - that rule, below, is the one that blocks.
    notes = structured.get("out_of_scope", structured.get("unverified_conditions", []))
    if not isinstance(notes, list) or not all(isinstance(n, str) for n in notes):
        raise ValueError("out_of_scope must be an array of strings")
    if unknown:
        add_scope_notes(structured, [f"실행기 역량 목록에 없는 요구(무시함, 검증식 종류로만 판단): {', '.join(unknown)}"])
    action = next(i for i, s in enumerate(steps) if s["phase"] == "action")
    by_name = {o["name"]: o for o in available_opcodes}
    for k, step in enumerate(steps):
        if step["opcode_name"] in UNEXECUTABLE_COMMANDS:
            raise ValueError("Abort/AER requires asynchronous command/event control, unavailable in this executor")
        status = step.get("expected_status")
        if (status is None or (isinstance(status, str) and not status.strip())) and k != action:
            status = "SUCCESS"  # a supporting step is there to succeed; only the action must say
        if not isinstance(status, str) or not status.strip():
            raise ValueError(f"steps_plan[{k}] (the action) must declare its expected completion status")
        step["expected_status"] = canonical_status(status)  # stored in nvme-cli's spelling
        if step.get("payload_hex") is not None:
            try:
                payload_bytes(step["payload_hex"])
            except (ValueError, TypeError) as exc:
                raise ValueError(f"payload_hex is not a hex byte string: {exc}") from exc
        constraints = step.get("field_constraints")
        if constraints is None:
            constraints = []
        elif isinstance(constraints, dict):
            constraints = [constraints]
        if not isinstance(constraints, list):
            raise ValueError(f"steps_plan[{k}].field_constraints must be an array")
        step["field_constraints"] = constraints
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
        required = required_selector_masks(by_name[step["opcode_name"]])
        # The action's selectors ARE the test, so the scenario must state them.
        # A setup/verify step that leaves them open gets them frozen from its
        # first authoring instead (tc_writer.freeze_selectors), so a retry still
        # cannot switch e.g. Identify CNS under a precondition check.
        if k == action and any(masks.get(field, 0) & mask != mask for field, mask in required.items()):
            raise ValueError(f"steps_plan[{k}] {step['opcode_name']} (the action): field_constraints must fix "
                             f"its selector/address fields {{field: mask}} = "
                             + ", ".join(f"{f}: {hex(m)}" for f, m in required.items()))
    _validate_comparisons(structured, steps, by_name)
    evidence_by_id = {e["evidence_id"]: e for e in evidence if e.get("evidence_id")}
    requirements = structured.get("requirements")
    if not isinstance(requirements, list) or not requirements:
        raise ValueError("a scenario needs at least one cited, executable requirement")
    for n, req in enumerate(requirements):
        if not isinstance(req, dict):
            raise ValueError("requirement must be an object")
        quote = plain_text(req.get("quote", ""))
        block = evidence_by_id.get(req.get("evidence_id"))
        if block is None or not quote_in(quote, block["text"]):
            # The quote is what proves provenance; a wrong evidence_id label on
            # a quote that is in another supplied block is just a mislabel.
            block = next((e for e in evidence if e.get("evidence_id") and quote_in(quote, e["text"])), None)
            if block is None:
                raise ValueError(
                    f"requirements[{n}].quote was not found in the supplied evidence: {quote[:120]!r}. "
                    "Copy one contiguous English sentence or table row exactly as written in an "
                    "evidence block (no translation or paraphrase; join pieces only with '...') "
                    "and give that block's evidence_id")
            req["evidence_id"] = block["evidence_id"]
        if not isinstance(req.get("description"), str) or not req["description"].strip():
            raise ValueError(f"requirements[{n}] needs a description")
        checks = req.get("checks")
        if not isinstance(checks, list) or not checks:
            raise ValueError(f"requirements[{n}] has no executable checks")
        for check in checks:
            validate_check(check, len(steps))
        req["requirement_id"] = stable_id("req", section_id, block["evidence_id"], quote)
        req["section_id"] = section_id
    # A "requirement" whose checks all observe steps before the action is a
    # precondition (e.g. "Identify reports the log page as supported"): it is
    # measured before the command under test and gates it. Moved there instead
    # of rejecting the whole scenario (measured: base:5.2.12 skipped over one
    # such entry). The scenario still needs at least one check on the action.
    setup_only = [r for r in requirements if not any(integer(c["step"]) >= action for c in r["checks"])]
    if len(setup_only) == len(requirements):
        action_name = steps[action]["opcode_name"]
        raise ValueError(
            f"every requirement only checks steps before the action. The action is steps_plan[{action}] "
            f"({action_name}) and step indexes are 0-based: give at least one requirement a check with "
            f"\"step\": {action} or later; observations of earlier steps belong in precondition_checks")
    if setup_only:
        conditions = structured.setdefault("precondition_checks", [])
        if not isinstance(structured.get("preconditions"), list) or not isinstance(conditions, list):
            raise ValueError("preconditions and precondition_checks must be arrays")
        structured["requirements"] = [r for r in requirements if r not in setup_only]
        for req in setup_only:
            structured["preconditions"].append(req["description"])
            conditions.append({"description": req["description"], "checks": req["checks"],
                               "moved_from_requirement": True})
    covered_conditions = structured.get("precondition_checks", [])
    preconditions = structured.get("preconditions", [])
    if not isinstance(covered_conditions, list) or not isinstance(preconditions, list):
        raise ValueError("preconditions and precondition_checks must be arrays")
    if not all(isinstance(c, dict) and isinstance(c.get("description"), str) for c in covered_conditions):
        raise ValueError("precondition checks need objects with descriptions")
    # A precondition gates the action, so only checks on steps BEFORE it count.
    # One that nothing before the action observes (a check on the action
    # itself, no check, or a description that matches no check) is kept as a
    # visible "not measured" note instead of rejecting the whole scenario:
    # measured, base:5.4.6/5.4.7 (Fabrics-only commands, "must be a Discovery
    # controller") were skipped this way, every run. The note makes plain the
    # result does not establish that condition; requirements still need checks.
    kept, unmeasured = [], []
    for condition in covered_conditions:
        checks = [c for c in condition.get("checks") or [] if isinstance(c, dict)]
        for check in checks:
            validate_check(check, len(steps))  # a malformed check is still an error
        early = [c for c in checks if integer(c["step"]) < action]
        if early:
            kept.append(dict(condition, checks=early))
        else:
            unmeasured.append(condition["description"])
    measured = {c["description"] for c in kept}
    unmeasured += [p for p in preconditions if isinstance(p, str) and p not in measured and p not in unmeasured]
    structured["precondition_checks"] = kept
    structured["preconditions"] = [c["description"] for c in kept]
    # Executed, but never a verdict: verify_tc keeps every requirement
    # UNVERIFIED while this list is non-empty (review: a "Discovery controller"
    # scenario that never checked the controller type ended as PASS).
    structured["unmeasured_preconditions"] = unmeasured
    if unmeasured:
        notes = structured.get("out_of_scope")
        if not isinstance(notes, list):
            notes = list(structured.get("unverified_conditions") or [])
        notes += [f"사전조건 미측정(action 전에 관측하는 스텝 없음 — 이 TC의 요구사항은 PASS/FAIL로 판정하지 않음): {d}"
                  for d in unmeasured]
        structured["out_of_scope"] = notes


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


def apply_fixed_fields(fields, constraints):
    """Write the scenario's fixed bits into `fields` and return what changed.

    The scenario already states those bits exactly; asking the argument
    author to copy them and rejecting any slip skipped whole targets
    (measured: Persistent Event Log ACT=3 rewritten to 2, NUMDL 0x4000 to
    0x03FF). The author still chooses every other bit and the buffer length,
    which are then checked against these values.
    """
    changes = []
    for c in constraints or []:
        field, mask, value = c["field"], integer(c["mask"]), integer(c["value"])
        current = integer(fields[field])
        merged = (current & ~mask) | value
        if merged != current:
            new = f"0x{merged:08X}" if field.startswith("cdw") else merged
            changes.append(f"{field} {fields[field]} -> {new}")
            fields[field] = new
    return changes


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
        if result and result.get("blocked_reason"):
            raise ValueError(f"step {i} not run (chain stopped earlier)")
        if not result or not result.get("started", True):
            raise ValueError(f"step {i} not run")
        if result.get("exit_code") is None:
            raise ValueError(f"step {i} did not complete (no exit status)")
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
    unmeasured = contract.get("unmeasured_preconditions") or []
    if unmeasured:
        # A requirement that depends on a condition nobody measured proves
        # nothing either way: not PASS, and a violation may be the unmet
        # condition rather than the drive.
        issues.append("사전조건 미측정이라 요구사항을 판정하지 않음: " + "; ".join(unmeasured))
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
        grounded = bool(block and quote_in(req.get("quote", ""), block["text"]))
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
