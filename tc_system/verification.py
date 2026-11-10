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
from tc_system import spec_fields

VERSION = 2
# data_length stays known only so stored records evaluate to "unevaluated":
# it compared the buffer length WE requested with a number, observing nothing
# about the device (2026-11-05 run: 68/64, 4100/4096 and 260/256 - three
# false FAILs from a 0-based NUMD slip in our own request).
CHECK_KINDS = {"completion", "result_bits", "data_length", "data_field", "data_all",
               "data_equal", "data_matches_write"}
SELF_REFERENCE_KINDS = {"data_length"}
FIELDS = {"nsid", "data_len", *(f"cdw{i}" for i in range(10, 16))}
CAPABILITIES = {"sequential", "zero_payload", "hex_payload", "completion_status",
                "cqe_bits", "data_bytes", "controller_reset", "power_cycle"}
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
    if opcode_entry.get("host_action"):
        return {}
    raw = int(opcode_entry["raw_opcode"], 16)
    if opcode_entry["command_set"] == "ADMIN":
        return {0x0A: {"cdw10": 0x7FF}, 0x09: {"cdw10": 0xFF},
                0x02: {"cdw10": 0xFF}, 0x06: {"cdw10": 0xFF},
                0x19: {"cdw11": 0xFFFF}, 0x1A: {"cdw11": 0xFFFF},
                0x10: {"cdw10": 0x3F},
                # Queue commands: the QID decides whether it is safe at all.
                0x00: {"cdw10": 0xFFFF}, 0x01: {"cdw10": 0xFFFF},
                0x04: {"cdw10": 0xFFFF}, 0x05: {"cdw10": 0xFFFF}}.get(raw, {})
    if opcode_entry["command_set"] == "NVM" and raw in {1, 2, 5}:
        return {"cdw10": 0xFFFFFFFF, "cdw11": 0xFFFFFFFF, "cdw12": 0xFFFF}
    return {}


# A step's role text naming its selector ("PLM Config FID 13h"). Measured: a
# setup step described as reading FID 13h was sent with CDW10=0x20D (HMB FID
# 0Dh, SEL 2) and its INVALID_FIELD "proved" a precondition about FID 13h.
_SELECTOR_TEXT = {
    (0x09, 0x0A): (r"(?:\bFID|Feature Identifier)", "FID"),
    (0x02,): (r"(?:\bLID|Log Page Identifier|Log Identifier)", "LID"),
    (0x06,): (r"\bCNS", "CNS"),
}


# A step that reads a support table names the id it looks up, not its own
# selector ("Supported Log Pages(LID 00h)에서 LID 7Eh 지원 여부").
_TABLE_TEXT_RE = re.compile(r"Supported Log Pages|Supported and Effects|지원 로그", re.I)


def selector_in_text(opcode_entry, text):
    """(label, value) when `text` names exactly one FID/LID/CNS value for this command."""
    if opcode_entry.get("command_set") != "ADMIN" or opcode_entry.get("host_action"):
        return None
    if _TABLE_TEXT_RE.search(str(text or "")):
        return None
    raw = int(opcode_entry["raw_opcode"], 16)
    for opcodes, (word, label) in _SELECTOR_TEXT.items():
        if raw in opcodes:
            values = {int(v, 16) for v in re.findall(word + r"\s*(?:=|:)?\s*(?:0x)?([0-9A-Fa-f]{1,2})h?(?![0-9A-Za-z])",
                                                        str(text or ""))}
            return (label, values.pop()) if len(values) == 1 else None
    return None


def pinned_value(constraints, field, mask):
    """The value `constraints` fix for every bit of `mask` in `field`, else None."""
    fixed, value = 0, 0
    for c in constraints or []:
        if c.get("field") == field:
            fixed |= integer(c["mask"])
            value = (value & ~integer(c["mask"])) | integer(c["value"])
    return value & mask if fixed & mask == mask else None


def normative_strength(quote):
    text = plain_text(quote or "")
    if re.search(r"\bshall\b|\bmust\b", text, re.I):
        return "SHALL"
    if re.search(r"\bshould\b", text, re.I):
        return "SHOULD"
    if re.search(r"\bmay\b", text, re.I):
        return "MAY"
    return "descriptive"


_UNSUPPORTED_PREMISE_RE = re.compile(r"not (?:be )?support|unsupported|does not implement|not implemented|"
                                     r"is not available|reserved", re.I)


def _bit_polarity(text):
    """"set"/"clear" when a description clearly states which, else None."""
    text = str(text or "")
    # Negated forms first, and removed before looking for the positive ones:
    # "supported\b" also matched the end of "unsupported" (review N03 - a
    # correct FSUPP=0 check was rewritten to FSUPP=1).
    negated = re.compile(r"\bun-?supported\b|\bnot\s+(?:be\s+)?supported\b|\b(?:does|do|is)\s*n[o']t\s+support"
                         r"|미지원\w*|지원하지\s*않\w*|지원되지\s*않\w*|지원 안\s*\w*", re.I)
    clear = re.search(r"=\s*0\b|0으로|0이어|0이면|0이고|'0'|가 0\b|cleared", text) or negated.search(text)
    rest = negated.sub(" ", text)
    is_set = re.search(r"=\s*1\b|1로 설정|1이어|1이고|'1'|가 1\b|지원해야|지원한다|지원함|지원하는|지원됨"
                       r"|\bsupported\b|\bsupports\b", rest, re.I)
    if bool(clear) == bool(is_set):
        return None
    return "clear" if clear else "set"


def _check_tests_bit(check):
    mask, value = integer(check.get("mask")), integer(check.get("value"))
    if mask & (mask - 1):
        return None
    op = check.get("operator", "eq")
    if op not in ("eq", "ne"):
        return None
    if (op == "eq") == (value == mask):
        return "set"
    return "clear"


def add_scope_notes(structured, new_notes):
    notes = structured.get("out_of_scope")
    if not isinstance(notes, list):
        notes = list(structured.get("unverified_conditions") or [])
    structured["out_of_scope"] = notes + list(new_notes)


def completion_status(result):
    if not result or not result.get("started", True):
        return None
    if result.get("host_action"):
        # Fixed host script: exit 0 = done and the controller answered again.
        return "SUCCESS" if result.get("exit_code") == 0 else None
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
# the same status "Invalid Command Opcode". Names are mapped to nvme-cli's
# token, and when both sides have a numeric code (spec_fields.STATUS_CODES and
# the "(0x2285)" nvme-cli prints) the codes decide: measured, COMPARE_FAILURE,
# UNRECOVERED_READ_ERROR and INVALID_QUEUE_IDENTIFIER never matched
# COMPARE_FAILED/READ_ERROR/QID_INVALID and four correct rejections were FAILs.
STATUS_ALIASES = spec_fields.STATUS_NAMES


def canonical_status(name):
    """A spec-style status name -> the token nvme-cli prints."""
    return spec_fields.normalize_status_name(name)


def status_matches(expected, result):
    """The step completed with `expected`: by token, else by (SCT, SC)."""
    actual = completion_status(result)
    if actual is None:
        return False
    want = canonical_status(expected)
    if actual == want:
        return True
    code = spec_fields.status_code_in_output((result or {}).get("stdout", ""))
    want_code = spec_fields.status_code_of_name(want)
    return code is not None and want_code is not None and code == want_code


def expected_status(step):
    return canonical_status(step.get("expected_status") or "SUCCESS")


def accepted_statuses(step):
    """The expected status plus any the spec allows instead (a variant's
    in-range Read of a never-written LBA may complete with Deallocated or
    Unwritten Logical Block when DULBE is enabled)."""
    return [expected_status(step)] + [canonical_status(s) for s in step.get("also_accept") or []]


def matches_expected(step, result):
    return any(status_matches(status, result) for status in accepted_statuses(step))


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
    """Bytes a write step sends. `payload_hex` that divides data_len is a
    pattern repeated to fill it (a 4 KiB block need not be spelled out in the
    prompt). One that does not is a structure: its bytes, then zeros for the
    rest (reserved fields are zero) - repeating a structure would write garbage
    into fields it never meant to set (measured: 8 targets skipped because a
    43-byte management structure did not divide 4096). Without payload_hex
    the buffer is zero-filled."""
    if step.get("direction") != "write":
        return b""
    raw = step.get("payload_hex")
    if raw is None:
        return bytes(step["data_len"])
    pattern = payload_bytes(raw)
    length = step["data_len"]
    if not pattern:
        raise ValueError("payload_hex is empty")
    if len(pattern) > length:
        raise ValueError(f"payload_hex has {len(pattern)} bytes but data_len={length}")
    if length % len(pattern):
        return pattern + bytes(length - len(pattern))
    return pattern * (length // len(pattern))


def payload_layout(step):
    """"repeat" or "structure" - how payload_for_step fills the buffer."""
    raw = step.get("payload_hex")
    if raw is None or step.get("direction") != "write":
        return None
    pattern = payload_bytes(raw)
    return "repeat" if pattern and step["data_len"] % len(pattern) == 0 else "structure"


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


def _byte_summary(data):
    import hashlib
    head = data[:16].hex()
    return f"len={len(data)} sha256={hashlib.sha256(data).hexdigest()[:16]} head={head}"


def _comparison_detail(data, other):
    if data == other:
        return f"{len(data)}바이트 일치"
    if len(data) != len(other):
        return f"길이 다름: {len(data)} vs {len(other)}"
    k = next(i for i, (a, b) in enumerate(zip(data, other)) if a != b)
    lo = k - k % 16
    return (f"byte {k}에서 처음 다름 (0x{data[k]:02X} vs 0x{other[k]:02X}); "
            f"offset {lo}: {data[lo:lo + 16].hex()} vs {other[lo:lo + 16].hex()}")


def validate_check(check, n_steps):
    if not isinstance(check, dict) or check.get("kind") not in CHECK_KINDS:
        raise ValueError(f"unsupported verification check {check!r}: kind must be one of "
                         f"{', '.join(sorted(CHECK_KINDS - SELF_REFERENCE_KINDS))}")
    missing = [k for k in (("step",) + (("mask", "value") if check["kind"] in {"result_bits", "data_field"} else ())
                           + (("offset", "width") if check["kind"] == "data_field" else ())
                           + (("other_step",) if check["kind"] in {"data_equal", "data_matches_write"} else ()))
               if check.get(k) is None]
    if missing:
        raise ValueError(f"check {check!r} has no {', '.join(missing)}")
    i = integer(check.get("step"))
    if not 0 <= i < n_steps:
        raise ValueError("check refers to a missing step")
    kind = check["kind"]
    if kind in SELF_REFERENCE_KINDS:
        raise ValueError("data_length compares the buffer length we requested, which observes nothing about "
                         "the device; check the returned structure's fields with data_field instead")
    if kind in {"data_equal", "data_matches_write"}:
        other = integer(check.get("other_step"))
        if not 0 <= other < i:
            raise ValueError("comparison source must be an earlier step")
    if kind == "data_all" and not 0 <= integer(check.get("value", 0)) <= 0xFF:
        raise ValueError("data_all value is one byte (0..0xFF)")
    if kind in {"result_bits", "data_field"}:
        mask, value = integer(check.get("mask")), integer(check.get("value"))
        if mask <= 0 or value < 0 or value & ~mask:
            raise ValueError("invalid comparison mask/value")
        operator = check.get("operator", "eq")
        if operator not in {"eq", "ne", "le", "ge"}:
            raise ValueError("unsupported comparison operator")
        # The masked value lies in 0..mask: these hold for every device.
        # Measured: "(AFI & 0x70) <= 0x70" was a requirement PASS.
        if (operator == "le" and value >= mask) or (operator == "ge" and value == 0):
            raise ValueError(f"check is always true ((x & {hex(mask)}) {operator} {hex(value)}): it cannot fail, "
                             "so it proves nothing - compare against the value the requirement demands")
        if kind == "data_field":
            width, offset = integer(check.get("width")), integer(check.get("offset"))
            if not 1 <= width <= 8 or not 0 <= offset < (1 << 20) or mask >= 1 << (8 * width):
                raise ValueError("invalid payload field range")
        elif mask > 0xFFFFFFFF:
            raise ValueError("CQE Dword 0 is 32 bits")


def _validate_shape(structured):
    """The nested shape, before anything reads it. A precondition the code
    cannot read used to disappear (review R08b: {"condition": ...} dropped,
    the TC passed) or crash a later step (R08a: a string where a check group
    belongs raised AttributeError and stopped the batch)."""
    preconditions = structured.get("preconditions", [])
    if preconditions is None:
        preconditions = structured["preconditions"] = []
    if not isinstance(preconditions, list):
        raise ValueError("preconditions must be an array of strings")
    for n, p in enumerate(preconditions):
        if not isinstance(p, str) or not p.strip():
            raise ValueError(f"preconditions[{n}] must be a non-empty string (one measurable condition), got {p!r}")
    for key in ("precondition_checks", "requirements"):
        groups = structured.get(key, [])
        if groups is None:
            groups = structured[key] = []
        if not isinstance(groups, list):
            raise ValueError(f"{key} must be an array of objects")
        for n, group in enumerate(groups):
            if not isinstance(group, dict):
                raise ValueError(f"{key}[{n}] must be an object with description and checks, got {group!r}")
            if not isinstance(group.get("description"), str) or not group["description"].strip():
                raise ValueError(f"{key}[{n}].description must be a non-empty string")
            checks = group.get("checks")
            if not isinstance(checks, list) or not all(isinstance(c, dict) for c in checks):
                raise ValueError(f"{key}[{n}].checks must be an array of check objects")


# Spellings of a constrained field the model uses for the same register.
# CDW1 is the NSID by the spec's own command layout.
_FIELD_ALIASES = {"cdw1": "nsid", "cdw01": "nsid", "namespace_id": "nsid", "data_length": "data_len",
                  **{f"cdw{i:02d}": f"cdw{i}" for i in range(10, 16)}}


def _step_no(check):
    try:
        return integer(check.get("step"))
    except ValueError:
        return None


def _normalize_contract(structured):
    """Mechanical slips the harness can undo without guessing intent, so the
    one scenario retry is spent on the real problem. Measured (2026-11-06,
    520 scenario replies replayed): 49 checks with kind "offset"/"data" that
    carry offset/width/mask/value, 42 constraints with mask 0 (fix nothing),
    35 constraints and 23 data_field checks with no mask, 20 constraints on
    "cdw1" - each one used up the retry or skipped the target. Every change is
    recorded in check_repairs (printed as 검사식 보정)."""
    repairs = structured.setdefault("check_repairs", [])
    for k, step in enumerate(structured.get("steps_plan") or []):
        if not isinstance(step, dict):
            continue
        constraints = step.get("field_constraints")
        if isinstance(constraints, dict):
            constraints = [constraints]
        if not isinstance(constraints, list):
            continue
        kept = []
        for c in constraints:
            if not isinstance(c, dict):
                kept.append(c)
                continue
            c = dict(c)
            field = str(c.get("field") or "").strip().lower()
            field = _FIELD_ALIASES.get(field, field)
            if field != c.get("field"):
                repairs.append({"where": f"steps_plan[{k}].field_constraints", "step": k, "description": "",
                                "problem": f"고정 필드 이름 {c.get('field')!r}", "reads": field})
                c["field"] = field
            if c.get("mask") is None and c.get("value") is not None and field in FIELDS:
                c["mask"] = "0xFFFFFFFF"
                repairs.append({"where": f"steps_plan[{k}].field_constraints", "step": k, "description": "",
                                "problem": f"{field} 고정값 {c.get('value')}에 mask 없음", "reads": f"{field} 전체(mask 0xFFFFFFFF)"})
            try:
                if c.get("mask") is not None and integer(c["mask"]) == 0:
                    repairs.append({"where": f"steps_plan[{k}].field_constraints", "step": k, "description": "",
                                    "problem": f"{field} mask 0(아무 비트도 고정하지 않음)", "reads": "고정 없음으로 제거"})
                    continue
            except ValueError:
                pass
            kept.append(c)
        step["field_constraints"] = kept
    groups = [(f"requirements[{n}]", g) for n, g in enumerate(structured.get("requirements") or [])]
    groups += [(f"precondition_checks[{n}]", g) for n, g in enumerate(structured.get("precondition_checks") or [])]
    for where, group in groups:
        for m, check in enumerate(group.get("checks") or []):
            if not isinstance(check, dict):
                continue
            at = re.fullmatch(r"\s*([^@]*?)\s*@\s*(\d+)\s*\+\s*(\d+)\s*", str(check.get("field") or ""))
            if at and check.get("offset") is None and check.get("width") is None:
                # "GENCTR@0+8", "offset@0+1": the model wrote offset+width into the name.
                repairs.append({"where": f"{where}.checks[{m}]", "step": _step_no(check),
                                "description": group.get("description", ""),
                                "problem": f"필드 이름 {check['field']!r}에 오프셋/폭을 적음",
                                "reads": f"offset {at.group(2)}, {at.group(3)}바이트"})
                check.pop("field")
                check.update(offset=int(at.group(2)), width=int(at.group(3)), label=at.group(1) or None)
            if check.get("kind") not in CHECK_KINDS and "offset" in check and "width" in check:
                repairs.append({"where": f"{where}.checks[{m}]", "step": _step_no(check),
                                "description": group.get("description", ""),
                                "problem": f"검사 종류 {check.get('kind')!r}(offset/width가 있는 반환 데이터 검사)",
                                "reads": "data_field"})
                check["kind"] = "data_field"
            if check.get("kind") == "data_field" and check.get("mask") is None and not check.get("field"):
                try:
                    width = integer(check.get("width"))
                except ValueError:
                    continue
                if 1 <= width <= 8:
                    check["mask"] = hex((1 << (8 * width)) - 1)
                    repairs.append({"where": f"{where}.checks[{m}]", "step": _step_no(check),
                                    "description": group.get("description", ""),
                                    "problem": "mask 없음", "reads": f"{width}바이트 전체(mask {check['mask']})"})


def validate_plan_contract(structured, evidence, section_id, available_opcodes, target_requirement=None,
                           device_support=None):
    _validate_shape(structured)
    _normalize_contract(structured)
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
        if step["expected_status"] != "SUCCESS" and spec_fields.status_code_of_name(step["expected_status"]) is None:
            # Compared by name only, any other spelling of the same code is a
            # "violation" (2026-11-06: READ_ERROR 2/81h vs UNRECOVERED_ERROR).
            import difflib
            close = difflib.get_close_matches(step["expected_status"], list(spec_fields.STATUS_CODES), n=4, cutoff=0.4)
            raise ValueError(f"steps_plan[{k}] expected_status {status!r} is not a status code this harness knows, "
                             f"so the device's answer could not be compared by (SCT, SC)"
                             + (f"; did you mean one of: {', '.join(close)}" if close else "")
                             + " (use the status name exactly as the spec's status table or nvme-cli prints it)")
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
                raise ValueError(f"steps_plan[{k}].field_constraints {c!r}: field must be one of "
                                 f"{', '.join(sorted(FIELDS))}")
            if c.get("mask") is None or c.get("value") is None:
                raise ValueError(f"steps_plan[{k}].field_constraints {c!r} needs both mask and value")
            mask, value = integer(c.get("mask")), integer(c.get("value"))
            if not 0 < mask <= 0xFFFFFFFF or value < 0 or value & ~mask:
                raise ValueError(f"steps_plan[{k}].field_constraints {c!r}: value has bits outside mask "
                                 f"(value & ~mask = {hex(value & ~mask & 0xFFFFFFFF)}) or mask is not 32-bit - "
                                 "set mask to cover every bit the value fixes")
            masks[c["field"]] = masks.get(c["field"], 0) | mask
        op = by_name[step["opcode_name"]]
        _check_step_selectors(k, step, op, constraints)
        for c in constraints:  # including what the role just pinned
            masks[c["field"]] = masks.get(c["field"], 0) | integer(c["mask"])
        required = required_selector_masks(op)
        # The action's selectors ARE the test, so the scenario must state them.
        # A setup/verify step that leaves them open gets them frozen from its
        # first authoring instead (tc_writer.freeze_selectors), so a retry still
        # cannot switch e.g. Identify CNS under a precondition check.
        if k == action and any(masks.get(field, 0) & mask != mask for field, mask in required.items()):
            raise ValueError(f"steps_plan[{k}] {step['opcode_name']} (the action): field_constraints must fix "
                             f"its selector/address fields {{field: mask}} = "
                             + ", ".join(f"{f}: {hex(m)}" for f, m in required.items()))
    _validate_comparisons(structured, steps, by_name)
    _validate_returned_layouts(structured, steps, by_name)
    structures = _resolve_structure_checks(structured, steps, by_name)
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
            if steps[integer(check["step"])]["phase"] == "cleanup":
                raise ValueError(f"requirements[{n}] checks cleanup step {check['step']}: cleanup steps restore "
                                 "state and run even after a failure; they are not observations")
        req["requirement_id"] = stable_id("req", section_id, block["evidence_id"], quote)
        req["section_id"] = section_id
        req["strength"] = normative_strength(quote)
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
    if target_requirement:
        _bind_target_requirement(structured, steps, action, target_requirement)
    support_notes = _support_premises(structured, steps, action, by_name, structures, device_support)
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
    unmeasured += [n for n in support_notes if n not in unmeasured]
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


def _bind_target_requirement(structured, steps, action, target):
    """The TC exists to test one extracted "shall" sentence: a requirement
    checked on the action must quote it (or a part of it), and an abort rule
    fixes the action's expected completion to the status it names."""
    text = target["text"]
    matched = [r for r in structured["requirements"]
               if quote_in(r.get("quote", ""), text) or quote_in(text, r.get("quote", ""))]
    if not matched:
        raise ValueError(f"TARGET_REQUIREMENT is not tested: one requirement checked on the action must quote "
                         f"it (or a part of it): {text[:160]!r}")
    for req in matched:
        req["target_requirement_id"] = target["requirement_id"]
    _require_host_event(steps, matched, target)
    reasons = [_target_unobserved(r, target, steps) for r in matched]
    if all(reasons):
        raise ValueError(f"TARGET_REQUIREMENT is not observed: {reasons[0]}. The requirement quoting it must read "
                         "what the sentence is about (a data_field/result_bits/data_* check on the action or a later "
                         "step), with the action expected to succeed unless the sentence itself is about a rejection")
    if target.get("kind") == "abort" and target.get("expected_status"):
        want = canonical_status(target["expected_status"])
        if canonical_status(steps[action].get("expected_status")) != want:
            raise ValueError(f"TARGET_REQUIREMENT is an abort rule: steps_plan[{action}] (the action) must provoke "
                             f"its condition and expect {want}")


# Commands that only report: they cannot establish the state a "retained
# across a reset" sentence is about.
READ_ONLY_COMMANDS = {"Identify", "Get Features", "Get Log Page", "Read", "Compare", "Verify", "Get LBA Status",
                      "Reservation Report", "Security Receive", "Directive Receive", "NVMe-MI Receive",
                      "Migration Receive", "Track Receive", "I/O Management Receive"}


def _require_host_event(steps, matched, target):
    """A sentence about state across a reset or a power loss is tested only if
    the chain performs that event and the requirement observes a step after
    it. Without this the model could "test" "retained across power cycles"
    with a single Get Log Page (nothing forced it to use the host step)."""
    from tc_system.execution.host_actions import HOST_ACTIONS
    names = target.get("host_steps")
    if names is None:
        names = [n for n, a in HOST_ACTIONS.items() if a in (target.get("host_actions") or [])]
    if not names:
        return
    hosts = [i for i, s in enumerate(steps) if s["opcode_name"] in names]
    observed = {integer(c["step"]) for r in matched for c in r.get("checks") or []
                if isinstance(c, dict) and c.get("step") is not None}
    usable = [h for h in hosts if any(o > h for o in observed)]
    for h in usable:
        # "Retained across" needs the state set or recorded BEFORE the event,
        # and nothing after it that could set it again before the check
        # (review: Reset -> Set -> Get passed as retention).
        if not any(s["opcode_name"] not in names for s in steps[:h]):
            raise ValueError(f"TARGET_REQUIREMENT is about state across a reset/power cycle: the state must be set or "
                             f"recorded by a step BEFORE the host step at {h}")
        last = max(o for o in observed if o > h)
        changers = sorted({s["opcode_name"] for s in steps[h + 1:last] if s["opcode_name"] not in READ_ONLY_COMMANDS
                           and s["opcode_name"] not in names})
        if changers:
            raise ValueError(f"TARGET_REQUIREMENT is about state across a reset/power cycle: {', '.join(changers)} "
                             f"runs between the host step at {h} and the check at {last}, so the check could see a "
                             "state set after the event, not one retained across it")
    if not usable:
        options = " or ".join(repr(n) for n in names)
        raise ValueError(f"TARGET_REQUIREMENT is about state across a reset/power cycle: steps_plan must perform it "
                         f"with a {options} step (setup or verify, after the state is established), and the "
                         f"requirement quoting it must check a step that runs after that host step "
                         f"(host steps now at {hosts or 'none'}, its checks read steps {sorted(observed)})")


def _check_step_selectors(k, step, op, constraints):
    """Rules on a plan step's fixed fields that do not need the model's reply."""
    if op.get("host_action"):
        return
    raw = int(op["raw_opcode"], 16)
    # The role names the selector: pin it when open, reject a contradiction.
    named = selector_in_text(op, step.get("role"))
    if named:
        label, value = named
        pinned = pinned_value(constraints, "cdw10", 0xFF)
        if pinned is None:
            constraints.append({"field": "cdw10", "mask": "0x000000FF", "value": hex(value),
                                "from_role": True})
        elif pinned != value:
            raise ValueError(f"steps_plan[{k}] {step['opcode_name']}: role says {label} {value:02X}h but "
                             f"field_constraints fix {label} {pinned:02X}h (cdw10[7:0]) - make them the same")
    if op["command_set"] == "ADMIN" and raw in spec_fields.QUEUE_COMMANDS:
        qid = pinned_value(constraints, "cdw10", 0xFFFF)
        hazard = spec_fields.queue_command_hazard("ADMIN", raw, qid if qid is not None else 1,
                                                  step.get("expected_status"))
        if hazard:
            raise ValueError(f"steps_plan[{k}] {step['opcode_name']}: {hazard}"
                             + ("" if qid is not None else " (fix the QID in cdw10[15:0])"))
    if op["command_set"] == "ADMIN" and raw == 0x09:
        fid = pinned_value(constraints, "cdw10", 0xFF)
        if fid in spec_fields.HOST_OWNED_SET_FEATURES:
            raise ValueError(f"steps_plan[{k}] Set Features FID {fid:02X}h: "
                             f"{spec_fields.HOST_OWNED_SET_FEATURES[fid]} - changing it is not a device test")
        codec = spec_fields.FEATURE_CODECS.get(fid) if fid is not None else None
        for mask, values in (codec or {}).get("irreversible", {}).items():
            value = pinned_value(constraints, "cdw11", mask)
            if value in values:
                raise ValueError(f"steps_plan[{k}] Set Features FID {fid:02X}h value {value}: this state cannot be "
                                 "undone by Set Features (power cycle or permanent) - not sent by this harness")
        if fid is not None and codec is None and canonical_status(step.get("expected_status")) == "SUCCESS":
            raise ValueError(f"steps_plan[{k}] Set Features FID {fid:02X}h expected to succeed: the harness does not "
                             "know how to put this feature's original value back, so it does not change it; test a "
                             "rejection, or a feature it can restore")


_IDENTIFY_ROLE = ((re.compile(r"Identify Controller|컨트롤러 식별"), 0x01),
                  (re.compile(r"Identify Namespace(?! (?:List|Granularity|Identification|ID Descriptor))"), 0x00))


# Logs whose bytes change without the test doing anything wrong: Firmware Slot
# AFI bits 6:4 (next-activation slot) clear on the reset that activates it
# (2026-11-06: 0x11 -> 0x01 "failed" a whole-log comparison), SMART/Health
# counters and temperature move between any two reads.
_DYNAMIC_LOGS = {0x02: "SMART / Health Information (counters, temperature)",
                 0x03: "Firmware Slot Information (AFI bits 6:4: slot to activate at the next reset)"}


def _validate_returned_layouts(structured, steps, by_name):
    """Checks on returned data whose layout the spec defines differently than
    the check assumes: Get Features DW0 bits the feature leaves reserved
    (2026-11-06: Arbitration low byte compared with 8; AB is bits 2:0), the
    SEL=011b capabilities DW0 (bits 2:0 only - a current-value bit read from it
    "measured" DULBE), whole-log comparison of a log that changes by itself."""
    groups = [(f"requirements[{n}]", g) for n, g in enumerate(structured.get("requirements") or [])]
    groups += [(f"precondition_checks[{n}]", g) for n, g in enumerate(structured.get("precondition_checks") or [])]

    def pinned(k, mask):
        return pinned_value(steps[k].get("field_constraints"), "cdw10", mask)

    def op_of(k):
        op = by_name.get(steps[k]["opcode_name"]) or {}
        return None if op.get("host_action") else (op.get("command_set"), int(op["raw_opcode"], 16))

    for where, group in groups:
        for m, check in enumerate(group.get("checks") or []):
            if not isinstance(check, dict):
                continue
            try:
                k = integer(check.get("step"))
            except ValueError:
                continue
            if not 0 <= k < len(steps):
                continue
            if check.get("kind") == "result_bits" and op_of(k) == ("ADMIN", 0x0A):
                fid, sel = pinned(k, 0xFF), pinned(k, 0x700)
                try:
                    mask = integer(check.get("mask"))
                except ValueError:
                    continue
                if sel is not None and sel >> 8 == 3:
                    defined, what = 0x7, "the SEL=011b capabilities (bits 2:0: saveable, namespace specific, changeable)"
                else:
                    codec = spec_fields.FEATURE_CODECS.get(fid) if fid is not None else None
                    if not codec or codec.get("buffer") or not (codec["value"] | codec["instance"]):
                        continue
                    defined = codec["value"] | codec["instance"]
                    what = f"FID {fid:02X}h ({codec['name']}) CQE Dword 0 (defined bits {hex(defined)})"
                if mask & ~defined:
                    raise ValueError(f"{where}.checks[{m}] reads bits {hex(mask & ~defined)} of step {k}'s "
                                     f"completion, which {what} leaves reserved - check the defined field only")
            if check.get("kind") == "data_equal":
                for j in (k, check.get("other_step")):
                    try:
                        j = integer(j)
                    except ValueError:
                        continue
                    if 0 <= j < len(steps) and op_of(j) == ("ADMIN", 0x02) and pinned(j, 0xFF) in _DYNAMIC_LOGS:
                        raise ValueError(f"{where}.checks[{m}] compares the whole LID {pinned(j, 0xFF):02X}h log "
                                         f"({_DYNAMIC_LOGS[pinned(j, 0xFF)]}), whose bytes change by design - "
                                         "compare the specific field the requirement is about with data_field")


def _plan_fields(plan_step):
    fields = {}
    for c in plan_step.get("field_constraints") or []:
        mask = integer(c["mask"])
        if mask:
            fields[c["field"]] = (integer(fields.get(c["field"], 0)) & ~mask) | integer(c["value"])
    return fields


def _resolve_structure_checks(structured, steps, by_name):
    """Named field checks become offsets; raw offsets on a known structure
    must read the field their description names. Returns {step: structure}."""
    groups = [(f"requirements[{n}]", r) for n, r in enumerate(structured.get("requirements") or [])
              if isinstance(r, dict)]
    groups += [(f"precondition_checks[{n}]", p) for n, p in enumerate(structured.get("precondition_checks") or [])
               if isinstance(p, dict)]
    structures = {}
    for where, group in groups:
        checks = group.get("checks")
        if not isinstance(checks, list):
            continue
        kept = []
        for check in checks:
            if isinstance(check, dict) and check.get("kind") in SELF_REFERENCE_KINDS:
                add_scope_notes(structured, [f"{where}: 요청 길이 자기비교(data_length)는 장비를 관측하지 않아 제외함"])
                continue
            kept.append(check)
        if checks and not kept:
            raise ValueError(f"{where} only had a data_length check, which compares the length we requested and "
                             "observes nothing; check the returned data with data_field/data_all instead")
        group["checks"] = kept
        for m, check in enumerate(kept):
            if not isinstance(check, dict) or check.get("kind") != "data_field":
                continue
            k = integer(check.get("step"))
            if not 0 <= k < len(steps):
                continue  # validate_check reports it
            plan_step, op = steps[k], by_name[steps[k]["opcode_name"]]
            structure = structures.get(k)
            if structure is None:
                fields = _plan_fields(plan_step)
                raw = None if op.get("host_action") else int(op["raw_opcode"], 16)
                if op.get("command_set") == "ADMIN" and raw == 0x06 and "cdw10" not in fields:
                    cns = next((v for rx, v in _IDENTIFY_ROLE if rx.search(str(plan_step.get("role") or ""))), None)
                    if cns is not None:
                        plan_step.setdefault("field_constraints", []).append(
                            {"field": "cdw10", "mask": "0x000000FF", "value": hex(cns), "from_role": True})
                        fields["cdw10"] = cns
                structure = spec_fields.structure_of(op, fields)
                if structure:
                    structures[k] = structure
            if check.get("field") and all(check.get(x) is not None for x in ("offset", "width", "mask", "value")):
                # A complete offset check with a name on it ("SSTAT", "raw",
                # "offset@0+1"): the name is a label unless the registry knows
                # it for this structure. Measured (2026-11-06): 32 targets
                # skipped as "CNS/LID is not fixed" although the LID was fixed -
                # Sanitize Status, Firmware Slot, SMART have no named fields.
                resolvable = False
                if structure is not None:
                    try:
                        spec_fields.resolve_named_check(check, structure)
                        resolvable = True
                    except ValueError:
                        pass
                if not resolvable:
                    kept[m] = check = {key: v for key, v in check.items() if key != "field"} | {"label": check["field"]}
            if structure is None and check.get("field"):
                selector = pinned_value(plan_step.get("field_constraints"), "cdw10", 0xFF)
                if selector is None and op.get("command_set") == "ADMIN" and raw in (0x02, 0x06):
                    raise ValueError(f"{where}.checks[{m}] reads field {check['field']!r} from step {k} "
                                     f"({plan_step['opcode_name']}), whose CNS/LID is not fixed: fix it in that "
                                     "step's field_constraints (cdw10[7:0])")
                what = (f"{'LID' if raw == 0x02 else 'CNS'} {selector:02X}h data"
                        if selector is not None and raw in (0x02, 0x06) else f"step {k} ({plan_step['opcode_name']}) data")
                raise ValueError(f"{where}.checks[{m}]: {what} has no named fields in this harness (named fields: "
                                 "Identify Controller/Namespace, Supported Log Pages, Commands Supported and "
                                 f"Effects, FID Supported and Effects); write {check['field']!r} as offset/width/"
                                 "mask/value from the spec's table for that structure")
            named = bool(check.get("field"))
            if check.get("field"):
                kept[m] = check = spec_fields.resolve_named_check(check, structure)
            if structure is None:
                continue
            siblings = {i["field"] for c in kept if c is not check and isinstance(c, dict)
                        and c.get("kind") == "data_field" and c.get("step") == check.get("step")
                        for i in [spec_fields.interpret_check(c, structure)] if i and i.get("field")}
            problem = spec_fields.check_matches_description(check, structure, group.get("description"), siblings)
            if problem is None:
                polarity, tests = _bit_polarity(group.get("description")), None
                try:
                    tests = _check_tests_bit(check)
                except (ValueError, TypeError):
                    pass
                if polarity and tests and polarity != tests:
                    problem = (f"설명은 비트가 {'1' if polarity == 'set' else '0'}인 조건인데 검사식 "
                               f"({check.get('operator', 'eq')} {check.get('value')}, mask {check.get('mask')})은 "
                               f"{'1' if tests == 'set' else '0'}을 확인함")
                    if named:
                        # The model named the field and wrote its value; the
                        # description is read by a heuristic. Neither wins.
                        raise ValueError(f"{where}.checks[{m}]: the description {group.get('description')!r} "
                                         f"says the bit is {'1' if polarity == 'set' else '0'} but the check "
                                         f"{check.get('field')} value={check.get('value')} tests "
                                         f"{'1' if tests == 'set' else '0'}; make them agree")
            if problem:
                # The description says which field it means: write that field
                # (the harness encodes, the model names) instead of skipping the
                # target. Measured: 106 of 215 Identify checks in one run read a
                # different field than their description - nearly all a
                # mis-encoding of a clearly named field.
                repaired = _repair_check(check, structure, group.get("description"), siblings)
                if repaired is None:
                    title = (spec_fields.STRUCTURES.get(structure) or spec_fields.ENTRY_LOGS.get(structure))[0]
                    raise ValueError(f"{where}.checks[{m}] on step {k} ({title}): {problem}. Prefer a named check, "
                                     f"e.g. {{\"kind\": \"data_field\", \"step\": {k}, \"field\": \"OACS.NMS\", "
                                     "\"value\": 1}")
                kept[m] = repaired
                structured.setdefault("check_repairs", []).append(
                    {"where": where, "step": k, "description": group.get("description"), "problem": problem,
                     "before": {x: check.get(x) for x in ("offset", "width", "mask", "value", "operator")},
                     "after": {x: repaired.get(x) for x in ("offset", "width", "mask", "value", "operator")},
                     "reads": spec_fields.interpret_check(repaired, structure)["label"]})
    return structures


def _repair_check(check, structure, description, siblings=()):
    """The check rewritten to the one field/bit the description names, or
    None when the description does not single one out."""
    polarity = _bit_polarity(description)
    try:
        tested = _check_tests_bit(check)
    except (ValueError, TypeError):
        tested = None
    want_set = (polarity or tested or "set") == "set"
    if structure in spec_fields.ENTRY_LOGS:
        ids = spec_fields.wanted_ids(structure, description)
        if len(ids) != 1:
            return None
        title, bit_name, bit, _ = spec_fields.ENTRY_LOGS[structure]
        base = 1024 if structure == "cse" and integer(check.get("offset", 0)) >= 1024 else 0
        return dict(check, offset=base + ids.pop() * 4, width=1, mask=hex(1 << bit),
                    value=hex((1 << bit) if want_set else 0), operator="eq", repaired=True)
    target = spec_fields.described_target(structure, description, siblings)
    if target is None:
        return None
    name, bit_name = target
    field = spec_fields.STRUCTURES[structure][1][name]
    out = dict(check, offset=field["offset"], width=field["width"], operator=check.get("operator", "eq"), repaired=True)
    if bit_name:
        bits = field["bits"][bit_name]["bits"]
        if isinstance(bits, tuple):
            return None  # a multi-bit value: its expected number cannot be inferred
        out.update(mask=hex(1 << bits), value=hex((1 << bits) if want_set else 0), operator="eq")
        return out
    if field["bits"]:
        return None  # a bit field without the bit named: which bit is meant is unknown
    full = (1 << (8 * field["width"])) - 1
    mask, value = integer(check.get("mask", full)), integer(check.get("value", 0))
    if mask > full or value & ~mask:
        mask = full
    if value & ~mask:
        return None
    out.update(mask=hex(mask), value=hex(value))
    return out


def _support_premises(structured, steps, action, by_name, structures, device_support):
    """Negative tests that rely on something being unsupported. Returns notes
    for unmeasured_preconditions; raises when the drive is known to contradict
    the premise. Measured: "LID 09h is unsupported" and "CNS 10h is
    unsupported" were assumed, the drive answered SUCCESS, and both became FAILs."""
    notes = []
    if not device_support:
        return notes
    step, op = steps[action], by_name[steps[action]["opcode_name"]]
    if op.get("host_action") or op.get("command_set") != "ADMIN":
        return notes
    raw, expected = int(op["raw_opcode"], 16), canonical_status(step.get("expected_status"))
    selector = pinned_value(step.get("field_constraints"), "cdw10", 0xFF)
    if selector is None:
        return notes
    quotes = " ".join(str(r.get("quote", "")) for r in structured.get("requirements") or [] if isinstance(r, dict))
    if raw == 0x02 and expected == "INVALID_LOG_PAGE":
        known = (device_support.get("lids") or {}).get(selector)
        if known is True:
            raise ValueError(f"this drive reports LID {selector:02X}h as supported (Supported Log Pages, probed at "
                             "the start of the run): a test expecting INVALID_LOG_PAGE for it has a false premise; "
                             "use a reserved or unsupported LID, or test the supported log")
        measured = _premise_measured(structured, structures, ("supported_logs", selector))
        if known is None and not measured:
            notes.append(f"LID {selector:02X}h 미지원 여부가 측정되지 않음(Supported Log Pages로 확인 필요)")
    if raw in (0x09, 0x0A) and expected == "INVALID_FIELD":
        known = (device_support.get("fids") or {}).get(selector)
        about_support = bool(_UNSUPPORTED_PREMISE_RE.search(quotes))
        if known is False and not about_support:
            raise ValueError(f"this drive does not support FID {selector:02X}h (probed at the start of the run), so "
                             "INVALID_FIELD would come from the FID itself and cannot show that the field this "
                             "requirement is about was checked; use a supported FID")
        if known is True and about_support and "reserved" not in quotes.lower():
            raise ValueError(f"this drive supports FID {selector:02X}h (probed): a requirement about an unsupported "
                             "feature cannot be tested with it")
        # No probe result is not the same as unmeasured: this TC may read the
        # FID's own FSUPP=0 before the action (review N02).
        if known is None and not _premise_measured(structured, structures, ("fid_effects", selector)):
            notes.append(f"FID {selector:02X}h 지원 여부가 측정되지 않음 — INVALID_FIELD가 FID 때문인지 다른 필드 때문인지 "
                         "구분할 수 없음")
    return notes


def _premise_measured(structured, structures, entry):
    """A precondition check reads `entry`'s own support bit and requires it clear."""
    for p in structured.get("precondition_checks") or []:
        for c in (p.get("checks") or []) if isinstance(p, dict) else []:
            if not isinstance(c, dict) or c.get("kind") != "data_field":
                continue
            try:
                if _check_says_unsupported(c, structures.get(integer(c["step"])), entry):
                    return True
            except (KeyError, TypeError, ValueError):
                continue
    return False


def _planned_range(plan_step, op):
    if op.get("host_action"):
        return None
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
        if op_i.get("host_action") or op_j.get("host_action"):
            raise ValueError(f"step {i} vs step {j}: a host step (reset/power cycle) has no data to compare")
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


_NVM_DATA_OPCODES = {0x01, 0x02, 0x05}  # Write, Read, Compare


def _bytes_surely_moved(step):
    """None when the transfer size is known (not an NVM Read/Write/Compare, or
    the LBA size was measured). Otherwise the bytes the device moved for
    certain: (NLB + 1) x 512, the smallest LBA size (LBADS >= 9). The buffer
    is sized from a guess, so a check past that reads bytes the device may
    never have written (follow-up review: data_all/data_field still judged)."""
    if step.get("mode") != "io-passthru" or step.get("lba_bytes"):
        return None
    try:
        if integer(step.get("opcode", "0x0")) not in _NVM_DATA_OPCODES:
            return None
        return ((integer(step.get("cdw12", "0x0")) & 0xFFFF) + 1) * 512
    except ValueError:
        return 0


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
            same = any(status_matches(s, result) for s in accepted_statuses(step))
            ok = same if check.get("operator", "eq") == "eq" else not same
            return {"check": check, "result": "satisfied" if ok else "violated", "observed": observed,
                    "expected": expected, "detail": f"{observed!r} {check.get('operator', 'eq')} {expected!r}"
                    + (" (같은 상태 코드)" if same and observed != expected else "")}
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
                moved = _bytes_surely_moved(step)
                if kind == "data_all" and moved is not None and len(data) > moved:
                    raise ValueError(f"LBA 크기가 측정되지 않아 앞 {moved}바이트만 확실히 전송됨 — 버퍼 전체 검사"
                                     "(data_all)는 하지 않음")
                if kind == "data_field" and moved is not None \
                        and integer(check["offset"]) + integer(check["width"]) > moved:
                    raise ValueError(f"LBA 크기가 측정되지 않아 앞 {moved}바이트만 확실히 전송됨 — 그 뒤의 필드는 "
                                     "읽지 않음")
                if kind == "data_all":
                    # "every byte" is about the whole buffer: a short capture
                    # (one zero byte for a 512-byte read) proves nothing.
                    if step.get("data_len") and len(data) != integer(step["data_len"]):
                        raise ValueError(f"captured {len(data)} of {step['data_len']} bytes; data_all needs the "
                                         "whole buffer")
                    want = integer(check.get("value", 0))
                    bad = next((k for k, b in enumerate(data) if b != want), None)
                    ok = bad is None if check.get("operator", "eq") == "eq" else bad is not None
                    detail = (f"{len(data)}바이트 전부 0x{want:02X}" if bad is None else
                              f"byte {bad} = 0x{data[bad]:02X} (기대 0x{want:02X}), 전체 {len(data)}바이트")
                    return {"check": check, "result": "satisfied" if ok else "violated",
                            "observed": None if bad is None else f"byte {bad}=0x{data[bad]:02X}",
                            "expected": f"all 0x{want:02X}", "detail": detail}
                elif kind == "data_field":
                    offset, width = integer(check["offset"]), integer(check["width"])
                    if len(data) < offset + width:
                        raise ValueError("response too short to observe the requested field")
                    observed = int.from_bytes(data[offset:offset + width], "little")
                else:
                    j = integer(check["other_step"])
                    if not matches_expected(steps[j], results.get(j)):
                        raise ValueError("comparison source did not complete as expected")
                    if step.get("data_len") and len(data) != integer(step["data_len"]):
                        raise ValueError(f"step {i}: captured {len(data)} of {step['data_len']} bytes")
                    other = (payload_for_step(steps[j]) if kind == "data_matches_write"
                             else decode_payload(results.get(j)))
                    if kind == "data_equal" and other is not None and steps[j].get("data_len") \
                            and len(other) != integer(steps[j]["data_len"]):
                        raise ValueError(f"step {j}: captured {len(other)} of {steps[j]['data_len']} bytes")
                    if other is None or (kind == "data_matches_write" and steps[j].get("direction") != "write"):
                        raise ValueError("comparison source bytes unavailable")
                    if kind == "data_matches_write" and not any(other):
                        raise ValueError("a zero-filled write cannot be told apart from unwritten LBAs")
                    window = comparison_window(step, steps[j])
                    for s in (step, steps[j]):
                        # The buffer is NLB x LBA size; without the size the
                        # device may have moved fewer bytes than the buffer
                        # (2026-11-06: 4 blocks into 4096 B, "differs from 2048").
                        if _bytes_surely_moved(s) is not None:
                            raise ValueError("LBA 크기가 측정되지 않아 장치가 실제로 옮긴 범위를 알 수 없음 — 비교하지 않음")
                    other = _compared_slice(data, other, window)
                    # Equality on the full bytes; only a summary is stored. The
                    # full hex was copied into verification, criteria_results
                    # and the judge prompt (measured: a 95,847-character prompt).
                    op = check.get("operator", "eq")
                    same = data == other
                    ok = same if op == "eq" else not same
                    observed, expected = _byte_summary(data), _byte_summary(other)
                    return {"check": check, "result": "satisfied" if ok else "violated",
                            "observed": observed, "expected": expected,
                            "detail": _comparison_detail(data, other)}
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


def _support_entry_of(step):
    """(support table, id) a negative test's premise is about: the LID of a
    Get Log Page, the FID of a Get/Set Features, the opcode itself for an
    expected INVALID_OPCODE. None when no support table covers it."""
    try:
        raw = integer(step["opcode"])
        selector = integer(step.get("cdw10", "0x0")) & 0xFF
    except (KeyError, TypeError, ValueError):
        return None
    if expected_status(step) == "INVALID_OPCODE":
        return "cse", raw + (1024 // 4 if step.get("mode") == "io-passthru" else 0)
    if step.get("mode") != "admin-passthru":
        return None
    if raw == 0x02:
        return "supported_logs", selector
    if raw in (0x09, 0x0A):
        return "fid_effects", selector
    return None


def _check_says_unsupported(check, structure, entry):
    """True when this data_field check reads exactly the support bit of
    `entry` and holds only if that bit is clear."""
    table, ident = entry
    if structure != table:
        return False
    interp = spec_fields.interpret_check(check, structure)
    if not interp or not interp.get("support_bit") or interp.get("index") is None:
        return False
    base = 1024 if structure == "cse" and integer(check["offset"]) >= 1024 else 0
    index = interp["index"] + base // 4
    if index != ident:
        return False
    try:
        tests = _check_tests_bit(check)
    except (ValueError, TypeError):
        return False
    return tests == "clear"


def _structure_of_step(step):
    try:
        fields = {k: step.get(k, "0x0") for k in ("cdw10", "cdw11", "cdw12", "cdw13")}
        return spec_fields.structure_of({"command_set": "ADMIN" if step.get("mode") == "admin-passthru" else "NVM",
                                         "raw_opcode": step["opcode"]}, fields)
    except (KeyError, TypeError, ValueError):
        return None


FIRMWARE_PENDING_STATUSES = {spec_fields.STATUS_CODES[n] for n in
                             ("FW_NEEDS_CONV_RESET", "FW_NEEDS_SUBSYS_RESET", "FW_NEEDS_RESET")}
FIRMWARE_PENDING_NOTE = "장비가 펌웨어 활성화 대기 상태"


def firmware_activation_pending(steps, results):
    """A command other than Firmware Commit refused with "Firmware Activation
    Requires ... Reset": the drive holds a committed image waiting for a
    reset - state an earlier Firmware Commit (this run or a previous one) left
    behind, not the rule under test. 2026-11-06: two Sanitize FAILs and one
    stopped chain, while the Firmware Slot log showed activation pending."""
    for i, step in enumerate(steps):
        r = results.get(i)
        if not r or step.get("harness"):
            continue
        try:
            if step.get("mode") == "admin-passthru" and integer(step.get("opcode", "0x0")) == 0x10:
                continue
        except ValueError:
            continue
        code = spec_fields.status_code_in_output(r.get("stdout", ""))
        if code in FIRMWARE_PENDING_STATUSES and spec_fields.status_code_of_name(expected_status(step)) != code:
            return (f"{FIRMWARE_PENDING_NOTE}: 스텝 {i} {step.get('name')}가 {completion_status(r)}"
                    f"(SCT {code[0]}h, SC {code[1]:02X}h)로 거부됨 — 이전 Firmware Commit이 남긴 상태라 이 요구사항을 "
                    "판정하지 않음. 장비 리셋(nvme reset 또는 전원 사이클) 후 다시 실행해야 함")
    return None


def command_support_measured_absent(tc):
    """The chain stopped before its action because a precondition read the
    action command's OWN support bit (Identify Controller OACS/ONCS bit named
    for that command, or its Commands Supported and Effects CSUPP) and found
    it 0. Returns a description, else None.

    Measured (2026-11-06): Copy (ONCS.NVMCPYS=0) 9 TCs and Cancel (CSUPP=0)
    8 TCs, each generated and sent only to stop at the same precondition -
    the drive had already answered once. Another command's bit, a feature
    bit (DPS, NWPC, ...) or a check that held says nothing about the command."""
    steps = tc.get("steps") or []
    results = {r["step_index"]: r for r in (tc.get("execution") or {}).get("step_results", [])}
    action_idx = next((i for i, s in enumerate(steps) if s.get("phase") == "action"), None)
    if action_idx is None or (results.get(action_idx) or {}).get("started", True):
        return None
    action = steps[action_idx]
    name = str(action.get("name") or "").lower()
    try:
        entry = integer(action["opcode"]) + (256 if action.get("mode") == "io-passthru" else 0)
    except (KeyError, TypeError, ValueError):
        return None
    for condition in (tc.get("verification") or {}).get("preconditions") or []:
        for outcome in condition.get("results") or []:
            check = outcome.get("check") or {}
            if outcome.get("result") != "violated" or check.get("kind") != "data_field":
                continue
            try:
                structure = _structure_of_step(steps[integer(check["step"])])
                tests = _check_tests_bit(check)
            except (KeyError, TypeError, ValueError, IndexError):
                continue
            if structure is None or tests != "set":
                continue
            interp = spec_fields.interpret_check(check, structure) or {}
            if structure == "cse":
                base = 256 if integer(check["offset"]) >= 1024 else 0
                if interp.get("support_bit") and interp.get("index") is not None and interp["index"] + base == entry:
                    return f"{condition.get('description', '')} (CSUPP=0)"
            elif structure == "id_ctrl" and interp.get("field") in ("OACS", "ONCS") and len(interp.get("bits") or ()) == 1:
                bit = next(iter(interp["bits"]))
                names = spec_fields.ID_CTRL[interp["field"]]["bits"][bit]["names"]
                if any(name == n.lower() or (len(n) >= 6 and name.startswith(n.lower() + " ")) for n in names):
                    return f"{condition.get('description', '')} ({interp['field']}.{bit}=0)"
    return None


def _support_measured(steps, conditions, action_step):
    """A precondition check held that reads THIS test's own entry in a
    support table and requires it unsupported. A held check on another LID
    (review F02: LID 00h supported was taken as proof LID 7Eh is not) proves
    nothing about this premise."""
    entry = _support_entry_of(action_step)
    if entry is None:
        return False
    for condition in conditions:
        for outcome in condition.get("results") or []:
            check = outcome.get("check") or {}
            if outcome.get("result") != "satisfied" or check.get("kind") != "data_field":
                continue
            try:
                structure = _structure_of_step(steps[integer(check["step"])])
            except (KeyError, TypeError, ValueError, IndexError):
                continue
            if _check_says_unsupported(check, structure, entry):
                return True
    return False


def _premise_refuted(req, checks, steps, results, conditions=()):
    """A requirement about unsupported/reserved values ("If a controller does
    not support the specified CNS value, then ... abort with Invalid Field")
    whose rejection was expected but the drive completed successfully: the
    drive supports that value, so the rule does not apply - not a violation."""
    if not _UNSUPPORTED_PREMISE_RE.search(plain_text(req.get("quote", ""))) or "reserved" in str(req.get("quote", "")).lower():
        return None
    for outcome in checks:
        check = outcome["check"]
        if check.get("kind") != "completion" or outcome["result"] != "violated":
            continue
        try:
            i = integer(check["step"])
        except (KeyError, TypeError, ValueError):
            continue
        # Measured unsupported (probe or a support-table precondition) and
        # still accepted: that is the violation, not a refuted premise.
        if steps[i].get("selector_support") is False or _support_measured(steps, conditions, steps[i]):
            return None
        if outcome.get("observed") == "SUCCESS" and expected_status(steps[i]).startswith("INVALID"):
            return (f"스텝 {i}이 '미지원이면 거부' 전제로 {expected_status(steps[i])}를 기대했지만 SUCCESS — "
                    "장비가 그 값을 지원한다는 뜻이라 이 규정의 위반이 아님(전제가 장비 응답으로 반증됨)")
    return None


# A sentence that is itself about a rejection or about unsupported values,
# including one that names the error it returns ("IEKEY ... shall return an
# error of Invalid Field in Command").
_REJECTION_TEXT_RE = re.compile(
    r"\babort|not (?:be )?support|unsupported|status code|shall fail|reject"
    r"|\b(?:return|report|post|complete)s?\b[^.]{0,40}\b(?:an? )?error\b"
    r"|\binvalid (?:field|namespace|command|log|format|queue|parameter|controller|firmware|interrupt|number|sgl"
    r"|use|prot|prp|resource|size|port)|command sequence error|not (?:saveable|changeable)"
    r"|lba out of range|capacity exceeded|access denied|conflicting attributes", re.I)
# A sentence whose observable is the completion itself: "shall complete
# successfully", "post a completion queue entry", "shall be ignored by the
# controller" (accepted, not refused), "shall not return this status value",
# "shall succeed", "shall be supported".
_COMPLETION_TEXT_RE = re.compile(
    r"\bcomplet|\bsuccess|\bsucceed|completion queue entry|shall (?:be )?(?:process|execut|accept)"
    r"|\bignored?\b|shall not return|shall (?:be )?support", re.I)


def _target_unobserved(req, target, steps):
    """Why a requirement that quotes the target sentence did not observe what
    the sentence is about, or None. Planned statuses only, so the plan check
    and verify_tc use the same rule.

    - Only a refusal was looked at (review 2026-11-06 midrun §2: a DSLBA rule,
      an ANA Change Count rollover, NRUH non-zero - each PASS on
      INVALID_OPCODE/INVALID_LOG_PAGE). The refusal stays a fact about the
      drive (UNSUPPORTED / unsupported-in-run); it is not this sentence's verdict.
    - The action is planned to be refused for a sentence that is not about a
      refusal: whatever else the chain checks (a later Identify succeeding)
      does not observe the sentence (follow-up review: an unsupported action
      plus an unrelated Identify check passed).
    - Only "it completed successfully" was looked at for a sentence about a
      value (follow-up review: DSLBA never read, PASS and judged). A sentence
      about the completion itself ("shall complete successfully", "post a
      completion queue entry") is observed by the action's completion."""
    if not req.get("target_requirement_id") or target.get("kind") in ("abort", "variant"):
        return None
    text = plain_text(target.get("text", ""))
    if _REJECTION_TEXT_RE.search(text):
        return None
    checks = [c for c in req.get("checks") or [] if isinstance(c, dict)]
    if not checks:
        return None
    action = next((i for i, s in enumerate(steps) if s.get("phase") == "action"), 0)
    about_completion = bool(_COMPLETION_TEXT_RE.search(text))
    if expected_status(steps[action]) != "SUCCESS" and not about_completion:
        return (f"타겟 문장은 거부를 말하지 않는데 action이 {expected_status(steps[action])}로 거부되도록 계획됨 — "
                "거부 응답이나 다른 스텝의 확인은 이 문장을 관측하지 않음(미지원이면 SUCCESS를 기대하고 보내야 "
                "UNSUPPORTED로 남음)")
    observing, completion_only = [], False
    for c in checks:
        try:
            i = integer(c.get("step"))
        except ValueError:
            continue
        if i < action or c.get("kind") in SELF_REFERENCE_KINDS:
            continue  # a support-table read before the action is a premise; data_length reads our request
        if c.get("kind") == "completion":
            completion_only = True
            if not (about_completion and i == action):
                # "It succeeded" is not the value the sentence is about, and
                # another step's completion says nothing about the action.
                continue
        observing.append(c)
    if observing:
        return None
    if completion_only:
        return ("타겟 문장이 말하는 값을 읽지 않음 — 성공 완료만 확인(문장이 말하는 필드·데이터·CQE 값을 "
                "action이나 그 뒤 스텝에서 읽는 검증식이 필요)")
    return ("타겟 문장이 말하는 값을 관측하지 않음 — 미지원/거부 응답만 확인(그 사실은 TC 결과로 남고 "
            "이 문장의 판정은 아님)")


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
    pending = firmware_activation_pending(steps, results)
    if pending:
        issues.append(pending)
    conditions = []
    for condition in contract.get("precondition_checks", []):
        checks = [evaluate_check(c, steps, results) for c in condition["checks"]]
        conditions.append(dict(condition, results=checks))
    # Harness snapshot/cleanup steps restore state; they are not part of the test.
    test_steps = [(i, s) for i, s in enumerate(steps) if not s.get("harness") and s.get("phase") != "cleanup"]
    preconditions_ok = (all(c["result"] == "satisfied" for p in conditions for c in p["results"])
                        and all(matches_expected(s, results.get(i)) for i, s in test_steps
                                if s.get("phase") == "setup"))
    # Every supporting command is a dependency; an unsupported/failed setup
    # cannot be discarded to turn its dependent action into a verified PASS.
    chain_ok = all(matches_expected(s, results.get(i)) for i, s in test_steps)
    evidence = {e.get("evidence_id"): e for e in contract.get("evidence", [])}
    requirements = []
    evaluated = [(req, [evaluate_check(c, steps, results) for c in req.get("checks", [])])
                 for req in contract["requirements"]]
    # A code variant sweeps a value the spec itself reserves: accepting it IS
    # the deviation, there is no "maybe the drive supports it" premise.
    is_variant = (contract.get("target_requirement") or {}).get("kind") == "variant"
    for req, checks in ([] if is_variant else evaluated):
        refuted = _premise_refuted(req, checks, steps, results, conditions)
        if refuted and refuted not in issues:
            issues.append(refuted)
    target = contract.get("target_requirement") or {}
    for req, checks in evaluated:
        block = evidence.get(req.get("evidence_id"))
        grounded = bool(block and quote_in(req.get("quote", ""), block["text"]))
        unobserved = _target_unobserved(req, target, steps)
        if unobserved:
            req = dict(req, unobserved=unobserved)
        if not grounded or issues or not preconditions_ok or unobserved:
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
