"""Code-generated variant TCs: no LLM call, a fixed oracle quoted from the spec.

Each family turns one spec rule into many concrete commands by sweeping a value
the rule is about, so the test space grows without an LLM scenario per test:

- lba_boundary: Read/Verify/Compare/Write/Write Zeroes at LBA 0, the last LBA,
  one past the end, a range crossing the end and the largest SLBA.
  "A namespace of size n consists of LBA 0 through LBA (n - 1)." (nvm:4.1.5.1)
  and "LBA Out of Range: The command references an LBA that exceeds the size
  of the namespace." (nvm:3.1.2). Needs NSZE and the LBA size from the device.
- reserved_fid: Get/Set Features for every Feature Identifier the Set Features
  table marks Reserved. "...specifies a Feature Identifier that is not
  supported, then the controller shall abort the command with a status code of
  Invalid Field in Command." (base:4.4)
- reserved_lid: Get Log Page for every Log Page Identifier the LID table marks
  Reserved. "...specifies a Log Page Identifier that is not supported, then the
  controller shall abort the command with a status code of Invalid Log Page..."
  (base:5.2.12)

A drive that implements a value this spec version reserves fails the reserved
families: that is a deviation from this spec version, and the report shows the
value. Every variant is one action step with a completion check.
"""
import re
from functools import lru_cache

from shared.ids import stable_id
from shared.spec_evidence import clause_catalog
from tc_system.verification import VERSION, quote_in

_RESERVED_ROW = re.compile(r"^\|\s*([0-9A-F]{2})h(?:\s+to\s+([0-9A-F]{2})h)?\s*\|\s*Reserved\s*(?:\||$)", re.M)

RULES = {
    "in_range": ("nvm:4.1.5.1", "A namespace of size n consists of LBA 0 through LBA (n - 1)."),
    "lba_range": ("nvm:3.1.2", "LBA Out of Range: The command references an LBA that exceeds the size of the namespace."),
    "reserved_fid": ("base:4.4", "If a Get Features command or Set Features command is processed that specifies a "
                                 "Feature Identifier that is not supported, then the controller shall abort the "
                                 "command with a status code of Invalid Field in Command."),
    "reserved_lid": ("base:5.2.12", "If a Get Log Page command is processed that specifies a Log Page Identifier that "
                                    "is not supported, then the controller shall abort the command with a status code "
                                    "of Invalid Log Page"),
}

# (label, SLBA as a function of NSZE, 0-based NLB, expected completion)
_LBA_CASES = (
    ("first_lba", lambda n: 0, 0, "SUCCESS"),
    ("last_lba", lambda n: n - 1, 0, "SUCCESS"),
    ("one_past_end", lambda n: n, 0, "LBA_RANGE"),
    ("crosses_end", lambda n: n - 1, 1, "LBA_RANGE"),
    ("max_slba", lambda n: (1 << 64) - 1, 0, "LBA_RANGE"),
)
# command -> (direction, carries data) ; Compare is only checked out of range (data is unknown)
_LBA_COMMANDS = {"Read": ("read", True), "Verify": ("none", False), "Compare": ("write", True),
                 "Write": ("write", True), "Write Zeroes": ("none", False)}


@lru_cache(maxsize=None)
def _evidence_cached(rule):
    return _evidence_uncached(rule)


def _evidence(rule):
    found = _evidence_cached(rule)
    return dict(found) if found else None


def _evidence_uncached(rule):
    """An excerpt of the block that holds the rule sentence (quote must occur in it)."""
    section_id, sentence = RULES[rule]
    block = clause_catalog().get(section_id)
    if not block:
        return None
    lines = block["text"].split("\n")
    at = next((i for i, line in enumerate(lines) if quote_in(sentence, line)), None)
    if at is None:
        return None
    text = "\n".join(lines[max(0, at - 2):at + 3])
    return {"evidence_id": stable_id("spec", section_id, text), "section_id": section_id, "title": block["title"],
            "text": text, "role": "rule", "chunk_id": block["chunk_ids"][0], "truncated": True}


@lru_cache(maxsize=None)
def _reserved_values(section_id):
    return tuple(_reserved_values_uncached(section_id))


def reserved_values(section_id):
    return list(_reserved_values(section_id))


def _reserved_values_uncached(section_id):
    block = clause_catalog().get(section_id)
    values = set()
    for m in _RESERVED_ROW.finditer(block["text"] if block else ""):
        lo = int(m.group(1), 16)
        hi = int(m.group(2), 16) if m.group(2) else lo
        values.update(range(lo, hi + 1))
    return sorted(values)


def variant_targets(index, nsze: int | None = None, lba_bytes: int | None = None) -> list[dict]:
    """Every variant this spec and device allow, as target requirements."""
    by_name = {o["name"]: o for o in index.list_opcodes()}
    sections = {s["section_id"]: s for s in index.list_sections()}
    out = []

    def add(family, command, label, fields, expected, rule, description):
        op = by_name.get(command)
        section = sections.get(op["section_ref"]) if op else None
        evidence = _evidence(rule) if section else None
        if not evidence:
            return
        # An in-range Read/Verify of a never-written LBA may complete with
        # Deallocated or Unwritten Logical Block when DULBE is enabled (the
        # spec allows both): accepted, not a FAIL.
        also = ["UNWRITTEN_BLOCK"] if family == "lba_boundary" and expected == "SUCCESS" \
            and command in ("Read", "Verify") else []
        out.append({"requirement_id": stable_id("var", family, command, label), "kind": "variant",
                    "family": family, "command": command, "label": label, "fields": fields,
                    "expected_status": expected, "also_accept": also, "section_id": section["section_id"],
                    "text": RULES[rule][1], "evidence": evidence, "description": description})

    if nsze and lba_bytes:
        for command, (direction, carries) in _LBA_COMMANDS.items():
            for label, slba_of, nlb, expected in _LBA_CASES:
                if command == "Compare" and expected == "SUCCESS":
                    continue
                slba = slba_of(nsze)
                fields = {"cdw10": f"0x{slba & 0xFFFFFFFF:08X}", "cdw11": f"0x{slba >> 32:08X}",
                          "cdw12": f"0x{nlb:08X}", "data_len": (nlb + 1) * lba_bytes if carries else 0,
                          "direction": direction}
                rule = "in_range" if expected == "SUCCESS" else "lba_range"
                add("lba_boundary", command, label, fields, expected, rule,
                    f"{command} SLBA=0x{slba:X} NLB={nlb + 1}블록(NSZE=0x{nsze:X}) → {expected}")
    for fid in reserved_values("base:5.2.26"):
        for command in ("Get Features", "Set Features"):
            add("reserved_fid", command, f"fid_{fid:02X}", {"cdw10": f"0x{fid:08X}", "data_len": 0, "direction": "none"},
                "INVALID_FIELD", "reserved_fid", f"{command} reserved FID {fid:02X}h → Invalid Field in Command")
    for lid in reserved_values("base:5.2.12"):
        add("reserved_lid", "Get Log Page", f"lid_{lid:02X}",
            {"cdw10": f"0x{lid:08X}", "data_len": 4, "direction": "read"},  # NUMD=0: one dword
            "INVALID_LOG_PAGE", "reserved_lid", f"Get Log Page reserved LID {lid:02X}h → Invalid Log Page")
    return out


def build_variant_tc(tc_id: str, variant: dict, opcode_entry: dict, nvme_ctrl: str, nvme_ns: str,
                     active_nsid: int, lba_bytes: int | None = None) -> dict:
    from tc_system.models import make_tc_record
    is_admin = opcode_entry["command_set"] == "ADMIN"
    zero = "0x00000000"
    step = {"name": opcode_entry["name"], "phase": "action", "role": variant["description"],
            "mode": "admin-passthru" if is_admin else "io-passthru",
            "device": nvme_ctrl if is_admin else nvme_ns, "opcode": opcode_entry["raw_opcode"],
            "nsid": 0 if is_admin else active_nsid, **{f"cdw{i}": zero for i in range(10, 16)},
            "data_len": 0, "direction": "none",
            "destructive": opcode_entry.get("destructive", False),
            "firmware_state": opcode_entry.get("firmware_state", False),
            "lockout_risk": opcode_entry.get("lockout_risk", False),
            "args_source": "authored", "shared_facts": {}, "field_value_verified": False,
            "test_intent": {}, "field_constraints": [], "expected_status": variant["expected_status"],
            "also_accept": list(variant.get("also_accept") or []),
            "payload_hex": None, "lba_bytes": lba_bytes, "variant": True}
    step.update(variant["fields"])
    requirement = {"requirement_id": stable_id("vreq", variant["requirement_id"]),
                   "section_id": variant["section_id"], "evidence_id": variant["evidence"]["evidence_id"],
                   "quote": variant["text"], "description": variant["description"],
                   "checks": [{"kind": "completion", "step": 0}],
                   "target_requirement_id": variant["requirement_id"]}
    target = {k: variant[k] for k in ("requirement_id", "kind", "family", "label", "section_id", "text",
                                      "expected_status")}
    tc = make_tc_record(
        tc_id=tc_id, name=f"TC_{opcode_entry['name'].replace(' ', '')}_{variant['family']}_{variant['label']}",
        source_section_ids=[variant["section_id"]], source_opcodes=[opcode_entry["opcode"]],
        generated_from={"variant": variant["requirement_id"], "family": variant["family"]},
        scenario={"description": variant["description"], "preconditions": [], "out_of_scope": []},
        expectation={"description": variant["description"], "fail_criteria": []},
        steps=[step], destructive=opcode_entry.get("destructive", False), uses_placeholder_args=False)
    tc.update(variant_id=variant["requirement_id"], step_section_ids=[variant["section_id"]],
              step_opcodes=[opcode_entry["opcode"]], chain_summary="")
    tc["verification_contract"] = {"version": VERSION, "target_section_id": variant["section_id"],
                                   "requirements": [requirement], "precondition_checks": [],
                                   "unmeasured_preconditions": [], "out_of_scope": [],
                                   "target_requirement": target, "evidence": [variant["evidence"]]}
    return tc
