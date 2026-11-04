from datetime import datetime, timezone

# A TC counts toward coverage once it actually reached the device and produced an
# answer about it:
#   PASS        — the command behaved as the clause describes.
#   FAIL        — it ran and misbehaved; the path was still exercised.
#   UNSUPPORTED — the controller reported INVALID_OPCODE. Most NVMe commands are
#                 optional, so "this drive does not implement it" is a real
#                 finding about the drive, not a gap in testing.
# ERROR is excluded: either the harness never landed the command (SSH failure)
# or our own arguments were malformed (INVALID_FIELD, host tool crash), so
# nothing was learned about the spec and the section is re-offered.
COVERING_STATUSES = ("PASS", "FAIL", "UNSUPPORTED")


def _covering_entries(tc: dict) -> list[tuple[str, str, str]]:
    """(section_id, opcode, status) triples this TC provides real evidence
    for — one per step. A multi-step TC's steps are judged independently
    here: a chain where an early step PASSed and a later one ERRORed still
    credits the early step's section, instead of the whole chain's evidence
    being thrown out together because of the one bad step.

    Opt-in like before: a record must explicitly declare `uses_placeholder_args:
    False`, or it contributes nothing — the failure mode of wrongly claiming
    coverage is worse than under-counting. Falls back to the whole-TC scalar
    `status` for every entry when `step_statuses`/`step_section_ids` are absent
    (legacy records, and today's single-step TCs, where there is only one step
    so there is nothing for the two views to disagree about).
    """
    if tc.get("uses_placeholder_args", True):
        return []
    section_ids = tc.get("step_section_ids") or tc.get("source_section_ids", [])
    opcodes = tc.get("step_opcodes") or tc.get("source_opcodes", [])
    statuses = tc.get("step_statuses")
    if not statuses or len(statuses) != len(section_ids):
        statuses = [tc.get("status")] * len(section_ids)
    return list(zip(section_ids, opcodes, statuses))


def compute_coverage(index, tc_records: list[dict]) -> dict:
    section_covering: dict[str, list[tuple[str, str]]] = {}
    opcode_covering: dict[str, list[tuple[str, str]]] = {}
    excluded_tc_ids = []
    for tc in tc_records:
        covering_entries = [(sid, op, status) for sid, op, status in _covering_entries(tc)
                             if status in COVERING_STATUSES]
        if not covering_entries:
            excluded_tc_ids.append(tc["tc_id"])
            continue
        for sid, op, status in covering_entries:
            section_covering.setdefault(sid, []).append((tc["tc_id"], status))
            opcode_covering.setdefault(op, []).append((tc["tc_id"], status))

    sections = index.list_sections()
    opcodes = index.list_opcodes()

    def _entry(key_name, key, covering):
        pairs = covering.get(key, [])
        tc_ids = list(dict.fromkeys(t for t, _ in pairs))
        statuses = {s for _, s in pairs}
        # Covered-but-only-via-FAIL is worth seeing separately: the path was
        # exercised, but nothing about it was confirmed good. "mixed" is its own
        # state — reporting a section with one PASS and one FAIL as "passing"
        # would hide the failure.
        if not pairs:
            outcome = None
        elif "FAIL" in statuses and ("PASS" in statuses or "UNSUPPORTED" in statuses):
            outcome = "mixed"
        elif "FAIL" in statuses:
            outcome = "failing"
        elif statuses == {"UNSUPPORTED"}:
            outcome = "unsupported"
        else:
            outcome = "passing"
        return {
            key_name: key,
            "status": "covered" if pairs else "not_covered",
            "outcome": outcome,
            "covering_tc_ids": tc_ids,
        }

    section_coverage = [_entry("section_id", s["section_id"], section_covering) for s in sections]
    opcode_coverage = [_entry("opcode", o["opcode"], opcode_covering) for o in opcodes]

    section_covered_count = sum(1 for s in section_coverage if s["status"] == "covered")
    opcode_covered_count = sum(1 for o in opcode_coverage if o["status"] == "covered")

    # Two denominators, because one number cannot honestly carry both facts.
    # Most clauses in the spec are prose with no command to issue (data
    # structure layouts, scope, references), so `section_total` is the real
    # size of the specification but its percentage tops out around 12% no
    # matter how complete the testing is. `reachable_*` is the denominator
    # progress should be read against.
    reachable_ids = {s["section_id"] for s in sections if s.get("related_opcodes")}
    reachable_covered = sum(1 for s in section_coverage
                            if s["status"] == "covered" and s["section_id"] in reachable_ids)
    # `mixed` is reported on its own rather than folded into failing: a section
    # with both a PASS and a FAIL is a different situation from one that only
    # ever failed, and merging them hid that distinction the moment it was made.
    section_passing_count = sum(1 for s in section_coverage if s["outcome"] == "passing")
    section_failing_count = sum(1 for s in section_coverage if s["outcome"] == "failing")
    section_mixed_count = sum(1 for s in section_coverage if s["outcome"] == "mixed")
    section_unsupported_count = sum(1 for s in section_coverage if s["outcome"] == "unsupported")

    per_doc: dict[str, dict] = {}
    for s in sections:
        doc = per_doc.setdefault(s["spec_doc"], {"total": 0, "covered": 0})
        doc["total"] += 1
        if s["section_id"] in section_covering:
            doc["covered"] += 1

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "section_coverage": section_coverage,
        "opcode_coverage": opcode_coverage,
        "excluded_tc_ids": excluded_tc_ids,
        "summary": {
            "section_total": len(sections),
            "section_covered": section_covered_count,
            "section_pct": round(100 * section_covered_count / len(sections), 1) if sections else 0.0,
            "reachable_total": len(reachable_ids),
            "reachable_covered": reachable_covered,
            "reachable_pct": round(100 * reachable_covered / len(reachable_ids), 1) if reachable_ids else 0.0,
            "section_passing": section_passing_count,
            "section_failing": section_failing_count,
            "section_mixed": section_mixed_count,
            "section_unsupported": section_unsupported_count,
            "opcode_total": len(opcodes),
            "opcode_covered": opcode_covered_count,
            "opcode_pct": round(100 * opcode_covered_count / len(opcodes), 1) if opcodes else 0.0,
            "excluded_tc_count": len(excluded_tc_ids),
            "per_spec_doc": [
                {"spec_doc": doc, "pct": round(100 * v["covered"] / v["total"], 1) if v["total"] else 0.0}
                for doc, v in per_doc.items()
            ],
        },
    }


def _target_rank(section: dict, opcode: dict) -> tuple:
    """Order targets so a run spends its budget before it can break the rig.

    1. `risk_class` from the index: harmless -> host/controller state-changing
       -> data-destructive -> lockout/firmware. Nothing is excluded, but a run
       should get through the cheap commands before Sanitize wipes the drive,
       Device Self-test blocks it for hours, or Security Send/Lockdown/Firmware
       Commit potentially lock it out.
    2. The clause the opcode table itself cites beats clauses merely mentioning
       the command — `nvm:4.1.5.10.1 Determining the Identify Command
       Information...` is explanatory, not the Identify clause.
    """
    if "risk_class" in opcode:
        risk = opcode["risk_class"]
    else:  # index predating risk_class
        risk = 3 if opcode.get("firmware_state") else 2 if opcode.get("destructive") else 0
    authoritative = 0 if opcode.get("section_ref") == section["section_id"] else 1
    return (risk, authoritative, section["section_id"])


def pick_next_targets(index, tc_records: list[dict], count: int) -> list[tuple[dict, dict]]:
    """Return up to `count` (section, opcode) pairs not yet covered by any TC.

    Sections whose only TCs ERRORed (or carried placeholder args) are offered
    again — those runs never established anything about the section. For a
    multi-step TC, a section is "covered" only via the specific step that was
    actually about it, not by the TC's overall (possibly worse) scalar status.
    """
    covered_sections = {
        sid for tc in tc_records
        for sid, _, status in _covering_entries(tc)
        if status in COVERING_STATUSES
    }
    candidates = []
    for section in index.list_sections():
        if section["section_id"] in covered_sections:
            continue
        for opcode in index.opcodes_for_section(section):
            candidates.append((section, opcode))
            break
    candidates.sort(key=lambda pair: _target_rank(*pair))
    return candidates[:count]
