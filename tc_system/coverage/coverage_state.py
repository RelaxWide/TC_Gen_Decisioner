from datetime import datetime, timezone
from collections import Counter

from collections import defaultdict

from tc_system.verification import UNEXECUTABLE_COMMANDS, UNVERIFIABLE_FIELD_VALUES, verify_tc
from tc_system.execution.expectation_checker import check_step_expectations, check_execution

# Historical command exposure only. Requirement verification is separately
# computed from cited executable checks; visiting an opcode never completes a clause.
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
    if tc.get("steps") and (tc.get("execution") or {}).get("step_results"):
        statuses = check_step_expectations(tc, tc["execution"])
    if not statuses or len(statuses) != len(section_ids):
        statuses = [tc.get("status")] * len(section_ids)
    return list(zip(section_ids, opcodes, statuses))


def requirement_coverage(tc_records):
    rows = {}
    for tc in tc_records:
        if tc.get("uses_placeholder_args", True):
            continue
        execution = tc.get("execution") or {}
        verification = verify_tc(tc, execution)
        command_status = check_execution(tc, execution) if tc.get("steps") else "ERROR"
        for req in verification["requirements"]:
            rid = req["requirement_id"]
            row = rows.setdefault(rid, {"requirement_id": rid, "section_id": req["section_id"],
                                        "description": req["description"], "quote": req["quote"],
                                        "evidence_id": req["evidence_id"], "observations": []})
            status = req["status"]
            if command_status in {"ERROR", "UNSUPPORTED"} or (command_status == "FAIL" and status == "PASS"):
                status = "UNVERIFIED"
            row["observations"].append({"tc_id": tc["tc_id"], "status": status})
    for row in rows.values():
        statuses = {o["status"] for o in row["observations"]} - {"UNVERIFIED"}
        row["status"] = "MIXED" if len(statuses) > 1 else next(iter(statuses), "UNVERIFIED")
    values = list(rows.values())
    counts = Counter(r["status"] for r in values)
    evaluated = sum(counts[s] for s in ("PASS", "FAIL", "MIXED"))
    return values, {"requirements_total": len(values), "requirements_evaluated": evaluated,
                    "requirements_passed": counts["PASS"], "requirements_failed": counts["FAIL"],
                    "requirements_mixed": counts["MIXED"], "requirements_unverified": counts["UNVERIFIED"],
                    "requirements_evaluated_pct": round(100 * evaluated / len(values), 1) if values else 0.0,
                    "sections_with_verified_cases": len({r["section_id"] for r in values
                                                          if r["status"] != "UNVERIFIED"})}


EXCLUDED_REASONS = {
    "unverifiable_value": "반환 데이터에서 가변 길이 레코드를 찾아야 검증됨(Event Type) — 고정 오프셋 검증식으로 불가",
    "unexecutable_command": "동시 실행/비동기 이벤트가 필요한 커맨드뿐(Abort/AER) — 순차 실행기로 불가",
}


def effective_status(tc: dict) -> str | None:
    """A stored PASS is a spec PASS only if the recomputed verification agrees
    (records from before the contract existed say PASS but prove nothing)."""
    status = tc.get("status")
    if status == "PASS":
        return verify_tc(tc, tc.get("execution") or {})["status"]
    return status


def target_breakdown(index, tc_records: list[dict], skip_records: list[dict] | None = None) -> dict:
    """Per-command view over the targets pick_next_targets can actually offer.

    The denominator is what this tool can test today, with every excluded
    clause counted under its reason - not the 258 opcode-linked clauses, 26 of
    which can never be offered.
    """
    name_by_opcode = {o["opcode"]: o["name"] for o in index.list_opcodes()}
    excluded, targets = Counter(), {}
    for section in index.list_sections():
        opcodes = index.opcodes_for_section(section)
        if not opcodes:
            continue
        if _needs_unverifiable_value(section):
            excluded["unverifiable_value"] += 1
            continue
        offered = [o for o in opcodes if o.get("name") not in UNEXECUTABLE_COMMANDS]
        if not offered:
            excluded["unexecutable_command"] += 1
            continue
        targets[section["section_id"]] = (section, offered)

    rows = {}
    for section, offered in targets.values():
        for op in offered:
            row = rows.setdefault(op["name"], {"name": op["name"], "command_set": op["command_set"],
                                               "targets": 0, "tried": 0, "statuses": Counter(), "skipped": 0,
                                               "verified_requirements": set(), "sections": {}})
            row["targets"] += 1
            row["sections"][section["section_id"]] = {"section_id": section["section_id"],
                                                      "title": section.get("title", ""), "status": None,
                                                      "tcs": 0, "skips": 0, "last_skip": None}
    for tc in tc_records:
        pair = _action_pair(tc)
        name = name_by_opcode.get(pair[1]) if pair else None
        entry = rows.get(name, {}).get("sections", {}).get(pair[0]) if pair else None
        if entry is None:
            continue
        status = effective_status(tc)
        rows[name]["statuses"][status] += 1
        entry["tcs"] += 1
        entry["status"] = status  # tc_store is append-ordered: the last one wins
        verification = tc.get("verification") or verify_tc(tc, tc.get("execution") or {})
        rows[name]["verified_requirements"].update(
            r["requirement_id"] for r in verification.get("requirements", []) if r.get("status") in ("PASS", "FAIL"))
    for skip in skip_records or []:
        name = name_by_opcode.get(skip.get("opcode"))
        entry = rows.get(name, {}).get("sections", {}).get(skip.get("section_id"))
        if entry is None:
            continue
        rows[name]["skipped"] += 1
        entry["skips"] += 1
        entry["last_skip"] = skip.get("reason")

    tried_sections = set()
    out = []
    for row in rows.values():
        sections = list(row["sections"].values())
        tried = [s for s in sections if s["tcs"] or s["skips"]]
        tried_sections.update(s["section_id"] for s in tried)
        out.append(dict(row, tried=len(tried), statuses=dict(row["statuses"]),
                        verified_requirements=len(row["verified_requirements"]),
                        sections=sorted(sections, key=lambda s: s["section_id"])))
    out.sort(key=lambda r: (-r["targets"], r["name"]))
    return {"testable_targets": len(targets), "targets_tried": len(tried_sections),
            "excluded": [{"reason": EXCLUDED_REASONS[k], "count": v} for k, v in excluded.items()],
            "commands": out}


def compute_coverage(index, tc_records: list[dict], skip_records: list[dict] | None = None) -> dict:
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

    requirements, verified_summary = requirement_coverage(tc_records)
    targets = target_breakdown(index, tc_records, skip_records)
    return {
        "schema_version": 2,
        "requirement_coverage": requirements,
        "targets": targets,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "section_coverage": section_coverage,
        "opcode_coverage": opcode_coverage,
        "excluded_tc_ids": excluded_tc_ids,
        "summary": {
            **verified_summary,
            "testable_targets": targets["testable_targets"],
            "targets_tried": targets["targets_tried"],
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
    # Message-Based Transport (Fabrics) admin commands: a PCIe controller
    # answers them with INVALID_OPCODE. Still offered, after everything else.
    fabrics_only = 1 if section["section_id"].startswith("base:5.4.") else 0
    return (fabrics_only, risk, authoritative, section["section_id"])


def pick_next_targets(index, tc_records: list[dict], count: int,
                      skip_records: list[dict] | None = None) -> list[tuple[dict, dict]]:
    """Rotate through clause/opcode pairs, prioritizing unverified, less tried ones.

    One tested requirement does not finish a clause. Neither a legacy PASS nor
    an unsupported setup step permanently removes a target. Completed requirement
    quotes are supplied to the next scenario so it can choose another behavior.
    """
    requirements, _ = requirement_coverage(tc_records)
    verified = Counter(r["section_id"] for r in requirements if r["status"] != "UNVERIFIED")
    attempts, pair_attempts, unsupported_pairs = Counter(), Counter(), set()
    for tc in tc_records:
        pair = _action_pair(tc)
        if pair:
            attempts[pair[0]] += 1
            pair_attempts[pair] += 1
            if _action_unsupported(tc):
                unsupported_pairs.add(pair)
        else:
            for sid in tc.get("source_section_ids", []):
                attempts[sid] += 1
    # A target skipped before reaching the device leaves no TC record. Without
    # counting it, an empty store re-picked the same first target every run
    # (measured: `--count 1` failed on the same generation forever).
    for skip in skip_records or []:
        attempts[skip["section_id"]] += 1
        pair_attempts[(skip["section_id"], skip["opcode"])] += 1

    def key(pair):
        sid, opcode = pair[0]["section_id"], pair[1]["opcode"]
        # "Has an answer": a verified requirement, the drive's own INVALID_OPCODE
        # for this command, or enough tries that more of the same is unlikely to
        # help. Such targets are still offered (one requirement never finishes a
        # clause), just after every target that has none — otherwise the ~half
        # of commands this drive does not implement would be re-generated and
        # re-sent ahead of every verified clause, every run.
        settled = (verified[sid] > 0 or (sid, opcode) in unsupported_pairs
                   or attempts[sid] >= UNRESOLVED_ATTEMPT_LIMIT)
        return (settled, attempts[sid], pair_attempts[(sid, opcode)], _target_rank(*pair))

    if count < 1:
        return []
    candidates = sorted(((section, opcode) for section in index.list_sections()
                         for opcode in index.opcodes_for_section(section)
                         if opcode.get("name") not in UNEXECUTABLE_COMMANDS
                         and not _needs_unverifiable_value(section)), key=key)
    # Round-robin over commands inside each priority band: sorted by section
    # id alone, a batch walked straight through one command's sub-clauses
    # (measured: 22 Persistent Event Log event types back to back).
    bands = defaultdict(list)
    for pair in candidates:
        bands[key(pair)[0]].append(pair)
    picked, seen_sections = [], set()
    for band in sorted(bands):
        pool, per_command, level = list(bands[band]), defaultdict(int), 0
        while pool and len(picked) < count:
            for pair in list(pool):
                section, opcode = pair
                if section["section_id"] in seen_sections:  # one opcode per clause per batch
                    pool.remove(pair)
                    continue
                if per_command[opcode["name"]] != level:
                    continue
                pool.remove(pair)
                seen_sections.add(section["section_id"])
                per_command[opcode["name"]] += 1
                picked.append(pair)
                if len(picked) == count:
                    break
            level += 1
    return picked


def _needs_unverifiable_value(section: dict) -> bool:
    return any(f.get("field_name") in UNVERIFIABLE_FIELD_VALUES for f in section.get("field_values") or [])


# Attempts without a verified requirement or an INVALID_OPCODE after which a
# clause stops outranking clauses that already have an answer.
UNRESOLVED_ATTEMPT_LIMIT = 3


def _action_pair(tc: dict) -> tuple[str, str] | None:
    """(section_id, opcode) of the command under test, from the per-step arrays."""
    steps = tc.get("steps") or []
    sections, opcodes = tc.get("step_section_ids") or [], tc.get("step_opcodes") or []
    idx = next((i for i, s in enumerate(steps) if s.get("phase") == "action"), None)
    if idx is not None and idx < len(sections) and idx < len(opcodes):
        return sections[idx], opcodes[idx]
    target = (tc.get("verification_contract") or {}).get("target_section_id")
    if target and tc.get("source_opcodes"):
        return target, tc["source_opcodes"][0]
    return None


def _action_unsupported(tc: dict) -> bool:
    execution = tc.get("execution") or {}
    if tc.get("steps") and execution.get("step_results"):
        return check_execution(tc, execution) == "UNSUPPORTED"
    return tc.get("status") == "UNSUPPORTED"
