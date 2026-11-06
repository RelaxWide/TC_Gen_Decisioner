from datetime import datetime, timezone
from collections import Counter, defaultdict, deque
from functools import lru_cache
from itertools import groupby
import re

from shared.ids import stable_id
from shared.spec_evidence import clause_catalog, plain_text
from tc_system.verification import UNEXECUTABLE_COMMANDS, UNVERIFIABLE_FIELD_VALUES, canonical_status, verify_tc
from tc_system.execution.expectation_checker import check_step_expectations, check_execution
from tc_system.execution.host_actions import required_host_actions

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
    return [(sid, op, st) for sid, op, st in zip(section_ids, opcodes, statuses) if sid]


_OBSERVATION_CACHE: dict = {}


def requirement_observations(tc: dict) -> list[tuple[dict, str]]:
    """Cached per stored TC version: coverage is recomputed after every TC
    and needs it several times per pass (was O(N^2) over an --all run)."""
    key = (tc.get("tc_id"), tc.get("updated_at"), tc.get("active_attempt_id"), tc.get("status"),
           len(tc.get("steps") or []), len((tc.get("execution") or {}).get("step_results") or []))
    if not tc.get("tc_id") or not tc.get("updated_at"):
        return _requirement_observations(tc)
    if key not in _OBSERVATION_CACHE:
        if len(_OBSERVATION_CACHE) > 20000:
            _OBSERVATION_CACHE.clear()
        _OBSERVATION_CACHE[key] = _requirement_observations(tc)
    return _OBSERVATION_CACHE[key]


def _requirement_observations(tc: dict) -> list[tuple[dict, str]]:
    """(requirement, status) for one TC under the single rule every count
    uses. A requirement PASS on a chain whose commands FAILed, ERRORed or were
    unsupported is not evidence (review: the per-command table counted a
    dummy-firmware-activation TC the totals had excluded)."""
    if tc.get("uses_placeholder_args", True):
        return []
    execution = tc.get("execution") or {}
    verification = verify_tc(tc, execution)
    command_status = check_execution(tc, execution) if tc.get("steps") else "ERROR"
    observations = []
    for req in verification["requirements"]:
        status = req["status"]
        if command_status in {"ERROR", "UNSUPPORTED"} or (command_status == "FAIL" and status == "PASS"):
            status = "UNVERIFIED"
        observations.append((req, status))
    return observations


# What a requirement PASS actually observed, strongest first. All of them
# count as verified; the report shows which kind each one is (a stored
# configuration round trip is not the behavior the feature controls).
PASS_SCOPES = ("데이터 비교", "필드 관측", "설정 왕복(저장된 값만 확인)", "거부 응답 확인", "미지원 응답 확인",
               "완료 상태만 확인")


def requirement_coverage(tc_records):
    from tc_system.review import requirement_scope
    rows = {}
    for tc in tc_records:
        for req, status in requirement_observations(tc):
            scope = requirement_scope(tc, req)
            rid = req["requirement_id"]
            row = rows.setdefault(rid, {"requirement_id": rid, "section_id": req["section_id"],
                                        "description": req["description"], "quote": req["quote"],
                                        "evidence_id": req["evidence_id"], "observations": []})
            row["observations"].append({"tc_id": tc["tc_id"], "status": status, "scope": scope})
    for row in rows.values():
        statuses = {o["status"] for o in row["observations"]} - {"UNVERIFIED"}
        row["status"] = "MIXED" if len(statuses) > 1 else next(iter(statuses), "UNVERIFIED")
        passed = [o["scope"] for o in row["observations"] if o["status"] == "PASS"]
        row["scope"] = min(passed, key=lambda s: PASS_SCOPES.index(s) if s in PASS_SCOPES else len(PASS_SCOPES)) \
            if passed else None
    values = list(rows.values())
    counts = Counter(r["status"] for r in values)
    by_scope = Counter(r["scope"] for r in values if r["status"] == "PASS")
    evaluated = sum(counts[s] for s in ("PASS", "FAIL", "MIXED"))
    return values, {"requirements_total": len(values), "requirements_evaluated": evaluated,
                    "requirements_passed": counts["PASS"], "requirements_failed": counts["FAIL"],
                    "requirements_passed_by_scope": {s: by_scope[s] for s in PASS_SCOPES if by_scope[s]},
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


def target_breakdown(index, tc_records: list[dict], skip_records: list[dict] | None = None,
                     variants: list[dict] | None = None) -> dict:
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
        rows[name]["verified_requirements"].update(
            req["requirement_id"] for req, st in requirement_observations(tc) if st in ("PASS", "FAIL"))
    for skip in skip_records or []:
        name = name_by_opcode.get(skip.get("opcode"))
        entry = rows.get(name, {}).get("sections", {}).get(skip.get("section_id"))
        if entry is None:
            continue
        rows[name]["skipped"] += 1
        entry["skips"] += 1
        entry["last_skip"] = skip.get("reason")

    # Requirement-level view: how many of each command's requirements exist,
    # were tried, and got a PASS/FAIL verdict.
    judged = judged_target_requirements(tc_records)
    tried_reqs = {_target_requirement_id(tc) for tc in tc_records} | \
        {s.get("requirement_id") for s in skip_records or []}
    req_total, req_tried, req_judged, kinds = Counter(), Counter(), Counter(), Counter()
    for section, opcode, req in requirement_targets(index):
        if req is None or opcode["name"] not in rows:
            continue
        req_total[opcode["name"]] += 1
        kinds[req["kind"]] += 1
        req_tried[opcode["name"]] += req["requirement_id"] in tried_reqs
        req_judged[opcode["name"]] += req["requirement_id"] in judged

    var_total, var_tried, var_judged, families = Counter(), Counter(), Counter(), Counter()
    for _, opcode, variant in variant_target_triples(index, variants):
        var_total[opcode["name"]] += 1
        families[variant["family"]] += 1
        var_tried[opcode["name"]] += variant["requirement_id"] in tried_reqs
        var_judged[opcode["name"]] += variant["requirement_id"] in judged

    tried_sections = set()
    out = []
    for row in rows.values():
        sections = list(row["sections"].values())
        tried = [s for s in sections if s["tcs"] or s["skips"]]
        tried_sections.update(s["section_id"] for s in tried)
        row.update(requirements=req_total[row["name"]], requirements_tried=req_tried[row["name"]],
                   requirements_judged=req_judged[row["name"]], variants=var_total[row["name"]],
                   variants_tried=var_tried[row["name"]], variants_judged=var_judged[row["name"]])
        out.append(dict(row, tried=len(tried), statuses=dict(row["statuses"]),
                        verified_requirements=len(row["verified_requirements"]),
                        sections=sorted(sections, key=lambda s: s["section_id"])))
    out.sort(key=lambda r: (-r["targets"], r["name"]))
    return {"testable_targets": len(targets), "targets_tried": len(tried_sections),
            "requirement_targets": sum(req_total.values()), "requirement_kinds": dict(kinds),
            "requirements_tried": sum(req_tried.values()), "requirements_judged": sum(req_judged.values()),
            "variant_targets": sum(var_total.values()), "variant_families": dict(families),
            "variants_tried": sum(var_tried.values()), "variants_judged": sum(var_judged.values()),
            "excluded": [{"reason": EXCLUDED_REASONS[k], "count": v} for k, v in excluded.items()],
            "commands": out}


def compute_coverage(index, tc_records: list[dict], skip_records: list[dict] | None = None,
                     variants: list[dict] | None = None) -> dict:
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
    targets = target_breakdown(index, tc_records, skip_records, variants)
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
            "requirement_targets": targets["requirement_targets"],
            "requirements_tried": targets["requirements_tried"],
            "requirements_judged": targets["requirements_judged"],
            "variant_targets": targets["variant_targets"],
            "variants_tried": targets["variants_tried"],
            "variants_judged": targets["variants_judged"],
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


# ---- requirement-level targets -------------------------------------------------
# A clause holds many requirements; one TC tests one. Targeting clauses left all
# but the first untested (spec: 3,341 "shall" sentences vs 232 clause targets).
_SHALL = re.compile(r"\bshall\b", re.I)
_ABORT_STATUS = re.compile(r"\bwith (?:a |the )?status(?: code)?(?: of)? ([A-Z][A-Za-z/ -]{3,60}?)"
                           r"(?=\s*(?:[.,;:()]|$|\b(?:if|and|for|when|or|status|with|unless|except)\b))")


@lru_cache(maxsize=None)
def _block_requirements(section_id: str) -> tuple:
    """Every "shall" sentence of one spec block, own text only. A sentence
    that says the command is aborted with a status is a negative-test rule
    (kind "abort") carrying that status as nvme-cli spells it."""
    block = clause_catalog().get(section_id)
    if not block:
        return ()
    out, seen = [], set()
    for line in block["text"].split("\n"):
        line = re.sub(r"\s*\|\s*", " ", line).strip()
        for sentence in re.split(r"(?<=[.!?])\s+(?=[A-Z(])", line):
            text = sentence.strip(" -•")
            if not 25 <= len(text) <= 600 or not _SHALL.search(text) or text.lower() in seen:
                continue
            seen.add(text.lower())
            abort = _ABORT_STATUS.search(text) if re.search(r"\babort", text, re.I) else None
            out.append({"requirement_id": stable_id("sreq", section_id, text), "section_id": section_id,
                        "text": text, "kind": "abort" if abort else "shall",
                        "expected_status": canonical_status(abort.group(1)) if abort else None,
                        "host_actions": required_host_actions(text)})
    return tuple(out)


def _same_title(a: str, b: str) -> bool:
    norm = lambda t: " ".join(plain_text(t or "").lower().split())  # noqa: E731
    return norm(a) == norm(b)


def section_requirements(section: dict, linked_sections: set) -> list[dict]:
    """Requirements of a target clause: its own block plus sub-clauses that are
    not targets themselves. Nothing when the index entry and the spec block
    disagree on the title (they must describe the same clause)."""
    catalog = clause_catalog()
    sid = section["section_id"]
    if sid not in catalog or not _same_title(section.get("title", ""), catalog[sid]["title"]):
        return []
    # A sub-clause's sentences belong to its nearest target ancestor only:
    # nvm:4.2.1.1.2 went to both nvm:4.2.1 and nvm:4.2.1.1 (58 duplicated
    # requirement ids of 1,274 targets, generated and sent twice).
    def nearest_target(key):
        parts = key.split(".")
        for n in range(len(parts) - 1, 0, -1):
            ancestor = ".".join(parts[:n])
            if ancestor in linked_sections:
                return ancestor
        return None

    keys = [sid] + [k for k in catalog if k.startswith(sid + ".") and k not in linked_sections
                    and nearest_target(k) == sid]
    return [r for k in keys for r in _block_requirements(k)]


def testable_sections(index) -> list[tuple[dict, list[dict]]]:
    """(section, opcodes this tool can offer for it) for every target clause."""
    out = []
    for section in index.list_sections():
        opcodes = index.opcodes_for_section(section)
        if not opcodes or _needs_unverifiable_value(section):
            continue
        offered = [o for o in opcodes if o.get("name") not in UNEXECUTABLE_COMMANDS]
        if offered:
            out.append((section, offered))
    return out


def requirement_targets(index) -> list[tuple[dict, dict, dict | None]]:
    """(section, opcode, requirement) for every requirement of every target
    clause; (section, opcode, None) for a clause with no extractable
    requirement, so no clause drops out. A requirement goes with the command
    it names, else the clause's own command."""
    cached = getattr(index, "_requirement_targets_cache", None)
    if cached is not None:  # the index is immutable for a run; recomputed per TC otherwise
        return cached
    linked = {s["section_id"] for s in index.list_sections() if index.opcodes_for_section(s)}
    out = []
    for section, offered in testable_sections(index):
        preferred = next((o for o in offered if o.get("section_ref") == section["section_id"]), offered[0])
        requirements = section_requirements(section, linked)
        if not requirements:
            out.append((section, preferred, None))
            continue
        for req in requirements:
            text = req["text"].lower()
            opcode = next((o for o in offered if o["name"].lower() in text), preferred)
            out.append((section, opcode, req))
    try:
        index._requirement_targets_cache = out
    except AttributeError:
        pass
    return out


def judged_target_requirements(tc_records: list[dict]) -> set:
    """Target requirement ids with a PASS/FAIL observation (same rule as totals)."""
    return {req["target_requirement_id"] for tc in tc_records for req, status in requirement_observations(tc)
            if status in ("PASS", "FAIL") and req.get("target_requirement_id")}


def _target_requirement_id(tc: dict) -> str | None:
    target = (tc.get("verification_contract") or {}).get("target_requirement") or {}
    return target.get("requirement_id")


def variant_target_triples(index, variants: list[dict] | None) -> list[tuple[dict, dict, dict]]:
    by_name = {o["name"]: o for o in index.list_opcodes()}
    sections = {s["section_id"]: s for s in index.list_sections()}
    out = []
    for variant in variants or []:
        section, opcode = sections.get(variant["section_id"]), by_name.get(variant["command"])
        if section and opcode:
            out.append((section, opcode, variant))
    return out


def pick_next_targets(index, tc_records: list[dict], count: int,
                      skip_records: list[dict] | None = None,
                      variants: list[dict] | None = None) -> list[tuple[dict, dict]]:
    """Rotate through requirements (each "shall" sentence of a target clause),
    prioritizing unjudged, less tried ones, round-robin over commands.

    The returned section carries `target_requirement` (None for a clause with
    no extractable requirement: the scenario then picks one, as before).
    Neither a legacy PASS nor an unsupported setup step permanently removes a
    target; answered ones go behind the unanswered ones.
    """
    if count < 1:
        return []
    requirements, _ = requirement_coverage(tc_records)
    verified = Counter(r["section_id"] for r in requirements if r["status"] != "UNVERIFIED")
    judged = judged_target_requirements(tc_records)
    attempts, pair_attempts, req_attempts, legacy = Counter(), Counter(), Counter(), Counter()
    unsupported_pairs = set()
    for tc in tc_records:
        pair = _action_pair(tc)
        rid = _target_requirement_id(tc)
        if rid:
            req_attempts[rid] += 1
        if pair:
            attempts[pair[0]] += 1
            pair_attempts[pair] += 1
            if not rid:
                legacy[pair[0]] += 1
            if _action_unsupported(tc):
                unsupported_pairs.add(pair)
        else:
            for sid in tc.get("source_section_ids", []):
                attempts[sid] += 1
                legacy[sid] += 1
    # A target skipped before reaching the device leaves no TC record. Without
    # counting it, an empty store re-picked the same first target every run
    # (measured: `--count 1` failed on the same generation forever).
    for skip in skip_records or []:
        attempts[skip["section_id"]] += 1
        pair_attempts[(skip["section_id"], skip["opcode"])] += 1
        if skip.get("kind") == "opcode_unsupported_in_run":
            # Another target of the same command got INVALID_OPCODE in that run.
            unsupported_pairs.add((skip["section_id"], skip["opcode"]))
        if skip.get("requirement_id"):
            req_attempts[skip["requirement_id"]] += 1
        else:
            legacy[skip["section_id"]] += 1

    def key(target):
        section, opcode, req = target
        sid, rid = section["section_id"], (req or {}).get("requirement_id")
        tries = req_attempts[rid] if rid else attempts[sid]
        # "Has an answer": judged, the drive's own INVALID_OPCODE for this
        # command, or enough tries that more of the same is unlikely to help.
        # Still offered, just after every target that has none.
        settled = ((rid in judged) if rid else verified[sid] > 0) or (sid, opcode["opcode"]) in unsupported_pairs \
            or tries >= UNRESOLVED_ATTEMPT_LIMIT or legacy[sid] >= UNRESOLVED_ATTEMPT_LIMIT
        return (settled, tries, attempts[sid], pair_attempts[(sid, opcode["opcode"])],
                _target_rank(section, opcode), rid or "")

    candidates = sorted(requirement_targets(index) + variant_target_triples(index, variants), key=key)
    # Round-robin over commands inside each priority band: in sorted order a
    # batch walked straight through one command's sub-clauses (measured: 22
    # Persistent Event Log event types back to back).
    picked = []
    for band in (False, True):
        queues, order = defaultdict(deque), []
        for target in candidates:
            if key(target)[0] is band:
                # Code variants rotate as their own queue so a command's few
                # hundred LLM requirements do not push them to the end.
                name = target[1]["name"] + (" [variant]" if (target[2] or {}).get("kind") == "variant" else "")
                if name not in queues:
                    order.append(name)
                queues[name].append(target)
        for name in order:  # within a command, rotate over its clauses too - among equally tried ones
            queues[name] = deque(t for _, group in groupby(queues[name], key=lambda t: key(t)[1])
                                 for t in _interleave_by_section(list(group)))
        while order and len(picked) < count:
            for name in list(order):
                section, opcode, req = queues[name].popleft()
                picked.append((dict(section, target_requirement=req) if req else section, opcode))
                if not queues[name]:
                    order.remove(name)
                if len(picked) == count:
                    break
    return picked


def _interleave_by_section(targets):
    """Same order inside each clause, clauses taken in turn: one clause's
    sentences no longer fill a batch back to back (it may still appear more
    than once per batch - a clause has many requirements now)."""
    by_section, order = defaultdict(deque), []
    for t in targets:
        sid = t[0]["section_id"]
        if sid not in by_section:
            order.append(sid)
        by_section[sid].append(t)
    out = []
    while order:
        for sid in list(order):
            out.append(by_section[sid].popleft())
            if not by_section[sid]:
                order.remove(sid)
    return out


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
