"""Offline evidence for the 2026-11-04 spec coverage review.

Run from any directory:
    python3 tests/reproduce_spec_coverage_audit.py
    python3 tests/reproduce_spec_coverage_audit.py --scan-retrieval

Reads local artifacts and calls pure validation/search functions. No SSH, LLM,
credentials, pipeline execution, or writes to project state. Synthetic responses
are explicitly labeled counterexamples; they are not hardware measurements.
"""
import argparse
from collections import Counter
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tc_system.coverage.coverage_state import compute_coverage
from tc_system.coverage.spec_coverage_index import SpecCoverageIndexFile
from tc_system.execution.expectation_checker import (
    check_expectation, check_step_expectations, evaluate_criteria,
)
from tc_system.generation.args_author import _verify_field_values


def execution(stdout, exit_code=0):
    return {"step_results": [{"step_index": 0, "exit_code": exit_code,
                              "stdout": stdout, "started": True}],
            "timed_out": False, "dmesg_text": ""}


def tc_for(step, criteria=None):
    return {"steps": [dict(phase="action", **step)],
            "expectation": {"fail_criteria": criteria or []}}


def counterexamples(index):
    cases = []
    # These values encode the intended scenario in the real Get Features TC,
    # even though the stored command actually used FID=02h instead.
    tc = tc_for({"opcode": "0x0A", "cdw10": "0x0000037D",
                 "direction": "none", "data_len": 0},
                ["Saveable 비트가 0이 아니거나 Changeable 비트가 1이 아니면 실패"])
    result = execution("Admin Command Get Features is Success and result: 0xFFFFFFFF")
    cases.append({"case": "wrong_completion_bits", "synthetic": True,
                  "observed_status": check_expectation(tc, result),
                  "prose_results": [c["result"] for c in evaluate_criteria(tc, result)
                                    if c["kind"] == "prose"],
                  "issue": "Completion bits are never compared with the declared criterion."})

    tc = tc_for({"opcode": "0x02", "cdw10": "0x007F0002",
                 "direction": "read", "data_len": 512},
                ["반환 데이터가 512바이트 미만이면 실패"])
    result = execution("Admin Command Get Log Page is Success and result: 0x00000000")
    cases.append({"case": "no_returned_payload_evidence", "synthetic": True,
                  "observed_status": check_expectation(tc, result),
                  "issue": "A declared transfer length is not evidence of returned data."})

    tc = tc_for({"opcode": "0x02", "direction": "read", "data_len": 512},
                ["지원하지 않는 LID에 INVALID_LOG_PAGE를 반환하지 않으면 실패"])
    result = execution("NVMe status: INVALID_LOG_PAGE: expected negative-test response", 22)
    cases.append({"case": "expected_error_status", "synthetic": True,
                  "observed_status": check_expectation(tc, result),
                  "issue": "Expected error responses cannot be represented as a passing assertion."})

    tc["steps"][0]["field_value_verified"] = _verify_field_values(
        "0x007F0002", [{"field_name": "Log Page Identifier", "hex_value": "02"}])
    result = execution("NVMe status: INVALID_NS: invalid namespace(0xb)", 22)
    cases.append({"case": "valid_lid_does_not_validate_namespace", "synthetic": True,
                  "observed_status": check_expectation(tc, result),
                  "issue": "One correct selector turns any INVALID_* into UNSUPPORTED."})

    read = next(o for o in index.list_opcodes() if o["name"] == "Read")
    tc = tc_for({"opcode": read["raw_opcode"], "direction": "read", "data_len": 512})
    tc.update(tc_id="audit-synthetic-host-error", uses_placeholder_args=False,
              step_section_ids=[read["section_ref"]], step_opcodes=[read["opcode"]])
    result = execution("/dev/nvme0n1: No such file or directory\nUsage: --timeout=<NUM>", 2)
    tc["status"] = check_expectation(tc, result)
    tc["step_statuses"] = check_step_expectations(tc, result)
    cases.append({"case": "host_error_counts_as_coverage", "synthetic": True,
                  "observed_status": tc["status"],
                  "covered_sections": compute_coverage(index, [tc])["summary"]["section_covered"],
                  "timeout_rule": next(c for c in evaluate_criteria(tc, result)
                                       if c["criterion"] == "command timeout exceeded"),
                  "issue": "Host failure becomes FAIL; a help option is mistaken for a timeout."})

    for cdw10 in ("0x00000001", "0x00000008", "0x00000009"):
        tc = tc_for({"opcode": "0x10", "cdw10": cdw10,
                     "direction": "none", "data_len": 0})
        result = execution("Success")
        cases.append({"case": "firmware_commit_" + cdw10, "synthetic": True,
                      "spec_CA_bits_5_3": (int(cdw10, 16) >> 3) & 7,
                      "spec_FS_bits_2_0": int(cdw10, 16) & 7,
                      "observed_status": check_expectation(tc, result),
                      "observed_step_statuses": check_step_expectations(tc, result),
                      "issue": "CA is decoded from FS bits; per-step checks omit the firmware rule."})
    return cases


def stored_evidence(records):
    mismatches = []
    for tc in records:
        for i, step in enumerate(tc["steps"]):
            if step.get("mode") != "admin-passthru" or int(step["opcode"], 16) != 2:
                continue
            numd = ((int(step["cdw11"], 16) & 0xFFFF) << 16) | (int(step["cdw10"], 16) >> 16)
            requested = (numd + 1) * 4
            if requested != step["data_len"]:
                mismatches.append({"tc_id": tc["tc_id"], "step_index": i,
                                   "cdw10": step["cdw10"], "cdw11": step["cdw11"],
                                   "requested_bytes": requested, "buffer_bytes": step["data_len"]})
    return {"record_count": len(records),
            "statuses": dict(Counter(t["status"] for t in records)),
            "prose_criteria": dict(Counter(c["result"] for t in records
                                           for c in t["execution"]["criteria_results"]
                                           if c["kind"] == "prose")),
            "get_log_page_length_mismatches": mismatches,
            "pass_records": [{"tc_id": t["tc_id"], "scenario": t["scenario"],
                              "steps": [{k: s.get(k) for k in
                                         ("name", "phase", "role", "cdw10", "cdw11",
                                          "cdw12", "nsid", "data_len", "direction")}
                                        for s in t["steps"]]}
                             for t in records if t["status"] == "PASS"]}


def retrieval_diagnostic(index):
    from shared.spec_chunks import load_chunks, search_chunks

    chunks = {c["doc_id"]: c for c in load_chunks()}
    opcodes = {o["opcode"]: o for o in index.list_opcodes()}
    counts = Counter()
    for section in index.list_sections():
        if not section.get("related_opcodes"):
            continue
        opcode = next((opcodes[k] for k in section["related_opcodes"] if k in opcodes), None)
        if opcode is None:
            continue
        query = f"{section['title']} ({opcode['name']}) expected behavior and error handling"
        results = search_chunks(query, top_k=3, doc_filter=[section["spec_doc"]])
        heading = re.compile(r"^#{1,6}\s+" + re.escape(section["clause"]) + r"\s+", re.M)
        full = any(heading.search(chunks[r["chunk_id"]]["content"]) for r in results)
        visible = any(heading.search(r["text"]) for r in results)
        counts["sections"] += 1
        counts["target_heading_in_full_selected_chunks"] += bool(full)
        counts["target_heading_visible_in_prompt"] += bool(visible)
        counts["heading_lost_to_2000char_cut"] += bool(full and not visible)
    return {"counts": dict(counts),
            "limitation": "Heading presence measures traceability, not semantic relevance or compliance."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scan-retrieval", action="store_true")
    args = parser.parse_args()
    index = SpecCoverageIndexFile(ROOT / "specs/spec_coverage_index.json")
    output = {"counterexamples": counterexamples(index)}
    store = ROOT / "data/tc_store.json"
    if store.exists():
        records = json.loads(store.read_text(encoding="utf-8"))
        output["stored_evidence"] = stored_evidence(records)
        output["recomputed_coverage"] = compute_coverage(index, records)["summary"]
    else:
        output["stored_evidence"] = {"unavailable": "Local data/tc_store.json is not in git."}
    if args.scan_retrieval:
        output["retrieval_diagnostic"] = retrieval_diagnostic(index)
    print(json.dumps(output, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
