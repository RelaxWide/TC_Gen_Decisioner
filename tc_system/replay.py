"""Re-judge a stored run with the current code, without the device or the LLM.

    python -m tc_system.replay <tc_store.json | run folder> [--target-skips <file>] [--json out.json]

Every stored TC keeps its raw step outputs, so statuses, requirement
verdicts and review reasons can be recomputed offline. Use it before and
after a change to see what the change does to real results: how many FAILs
remain, which were our own errors, which PASSes claim more than they
observed. It never writes to the input.

Limits: the stored steps are what was sent then; contract rules that act at
plan time (named fields, support premises) show up here only as review
reasons, and the start-of-run support probe did not exist in old runs.
"""
import argparse
import json
import re
from collections import Counter
from pathlib import Path

from tc_system.execution.expectation_checker import check_execution, check_expectation, check_step_expectations
from tc_system.review import claim_scope, code_review
from tc_system.verification import verify_tc

# Skip reasons the current code computes or explains instead of skipping on.
SKIP_RULES = [
    ("길이 필드(NUMD)는 하네스가 계산", re.compile(r"NUMD|NUMDL|NUMDU")),
    ("구조체 payload는 0으로 채움", re.compile(r"payload_hex pattern")),
    ("data_length 검사 제외 + 위치를 알려주는 메시지", re.compile(r"integer required: None")),
    ("조항 선택자는 하네스가 씀", re.compile(r"clause requires|must fix its selector")),
    ("NSID 메시지(24비트 FFFFFF 안내, INVALID_NS 부정 테스트 허용)", re.compile(r"nsid=")),
]


def _load(path):
    path = Path(path)
    store = path / "data" / "tc_store.json" if path.is_dir() else path
    skips = store.parent / "target_skips.json"
    return json.loads(store.read_text(encoding="utf-8")), (
        json.loads(skips.read_text(encoding="utf-8")) if skips.exists() else [])


def _counted(tc_status, requirements):
    """The coverage rule (coverage_state.requirement_observations): a
    requirement of an ERROR/UNSUPPORTED command, or a PASS under a FAILed
    command, is not a verdict."""
    out = Counter()
    for r in requirements:
        status = r.get("status")
        if tc_status in ("ERROR", "UNSUPPORTED") or (tc_status == "FAIL" and status == "PASS"):
            status = "UNVERIFIED"
        out[status] += 1
    return out


def replay(tcs, skips=()):
    rows = []
    for tc in tcs:
        execution = tc.get("execution") or {}
        if not execution.get("step_results"):
            continue
        new = dict(tc)
        new["step_statuses"] = check_step_expectations(tc, execution)
        new["verification"] = verify_tc(tc, execution)
        new["execution_status"] = check_execution(tc, execution)
        new["status"] = check_expectation(tc, execution)
        reasons = code_review(new)
        rows.append({"tc_id": tc.get("tc_id"), "name": tc.get("name"), "old": tc.get("status"), "new": new["status"],
                     "old_requirements": _counted(tc.get("status"), (tc.get("verification") or {}).get("requirements", [])),
                     "new_requirements": _counted(new["status"], new["verification"]["requirements"]),
                     "scope": claim_scope(new) if new["status"] == "PASS" else None,
                     "reasons": reasons})
    skip_rows = []
    for skip in skips:
        fixed = next((label for label, rx in SKIP_RULES if rx.search(skip.get("reason", ""))), None)
        skip_rows.append({"section_id": skip.get("section_id"), "fixed_by": fixed, "reason": skip.get("reason", "")})
    return rows, skip_rows


def summary(rows, skip_rows):
    lines = []
    lines.append(f"TC {len(rows)}건 재판정")
    lines.append("상태 변화(이전 -> 현재 코드): " + ", ".join(
        f"{a}->{b} {n}" for (a, b), n in sorted(Counter((r["old"], r["new"]) for r in rows).items())))
    old_req, new_req = Counter(), Counter()
    for r in rows:
        old_req.update(r["old_requirements"])
        new_req.update(r["new_requirements"])
    lines.append(f"요구사항: 이전 {dict(old_req)} -> 현재 {dict(new_req)}")
    level = Counter(max((x["level"] for x in r["reasons"]), key=("info", "recommend", "must").index, default="info")
                    for r in rows)
    lines.append(f"검토 요청: 꼭 확인 {level['must']}, 확인 권장 {level['recommend']}, 참고 {level['info']}")
    codes = Counter(x["code"] for r in rows for x in r["reasons"])
    lines.append("사유 종류: " + ", ".join(f"{c} {n}" for c, n in codes.most_common()))
    lines.append("PASS 범위: " + ", ".join(f"{s} {n}" for s, n in Counter(r["scope"] for r in rows if r["scope"]).most_common()))
    if skip_rows:
        fixed = Counter(s["fixed_by"] for s in skip_rows)
        lines.append(f"건너뜀 {len(skip_rows)}건 중 현재 코드가 계산/설명으로 대신하는 것: "
                     + ", ".join(f"{k} {v}" for k, v in fixed.items() if k) + f"; 그대로 {fixed[None]}")
    for r in rows:
        if r["old"] == "FAIL" or r["new"] == "FAIL":
            lines.append(f"  [{r['old']} -> {r['new']}] {r['name']}")
            for x in r["reasons"]:
                if x["level"] == "must" and x["code"] != "fail":
                    lines.append(f"      - {x['text']}")
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("store", help="tc_store.json, or a run folder containing data/tc_store.json")
    parser.add_argument("--json", help="write per-TC rows here")
    args = parser.parse_args(argv)
    tcs, skips = _load(args.store)
    rows, skip_rows = replay(tcs, skips)
    print(summary(rows, skip_rows))
    if args.json:
        Path(args.json).write_text(json.dumps({"tcs": rows, "skips": skip_rows}, ensure_ascii=False, indent=1,
                                              default=dict), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
