import argparse
import sys

import config
from log_judge.judge import judge_failure_context
from shared.file_store import load_json, save_json_atomic
from shared.llm_client import LLMCallError

SOURCES = ("qst", "pulsefz", "tc_exec")


def _merge_verdicts(existing: list[dict], fresh: list[dict]) -> list[dict]:
    fresh_ids = {v["failure_context_id"] for v in fresh}
    return [v for v in existing if v["failure_context_id"] not in fresh_ids] + fresh


def judge_source(source: str, force: bool = False) -> tuple[list[dict], int, list[tuple[str, str]]]:
    fc_dir = config.FAILURE_CONTEXTS_DIR / source
    verdicts_path = config.VERDICTS_DIR / f"{source}.json"
    verdicts = load_json(verdicts_path, default=[])
    judged_ids = {v["failure_context_id"] for v in verdicts}

    present_ids = set()
    new_verdicts = []
    failures = []
    for fc_path in sorted(fc_dir.glob("*.json")):
        fc = load_json(fc_path)
        present_ids.add(fc["failure_context_id"])
        if not force and fc["failure_context_id"] in judged_ids:
            continue
        try:
            verdict = judge_failure_context(fc)
        except (LLMCallError, ValueError, KeyError, TypeError) as exc:
            # Leave this one unjudged so the next run retries it; fabricating a
            # verdict would put an unfounded classification in the report. Broad
            # on purpose: one malformed LLM reply must not discard the verdicts
            # already earned in this batch.
            failures.append((fc["failure_context_id"], f"{type(exc).__name__}: {exc}"))
            continue
        new_verdicts.append(verdict)
        save_json_atomic(fc_path, fc)  # persists spec_grounding populated during judging
        # Persist after each item: judging costs an LLM call apiece, so an
        # interruption partway through must not throw away what is done. No
        # orphan pruning here — `present_ids` is still incomplete mid-loop, and
        # pruning against it would delete verdicts for contexts not yet visited.
        save_json_atomic(verdicts_path, _merge_verdicts(verdicts, new_verdicts))

    # Final pass prunes verdicts whose FailureContext no longer exists — now
    # that `present_ids` is complete. Without this, renaming the fc_id scheme
    # or deleting a context leaves its verdict behind forever and the report
    # renders it as a classification row with no evidence at all.
    merged = _merge_verdicts(verdicts, new_verdicts)
    kept = [v for v in merged if v["failure_context_id"] in present_ids]
    orphaned = len(merged) - len(kept)
    save_json_atomic(verdicts_path, kept)
    return new_verdicts, orphaned, failures


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", choices=SOURCES + ("all",), default="all")
    parser.add_argument("--force", action="store_true", help="re-judge already-judged failure contexts")
    args = parser.parse_args()

    sources = SOURCES if args.source == "all" else (args.source,)
    total_failures = 0
    for source in sources:
        new_verdicts, orphaned, failures = judge_source(source, force=args.force)
        suffix = f", dropped {orphaned} orphaned verdict(s)" if orphaned else ""
        print(f"{source}: {len(new_verdicts)} new verdict(s){suffix}")
        for v in new_verdicts:
            print(f"  {v['failure_context_id']} -> {v['classification']} (confidence={v['confidence']})")
        for fc_id, err in failures:
            print(f"  {fc_id} -> SKIPPED (will retry next run): {err}", file=sys.stderr)
        total_failures += len(failures)

    _write_reports(sources)
    if total_failures:
        print(f"\n{total_failures} context(s) left unjudged due to LLM errors.", file=sys.stderr)
        return 1
    return 0


def _write_reports(sources):
    """The log judgment report after QST/PULSEFZ judging, the TC report after
    re-judging TC failures. Never fails the run."""
    try:
        from report.aggregator import build_log_model, build_tc_model
        from report.html_report import write_log_report, write_tc_report
        if set(sources) & {"qst", "pulsefz"}:
            print(f"로그 판정 리포트: {write_log_report(build_log_model())}")
        if "tc_exec" in sources:
            print(f"TC 리포트: {write_tc_report(build_tc_model())}")
    except Exception as exc:  # noqa: BLE001
        print(f"report generation failed (run_report.py rebuilds it): {exc}", file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
