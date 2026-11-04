"""FailureContext / Verdict are plain dicts with a fixed shape (see plan doc)
rather than dataclasses — they're built incrementally by parsers from regex
matches and persisted straight to JSON, so a dict keeps construction simple.
"""
CLASSIFICATIONS = ("firmware_defect", "test_env_issue", "needs_engineer_review")


def make_failure_context(*, failure_context_id, source_type, run_id, timestamp,
                          primary_log_excerpt, signals, dmesg_file=None, dmesg_excerpt=None,
                          extraction_meta=None, **extra):
    ctx = {
        "failure_context_id": failure_context_id,
        "source_type": source_type,
        "run_id": run_id,
        "timestamp": timestamp,
        "primary_log_excerpt": primary_log_excerpt,
        "signals": signals,
        "dmesg_file": dmesg_file,
        "dmesg_excerpt": dmesg_excerpt,
        "spec_grounding": {"queried": False, "rag_response_id": None, "matched_section_ids": []},
        "extraction_meta": extraction_meta or {},
    }
    ctx.update(extra)
    return ctx


def make_verdict(*, verdict_id, failure_context_id, classification, confidence,
                  rationale, guidance, llm_response_id, judged_at, judge_version="v1-llm"):
    if classification not in CLASSIFICATIONS:
        raise ValueError(f"invalid classification: {classification!r}, must be one of {CLASSIFICATIONS}")
    return {
        "verdict_id": verdict_id,
        "failure_context_id": failure_context_id,
        "classification": classification,
        "confidence": confidence,
        "rationale": rationale,
        "guidance": guidance,
        "llm_response_id": llm_response_id,
        "judged_at": judged_at,
        "judge_version": judge_version,
    }
