def apply_post_rules(verdict: dict, failure_context: dict) -> dict:
    """Safety net on top of the (dummy, for now) LLM judge: low-confidence calls
    get downgraded to needs_engineer_review rather than asserting a firm verdict."""
    if verdict["confidence"] < 0.5 and verdict["classification"] != "needs_engineer_review":
        verdict["classification"] = "needs_engineer_review"
        verdict["rationale"] += " [post-rule: low confidence downgraded to needs_engineer_review]"
    return verdict
