import json
import re
from datetime import datetime, timezone

import config
from log_judge.classify import apply_post_rules
from log_judge.models import CLASSIFICATIONS, make_verdict
from shared.file_store import load_json
from shared.ids import stable_id
from shared.llm_client import generate_llm_response
from shared.rag_client import generate_rag_response

JUDGE_RESPONSE_SCHEMA = {
    "classification": 'exactly one of "firmware_defect", "test_env_issue", "needs_engineer_review"',
    "confidence": "number between 0 and 1",
    "rationale": "string — cite the specific evidence that drove the classification",
    "guidance": "array of strings — concrete places for an engineer to look "
                 "(file:line, opcode, dmesg timestamp), empty array if none",
}

JUDGE_SYSTEM_PROMPT = (
    "You are an SSD firmware QA triage assistant. You are given one failure from an NVMe "
    "SSD test run: extracted signals, a log excerpt, the correlated kernel dmesg excerpt, "
    "and relevant NVMe specification text. Decide whether the evidence points to a "
    "firmware defect in the drive, an issue with the test environment/harness, or whether "
    "an engineer must investigate further. Base the verdict only on the given evidence; "
    "if the evidence is thin or ambiguous, say so and choose needs_engineer_review.\n\n"
    "Write rationale and every guidance entry in Korean (한국어). classification itself "
    "must stay exactly one of the three literal English enum values given in the schema "
    "— do not translate it."
)

_opcode_name_cache: dict | None = None


def _opcode_name_lookup() -> dict:
    # The real RAG index is tagged with human-readable command names (covers_
    # commands), not hex opcodes — a query built from a bare "0x09" scores far
    # lower (~2) than one naming "Dataset Management" (~22, measured). This
    # maps our coverage-index opcode keys back to that name for the RAG query.
    global _opcode_name_cache
    if _opcode_name_cache is None:
        data = load_json(config.active_coverage_index_path(), default={"opcodes": []})
        _opcode_name_cache = {o["opcode"]: o["name"] for o in data.get("opcodes", [])}
    return _opcode_name_cache


def _extract_opcode(fc: dict) -> str | None:
    signals = fc["signals"]
    opcode = signals.get("opcode") or (signals.get("cmd") or {}).get("OPCODE")
    if opcode:
        return opcode
    source_opcodes = signals.get("source_opcodes")
    if source_opcodes:
        return source_opcodes[0]
    # Failures whose only command context is in the post-FAILED teardown (the
    # device stopped answering vendor commands) have no in-window opcode, and
    # those are precisely the ones worth grounding against the spec.
    for entry in signals.get("post_failure_errors", []):
        candidate = (entry.get("cmd") or {}).get("OPCODE")
        if candidate:
            return candidate
    return None


def _extract_command_name(fc: dict) -> str | None:
    signals = fc["signals"]
    if signals.get("cmd_name"):  # PULSEFZ: already a human-readable name
        return signals["cmd_name"]
    for key in signals.get("source_opcodes", []):  # TC_EXEC: our own coverage-index key
        name = _opcode_name_lookup().get(key)
        if name:
            return name
    return None


def _build_prompt(fc: dict) -> tuple[str, str | None, str | None]:
    opcode = _extract_opcode(fc)
    name = _extract_command_name(fc)
    lines = [
        f"source_type={fc['source_type']} run_id={fc['run_id']} timestamp={fc['timestamp']}",
        # Budgets are generous on purpose: the stored excerpts are already
        # signal-prioritised and capped, so a tight slice here was dropping the
        # discriminating kernel lines (one context carries 155 resets and 45
        # timeouts; 2 KB showed only the first handful of resets).
        f"signals={json.dumps(fc['signals'], ensure_ascii=False)[:4000]}",
        f"primary_log_excerpt=\n{fc['primary_log_excerpt'][:8000]}",
        f"dmesg_excerpt=\n{(fc.get('dmesg_excerpt') or '')[:12000]}",
    ]
    return "\n\n".join(lines), opcode, name


def _as_classification(value) -> str:
    """Map the model's wording onto the fixed enum.

    `make_verdict` rejects anything outside the enum, and a single reply of
    "firmware defect" (space, or title case) would otherwise raise ValueError
    and abort the whole run. Unrecognized wording becomes the conservative
    needs_engineer_review rather than a confident claim either way.
    """
    text = re.sub(r"[^a-z]+", "_", str(value).strip().lower()).strip("_")
    if text in CLASSIFICATIONS:
        return text
    if "firmware" in text or "defect" in text:
        return "firmware_defect"
    if "env" in text or "test" in text or "harness" in text:
        return "test_env_issue"
    return "needs_engineer_review"


def _as_guidance(value) -> list[str]:
    """Always a list of strings — the report iterates this, so a bare string
    would render one character per row."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value.strip() else []
    if isinstance(value, dict):
        return [f"{k}: {v}" for k, v in value.items()]
    try:
        return [str(v) for v in value]
    except TypeError:
        return [str(value)]


def _as_confidence(value) -> float:
    # Models sometimes answer "0.7", "70%" or 70 instead of 0.7; post-rules key
    # off this number, so normalize rather than letting a stray scale through.
    if isinstance(value, str):
        value = value.strip().rstrip("%")
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0.0
    if number > 1:
        number = number / 100 if number <= 100 else 1.0
    return max(0.0, min(1.0, number))


def judge_failure_context(fc: dict, use_rag_grounding: bool = True) -> dict:
    prompt, opcode, name = _build_prompt(fc)

    if use_rag_grounding and (opcode or name):
        query = " ".join(t for t in (name, f"opcode {opcode}" if opcode else None) if t)
        rag = generate_rag_response(f"NVMe {query} expected behavior and error handling", top_k=3)
        fc["spec_grounding"] = {
            "queried": True,
            "rag_response_id": rag["response_id"],
            "matched_section_ids": [c["section_id"] for c in rag["chunks"] if c.get("section_id")],
        }
        prompt += "\n\nspec_context=\n" + "\n".join(c["text"] for c in rag["chunks"])

    llm = generate_llm_response(prompt, system=JUDGE_SYSTEM_PROMPT,
                                 response_schema=JUDGE_RESPONSE_SCHEMA, caller="judge")
    structured = llm["structured"]
    verdict = make_verdict(
        verdict_id=stable_id("verdict", fc["failure_context_id"]),
        failure_context_id=fc["failure_context_id"],
        classification=_as_classification(structured["classification"]),
        confidence=_as_confidence(structured["confidence"]),
        rationale=structured["rationale"],
        guidance=_as_guidance(structured["guidance"]),
        llm_response_id=llm["response_id"],
        judged_at=datetime.now(timezone.utc).isoformat(),
    )
    return apply_post_rules(verdict, fc)
