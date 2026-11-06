"""Real LLM completion calls, via the authenticated client in `rag/srag_llm_guide.py`.

The guide module's own `generate_rag_response()` is not used here: it hardcodes
its system prompt and runs its own server-side RAG search, while our callers
need a controllable system prompt and a structured JSON answer. We reuse its
already-authenticated `client` object instead — credential values are never
read or logged by this module.

Failures raise `LLMCallError` rather than returning a fabricated answer, so a
caller can leave the item unjudged and retry it on the next run.

Every call — including failed ones — is appended to `config.LLM_CALL_LOG_PATH`
as one JSON line: prompt, system prompt, raw response, parsed structure, which
module made the call (`caller`), and the error if it failed. Before this, the
prompt and raw completion text were never persisted anywhere; the only
retrievable fields were whatever a caller happened to copy into its own data
(e.g. `scenario.description`), which is not the same as being able to see what
was actually sent and actually came back.
"""
import json
import re
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import config
from shared.ids import stable_id

IS_DUMMY = False

REASONING_EFFORT = "low"
_FENCE_RE = re.compile(r"^```(?:json)?\s*(.*?)\s*```$", re.DOTALL)
_guide = None
# Scenario/argument generation runs in worker threads (pipeline prefetch).
_lock = threading.Lock()


class LLMCallError(RuntimeError):
    pass


def _load_guide():
    # Imported lazily so that importing this module never touches the network
    # or requires credentials to be present (tests import siblings of it).
    with _lock:
        return _load_guide_locked()


def _load_guide_locked():
    global _guide
    if _guide is None:
        rag_dir = str(config.RAG_DIR)
        if rag_dir not in sys.path:
            sys.path.insert(0, rag_dir)
        try:
            import srag_llm_guide
        except Exception as exc:
            raise LLMCallError(
                f"could not load {Path(config.RAG_DIR) / 'srag_llm_guide.py'}: "
                f"{type(exc).__name__} — fill in its credential constants"
            ) from exc
        _guide = srag_llm_guide
    return _guide


def _schema_instruction(response_schema: dict) -> str:
    lines = ["Respond with ONLY a JSON object. No prose, no markdown code fences.",
             "The object must have exactly these keys and nothing else:"]
    for key, spec in response_schema.items():
        hint = spec if isinstance(spec, str) and spec.strip() else "value"
        lines.append(f'  "{key}": {hint}')
    return "\n".join(lines)


def _extract_json(raw: str) -> dict:
    """Always returns a dict or raises JSONDecodeError. Valid JSON that is not
    an object (`[...]`, a bare string/number) is treated as a parse failure,
    so it goes through the same one-retry path — passing it on used to
    surface later as a TypeError (`structured["direction"]` on a list), which
    no caller expects from this module."""
    text = (raw or "").strip()
    fenced = _FENCE_RE.match(text)
    if fenced:
        text = fenced.group(1).strip()
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        value = None
    if isinstance(value, dict):
        return value
    # Some answers wrap the object in a sentence (or in an array); fall back to
    # the outermost brace pair rather than discarding an otherwise-good response.
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end <= start:
        raise json.JSONDecodeError("expected a JSON object", text, 0)
    value = json.loads(text[start:end + 1])
    if not isinstance(value, dict):
        raise json.JSONDecodeError("expected a JSON object", text, start)
    return value


def _complete(guide, prompt: str, system: str | None) -> str:
    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})
    try:
        completion = guide.client.chat.completions.create(
            model=guide.model or "testmodel",
            messages=messages,
            reasoning_effort=REASONING_EFFORT,
        )
    except Exception as exc:
        raise LLMCallError(f"LLM request failed: {type(exc).__name__}") from exc
    try:
        text = completion.choices[0].message.content
    except (AttributeError, IndexError, TypeError) as exc:
        # An empty `choices` list or a reshaped reply object must surface as
        # the one exception type every caller is prepared to catch.
        raise LLMCallError(f"LLM returned a malformed completion: {type(exc).__name__}") from exc
    if not (text or "").strip():
        # Reasoning tokens can consume the budget before any visible content.
        raise LLMCallError("LLM returned an empty response")
    return text


def _append_log(record: dict) -> None:
    config.LOGS_DIR.mkdir(parents=True, exist_ok=True)
    line = json.dumps(record, ensure_ascii=False) + "\n"
    with _lock, config.LLM_CALL_LOG_PATH.open("a", encoding="utf-8") as f:
        f.write(line)


def generate_llm_response(prompt: str, *, system: str | None = None,
                           response_schema: dict | None = None, caller: str | None = None) -> dict:
    """`caller` is a free-text tag (e.g. "judge", "scenario_generator",
    "args_author") recorded in the call log so a given log line can be traced
    back to which part of the system made it."""
    guide = _load_guide()
    full_prompt = prompt if not response_schema else f"{prompt}\n\n{_schema_instruction(response_schema)}"

    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "caller": caller,
        "system": system,
        "prompt": full_prompt,
        "response_schema_keys": list(response_schema) if response_schema else None,
        "raw_response": None,
        "retry_prompt": None,
        "retry_raw_response": None,
        "structured": None,
        "response_id": None,
        "error": None,
    }
    started = time.monotonic()
    try:
        text = _complete(guide, full_prompt, system)
        record["raw_response"] = text
        structured = {}
        if response_schema:
            try:
                structured = _extract_json(text)
            except json.JSONDecodeError:
                retry_prompt = (f"{full_prompt}\n\nYour previous reply was not valid JSON. "
                                 "Reply with the JSON object only.")
                record["retry_prompt"] = retry_prompt
                text = _complete(guide, retry_prompt, system)
                record["retry_raw_response"] = text
                try:
                    structured = _extract_json(text)
                except json.JSONDecodeError as exc:
                    raise LLMCallError(f"LLM did not return parseable JSON: {exc}") from exc

            missing = [k for k in response_schema if k not in structured]
            # Valid JSON that just dropped a key got no retry at all before —
            # straight to LLMCallError, which a caller with no try/except
            # around this call (scenario_generator's, at the time) turned
            # into a crash of the whole batch over one incomplete reply.
            # One retry here, same "retry once" budget used everywhere else
            # in this project — skipped if the JSON-parse retry above
            # already spent it.
            if missing and not record["retry_prompt"]:
                retry_prompt = (f"{full_prompt}\n\nYour previous reply was missing required keys: "
                                 f"{missing}. Reply again with the complete JSON object, including "
                                 "every key listed above.")
                record["retry_prompt"] = retry_prompt
                text = _complete(guide, retry_prompt, system)
                record["retry_raw_response"] = text
                try:
                    structured = _extract_json(text)
                except json.JSONDecodeError as exc:
                    raise LLMCallError(f"retry LLM did not return parseable JSON: {exc}") from exc
                missing = [k for k in response_schema if k not in structured]
            if missing:
                raise LLMCallError(f"LLM response missing required keys: {missing}")

        # The whole reply: two replies sharing their first 200 characters got
        # the same id (review R11).
        response_id = stable_id("llm", prompt, system or "", str(response_schema), text)
        record["structured"], record["response_id"] = structured, response_id
        return {"response_id": response_id, "text": text, "structured": structured, "is_dummy": False}
    except LLMCallError as exc:
        record["error"] = str(exc)
        raise
    finally:
        record["elapsed_sec"] = round(time.monotonic() - started, 2)
        _append_log(record)
