"""Evaluates an execution result against the TC's Expectation / Fail Criteria.

Criteria come in two kinds. Machine-checkable ones are declared as structured
rules and actually evaluated here. Prose criteria (currently authored by the
dummy LLM, later by the real one) cannot be evaluated automatically, so they
are reported as `unevaluated` rather than silently treated as satisfied — a
criterion nobody checked must not read as a pass.

Output-scanning rules below depend on `ssh_runner` folding each command's
stderr into its own stdout block: nvme-cli prints all diagnostics to stderr and
leaves stdout empty, so without that merge these rules can never fire.
"""
import re

TIMEOUT_MARKERS = ("timeout", "timed out", "TimeoutExpired")
ERROR_STATUS_MARKERS = ("NVMe status:", "nvme status:")

# A crash of nvme-cli itself on the host, not a device fault. Seen for real:
# authored args asked Get Log Page for 512 dwords (2048 B) while allocating a
# 512 B buffer, so the controller's reply overran the heap and the tool died
# with `malloc(): corrupted top size` and exit 134. Attributing that to the
# firmware would be wrong — it is our own argument bug.
HOST_CRASH_EXIT_CODES = {134, 136, 139}  # SIGABRT, SIGFPE, SIGSEGV
HOST_CRASH_MARKERS = ("malloc(", "corrupted", "Segmentation fault", "double free",
                       "free(): invalid", "stack smashing", "core dumped")


def _nonzero_exit(tc_record: dict, execution_result: dict) -> tuple[bool, str]:
    offenders = [r for r in execution_result["step_results"] if r["exit_code"] != 0]
    if offenders:
        codes = ", ".join(f"step{r['step_index']}={r['exit_code']}" for r in offenders)
        return True, f"nvme-cli exit code != 0 ({codes})"
    return False, "all steps exited 0"


def _timed_out(tc_record: dict, execution_result: dict) -> tuple[bool, str]:
    if execution_result.get("timed_out"):
        return True, "command batch exceeded its SSH timeout"
    blob = " ".join(str(r.get("stdout", "")) for r in execution_result["step_results"])
    hit = next((m for m in TIMEOUT_MARKERS if m.lower() in blob.lower()), None)
    return (True, f"timeout reported in command output ({hit})") if hit else (False, "no timeout reported")


def _controller_error_status(tc_record: dict, execution_result: dict) -> tuple[bool, str]:
    for r in execution_result["step_results"]:
        out = str(r.get("stdout", ""))
        if any(m in out for m in ERROR_STATUS_MARKERS) and "SUCCESS" not in out.upper():
            # Just the one line carrying the status text, not out.strip()[:200]
            # (a hard char cut used to chop the controller's own explanation
            # of the status code mid-sentence — e.g. "...currently in u" —
            # even though the terminal/log layer already has its own
            # separate short/full display split and doesn't need the data
            # itself pre-truncated).
            line = next((l for l in out.splitlines() if any(m in l for m in ERROR_STATUS_MARKERS)), out.strip())
            return True, f"controller returned an error status (step{r['step_index']}): {line.strip()}"
    return False, "no controller error status reported"


def _vacuous_success(tc_record: dict, execution_result: dict) -> tuple[bool, str]:
    """A step that declares a data direction but moves no data proves nothing.

    Measured on the target: `io-passthru --opcode=0x02 --cdw10=0` with no
    `--data-len` exits 0 ("IO Command Read is Success"), transferring nothing.
    Without this rule that becomes a PASS and counts as real spec coverage —
    a false confirmation, which is worse than a failure.
    """
    steps = tc_record.get("steps") or []
    by_index = {r["step_index"]: r for r in execution_result["step_results"]}
    for i, step in enumerate(steps):
        result = by_index.get(i)
        if result is None or result.get("exit_code") != 0:
            continue
        if step.get("direction", "none") != "none" and not step.get("data_len"):
            return True, (f"step{i} declares direction={step['direction']} but data_len=0, "
                           "so it exited 0 without transferring data")
    return False, "no vacuous success detected"


def _firmware_commit_activated_unvalidated_image(tc_record: dict, execution_result: dict) -> tuple[bool, str]:
    """Firmware Image Download has no real signed image to send — the batch
    sends a zero-filled dummy buffer instead (see `ssh_runner.execute_tc_steps`'s
    stdin handling), deliberately, so this exercises whether the controller
    actually validates an image before letting Firmware Commit (opcode 0x10)
    activate it. CDW10 bits 2:0 are the Commit Action (CA): 0 just stages the
    image into the slot without activating it (harmless regardless of
    content); 1/2/3/6/7 activate it, immediately or at the next reset. A
    controller that validates images should reject an activating commit
    against a dummy image with a non-zero exit code — the exact status text
    isn't load-bearing here, only whether it let an invalid image through.
    Accepting one is the serious finding this TC exists to catch, not an
    argument-authoring mistake on our side, so it must not get swallowed by
    the generic INVALID_* "our bug" classification the way a real mistake
    would be.
    """
    steps = tc_record.get("steps") or []
    by_index = {r["step_index"]: r for r in execution_result["step_results"]}
    for i, step in enumerate(steps):
        if str(step.get("opcode", "")).lower() != "0x10":
            continue
        try:
            commit_action = int(step["cdw10"], 16) & 0b111
        except (TypeError, ValueError, KeyError):
            continue
        if commit_action == 0:
            continue
        result = by_index.get(i)
        if result is not None and result.get("exit_code") == 0:
            return True, (f"step{i}: Firmware Commit with an activating Commit Action "
                           f"(CA={commit_action}) succeeded against a dummy, unvalidated firmware "
                           "image — the controller should reject an invalid image before "
                           "activating it")
    return False, "no activating Firmware Commit succeeded against a dummy image"


def unsupported_opcode(execution_result: dict) -> str | None:
    """Returns the controller's text when it does not implement the command.

    INVALID_OPCODE is a legitimate result, not a defect and not our bug: most
    NVMe commands are optional, and "this drive does not implement Track Send"
    is exactly what a spec-coverage sweep is supposed to establish. It counts
    toward coverage and must not be retried — no argument fix can make an
    unimplemented command succeed.
    """
    for r in execution_result["step_results"]:
        out = str(r.get("stdout", ""))
        if "INVALID_OPCODE" in out:
            return out.strip().splitlines()[0]
    return None


_INVALID_STATUS_RE = re.compile(r"\bINVALID_[A-Z_]+")


def rejected_arguments(execution_result: dict, tc_record: dict | None = None) -> tuple[int, str] | None:
    """Returns (step_index, controller's rejection text) when some step's
    *parameters* were refused, else None.

    Matches the whole `INVALID_*` family rather than INVALID_FIELD alone. Seen
    for real: the model put Get Log Page's LID in bits 31:16 instead of 07:00,
    so the drive answered INVALID_LOG_PAGE — which, matching only
    INVALID_FIELD, fell through and was recorded as a firmware FAIL *and*
    counted as coverage. Every one of these means the command we built was not
    acceptable, so the drive never ran the behaviour the clause describes.

    INVALID_OPCODE is excluded on purpose: an unimplemented optional command is
    a finding about the drive, not a malformed request (see `unsupported_opcode`).

    A genuine firmware bug could in principle also surface as INVALID_*, but it
    is indistinguishable from our own mistake without per-command knowledge, so
    the conservative reading wins: retry once, and if it persists record ERROR
    (excluded from coverage) rather than claim a defect. The one exception is a
    step whose `field_value_verified=True` (see `args_author._verify_field_values`)
    — its required Log Page/Feature Identifier/CNS/etc. value was deterministically
    confirmed to be in CDW10 before this ever reached the wire, so a rejection
    there isn't "our bug" the way an unverified one is; `tc_record`, when given,
    lets this function skip those steps so `field_value_unsupported` (not this)
    is what explains them.

    The step_index matters for multi-step TCs: `pipeline.py` uses it to decide
    whether a local one-step reauthor is safe (nothing after it depends on
    it) or whether the whole chain needs replanning.
    """
    verified_indices = {i for i, s in enumerate((tc_record or {}).get("steps") or [])
                         if s.get("field_value_verified")}
    for r in execution_result["step_results"]:
        if r["step_index"] in verified_indices:
            continue
        out = str(r.get("stdout", ""))
        for match in _INVALID_STATUS_RE.finditer(out):
            if match.group(0) != "INVALID_OPCODE":
                return r["step_index"], out.strip().splitlines()[0]
    return None


def field_value_unsupported(tc_record: dict, execution_result: dict) -> tuple[int, str] | None:
    """Returns (step_index, controller's rejection text) when a step whose
    required field value was deterministically verified (CDW10 confirmed to
    carry the exact Log Page/Feature Identifier/CNS/etc. the clause names —
    see `args_author._verify_field_values`) was still rejected by the
    controller with any non-INVALID_OPCODE `INVALID_*` status.

    Unlike `rejected_arguments`'s bucket, this is a real finding about the
    drive — the value was confirmed correctly placed before this reached the
    wire, so the rejection means this specific value isn't implemented, the
    same kind of legitimate answer `unsupported_opcode` already produces for
    a whole unimplemented command, just at finer grain.
    """
    steps = tc_record.get("steps") or []
    by_index = {r["step_index"]: r for r in execution_result["step_results"]}
    for i, step in enumerate(steps):
        if not step.get("field_value_verified"):
            continue
        result = by_index.get(i)
        if result is None:
            continue
        out = str(result.get("stdout", ""))
        for match in _INVALID_STATUS_RE.finditer(out):
            if match.group(0) != "INVALID_OPCODE":
                return i, out.strip().splitlines()[0]
    return None


def host_tool_crash(execution_result: dict) -> str | None:
    """Returns a description when nvme-cli itself crashed, else None.

    Checked before any firmware verdict: the drive told us nothing here, so the
    run must not be judged, must not count toward coverage, and should be
    retried once the arguments are fixed.
    """
    for r in execution_result["step_results"]:
        out = str(r.get("stdout", ""))
        marker = next((m for m in HOST_CRASH_MARKERS if m in out), None)
        if r.get("exit_code") in HOST_CRASH_EXIT_CODES or marker:
            reason = marker or f"exit {r.get('exit_code')}"
            return (f"nvme-cli crashed on the host at step{r['step_index']} ({reason}) — "
                     "the command arguments are almost certainly inconsistent "
                     "(e.g. a dword count that exceeds the allocated buffer)")
    return None


# Structured rules evaluated for every TC, independent of what the generator wrote.
BUILTIN_RULES = {
    "nvme-cli exit code != 0": _nonzero_exit,
    "command timeout exceeded": _timed_out,
    "controller error status returned": _controller_error_status,
    "succeeded without transferring declared data": _vacuous_success,
    "firmware commit activated an unvalidated dummy image": _firmware_commit_activated_unvalidated_image,
}


def evaluate_criteria(tc_record: dict, execution_result: dict) -> list[dict]:
    results = []
    for name, rule in BUILTIN_RULES.items():
        violated, detail = rule(tc_record, execution_result)
        results.append({"criterion": name, "kind": "builtin",
                         "result": "violated" if violated else "satisfied", "detail": detail})

    declared = (tc_record.get("expectation") or {}).get("fail_criteria", [])
    for criterion in declared:
        if criterion in BUILTIN_RULES:
            continue
        results.append({"criterion": criterion, "kind": "prose", "result": "unevaluated",
                         "detail": "free-text criterion — needs the real LLM to emit a structured rule"})
    return results


def check_step_expectations(tc_record: dict, execution_result: dict) -> list[str]:
    """One PASS/FAIL/UNSUPPORTED/ERROR per step, independent of its siblings.

    `tc_record["status"]` (from `check_expectation`) stays the single
    verdict used for routing (judge invocation, the placeholder-args skip,
    etc.) — this is a separate, additive per-step view
    so coverage can credit a chain's early PASS step even when a later step
    in the same TC errors out, instead of the whole chain being thrown out
    together. Mirrors `check_expectation`'s priority order (UNSUPPORTED >
    ERROR > FAIL > PASS) but scoped to one step's own result.
    """
    steps = tc_record.get("steps") or []
    by_index = {r["step_index"]: r for r in execution_result["step_results"]}
    statuses = []
    for i, step in enumerate(steps):
        result = by_index.get(i)
        if result is None or not result.get("started", True):
            # Never executed — e.g. an earlier step in the same shared-timeout
            # batch hung, so this one's delimiter was never even echoed. ERROR,
            # not FAIL: FAIL counts toward coverage, and a step that never
            # reached the device established nothing about its clause. (The
            # step that actually hung *did* start, so it still lands on FAIL
            # via the `exit_code is None` branch below.)
            statuses.append("ERROR")
            continue
        out = str(result.get("stdout", ""))
        exit_code = result.get("exit_code")
        if "INVALID_OPCODE" in out:
            statuses.append("UNSUPPORTED")
            continue
        crash_marker = next((m for m in HOST_CRASH_MARKERS if m in out), None)
        if exit_code in HOST_CRASH_EXIT_CODES or crash_marker:
            statuses.append("ERROR")
            continue
        if any(m.group(0) != "INVALID_OPCODE" for m in _INVALID_STATUS_RE.finditer(out)):
            # A verified step's rejection means this specific Log Page/
            # Feature Identifier/CNS/etc. value isn't implemented — a real
            # finding, not an authoring mistake — since CDW10 was already
            # deterministically confirmed to carry the exact value the
            # clause names before this ever reached the wire.
            statuses.append("UNSUPPORTED" if step.get("field_value_verified") else "ERROR")
            continue
        if exit_code is None:
            statuses.append("FAIL" if execution_result.get("timed_out") else "ERROR")
            continue
        timed_out_here = any(m.lower() in out.lower() for m in TIMEOUT_MARKERS)
        controller_error = any(m in out for m in ERROR_STATUS_MARKERS) and "SUCCESS" not in out.upper()
        vacuous = step.get("direction", "none") != "none" and not step.get("data_len")
        violated = exit_code != 0 or timed_out_here or controller_error or vacuous
        statuses.append("FAIL" if violated else "PASS")
    return statuses


def _action_step_indices(tc_record: dict, n_results: int) -> set[int]:
    """Indices of the chain's action step(s), read from each step's `phase`.
    A record with no phase tags (legacy, or a fake in tests) treats every
    step as the action — which reproduces the old any-step behavior."""
    steps = tc_record.get("steps") or []
    indices = {i for i, s in enumerate(steps) if s.get("phase") == "action"}
    return indices or set(range(max(n_results, len(steps))))


def _unsupported_step_indices(tc_record: dict, execution_result: dict) -> set[int]:
    """Steps the drive answered "not implemented" for: INVALID_OPCODE, or any
    non-INVALID_OPCODE `INVALID_*` on a step whose required field value was
    deterministically verified (see `field_value_unsupported`)."""
    steps = tc_record.get("steps") or []
    indices = set()
    for r in execution_result["step_results"]:
        i, out = r["step_index"], str(r.get("stdout", ""))
        if "INVALID_OPCODE" in out:
            indices.add(i)
        elif (i < len(steps) and steps[i].get("field_value_verified")
              and any(m.group(0) != "INVALID_OPCODE" for m in _INVALID_STATUS_RE.finditer(out))):
            indices.add(i)
    return indices


def check_expectation(tc_record: dict, execution_result: dict) -> str:
    if not execution_result["step_results"]:
        return "ERROR"
    if execution_result.get("timed_out"):
        # A wedged device is the headline finding this tool exists to produce, so
        # it is a FAIL — checked first, so nothing else about the chain (a setup
        # step that happened to be UNSUPPORTED, a rejected field elsewhere) can
        # relabel the hang and keep it away from judging. Only non-timeout
        # causes of a missing EXIT_CODE marker (SSH dropped, output truncated)
        # are ERROR — those say nothing about the device.
        return "FAIL"

    unsupported = _unsupported_step_indices(tc_record, execution_result)
    if unsupported & _action_step_indices(tc_record, len(execution_result["step_results"])):
        # A real answer about the drive: the command under test — or, for a
        # step whose required value was deterministically verified before it
        # was sent, this specific value of an otherwise-implemented command —
        # is not implemented.
        return "UNSUPPORTED"
    if unsupported:
        # Only a setup/verify step is unimplemented. That says nothing about
        # the clause under test, so it must not decide the TC's status in
        # either direction: not UNSUPPORTED (that used to mask a real FAIL of
        # the action step and skip judging it), and not FAIL either (its own
        # non-zero exit is not a firmware misbehavior). The per-step view
        # (`check_step_expectations`) still records it as UNSUPPORTED.
        execution_result = dict(execution_result, step_results=[
            r for r in execution_result["step_results"] if r["step_index"] not in unsupported])

    if host_tool_crash(execution_result) or rejected_arguments(execution_result, tc_record):
        # Our bug, not the drive's — ERROR keeps it out of coverage and re-queues it.
        return "ERROR"

    criteria = evaluate_criteria(tc_record, execution_result)
    violated = any(c["result"] == "violated" for c in criteria)
    if any(r["exit_code"] is None for r in execution_result["step_results"]):
        return "ERROR"
    return "FAIL" if violated else "PASS"
