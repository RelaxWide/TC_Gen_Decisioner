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

from tc_system.verification import (HOST_ERROR_RE, KERNEL_ABORT_RE, completion_status, matches_expected,
                                    expected_status, payload_for_step, verify_tc)

TIMEOUT_MARKERS = ("timed out", "TimeoutExpired", "command timeout", "I/O timeout")
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
    steps = tc_record.get("steps", [])
    offenders = [r for r in execution_result.get("step_results", []) if r["exit_code"] != 0
                 and not (r["step_index"] < len(steps) and matches_expected(steps[r["step_index"]], r))]
    if offenders:
        codes = ", ".join(f"step{r['step_index']}={r['exit_code']}" for r in offenders)
        return True, f"nvme-cli exit code != 0 ({codes})"
    return False, "all steps exited 0"


def kernel_aborted(execution_result: dict) -> int | None:
    """Index of the first step the kernel cancelled (see KERNEL_ABORT_RE) -
    the same finding as an SSH timeout, caught one layer lower."""
    for r in execution_result.get("step_results", []):
        if r.get("started", True) and KERNEL_ABORT_RE.search(str(r.get("stdout", ""))):
            return r["step_index"]
    return None


def device_hung(execution_result: dict) -> bool:
    """SSH batch timeout or kernel-side cancellation: never retried, always
    followed by a health check, and always FAIL."""
    return bool(execution_result.get("timed_out")) or kernel_aborted(execution_result) is not None


def _timed_out(tc_record: dict, execution_result: dict) -> tuple[bool, str]:
    if execution_result.get("timed_out"):
        return True, "command batch exceeded its SSH timeout"
    aborted = kernel_aborted(execution_result)
    if aborted is not None:
        return True, f"step{aborted}: the kernel cancelled the command (EINTR/EIO after its nvme timeout or a reset)"
    blob = " ".join(str(r.get("stdout", "")) for r in execution_result.get("step_results", []))
    hit = next((m for m in TIMEOUT_MARKERS if m.lower() in blob.lower()), None)
    return (True, f"timeout reported in command output ({hit})") if hit else (False, "no timeout reported")


def _controller_error_status(tc_record: dict, execution_result: dict) -> tuple[bool, str]:
    for r in execution_result.get("step_results", []):
        steps = tc_record.get("steps", [])
        if r["step_index"] < len(steps) and matches_expected(steps[r["step_index"]], r):
            continue
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
    by_index = {r["step_index"]: r for r in execution_result.get("step_results", [])}
    for i, step in enumerate(steps):
        result = by_index.get(i)
        if result is None or result.get("exit_code") != 0:
            continue
        if step.get("direction", "none") != "none" and not step.get("data_len"):
            return True, (f"step{i} declares direction={step['direction']} but data_len=0, "
                           "so it exited 0 without transferring data")
    return False, "no vacuous success detected"


def _firmware_violation_indices(tc_record, execution_result):
    steps = tc_record.get("steps", [])
    results = {r["step_index"]: r for r in execution_result.get("step_results", [])}
    dummy_downloaded = False
    violations = set()
    for i, step in enumerate(steps):
        if step.get("mode", "admin-passthru") != "admin-passthru":
            continue
        opcode = str(step.get("opcode", "")).lower()
        result = results.get(i)
        if opcode == "0x11":
            # Provenance matters: CA=2 can activate a valid existing slot.
            try:
                payload = payload_for_step(step)
                dummy_downloaded = bool(payload and not any(payload) and
                                        completion_status(result) == "SUCCESS")
            except (ValueError, KeyError):
                dummy_downloaded = False
        if opcode == "0x10" and dummy_downloaded:
            try:
                ca = (int(step["cdw10"], 16) >> 3) & 7
            except (ValueError, TypeError, KeyError):
                continue
            if ca in {1, 3} and completion_status(result) == "SUCCESS":
                violations.add(i)
            # The download/commit relationship must not be reused indefinitely.
            dummy_downloaded = False
    return violations


def _firmware_commit_activated_unvalidated_image(tc_record, execution_result):
    indices = _firmware_violation_indices(tc_record, execution_result)
    if indices:
        return True, f"steps {sorted(indices)} activated after a successful zero-filled dummy download (CA bits 5:3)"
    return False, "no proven dummy-download activation observed"


def unsupported_opcode(execution_result: dict) -> str | None:
    """Returns the controller's text when it does not implement the command.

    INVALID_OPCODE is a legitimate result, not a defect and not our bug: most
    NVMe commands are optional, and "this drive does not implement Track Send"
    is exactly what a spec-coverage sweep is supposed to establish. It counts
    toward coverage and must not be retried — no argument fix can make an
    unimplemented command succeed.
    """
    for r in execution_result.get("step_results", []):
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
    steps = (tc_record or {}).get("steps", [])
    for r in execution_result.get("step_results", []):
        if r["step_index"] < len(steps) and (matches_expected(steps[r["step_index"]], r)
                                             or expected_status(steps[r["step_index"]]) != "SUCCESS"):
            continue
        out = str(r.get("stdout", ""))
        for match in _INVALID_STATUS_RE.finditer(out):
            if match.group(0) != "INVALID_OPCODE":
                return r["step_index"], out.strip().splitlines()[0]
    return None


def field_value_unsupported(tc_record: dict, execution_result: dict):
    # A correct selector is not proof that NSID/length/other fields/state are
    # valid. Keep the public helper for old callers; never infer support here.
    return None


def host_tool_crash(execution_result: dict) -> str | None:
    """Returns a description when nvme-cli itself crashed, else None.

    Checked before any firmware verdict: the drive told us nothing here, so the
    run must not be judged, must not count toward coverage, and should be
    retried once the arguments are fixed.
    """
    for r in execution_result.get("step_results", []):
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

    verification = verify_tc(tc_record, execution_result)
    for req in verification["requirements"]:
        for check in req["results"]:
            results.append({"criterion": req["description"], "kind": "spec",
                            "requirement_id": req["requirement_id"], **check})
    declared = (tc_record.get("expectation") or {}).get("fail_criteria", [])
    for criterion in declared:
        if criterion in BUILTIN_RULES:
            continue
        results.append({"criterion": criterion, "kind": "prose", "result": "unevaluated",
                         "detail": "free-text criterion — needs the real LLM to emit a structured rule"})
    return results


def check_step_expectations(tc_record: dict, execution_result: dict) -> list[str]:
    """Transport/command outcomes, not a claim that a spec requirement passed."""
    steps = tc_record.get("steps", [])
    results = {r["step_index"]: r for r in execution_result.get("step_results", [])}
    firmware = _firmware_violation_indices(tc_record, execution_result)
    statuses = []
    for i, step in enumerate(steps):
        r = results.get(i)
        if not r or not r.get("started", True):
            status = "ERROR"
        else:
            out, code = str(r.get("stdout", "")), r.get("exit_code")
            actual = completion_status(r)
            if HOST_ERROR_RE.search(out) or code in HOST_CRASH_EXIT_CODES or any(m in out for m in HOST_CRASH_MARKERS):
                status = "ERROR"
            elif KERNEL_ABORT_RE.search(out):
                status = "FAIL"  # The device did not complete it; see KERNEL_ABORT_RE.
            elif code is None:
                status = "FAIL" if execution_result.get("timed_out") else "ERROR"
            elif i in firmware:
                status = "FAIL"
            elif matches_expected(step, r):
                status = "FAIL" if step.get("direction", "none") != "none" and not step.get("data_len") else "PASS"
            elif actual == "INVALID_OPCODE":
                status = "UNSUPPORTED"
            elif actual and expected_status(step) != "SUCCESS":
                # A negative test observed the wrong completion. Accepting the
                # invalid request is a device finding; a *different* rejection
                # (INVALID_NS instead of INVALID_FIELD) is as likely to be one of
                # our other fields as the device, so it is re-queued, not judged.
                status = "ERROR" if actual.startswith("INVALID_") else "FAIL"
            elif _INVALID_STATUS_RE.search(out):
                status = "ERROR"
            elif actual or any(m.lower() in out.lower() for m in TIMEOUT_MARKERS):
                status = "FAIL"
            elif code == 0:
                status = "PASS"  # Process completed; contract still requires a captured completion.
            else:
                status = "ERROR"  # A process exit alone is not device behavior.
        statuses.append(status)
    return statuses


def check_execution(tc_record: dict, execution_result: dict) -> str:
    """Aggregate command outcomes. Failed dependencies cannot be ignored.

    Steps the contract executor deliberately did not send (`blocked_reason`:
    an earlier step or precondition check already failed) are left out of the
    aggregate - their per-step ERROR only keeps them out of coverage. Counting
    them let a verify step that never ran turn the action's real FAIL into an
    ERROR, which is excluded from coverage and re-queued as our own mistake.
    """
    statuses = check_step_expectations(tc_record, execution_result)
    if not statuses:
        return "ERROR"
    if device_hung(execution_result):
        return "FAIL"
    blocked = {r["step_index"] for r in execution_result.get("step_results", []) if r.get("blocked_reason")}
    considered = {i: s for i, s in enumerate(statuses) if i not in blocked}
    action_indices = {i for i, step in enumerate(tc_record.get("steps", [])) if step.get("phase") == "action"}
    if not action_indices:
        action_indices = set(range(len(statuses)))
    first_action = min(action_indices)
    if any(considered.get(i) == "UNSUPPORTED" for i in action_indices):
        return "UNSUPPORTED"
    # The action's own FAIL decides the TC unless a setup step ERRORed (its
    # precondition was never established, so the FAIL may be ours).
    setup_error = any(considered.get(i) == "ERROR" for i in range(first_action))
    if not setup_error and any(considered.get(i) == "FAIL" for i in action_indices):
        return "FAIL"
    values = set(considered.values())
    if "UNSUPPORTED" in values:
        return "UNVERIFIED"  # Missing setup/verify capability, not an unsupported action.
    if "ERROR" in values:
        return "ERROR"
    if "FAIL" in values:
        return "FAIL"
    if blocked:
        return "UNVERIFIED"  # Stopped by an unmet precondition check, nothing failed.
    return "PASS"


def check_expectation(tc_record: dict, execution_result: dict) -> str:
    status = check_execution(tc_record, execution_result)
    if status != "PASS":
        return status
    # Successful command delivery is necessary, never sufficient, for PASS.
    return verify_tc(tc_record, execution_result)["status"]
