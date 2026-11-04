import shutil
from datetime import datetime, timezone

import config
from log_judge.judge import judge_failure_context
from log_judge.models import make_failure_context
from log_judge.parsers.dmesg_parser import classify_text
from shared.file_store import load_json, save_json_atomic
from shared.ids import stable_id
from tc_system.coverage.coverage_state import compute_coverage, pick_next_targets
from tc_system.coverage.spec_coverage_index import SpecCoverageIndexFile
from tc_system.execution.expectation_checker import (check_expectation, check_step_expectations,
                                                      evaluate_criteria, host_tool_crash,
                                                      rejected_arguments, unsupported_opcode)
from shared.llm_client import LLMCallError
from tc_system.execution.ssh_runner import DestructiveStepBlocked, device_responsive, probe_device_capabilities
from tc_system.execution.tc_executor import SSHTCExecutor
from tc_system.generation.device_capabilities import summarize_device_capabilities
from tc_system.generation.scenario_generator import generate_scenario
from tc_system.generation.tc_writer import build_tc, namespace_id_from_device_path, reauthor_steps
from tc_system.store import tc_store


def _build_tc_exec_failure_context(tc: dict, execution: dict) -> dict:
    fc_id = stable_id("fc-tc_exec", tc["tc_id"], execution["executed_at"])
    excerpt = [f"TC {tc['tc_id']} ({tc['name']}): expectation={tc['expectation']['description']}"]
    for r in execution["step_results"]:
        excerpt.append(f"step {r['step_index']}: exit_code={r['exit_code']}\n{r['stdout']}")
    violated = [c for c in (tc["execution"] or {}).get("criteria_results", []) if c["result"] == "violated"]
    if violated:
        excerpt.append("violated fail criteria:\n" + "\n".join(f"- {c['criterion']}: {c['detail']}" for c in violated))
    dmesg_signals = classify_text(execution["dmesg_text"])
    # The judge grounds its spec lookup on signals["cmd_name"]/["opcode"]
    # before falling back to source_opcodes[0] — and for a chain that
    # fallback is the *first* step (a Write setup), not the command under
    # test (the Read action), so a Write->Read TC got judged against Write's
    # spec text. Name the action step explicitly.
    action_step = next((s for s in tc["steps"] if s.get("phase") == "action"),
                       tc["steps"][0] if tc["steps"] else {})
    return make_failure_context(
        failure_context_id=fc_id,
        source_type="TC_EXEC",
        run_id=tc["tc_id"],
        timestamp=execution["executed_at"],
        primary_log_excerpt="\n".join(excerpt),
        signals={
            "tc_name": tc["name"],
            "cmd_name": action_step.get("name"),
            "opcode": action_step.get("opcode"),
            "source_opcodes": tc["source_opcodes"],
            "criteria_results": (tc["execution"] or {}).get("criteria_results", []),
            "step_results": execution["step_results"],
            "step_statuses": tc.get("step_statuses", []),
            "dmesg_signals": dmesg_signals,
            "dmesg_captured_scoped": execution.get("dmesg_captured_scoped", True),
        },
        dmesg_file=None,
        dmesg_excerpt=execution["dmesg_text"],
        extraction_meta={"tc_id": tc["tc_id"], "extraction_method": "ssh_batch_capture"},
    )


def _resolve_steps_plan(index, steps_plan: list[dict], available_opcodes: list[dict],
                         fallback_section: dict) -> list[dict]:
    """Turns `scenario["steps_plan"]` (opcode *names*, already validated against
    `available_opcodes`) into `{"section", "opcode_entry", "phase", "role"}`
    entries `build_tc` can act on. Looked up by name across the full opcode
    table (not scoped to one command_set) because ADMIN/NVM combos are
    allowed and the real table has no two opcodes sharing a name.

    The action step always keeps `fallback_section` as-is — it is the exact
    section `pick_next_targets` picked for this iteration, which can be a
    sibling/sub-clause of the opcode table's own `section_ref` (e.g.
    `base:5.2.17.1` "Migration Send Management Operations" vs. the opcode's
    generic `base:5.2.17` "Migration Send command"; measured: 43 of 103
    reachable sections differ from their opcode's section_ref this way).
    Re-deriving the action step's section via `section_ref` — as this once
    did — silently credited coverage to the generic section instead, so the
    specific sub-clause actually picked could never be marked covered and
    was offered again, batch after batch, testing the exact same command
    under a different "target" label forever. setup/verify steps have no
    such pre-assigned target (the LLM chose them freely), so they still
    resolve via section_ref."""
    by_name = {o["name"]: o for o in available_opcodes}
    resolved = []
    for entry in steps_plan:
        opcode_entry = by_name[entry["opcode_name"]]
        if entry["phase"] == "action":
            section = fallback_section
        else:
            section = index.get_section(opcode_entry["section_ref"]) or fallback_section
        resolved.append({"section": section, "opcode_entry": opcode_entry,
                          "phase": entry["phase"], "role": entry.get("role", "")})
    return resolved


def _reset_tc_exec_judgments() -> None:
    """Each run starts the TC_EXEC judgment trail fresh instead of
    accumulating every verdict ever produced across every invocation —
    `data/verdicts/tc_exec.json` otherwise only ever grows. `tc_store.json`/
    `coverage_state.json` are deliberately NOT touched here: coverage is
    meant to accumulate across runs; only the detailed judgment history
    (which is cheap to regenerate by re-judging) resets. Any TC record whose
    `verdict_id`/`failure_context_id` pointed at what was just deleted has
    that stale reference cleared too, so nothing in the store points at a
    file that no longer exists.
    """
    save_json_atomic(config.VERDICTS_DIR / "tc_exec.json", [])
    tc_exec_dir = config.FAILURE_CONTEXTS_DIR / "tc_exec"
    if tc_exec_dir.exists():
        for f in tc_exec_dir.glob("*.json"):
            f.unlink()
    records = tc_store.load_all()
    changed = False
    for tc in records:
        # Both pops must run unconditionally — `or` short-circuiting here
        # would skip clearing failure_context_id whenever verdict_id was
        # already non-None, leaving exactly the dangling reference this
        # function exists to clean up.
        had_verdict = tc.pop("verdict_id", None) is not None
        had_fc = tc.pop("failure_context_id", None) is not None
        changed = changed or had_verdict or had_fc
    if changed:
        tc_store.save_all(records)


def _reset_coverage() -> None:
    """Wipes `tc_store.json`/`coverage_state.json` — opt-in via
    `--reset-coverage`, for when the physical drive under test changed.

    Coverage is meant to accumulate across runs *of the same device*
    (that's the whole point of `_reset_tc_exec_judgments` leaving these two
    files alone). But nothing in them records which physical drive a TC's
    result came from, so swapping in a different drive without this makes
    the new drive silently inherit the old one's accumulated coverage —
    including UNSUPPORTED verdicts, which are drive-specific — and
    `pick_next_targets` sees nothing left to offer even though the new
    device has never actually been touched.

    The previous files are copied to `<tc_store's folder>/coverage_backups/
    <UTC timestamp>/` first, not just overwritten — a mistaken
    `--reset-coverage` would otherwise permanently discard however much
    coverage history had accumulated, with no way back. Derived from
    `TC_STORE_PATH` rather than `config.DATA_DIR` directly so tests that
    redirect `TC_STORE_PATH` into a tmp dir (see `PipelineTestCase`) never
    touch the real `data/` folder.
    """
    backup_dir = (config.TC_STORE_PATH.parent / "coverage_backups"
                  / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
    backup_dir.mkdir(parents=True, exist_ok=True)
    for path in (config.TC_STORE_PATH, config.COVERAGE_STATE_PATH):
        if path.exists():
            shutil.copy2(path, backup_dir / path.name)
    save_json_atomic(config.TC_STORE_PATH, [])
    save_json_atomic(config.COVERAGE_STATE_PATH, {})


# What one bad LLM reply can raise on its way through generation or judging.
# LLMCallError is the documented one; the rest are what a malformed-but-
# parseable reply turns into downstream. Same set run_judge.py has always
# caught around judge_failure_context — the TC pipeline caught only
# LLMCallError, so the same malformed reply that run_judge skips killed the
# whole --count batch here.
_LLM_REPLY_ERRORS = (LLMCallError, ValueError, KeyError, TypeError)


def run_pipeline(count: int = 5, executor=None, allow_placeholder_args: bool = False,
                  allow_destructive: bool = False, on_start=None, on_progress=None, on_skip=None,
                  reset_coverage: bool = False) -> dict:
    """`on_start(index, total, tc)`, if given, fires right after a TC is built —
    scenario and Expectation are already filled in, but execution hasn't
    happened yet, so a caller can show what is about to be sent before it is.

    `on_progress(index, total, tc)` fires after the TC is fully processed
    (`tc["execution"]`/`tc["status"]` populated). Before either existed, a
    batch printed nothing until every TC was done, which for `--count 20`
    (LLM calls + SSH per TC) looked identical to a hang with no way to tell
    from the terminal what — if anything — was happening.

    `on_skip(index, total, section, opcode_entry, reason)` fires whenever a
    target is abandoned without ever reaching a final PASS/FAIL/UNSUPPORTED
    (nothing was learned, so it is offered again next run) — `on_progress`
    can't describe these since there is no finished `tc` to show. Three
    things used to escape as uncaught exceptions and take the whole
    `--count N` batch down over one unrelated target: the placeholder-args
    gate (raised `PlaceholderArgsGuard`), a destructive step turning up in a
    chain under `--no-destructive` (`DestructiveStepBlocked`), and an LLM
    hiccup during a replan or judging. Measured: a batch stopped at TC 4 of
    10 because one command's args fell back to a placeholder — nine
    unrelated targets were lost over it. All are now per-target skips.

    `reset_coverage`, if true, wipes `tc_store.json`/`coverage_state.json`
    (backed up first — see `_reset_coverage`) before anything else runs.
    Opt-in and separate from the always-on `tc_exec` judgment reset above:
    that one just clears a per-run trail; this one clears state that's
    meant to persist across runs *of the same physical drive*, so it must
    stay a deliberate, explicit action (CLI: `--reset-coverage`).
    """
    if reset_coverage:
        _reset_coverage()
    _reset_tc_exec_judgments()
    index = SpecCoverageIndexFile(config.active_coverage_index_path())
    target = config.get_ssh_target()
    # The one real namespace this harness is configured to test, derived from
    # the target's own device path (not assumed) — the single source of truth
    # that author_args checks every authored nsid against.
    active_nsid = namespace_id_from_device_path(target["nvme_ns"])
    try:
        # Best-effort and run exactly once per batch, not once per TC: a probe
        # failure (unreachable target, an nvme-cli version missing a
        # subcommand) must never block the run it only exists to speed up.
        device_facts = summarize_device_capabilities(
            probe_device_capabilities(target["nvme_ctrl"], target["nvme_ns"]))
    except Exception:
        device_facts = None
    executor = executor or SSHTCExecutor(allow_destructive=allow_destructive)
    # ADMIN/NVM combos are allowed in one chain, so the model is always shown
    # the whole table, not just the primary target's own command_set.
    available_opcodes = index.list_opcodes()

    existing = tc_store.load_all()
    targets = pick_next_targets(index, existing, count)
    total = len(targets)

    generated, executed, failed, host_crashes, unsupported, skipped = [], [], [], [], [], []
    for i, (section, opcode_entry) in enumerate(targets, start=1):
        # Distinct per attempt: a stable (section, opcode) id would overwrite the
        # previous record on a re-run, orphaning its FailureContext and verdict.
        attempt_at = datetime.now(timezone.utc).isoformat()
        tc_id = stable_id("tc", section["section_id"], opcode_entry["opcode"], attempt_at)
        try:
            scenario = generate_scenario(section, opcode_entry, available_opcodes, device_facts=device_facts)
            resolved_steps = _resolve_steps_plan(index, scenario["steps_plan"], available_opcodes, section)
            tc = build_tc(tc_id, resolved_steps, scenario, target["nvme_ctrl"], target["nvme_ns"], active_nsid,
                           device_facts=device_facts)
        except _LLM_REPLY_ERRORS as exc:
            # A transient malformed/incomplete reply for this one target must
            # not take down the rest of the batch (measured: one missing key
            # in a scenario response used to crash the whole --count run,
            # losing every target after it even though they were unrelated).
            # Nothing was built or sent to the device, so this section is
            # simply offered again next run.
            skipped.append({"section_id": section["section_id"], "opcode": opcode_entry["opcode"], "reason": str(exc)})
            if on_skip:
                on_skip(i, total, section, opcode_entry, str(exc))
            continue

        if on_start:
            on_start(i, total, tc)

        # Gate on what actually makes the command meaningless — placeholder
        # arguments hardcoded in tc_writer — not on whether the LLM is a stub.
        # Those are independent: a real LLM authoring prose scenarios does not
        # by itself make cdw10=0 a valid CNS/LID/FID. This used to raise and
        # halt the whole --count batch over one target (measured: one command
        # the model couldn't argue real values for took nine unrelated targets
        # down with it) — now it's a skip like the LLMCallError case above:
        # nothing was sent to the device, so the section is offered again.
        if tc["uses_placeholder_args"] and not allow_placeholder_args:
            reason = (
                f"{tc['name']} carries placeholder command arguments (cdw10=0, data_len=0) after "
                "the one retry — measured on the target, cdw10=0 is a reserved field value (admin "
                "0x06/0x02/0x0A return INVALID_FIELD(0x2)/exit 22, and NVM Read 0x02 exits 0 while "
                "transferring nothing, which would be recorded as a false PASS). Pass "
                "allow_placeholder_args=True (CLI: --allow-placeholder-args) to execute it anyway "
                "for plumbing experiments — those records are excluded from the coverage claim."
            )
            skipped.append({"section_id": section["section_id"], "opcode": opcode_entry["opcode"], "reason": reason})
            if on_skip:
                on_skip(i, total, section, opcode_entry, reason)
            continue
        generated.append(tc)

        try:
            execution = executor.execute(tc)
        except DestructiveStepBlocked as exc:
            # A chain the model built on its own (a destructive setup/verify
            # step it chose, or the action target itself) hit the gate that
            # exists for --no-destructive — unrelated to this one target's
            # own correctness, so it must not take the rest of the batch with
            # it either.
            skipped.append({"section_id": section["section_id"], "opcode": opcode_entry["opcode"], "reason": str(exc)})
            if on_skip:
                on_skip(i, total, section, opcode_entry, str(exc))
            continue
        step_statuses = check_step_expectations(tc, execution)
        rejection = rejected_arguments(execution, tc)  # (step_index, reason) | None

        action_idx = next(j for j, rs in enumerate(resolved_steps) if rs["phase"] == "action")
        broken_idx = next((j for j, st in enumerate(step_statuses) if st in ("ERROR", "UNSUPPORTED")), None)
        # Retrying at all after a destructive/firmware_state step already ran
        # risks re-sending that step purely to fix an unrelated later one —
        # SSH batches can't be partially replayed, so any retry resends
        # everything. Skip retrying entirely rather than risk that.
        precedes_destructive = broken_idx is not None and any(
            s.get("destructive") or s.get("firmware_state") for s in tc["steps"][:broken_idx])
        # A hang is the finding itself, not something to fix and resend: a
        # retry would overwrite it with whatever a second attempt does (if the
        # device recovered in between, a PASS), and the batch is sent to a
        # device that just stopped answering.
        timed_out = bool(execution.get("timed_out"))

        if broken_idx is not None and not precedes_destructive and not timed_out:
            if rejection is not None and rejection[0] == broken_idx:
                # Fixable by different field values. Rebuilds the rejected
                # step plus everything after it (not just the one step) —
                # later steps may already have been authored assuming this
                # step's about-to-change shared_facts, which would otherwise
                # go stale. For a single-step TC this degenerates to exactly
                # today's one-step reauthor.
                retry_steps = reauthor_steps(tc, resolved_steps,
                                              {"step_index": broken_idx, "reason": rejection[1]}, active_nsid,
                                              device_facts=device_facts)
                # Only adopted if it will actually be sent. Assigning it to
                # tc["steps"] first (as this once did) left a placeholder
                # retry that was never executed stored as the TC's steps —
                # paired with the *previous* execution's results, and with the
                # criteria/status checks below reading the new steps' cdw10/
                # field_value_verified against that old output.
                if not any(s.get("args_source") == "placeholder" for s in retry_steps):
                    # `tc["retried"]` is purely a display aid for
                    # run_tc_pipeline.py — without it, the "실행할 명령" block
                    # printed before execution (built from the pre-retry steps)
                    # silently disagrees with the final cdw10/data_len printed
                    # after, with nothing on screen explaining why.
                    tc["retried"] = {"kind": "args_rejected", "step_index": broken_idx,
                                      "step_name": tc["steps"][broken_idx].get("name"), "reason": rejection[1]}
                    tc["steps"] = retry_steps
                    execution = executor.execute(tc)
                    step_statuses = check_step_expectations(tc, execution)
                    rejection = rejected_arguments(execution, tc)
            elif step_statuses[broken_idx] == "UNSUPPORTED" and broken_idx != action_idx:
                # A setup/verify command that simply doesn't exist on this
                # drive — no argument fix helps, and the dependent steps
                # after it can't be trusted either. Unlike a rejection this
                # is structural, so it needs a different *plan*, not
                # different field values: ask for one, and only commit to it
                # if it comes back usable (not placeholder-gated itself).
                broken_name = resolved_steps[broken_idx]["opcode_entry"]["name"]
                replan_reason = f"{broken_name} is UNSUPPORTED (INVALID_OPCODE) on this drive"
                try:
                    replanned_scenario = generate_scenario(
                        section, opcode_entry, available_opcodes,
                        feedback=f"step {broken_idx} ({broken_name}) is UNSUPPORTED (INVALID_OPCODE) on this drive",
                        device_facts=device_facts)
                    replanned_steps = _resolve_steps_plan(index, replanned_scenario["steps_plan"],
                                                           available_opcodes, section)
                    replanned_tc = build_tc(tc_id, replanned_steps, replanned_scenario,
                                             target["nvme_ctrl"], target["nvme_ns"], active_nsid,
                                             device_facts=device_facts)
                except _LLM_REPLY_ERRORS:
                    # The replan is "nice to have, falls back to what's
                    # already been measured" — same as a replan that itself
                    # lands on placeholder args just below. An LLM hiccup
                    # here must not crash the batch; keep the original tc's
                    # already-executed result (the action step still PASSED
                    # or whatever it did — only the broken non-action step's
                    # plan couldn't be improved) and move on below.
                    replanned_tc = None
                if replanned_tc is not None and not replanned_tc["uses_placeholder_args"]:
                    try:
                        replanned_execution = executor.execute(replanned_tc)
                    except DestructiveStepBlocked:
                        # The replanned chain (the model's own new choice of
                        # setup/verify commands) introduced a destructive step
                        # under --no-destructive. The gate raises before
                        # anything is sent, and the *original* chain already
                        # ran on the device — so fall back to that result,
                        # exactly like an LLM failure during the replan does.
                        # Skipping the target here (as this once did) threw
                        # away a real execution and also skipped the post-TC
                        # health check below for a chain that had already run.
                        replanned_execution = None
                    if replanned_execution is not None:
                        # See the comment on "retried" above — same display
                        # aid, attached to replanned_tc (the one that becomes
                        # the final `tc`) since this path replaces the object
                        # rather than mutating it in place.
                        replanned_tc["retried"] = {"kind": "replanned", "step_index": broken_idx,
                                                    "step_name": broken_name, "reason": replan_reason}
                        tc, scenario, resolved_steps = replanned_tc, replanned_scenario, replanned_steps
                        execution = replanned_execution
                        step_statuses = check_step_expectations(tc, execution)
                        rejection = rejected_arguments(execution, tc)
            # Else: UNSUPPORTED on the action step itself (the fixed primary
            # target — no plan change can avoid testing it) or a generic
            # host-tool/SSH ERROR with no specific rejection to act on.
            # Neither is retried, matching the existing single-step rule that
            # INVALID_OPCODE and host crashes are never retried.

        criteria_results = evaluate_criteria(tc, execution)
        tc["status"] = check_expectation(tc, execution)
        tc["step_statuses"] = step_statuses
        crash = host_tool_crash(execution)
        tc["execution"] = {
            "executor": execution["executor"],
            "executed_at": execution["executed_at"],
            "result": tc["status"],
            "step_results": execution["step_results"],
            "step_statuses": step_statuses,
            "criteria_results": criteria_results,
            "host_tool_crash": crash,
            "args_rejected": rejection[1] if rejection else None,
            "unsupported": unsupported_opcode(execution),
            "dmesg_captured_scoped": execution.get("dmesg_captured_scoped", True),
        }
        executed.append(tc)

        if tc["status"] == "UNSUPPORTED":
            # A valid answer about the drive, not a failure — no judging needed.
            unsupported.append(tc)
        elif crash or rejection:
            # Either nvme-cli died on the host or the controller rejected our
            # fields. Both are our bug with no device behaviour to judge —
            # sending them on would invite a firmware verdict about our mistake.
            host_crashes.append(tc)
        elif tc["status"] in ("FAIL", "ERROR"):
            fc = _build_tc_exec_failure_context(tc, execution)
            try:
                verdict = judge_failure_context(fc)
            except _LLM_REPLY_ERRORS:
                # The device-side FAIL/ERROR is real regardless of whether
                # judging succeeds — an LLM hiccup here must not crash the
                # batch over a result that already happened. tc_store still
                # gets this TC with its real status, just without a
                # classification; nothing currently re-judges it later, so
                # it stays unjudged until a future run happens to re-pick
                # this exact (section, opcode) and judges a fresh FAIL/ERROR.
                verdict = None
            if verdict is not None:
                # judge_failure_context fills fc["spec_grounding"] in place, so save
                # after judging — not before — or the stored context keeps queried=false.
                fc_path = config.FAILURE_CONTEXTS_DIR / "tc_exec" / f"{fc['failure_context_id']}.json"
                save_json_atomic(fc_path, fc)
                verdict_path = config.VERDICTS_DIR / "tc_exec.json"
                verdicts = load_json(verdict_path, default=[])
                verdicts.append(verdict)
                save_json_atomic(verdict_path, verdicts)
                tc["verdict_id"] = verdict["verdict_id"]
                tc["failure_context_id"] = fc["failure_context_id"]
            failed.append(tc)

        tc["updated_at"] = datetime.now(timezone.utc).isoformat()
        tc_store.upsert(tc)
        # Recomputed per TC, not just after the loop: a crash or device hang
        # mid-run would otherwise leave coverage_state.json describing a store
        # that has already moved on.
        coverage = compute_coverage(index, tc_store.load_all())
        save_json_atomic(config.COVERAGE_STATE_PATH, coverage)

        if on_progress:
            on_progress(i, total, tc)

        risky_steps = any(s.get("destructive") or s.get("firmware_state") or s.get("lockout_risk")
                          for s in tc["steps"])
        # A timeout gets the same check: the batch was killed because the
        # device stopped answering, and without this every remaining target
        # would spend its own full timeout (SECONDS_PER_STEP x steps) finding
        # that out again.
        if risky_steps or execution.get("timed_out"):
            # Sanitize/Namespace Management can make /dev/nvme0n1 disappear
            # for a while; Lockdown/Security Send can make the controller
            # reject subsequent admin commands without removing the device
            # node at all (measured: a later TC's Write/Read failed with
            # "No such file or directory" — almost certainly an earlier
            # destructive TC in the same batch, not a firmware defect, and
            # judged as one anyway since nothing checked in between). Grinding
            # through the rest of the batch against a device that's gone or
            # locked out would just repeat the same failure for every
            # remaining target, so stop here instead.
            alive, reason = device_responsive(target["nvme_ctrl"])
            if not alive:
                for j, (remaining_section, remaining_opcode) in enumerate(targets[i:], start=i + 1):
                    cause = "상태 변경 커맨드" if risky_steps else "타임아웃"
                    skip_reason = f"이전 TC의 {cause} 이후 디바이스가 응답하지 않음: {reason}"
                    skipped.append({"section_id": remaining_section["section_id"],
                                     "opcode": remaining_opcode["opcode"], "reason": skip_reason})
                    if on_skip:
                        on_skip(j, total, remaining_section, remaining_opcode, skip_reason)
                break

    coverage = compute_coverage(index, tc_store.load_all())
    save_json_atomic(config.COVERAGE_STATE_PATH, coverage)

    return {"generated": len(generated), "executed": len(executed), "failed": len(failed),
            "our_bugs": len(host_crashes), "unsupported": len(unsupported), "skipped": len(skipped),
            "coverage": coverage["summary"]}
