import hashlib
import shutil
import subprocess
import sys
import queue
import threading
from concurrent.futures import Future
from functools import lru_cache
from copy import deepcopy
from datetime import datetime, timezone

import config
from log_judge.judge import judge_failure_context
from log_judge.models import make_failure_context
from log_judge.parsers.dmesg_parser import classify_text
from shared.file_store import load_json, save_json_atomic
from shared.ids import stable_id
from tc_system.coverage.coverage_state import compute_coverage, pick_next_targets
from tc_system.coverage.spec_coverage_index import SpecCoverageIndexFile
from tc_system.execution.expectation_checker import (check_expectation, check_execution, check_step_expectations,
                                                      is_test_step,
                                                      device_hung, error_cause, evaluate_criteria, host_tool_crash,
                                                      status_line,
                                                      rejected_arguments, unsupported_opcode)
from shared.llm_client import LLMCallError
from tc_system.execution.host_actions import host_action_entries, usable_host_steps
from tc_system.execution.ssh_runner import (DestructiveStepBlocked, device_responsive, passthru_cmd,
                                            probe_device_capabilities)
from tc_system.execution.tc_executor import SSHTCExecutor
from tc_system.generation.variants import build_variant_tc, variant_targets
from tc_system.generation.device_capabilities import (device_support as probed_support, firmware_activation_pending,
                                                     host_versions,
                                                     in_use_lba_bytes, namespace_size, summarize_device_capabilities)
from tc_system.generation.scenario_generator import generate_scenario
from tc_system.generation.tc_writer import build_tc, namespace_id_from_device_path, reauthor_steps
from tc_system.review import apply_tc_verdict, code_review, review_tc
from tc_system.store import tc_store
from tc_system.verification import command_support_measured_absent, completion_status, verify_tc


def _execute_attempt(tc, executor, attempts):
    tc["active_attempt_id"] = stable_id("attempt", tc["tc_id"], str(len(attempts)))
    result = executor.execute(tc)
    attempts.append({"attempt_id": tc["active_attempt_id"], "steps": deepcopy(tc["steps"]),
                     "execution": deepcopy(result)})
    return result


_ARG_FIELDS = ("nsid", "cdw10", "cdw11", "cdw12", "cdw13", "cdw14", "cdw15", "data_len", "direction")


def _changed_args(before: list[dict], after: list[dict]) -> list[str]:
    """"스텝 0 cdw10 0x00000084 -> 0x00000184" for every field a retry changed."""
    changes = []
    for i, (old, new) in enumerate(zip(before, after)):
        for field in _ARG_FIELDS:
            if old.get(field) != new.get(field):
                changes.append(f"스텝 {i} {field} {old.get(field)} -> {new.get(field)}")
    return changes


def _step_outcome(execution: dict, step_index: int) -> str:
    result = next((r for r in execution.get("step_results", []) if r["step_index"] == step_index), None)
    if result is None or not result.get("started", True):
        return "실행되지 않음"
    return status_line(str(result.get("stdout", "")))


def _step_excerpts(tc: dict, execution: dict) -> list[str]:
    """Each step's output with its own budget, the action and the steps the
    checks read first, plus what code decoded from it. Measured: in 12 of 23
    judge prompts the action's response was cut off because the setup Identify
    dump came first and used the whole 8,000-character slice."""
    from tc_system import spec_fields
    from tc_system.review import step_structure
    steps = tc.get("steps") or []
    checked = {c.get("step") for g in ((tc.get("verification_contract") or {}).get("requirements") or [])
               for c in g.get("checks") or [] if isinstance(c, dict)}
    results = sorted(execution["step_results"],
                     key=lambda r: (0 if r["step_index"] < len(steps) and steps[r["step_index"]].get("phase") == "action"
                                    else 1 if r["step_index"] in checked else 2, r["step_index"]))
    out = []
    for r in results:
        i = r["step_index"]
        step = steps[i] if i < len(steps) else {}
        budget = 2500 if step.get("phase") == "action" or i in checked else 700
        code = spec_fields.status_code_in_output(r.get("stdout", ""))
        head = (f"step {i} {step.get('name', '')} ({step.get('phase')}{', harness' if step.get('harness') else ''}): "
                f"exit_code={r['exit_code']} completion={completion_status(r)}"
                + (f" status_code=SCT{code[0]}/SC{code[1]:02X}h" if code else "")
                + (f" NOT SENT: {r.get('blocked_reason') or r.get('cleanup_skipped')}"
                   if r.get("blocked_reason") or r.get("cleanup_skipped") else ""))
        text = str(r.get("stdout", ""))
        body = text if len(text) <= budget else text[:budget] + f"\n...[{len(text) - budget} chars omitted]"
        structure = step_structure(step) if step else None
        decoded = []
        if structure:
            for group in ((tc.get("verification_contract") or {}).get("requirements") or []) + \
                         ((tc.get("verification_contract") or {}).get("precondition_checks") or []):
                for c in group.get("checks") or []:
                    if isinstance(c, dict) and c.get("kind") == "data_field" and c.get("step") == i:
                        interp = spec_fields.interpret_check(c, structure)
                        if interp:
                            decoded.append(f"  check reads {interp['label']}"
                                           + (f" — PROBLEM: {interp['error']}" if interp["error"] else ""))
        out.append(head + "\n" + body + ("\n" + "\n".join(decoded) if decoded else ""))
    return out


def _build_tc_exec_failure_context(tc: dict, execution: dict) -> dict:
    fc_id = stable_id("fc-tc_exec", tc["tc_id"], execution["executed_at"])
    excerpt = [f"TC {tc['tc_id']} ({tc['name']}): expectation={tc['expectation']['description']}"]
    violated = [c for c in (tc["execution"] or {}).get("criteria_results", []) if c["result"] == "violated"]
    if violated:
        excerpt.append("violated fail criteria:\n" + "\n".join(f"- {c['criterion']}: {c['detail']}" for c in violated))
    excerpt += _step_excerpts(tc, execution)
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
            # Contract problems found by code (wrong field read, status name vs
            # code, self-compared length, unrestored state ...).
            "harness_findings": [r["text"] for r in code_review(tc)],
            "test_definition": {"scenario": tc.get("scenario"), "steps": tc["steps"],
                                "contract": tc.get("verification_contract"),
                                "verification": tc.get("verification")},
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
                          "phase": entry["phase"], "role": entry.get("role", ""),
                          "field_constraints": entry.get("field_constraints", []),
                          "expected_status": entry.get("expected_status", "SUCCESS"),
                          "payload_hex": entry.get("payload_hex")})
    return resolved


def _reset_coverage() -> None:
    """Wipes `tc_store.json`/`coverage_state.json` — opt-in via
    `--reset-coverage`, for when the physical drive under test changed.

    Coverage is meant to accumulate across runs *of the same device*
    (normal runs leave these two
    files alone). But nothing in them records which physical drive a TC's
    result came from, so swapping in a different drive without this makes
    the new drive silently inherit the old one's accumulated coverage —
    including UNSUPPORTED observations, which are drive-specific.

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
    for path in (config.TC_STORE_PATH, config.COVERAGE_STATE_PATH, config.TARGET_SKIPS_PATH):
        if path.exists():
            shutil.copy2(path, backup_dir / path.name)
    save_json_atomic(config.TC_STORE_PATH, [])
    save_json_atomic(config.COVERAGE_STATE_PATH, {})
    save_json_atomic(config.TARGET_SKIPS_PATH, [])


def _preflight(tc: dict, allow_destructive: bool) -> None:
    """The checks the executor makes before anything reaches the wire, run
    before the TC is announced. Otherwise the terminal printed the TC, its
    commands and "실행 중...", then a second "[i/N] ... 건너뜀" header for the
    same index, while nothing had been sent (so no SSH log either)."""
    for i, step in enumerate(tc["steps"]):
        if not step.get("host_action"):
            passthru_cmd(step)  # the same field validation execute_tc_steps applies
        if not allow_destructive and (step.get("destructive") or step.get("firmware_state")):
            kind = "펌웨어 상태 변경" if step.get("firmware_state") else "데이터 파괴"
            raise DestructiveStepBlocked(
                f"--no-destructive: 스텝 {i} {step.get('name') or '?'}(opcode {step.get('opcode')}, {kind})이 "
                "체인에 포함돼 보내지 않음 — 허용하려면 --no-destructive 없이 실행")


def _placeholder_reason(tc: dict) -> str:
    failed = [(k, s) for k, s in enumerate(tc["steps"]) if s.get("args_source") == "placeholder"]
    where = "; ".join(f"스텝 {k} {s.get('name') or '?'}: {s.get('args_error') or '사유 미기록'}" for k, s in failed)
    return (f"인자 생성이 재시도까지 실패해 placeholder 인자(cdw10=0 등)만 남음 — {where}. "
            "placeholder 값은 대부분 reserved라 결과가 무의미하므로 보내지 않음"
            "(실험용으로 보내려면 --allow-placeholder-args, 그 결과는 커버리지 제외)")


def _record_skip(skipped: list, section: dict, opcode_entry: dict, reason: str, kind: str, run_id=None) -> None:
    """A target that was tried but never reached the device. Persisted so the
    next `pick_next_targets` counts it as an attempt and moves on. `run_id`
    lets the report count this run's skips, not every skip ever."""
    entry = {"section_id": section["section_id"], "opcode": opcode_entry["opcode"], "reason": reason,
             "requirement_id": (section.get("target_requirement") or {}).get("requirement_id"), "run_id": run_id}
    skipped.append(entry)
    log = load_json(config.TARGET_SKIPS_PATH, default=[])
    log.append(dict(entry, kind=kind, at=datetime.now(timezone.utc).isoformat()))
    save_json_atomic(config.TARGET_SKIPS_PATH, log)


@lru_cache(maxsize=1)
def _code_fingerprint() -> dict:
    """Which code produced a run: git commit when available, and always a
    hash of the Python sources (the copied run folder had no git metadata)."""
    info = {}
    try:
        head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=config.BASE_DIR, capture_output=True, text=True,
                              timeout=5)
        dirty = subprocess.run(["git", "status", "--porcelain"], cwd=config.BASE_DIR, capture_output=True,
                               text=True, timeout=5)
        if head.returncode == 0:
            info = {"git_commit": head.stdout.strip(), "git_dirty": bool(dirty.stdout.strip())}
    except (OSError, subprocess.SubprocessError):
        pass
    digest = hashlib.sha256()
    paths = sorted(config.BASE_DIR.glob("*.py"))
    for package in ("tc_system", "shared", "log_judge", "report"):  # never the raw-log folders
        paths += sorted((config.BASE_DIR / package).rglob("*.py"))
    for path in paths:
        if "__pycache__" in path.parts:
            continue
        digest.update(str(path.relative_to(config.BASE_DIR)).encode())
        digest.update(path.read_bytes())
    info["source_sha256"] = digest.hexdigest()[:16]
    return info


def _file_sha(path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()[:16]
    except OSError:
        return None


def _write_manifest(run_id, probe, options) -> dict:
    from log_judge.judge import JUDGE_SYSTEM_PROMPT
    from tc_system.generation.args_author import SYSTEM_PROMPT as ARGS_PROMPT
    from tc_system.generation.scenario_generator import SCENARIO_SYSTEM_PROMPT
    from tc_system.review import AUDIT_SYSTEM_PROMPT
    prompts = {name: hashlib.sha256(text.encode()).hexdigest()[:16] for name, text in (
        ("scenario", SCENARIO_SYSTEM_PROMPT), ("args", ARGS_PROMPT), ("judge", JUDGE_SYSTEM_PROMPT),
        ("review_audit", AUDIT_SYSTEM_PROMPT))}
    try:
        rag_version = config.RAG_INDEX_CURRENT_PATH.read_text(encoding="utf-8").strip()
    except OSError:
        rag_version = None
    manifest = {"run_id": run_id, "started_at": datetime.now(timezone.utc).isoformat(),
                "code": _code_fingerprint(), "coverage_index_sha256": _file_sha(config.active_coverage_index_path()),
                "rag_index": rag_version, "prompts_sha256": prompts, "host": host_versions(probe) if probe else None,
                "options": options}
    save_json_atomic(config.RUN_MANIFESTS_DIR / f"{run_id}.json", manifest)
    return manifest


class _DaemonPool:
    """Ahead-of-execution generation. Daemon threads: Ctrl+C ends the run at
    once instead of waiting for in-flight LLM calls (ThreadPoolExecutor joins
    its workers at interpreter exit). Results are only ever read in order by
    the main loop; an unread one is simply dropped."""

    def __init__(self, workers):
        self._jobs = queue.Queue()
        self._closed = False
        for _ in range(workers):
            threading.Thread(target=self._work, daemon=True).start()

    def _work(self):
        while True:
            job = self._jobs.get()
            if job is None:
                return
            future, fn, args = job
            if not future.set_running_or_notify_cancel():
                continue
            try:
                future.set_result(fn(*args))
            except BaseException as exc:  # handed to the main loop, raised there
                future.set_exception(exc)

    def submit(self, fn, *args):
        future = Future()
        if self._closed:
            future.cancel()
        else:
            self._jobs.put((future, fn, args))
        return future

    def shutdown(self):
        self._closed = True
        while True:  # drop queued work; running calls finish on their own
            try:
                job = self._jobs.get_nowait()
            except queue.Empty:
                break
            if job:
                job[0].cancel()
        for _ in range(64):
            self._jobs.put(None)


def _support_kwarg(support):
    """Passed only when the probe produced one (older callers/test doubles
    of generate_scenario take no such argument)."""
    return {"device_support": support} if support else {}


def _opcode_key(opcode_entry: dict):
    if opcode_entry.get("host_action") or not opcode_entry.get("raw_opcode"):
        return None
    return opcode_entry["command_set"], opcode_entry["raw_opcode"].lower()


def _action_unsupported_opcode(tc: dict) -> bool:
    """The action itself came back INVALID_OPCODE (not a feature-level rejection)."""
    results = {r["step_index"]: r for r in (tc.get("execution") or {}).get("step_results", [])}
    return any(s.get("phase") == "action" and completion_status(results.get(i)) == "INVALID_OPCODE"
               for i, s in enumerate(tc.get("steps") or []))


# What one bad LLM reply can raise on its way through generation or judging.
# LLMCallError is the documented one; the rest are what a malformed-but-
# parseable reply turns into downstream. Same set run_judge.py has always
# caught around judge_failure_context — the TC pipeline caught only
# LLMCallError, so the same malformed reply that run_judge skips killed the
# whole --count batch here.
_LLM_REPLY_ERRORS = (LLMCallError, ValueError, KeyError, TypeError, AttributeError)


def _prepare_target(section, opcode_entry, ctx) -> dict:
    """Everything up to the wire for one target: no device, no shared files,
    so it runs ahead of execution in a worker thread. Returns {"skip": reason,
    "kind": ...} or {"tc", "scenario", "resolved_steps", "variant", "section"}."""
    section = dict(section, previous_requirements=[
        {"requirement_id": r["requirement_id"], "quote": r["quote"], "description": r["description"]}
        for old in ctx["existing"] for r in (old.get("verification") or {}).get("requirements", [])
        if r.get("section_id") == section["section_id"] and r.get("status") in ("PASS", "FAIL")])
    # Distinct per attempt: a stable (section, opcode) id would overwrite the
    # previous record on a re-run, orphaning its FailureContext and verdict.
    attempt_at = datetime.now(timezone.utc).isoformat()
    # The requirement id too: several requirements of one clause and command
    # are generated at the same moment by the prefetch threads, and the clock
    # resolution on Windows can give them the same attempt_at.
    target_req = section.get("target_requirement") or {}
    tc_id = stable_id("tc", section["section_id"], opcode_entry["opcode"], target_req.get("requirement_id") or "",
                      attempt_at)
    variant = target_req if target_req.get("kind") == "variant" else None
    host_steps = usable_host_steps(target_req, ctx["available_opcodes"], ctx["allow_destructive"])
    if host_steps == []:
        # The sentence is about state across a reset/power loss and this
        # run has no way to cause one: no LLM call, a reason to fix it.
        needed = ", ".join(target_req["host_actions"])
        return {"section": section, "kind": "host_step_unavailable",
                "skip": (f"리셋/전원 사이클 전후 상태를 요구하는 문장인데 이 실행에서 쓸 수 있는 호스트 스텝이 없음"
                         f"(필요: {needed}) — 전원 사이클은 secrets.local.json의 pmu.enabled와 파괴적 명령 허용"
                         f"(--no-destructive 없이)이 필요. 장비에 아무것도 보내지 않음")}
    if host_steps:
        section = dict(section, target_requirement=dict(target_req, host_steps=host_steps))
    target = ctx["target"]
    try:
        if variant:
            # Built by code: the swept value IS the test, no LLM involved.
            tc = build_variant_tc(tc_id, variant, opcode_entry, target["nvme_ctrl"], target["nvme_ns"],
                                  ctx["active_nsid"], ctx["lba_bytes"], ctx.get("device_support"))
            scenario = {"description": variant["description"]}
            resolved_steps = [{"section": section, "opcode_entry": opcode_entry, "phase": "action",
                               "role": variant["description"]}]
        else:
            scenario = generate_scenario(section, opcode_entry, ctx["available_opcodes"],
                                         device_facts=ctx["device_facts"], **_support_kwarg(ctx["device_support"]))
            resolved_steps = _resolve_steps_plan(ctx["index"], scenario["steps_plan"], ctx["available_opcodes"], section)
            tc = build_tc(tc_id, resolved_steps, scenario, target["nvme_ctrl"], target["nvme_ns"], ctx["active_nsid"],
                          device_facts=ctx["device_facts"], lba_bytes=ctx["lba_bytes"],
                          device_support=ctx["device_support"])
    except _LLM_REPLY_ERRORS as exc:
        # A transient malformed/incomplete reply for this one target must
        # not take down the rest of the batch (measured: one missing key
        # in a scenario response used to crash the whole --count run,
        # losing every target after it even though they were unrelated).
        # Nothing was built or sent to the device, so this section is
        # simply offered again next run.
        return {"section": section, "kind": "generation_failed", "skip": str(exc) or type(exc).__name__}
    # Gate on what actually makes the command meaningless — placeholder
    # arguments hardcoded in tc_writer — not on whether the LLM is a stub.
    # Measured on the target: cdw10=0 is a reserved value for most admin
    # commands (INVALID_FIELD/exit 22) and NVM Read 0x02 exits 0 while
    # transferring nothing, which would be recorded as a false PASS. A skip,
    # not a batch stop: nothing was sent, the section is offered again.
    if tc["uses_placeholder_args"] and not ctx["allow_placeholder_args"]:
        return {"section": section, "kind": "placeholder_args", "skip": _placeholder_reason(tc)}
    try:
        _preflight(tc, ctx["allow_destructive"])
    except (DestructiveStepBlocked, ValueError) as exc:
        return {"section": section, "kind": "blocked_before_wire", "skip": str(exc) or type(exc).__name__}
    return {"section": section, "tc": tc, "tc_id": tc_id, "scenario": scenario, "resolved_steps": resolved_steps,
            "variant": variant}


def run_pipeline(count: int | None = 5, executor=None, allow_placeholder_args: bool = False,
                  allow_destructive: bool = False, on_start=None, on_progress=None, on_skip=None,
                  reset_coverage: bool = False, generation_workers: int | None = None,
                  review_with_llm: bool | None = None) -> dict:
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
    # None = every target pick_next_targets can offer (CLI --all). Anything
    # else must be a positive int: 0 or a negative once fell through to "all",
    # destructive commands included, without anyone asking for it.
    if count is not None and (isinstance(count, bool) or not isinstance(count, int) or count < 1):
        raise ValueError(f"count must be a positive integer or None (all), got {count!r}")
    if reset_coverage:
        _reset_coverage()
    # Keep per-attempt evidence and judgments across runs. IDs already identify
    # individual attempts; deleting the trail made later audits impossible.
    index = SpecCoverageIndexFile(config.active_coverage_index_path())
    target = config.get_ssh_target()
    # The one real namespace this harness is configured to test, derived from
    # the target's own device path (not assumed) — the single source of truth
    # that author_args checks every authored nsid against.
    active_nsid = namespace_id_from_device_path(target["nvme_ns"])
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    probe, support = None, None
    pmu, pmu_off = config.pmu_status()
    try:
        # Best-effort and run exactly once per batch, not once per TC: a probe
        # failure (unreachable target, an nvme-cli version missing a
        # subcommand) must never block the run it only exists to speed up.
        probe = probe_device_capabilities(target["nvme_ctrl"], target["nvme_ns"],
                                          (pmu or {}).get("script"))
        device_facts = summarize_device_capabilities(probe)
        # Measured, not assumed: NVM Read/Write/Compare buffers are checked
        # against NLB x this before anything reaches the wire.
        lba_bytes = in_use_lba_bytes(probe)
        nsze = namespace_size(probe)
        # Which LIDs/FIDs this drive implements (Supported Log Pages, Get
        # Features SEL=011b): rejections of unsupported ones are findings
        # about the drive, and negative tests built on a false premise are
        # refused before they are sent.
        support = probed_support(probe)
        save_json_atomic(config.DEVICE_INFO_PATH, {"nsze": nsze, "lba_bytes": lba_bytes,
                                                   "supported_lids": sorted(k for k, v in support["lids"].items() if v),
                                                   "fids": {f"{k:02X}": v for k, v in support["fids"].items()},
                                                   "probed_at": datetime.now(timezone.utc).isoformat()})
    except Exception:
        device_facts, lba_bytes, nsze = None, None, None
    pending_afi = firmware_activation_pending(probe) if probe is not None else None
    if pending_afi is not None:
        print(f"[경고] 장비가 펌웨어 활성화 대기 상태(AFI=0x{pending_afi:02X}) - 이전 Firmware Commit이 남긴 상태. "
              "Sanitize 등 일부 명령이 거부되고 그 TC는 판정하지 않음. nvme reset 또는 전원 사이클 후 실행 권장")
    if probe is not None and not lba_bytes:
        # Silent before: a whole run went without it (2026-11-06).
        # cp949-safe text: a console that cannot encode a symbol must not end the run.
        print("[경고] 장비 조회에서 LBA 크기를 읽지 못함 - NVM Read/Write/Compare 버퍼를 NLB x LBA로 검사하지 못하고 "
              "LBA 경계 변형 TC도 만들지 않음(nvme id-ns 출력 형식 확인 필요)")
    if support is not None and not support["lids"] and not support["fids"]:
        support = None
    workers = config.TC_GENERATION_WORKERS if generation_workers is None else generation_workers
    review_llm = config.REVIEW_AUDIT_WITH_LLM if review_with_llm is None else review_with_llm
    try:
        _write_manifest(run_id, probe, {"count": count, "allow_destructive": allow_destructive,
                                        "allow_placeholder_args": allow_placeholder_args,
                                        "generation_workers": workers, "review_with_llm": review_llm})
    except Exception:
        pass  # a record of the run, never a precondition for it
    # Code-generated variants (no LLM): values swept under a fixed spec oracle.
    variants = variant_targets(index, nsze=nsze, lba_bytes=lba_bytes)
    executor = executor or SSHTCExecutor(allow_destructive=allow_destructive)
    # ADMIN/NVM combos are allowed in one chain, so the model is always shown
    # the whole table, not just the primary target's own command_set.
    # Host steps (reset, PMU power cycle) can be setup/verify steps of a chain.
    if pmu and probe is not None and "PMU_SCRIPT_MISSING" in (probe.get("pmu_script") or ""):
        pmu, pmu_off = None, f"대상 호스트에 {pmu['script']}(또는 python3)가 없음"
    # Said once at the start: which host steps this run offers, and why not
    # the power cycle (2026-11-06: off for the whole run, never mentioned).
    print("호스트 스텝: Controller Reset" + (", Power Cycle (PMU)" if pmu and allow_destructive else "")
          + ("" if pmu and allow_destructive else
             f" - 전원 사이클 없음({pmu_off or '--no-destructive'}); 전원 사이클 전후 문장은 건너뜀"))
    available_opcodes = index.list_opcodes() + host_action_entries(pmu)

    existing = tc_store.load_all()
    targets = pick_next_targets(index, existing, sys.maxsize if count is None else count,
                                skip_records=load_json(config.TARGET_SKIPS_PATH, default=[]), variants=variants)
    total = len(targets)

    generated, executed, failed, host_crashes, unsupported, skipped = [], [], [], [], [], []
    ctx = {"existing": existing, "available_opcodes": available_opcodes, "allow_destructive": allow_destructive,
           "allow_placeholder_args": allow_placeholder_args, "target": target, "active_nsid": active_nsid,
           "lba_bytes": lba_bytes, "device_facts": device_facts, "device_support": support, "index": index}
    unsupported_in_run = {}  # (command set, opcode) -> section id that showed it
    pool = _DaemonPool(workers) if workers and workers > 1 else None
    futures = {}

    def _ensure(upto):
        for j in range(len(futures), min(upto, len(targets))):
            # A run of skipped targets of an unsupported command can outlast
            # the prefetch window; their generation would never be read.
            if pool and _opcode_key(targets[j][1]) not in unsupported_in_run:
                futures[j] = pool.submit(_prepare_target, targets[j][0], targets[j][1], ctx)
            else:
                futures[j] = None

    try:
        return _run_targets(targets, total, ctx, pool, futures, _ensure, unsupported_in_run, workers, executor,
                            index, variants, target, active_nsid, device_facts, support, lba_bytes,
                            available_opcodes, allow_destructive, review_llm, run_id, on_start, on_progress, on_skip,
                            generated, executed, failed, host_crashes, unsupported, skipped)
    finally:
        if pool:
            pool.shutdown()


def _run_targets(targets, total, ctx, pool, futures, _ensure, unsupported_in_run, workers, executor, index, variants,
                 target, active_nsid, device_facts, support, lba_bytes, available_opcodes, allow_destructive,
                 review_llm, run_id, on_start, on_progress, on_skip,
                 generated, executed, failed, host_crashes, unsupported, skipped):
    for i, (section, opcode_entry) in enumerate(targets, start=1):
        attempts, verdict = [], None
        key = _opcode_key(opcode_entry)
        if key in unsupported_in_run:
            # The drive already answered INVALID_OPCODE for this command in
            # this run: another clause of it cannot learn more (measured: 41
            # UNSUPPORTED TCs over 23 opcodes, 18 of them repeats).
            ahead = futures.get(i - 1)
            spent = ahead is not None and not ahead.cancelled() and (ahead.done() or ahead.running())
            reason = (f"같은 실행에서 {opcode_entry['name']}({opcode_entry['raw_opcode']})가 이미 "
                      f"미지원 확인됨({unsupported_in_run[key]}) — 전송 생략"
                      + ("(미리 생성은 이미 진행돼 결과를 버림)" if spent else ", LLM 호출도 생략"))
            _record_skip(skipped, section, opcode_entry, reason, "opcode_unsupported_in_run", run_id=run_id)
            if on_skip:
                on_skip(i, total, section, opcode_entry, reason)
            continue
        _ensure(i + max(workers or 1, 1))
        future = futures.get(i - 1)
        if future is not None and future.cancelled():
            future = None
        prepared = future.result() if future is not None else _prepare_target(section, opcode_entry, ctx)
        section = prepared["section"]
        if "skip" in prepared:
            _record_skip(skipped, section, opcode_entry, prepared["skip"], prepared["kind"], run_id=run_id)
            if on_skip:
                on_skip(i, total, section, opcode_entry, prepared["skip"])
            continue
        tc, tc_id, scenario = prepared["tc"], prepared["tc_id"], prepared["scenario"]
        resolved_steps, variant = prepared["resolved_steps"], prepared["variant"]
        tc["run_id"] = run_id

        if on_start:
            on_start(i, total, tc)
        generated.append(tc)

        try:
            execution = _execute_attempt(tc, executor, attempts)
        except (DestructiveStepBlocked, ValueError) as exc:
            # A chain the model built on its own (a destructive setup/verify
            # step it chose, or the action target itself) hit the gate that
            # exists for --no-destructive — unrelated to this one target's
            # own correctness, so it must not take the rest of the batch with
            # it either.
            reason = str(exc) or type(exc).__name__
            _record_skip(skipped, section, opcode_entry, reason, "blocked_before_wire", run_id=run_id)
            if on_skip:
                on_skip(i, total, section, opcode_entry, reason)
            continue
        step_statuses = check_step_expectations(tc, execution)
        rejection = rejected_arguments(execution, tc)  # (step_index, reason) | None

        action_idx = next(j for j, rs in enumerate(resolved_steps) if rs["phase"] == "action")
        unsent = {r["step_index"]: r["blocked_reason"] for r in execution["step_results"] if r.get("blocked_reason")}
        # Only the test's own steps: an unsent restore (cleanup_not_needed) or
        # a failed snapshot is not what a retry or replan can fix, and picking
        # it hid the real stop reason and the action's own rejection.
        broken_idx = next((j for j, st in enumerate(step_statuses)
                           if st in ("ERROR", "UNSUPPORTED") and j not in unsent
                           and is_test_step(tc["steps"][j])), None)
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
        # Includes the kernel cancelling the command (EINTR/EIO), the same
        # hang seen one layer lower than the SSH timeout.
        timed_out = device_hung(execution)
        # Every retry decision, including the ones that send nothing, so the
        # log says what was tried, what changed and what came back (measured:
        # "Get Features FID 84h -> 실행/인자 오류" with no way to tell whether
        # or how the retry changed the arguments).
        retry_log = []
        if broken_idx is None and unsent:
            first_unsent = min(unsent)
            retry_log.append({"kind": "none", "step_index": first_unsent,
                              "step_name": tc["steps"][first_unsent].get("name"),
                              "detail": (f"체인 중단: {unsent[first_unsent]}. 사전조건/기대 상태 불충족은 "
                                         "인자를 바꿔 고칠 문제가 아니라 재시도하지 않음")})
        if broken_idx is not None and (precedes_destructive or timed_out):
            retry_log.append({"kind": "none", "step_index": broken_idx,
                              "step_name": tc["steps"][broken_idx].get("name"),
                              "detail": ("앞 스텝에서 파괴적/펌웨어 커맨드가 이미 실행돼 재시도하지 않음"
                                         if precedes_destructive else "장비 행(타임아웃/커널 취소)이라 재시도하지 않음")})

        if broken_idx is not None and variant:
            retry_log.append({"kind": "none", "step_index": broken_idx, "step_name": tc["steps"][broken_idx].get("name"),
                              "detail": "코드 변형 TC는 값 자체가 테스트라 인자를 바꿔 재시도하지 않음"})
        elif broken_idx is not None and not precedes_destructive and not timed_out:
            if rejection is not None and rejection[0] == broken_idx:
                # Fixable by different field values. Rebuilds the rejected
                # step plus everything after it (not just the one step) —
                # later steps may already have been authored assuming this
                # step's about-to-change shared_facts, which would otherwise
                # go stale. For a single-step TC this degenerates to exactly
                # today's one-step reauthor.
                entry = {"kind": "args_rejected", "step_index": broken_idx,
                         "step_name": tc["steps"][broken_idx].get("name"), "trigger": rejection[1]}
                retry_log.append(entry)
                try:
                    retry_steps = reauthor_steps(tc, resolved_steps,
                                                  {"step_index": broken_idx, "reason": rejection[1]}, active_nsid,
                                                  device_facts=device_facts, device_support=support)
                except _LLM_REPLY_ERRORS as exc:
                    retry_steps = None
                    entry["detail"] = f"인자 재생성 LLM 호출 실패로 재시도하지 않음: {exc}"
                if retry_steps is not None and any(s.get("args_source") == "placeholder" for s in retry_steps):
                    placeholder_step = next(s for s in retry_steps if s.get("args_source") == "placeholder")
                    entry["detail"] = ("새 인자를 만들지 못해(placeholder) 재시도하지 않음: "
                                       f"{placeholder_step.get('args_error', '')}")
                # Only adopted if it will actually be sent. Assigning it to
                # tc["steps"] first (as this once did) left a placeholder
                # retry that was never executed stored as the TC's steps —
                # paired with the *previous* execution's results, and with the
                # criteria/status checks below reading the new steps' cdw10/
                # field_value_verified against that old output.
                if retry_steps is not None and not any(s.get("args_source") == "placeholder" for s in retry_steps) \
                        and not _changed_args(tc["steps"], retry_steps):
                    # Measured: 11 of 34 retries resent the identical command
                    # and got the identical rejection.
                    entry["changes"] = ["바뀐 인자 없음"]
                    entry["detail"] = "재생성한 인자가 거부된 인자와 같아 다시 보내지 않음"
                    retry_steps = None
                if retry_steps is not None and not any(s.get("args_source") == "placeholder" for s in retry_steps):
                    # `tc["retried"]` is purely a display aid for
                    # run_tc_pipeline.py — without it, the "실행할 명령" block
                    # printed before execution (built from the pre-retry steps)
                    # silently disagrees with the final cdw10/data_len printed
                    # after, with nothing on screen explaining why.
                    candidate = deepcopy(tc)
                    candidate["retried"] = {"kind": "args_rejected", "step_index": broken_idx,
                                            "step_name": tc["steps"][broken_idx].get("name"), "reason": rejection[1]}
                    candidate["steps"] = retry_steps
                    entry["changes"] = _changed_args(tc["steps"], retry_steps) or ["바뀐 인자 없음"]
                    try:
                        retry_execution = _execute_attempt(candidate, executor, attempts)
                    except (DestructiveStepBlocked, ValueError) as exc:
                        retry_execution = None
                        entry["detail"] = f"재시도 인자가 전송 전 검증에서 막혀 보내지 않음: {exc}"
                    if retry_execution is not None:
                        tc, execution = candidate, retry_execution
                        step_statuses = check_step_expectations(tc, execution)
                        rejection = rejected_arguments(execution, tc)
                        entry["result"] = _step_outcome(execution, broken_idx)
                        entry["detail"] = ("재시도도 거부됨" if rejection and rejection[0] == broken_idx
                                           else f"재시도 후 스텝 상태: {step_statuses[broken_idx]}")
            elif step_statuses[broken_idx] == "UNSUPPORTED" and broken_idx != action_idx:
                # A setup/verify command that simply doesn't exist on this
                # drive — no argument fix helps, and the dependent steps
                # after it can't be trusted either. Unlike a rejection this
                # is structural, so it needs a different *plan*, not
                # different field values: ask for one, and only commit to it
                # if it comes back usable (not placeholder-gated itself).
                broken_name = resolved_steps[broken_idx]["opcode_entry"]["name"]
                broken_result = next((r for r in execution["step_results"] if r["step_index"] == broken_idx), None)
                if completion_status(broken_result) == "INVALID_OPCODE":
                    replan_reason = f"{broken_name} is UNSUPPORTED (INVALID_OPCODE) on this drive"
                else:
                    replan_reason = (f"{broken_name} with cdw10={tc['steps'][broken_idx].get('cdw10')} is rejected because "
                                     "this drive does not support that feature/log page (probed at the start of the "
                                     "run); do not depend on it")
                entry = {"kind": "replanned", "step_index": broken_idx, "step_name": broken_name,
                         "trigger": replan_reason}
                retry_log.append(entry)
                try:
                    replanned_scenario = generate_scenario(
                        section, opcode_entry, available_opcodes,
                        feedback=f"step {broken_idx}: {replan_reason}",
                        device_facts=device_facts, **_support_kwarg(support))
                    replanned_steps = _resolve_steps_plan(index, replanned_scenario["steps_plan"],
                                                           available_opcodes, section)
                    replanned_tc = build_tc(tc_id, replanned_steps, replanned_scenario,
                                             target["nvme_ctrl"], target["nvme_ns"], active_nsid,
                                             device_facts=device_facts, lba_bytes=lba_bytes,
                                             device_support=support)
                    replanned_tc["run_id"] = run_id
                except _LLM_REPLY_ERRORS:
                    # The replan is "nice to have, falls back to what's
                    # already been measured" — same as a replan that itself
                    # lands on placeholder args just below. An LLM hiccup
                    # here must not crash the batch; keep the original tc's
                    # already-executed result (the action step still PASSED
                    # or whatever it did — only the broken non-action step's
                    # plan couldn't be improved) and move on below.
                    replanned_tc = None
                    entry["detail"] = "재계획 LLM 호출/검증 실패로 원래 결과 유지"
                if replanned_tc is not None and replanned_tc["uses_placeholder_args"]:
                    entry["detail"] = "재계획한 체인의 인자를 만들지 못해(placeholder) 원래 결과 유지"
                if replanned_tc is not None and not replanned_tc["uses_placeholder_args"]:
                    entry["changes"] = [" -> ".join(s.get("name") or "?" for s in replanned_tc["steps"])]
                    try:
                        replanned_execution = _execute_attempt(replanned_tc, executor, attempts)
                    except (DestructiveStepBlocked, ValueError) as exc:
                        entry["detail"] = f"재계획한 체인이 전송 전에 막혀 원래 결과 유지: {exc}"
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
                    if replanned_execution is not None and replanned_tc is not None:
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
                        entry["detail"] = "재계획한 체인으로 다시 실행함"
                        entry["result"] = "; ".join(f"스텝 {k} {st}" for k, st in enumerate(step_statuses))
            else:
                retry_log.append({"kind": "none", "step_index": broken_idx,
                                  "step_name": tc["steps"][broken_idx].get("name"),
                                  "detail": ("action 커맨드 자체가 미지원이라 재시도해도 바뀌지 않음"
                                             if step_statuses[broken_idx] == "UNSUPPORTED"
                                             else "컨트롤러의 인자 거부가 아니어서(환경/호스트 오류 등) 재시도 대상 아님")})
            # Else: UNSUPPORTED on the action step itself (the fixed primary
            # target — no plan change can avoid testing it) or a generic
            # host-tool/SSH ERROR with no specific rejection to act on.
            # Neither is retried, matching the existing single-step rule that
            # INVALID_OPCODE and host crashes are never retried.

        criteria_results = evaluate_criteria(tc, execution)
        tc["attempts"] = attempts
        tc["retry_log"] = retry_log
        tc["verification"] = verify_tc(tc, execution)
        tc["execution_status"] = check_execution(tc, execution)
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
            "dmesg_text": execution.get("dmesg_text", ""),
            "batch_stderr": execution.get("batch_stderr", ""),
            "timed_out": execution.get("timed_out", False),
            # Which step made an ERROR and whose problem it is - shown by the
            # terminal and the report so the reader need not dig through logs.
            "error_cause": error_cause(tc, execution) if tc["status"] == "ERROR" else None,
        }
        executed.append(tc)
        # Stored before any judging: the device result exists now. An
        # interrupted or failing judge used to drop it (review: Ctrl+C during
        # judging left one execution and zero stored TCs).
        tc["updated_at"] = datetime.now(timezone.utc).isoformat()
        tc_store.upsert(tc)

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
            fc_path = config.FAILURE_CONTEXTS_DIR / "tc_exec" / f"{fc['failure_context_id']}.json"
            save_json_atomic(fc_path, fc)
            tc["failure_context_id"] = fc["failure_context_id"]
            tc_store.upsert(tc)  # the stored TC points at its saved FailureContext before judging
            try:
                verdict = judge_failure_context(fc)
                # Same path as a later run_judge: holds an unfounded defect
                # verdict and links it to this TC.
                verdict = apply_tc_verdict(tc, verdict)
            except _LLM_REPLY_ERRORS:
                # The device-side FAIL/ERROR is real regardless of whether
                # judging succeeds — an LLM hiccup here must not crash the
                # batch over a result that already happened. tc_store still
                # gets this TC with its real status, just without a
                # classification. The saved FailureContext can be re-judged
                # with run_judge --source tc_exec.
                verdict = None
            if verdict is not None:
                # judge_failure_context fills fc["spec_grounding"] in place, so save
                # after judging — not before — or the stored context keeps queried=false.
                save_json_atomic(fc_path, fc)
                verdict_path = config.VERDICTS_DIR / "tc_exec.json"
                verdicts = load_json(verdict_path, default=[])
                verdicts.append(verdict)
                save_json_atomic(verdict_path, verdicts)
                tc["verdict_id"] = verdict["verdict_id"]
                tc["failure_context_id"] = fc["failure_context_id"]
            failed.append(tc)

        try:
            tc["review"] = review_tc(tc, verdict=verdict if tc.get("verdict_id") else None, use_llm=review_llm)
        except Exception as exc:  # the review annotates a result, it never decides one
            tc["review"] = {"level": "must", "label": "꼭 확인", "scope": None, "audit_llm_response_id": None,
                            "reasons": [{"level": "must", "code": "review_error", "source": "code",
                                         "text": f"검토 사유 계산 실패: {exc}"}]}
        # The drive answered for the command itself: INVALID_OPCODE on the
        # action, or a precondition read the command's own support bit as 0
        # (OACS/ONCS bit, CSUPP) and the action was not sent.
        absent = None if _action_unsupported_opcode(tc) else command_support_measured_absent(tc)
        if (_action_unsupported_opcode(tc) or absent) and _opcode_key(opcode_entry):
            unsupported_in_run.setdefault(_opcode_key(opcode_entry),
                                          f"{section['section_id']}: "
                                          + (f"사전조건 측정 {absent}" if absent else "INVALID_OPCODE"))
            # Prefetched generation for the same command that has not started
            # yet is dropped before it spends LLM calls.
            for j, ahead in futures.items():
                if ahead is not None and j >= i and _opcode_key(targets[j][1]) == _opcode_key(opcode_entry):
                    ahead.cancel()
        tc["updated_at"] = datetime.now(timezone.utc).isoformat()
        tc_store.upsert(tc)
        # Recomputed per TC, not just after the loop: a crash or device hang
        # mid-run would otherwise leave coverage_state.json describing a store
        # that has already moved on.
        coverage = compute_coverage(index, tc_store.load_all(), load_json(config.TARGET_SKIPS_PATH, default=[]),
                                    variants)
        save_json_atomic(config.COVERAGE_STATE_PATH, coverage)

        if on_progress:
            on_progress(i, total, tc)

        risky_steps = any(s.get("destructive") or s.get("firmware_state") or s.get("lockout_risk")
                          or s.get("host_action") for s in tc["steps"])
        # A timeout gets the same check: the batch was killed because the
        # device stopped answering, and without this every remaining target
        # would spend its own full timeout (SECONDS_PER_STEP x steps) finding
        # that out again.
        if risky_steps or device_hung(execution):
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

    coverage = compute_coverage(index, tc_store.load_all(), load_json(config.TARGET_SKIPS_PATH, default=[]),
                                variants)
    save_json_atomic(config.COVERAGE_STATE_PATH, coverage)

    review_counts = {}
    for tc in executed:
        level = (tc.get("review") or {}).get("level", "info")
        review_counts[level] = review_counts.get(level, 0) + 1
    return {"generated": len(generated), "executed": len(executed), "failed": len(failed), "review": review_counts,
            "our_bugs": len(host_crashes), "unsupported": len(unsupported), "skipped": len(skipped),
            "coverage": coverage["summary"]}
