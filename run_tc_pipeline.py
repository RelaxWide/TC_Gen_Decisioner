import argparse
import sys
import textwrap
import time

from shared.run_log import capture_to_file
from tc_system.execution.ssh_runner import DestructiveStepBlocked, passthru_cmd
from tc_system.pipeline import run_pipeline

_STATUS_LABEL = {"PASS": "PASS", "FAIL": "FAIL", "ERROR": "실행/인자 오류", "UNSUPPORTED": "미지원 응답",
                 "UNVERIFIED": "미검증"}
_PHASE_LABEL = {"setup": "사전조건", "action": "본동작", "verify": "확인"}
_tc_start_times = {}


def _one_line(text, width=100):
    text = " ".join(str(text or "").split())
    return textwrap.shorten(text, width=width, placeholder=" ...")


def _dual_line(console_text, file_text=None):
    """Writes one logical line — `console_text` to the console, `file_text`
    (full, untruncated; defaults to `console_text`) to the log file — instead
    of printing the line twice (a shortened version, then a separate "[label
    전체]" duplicate) to get different content per destination. Goes through
    `sys.stdout.dual_write` (the same handle `capture_to_file` already has
    open for the whole run) rather than opening a second handle on the same
    path — two handles writing to one file independently corrupt it, since
    each tracks its own buffered position. Falls back to a plain print when
    stdout isn't wrapped (e.g. called outside `capture_to_file`, as in tests).
    """
    if file_text is None:
        file_text = console_text
    dual_write = getattr(sys.stdout, "dual_write", None)
    if dual_write:
        dual_write(console_text + "\n", file_text + "\n")
    else:
        print(console_text)


def _dual_label(indent, label, text, width=100):
    """The common "label: text" line — shortened on console, full in the file."""
    if not text:
        return
    _dual_line(f"{indent}{label}: {_one_line(text, width=width)}", f"{indent}{label}: {text}")


def _print_start(index, total, tc):
    _tc_start_times[tc["tc_id"]] = time.monotonic()
    steps = tc["steps"]
    scenario = tc.get("scenario") or {}
    expectation = tc.get("expectation") or {}
    flags = []
    if tc.get("destructive"):
        flags.append("파괴적")
    if any(s.get("firmware_state") for s in steps):
        flags.append("펌웨어")
    flag_str = f" [{'/'.join(flags)}]" if flags else ""

    # Scenario/intent first, then which real commands make up the sequence,
    # then the exact CLI line each one will run, and the rest (Expectation/
    # Fail 기준) last — not a register-level opcode=/nsid=/mode= dump up
    # front, which says nothing about what's actually being tested.
    print(f"\n[{index}/{total}] {tc['name']}{flag_str}")
    _dual_label("  ", "시나리오", scenario.get("description"))

    if len(steps) > 1:
        chain_summary = tc.get("chain_summary")
        if chain_summary:
            _dual_label("  ", "체인 요약", chain_summary)
        names = " → ".join(s.get("name") or "?" for s in steps)
        print(f"  명령 조합: {names}")

    print("  실행할 명령:")
    for i, step in enumerate(steps):
        phase_label = _PHASE_LABEL.get(step.get("phase"), step.get("phase"))
        tag = f"[{i}] ({phase_label}) " if len(steps) > 1 else ""
        base = f"    {tag}{step.get('name') or '?'}"
        role = step.get("role")
        if role:
            _dual_line(f"{base} — {_one_line(role, width=70)}", f"{base} — {role}")
        else:
            print(base)
        try:
            cmd = passthru_cmd(step)
        except ValueError as exc:
            cmd = f"(명령 생성 불가 — {exc})"
        print(f"        $ {cmd}")

    _dual_label("  ", "Expectation", expectation.get("description"))
    fail_criteria = expectation.get("fail_criteria") or []
    if fail_criteria:
        joined = "; ".join(str(c) for c in fail_criteria)
        _dual_label("  ", "Fail 기준", joined)
    print("  -> 실행 중...", flush=True)


def _print_result(index, total, tc):
    started = _tc_start_times.pop(tc["tc_id"], None)
    elapsed = (time.monotonic() - started) if started else 0.0
    status = tc["status"]
    label = _STATUS_LABEL.get(status, status)
    steps = tc["steps"]
    if len(steps) == 1:
        step = steps[0]
        print(f"  <- 결과: {label} ({elapsed:.1f}s)  cdw10={step['cdw10']} data_len={step['data_len']}")
    else:
        print(f"  <- 결과: {label} ({elapsed:.1f}s)")
        step_statuses = tc.get("step_statuses") or [status] * len(steps)
        for i, step in enumerate(steps):
            step_label = _STATUS_LABEL.get(step_statuses[i], step_statuses[i])
            print(f"    [{i}] {step.get('name') or '?'}  {step_label}  cdw10={step['cdw10']} data_len={step['data_len']}")

    retried = tc.get("retried")
    if retried:
        # Without this, the command block above (printed by _print_start
        # before any retry) can silently disagree with the cdw10/data_len
        # values just printed above — e.g. a rejected Set Features authored
        # with cdw10=0x16 up there, re-authored to 0x01 down here — with
        # nothing on screen explaining why. Measured: this read as a bug
        # on first glance until the SSH/LLM call logs were cross-checked.
        kind_label = {"args_rejected": "인자 거부", "replanned": "미지원 → 재계획"}.get(
            retried["kind"], retried["kind"])
        detail = (f"스텝 {retried['step_index']}({retried.get('step_name') or '?'})이 "
                  f"{kind_label}로 재시도됨 — 위 \"실행할 명령\"은 재시도 전 값이고, 방금 찍힌 cdw 값이 "
                  f"실제로 전송된 최종 값입니다. 사유: {retried['reason']}")
        _dual_label("     ", "⚠ 재시도", detail)

    execution = tc.get("execution") or {}
    verification = tc.get("verification") or {}
    print(f"     스펙 검증: {verification.get('status', 'UNVERIFIED')}")
    for req in verification.get("requirements", []):
        _dual_label("     ", req["status"], req["description"])
        for check in req.get("results", []):
            _dual_label("       ", check["result"], check["detail"])
    for issue in verification.get("issues", []):
        _dual_label("     ", "미검증 사유", issue)
    reason = execution.get("args_rejected") or execution.get("host_tool_crash")
    _dual_label("     ", "사유", reason, width=110)
    if status == "UNSUPPORTED":
        # evaluate_criteria runs the generic rules regardless of status, so
        # "exit code != 0" always fires here too — that's expected for an
        # unimplemented command and not a real violation, so it's not shown.
        print("     (미지원 응답 관측 — 필수/선택 기능의 스펙 적합성을 뜻하지 않음)")
    elif status == "FAIL":
        violated = [c for c in execution.get("criteria_results", []) if c["result"] == "violated"]
        for c in violated:
            _dual_line(f"     위반: {c['criterion']} — {_one_line(c['detail'], width=100)}",
                       f"     위반: {c['criterion']} — {c['detail']}")

    # Printed for either FAIL or ERROR — both get judged (pipeline.py routes
    # anything not already caught as a host crash/rejection to judge_failure_context
    # regardless of which of the two it is). This used to only print under
    # `status == "FAIL"`, so a judged ERROR left no way to find its verdict
    # or FailureContext file from the terminal at all.
    if tc.get("verdict_id"):
        print(f"     -> LLM 판정 완료 (verdict_id={tc['verdict_id']}, data/verdicts/tc_exec.json 참고)")
        print(f"        failure_context_id={tc.get('failure_context_id')} "
              f"(data/failure_contexts/tc_exec/{tc.get('failure_context_id')}.json 참고)")


def _print_skip(index, total, section, opcode_entry, reason):
    # Without this, a target abandoned mid-way (placeholder args, a
    # destructive step blocked under --no-destructive, an LLM hiccup) prints
    # nothing at all — indistinguishable on screen from a hang, which is
    # exactly the confusion on_start/on_progress already exist to avoid for
    # TCs that do reach a final status.
    print(f"\n[{index}/{total}] {section['section_id']} ({opcode_entry['name']}) — 건너뜀, 다음 타겟으로 진행")
    _dual_label("  ", "사유", reason, width=110)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--count", type=int, default=5, help="how many new TCs to generate+execute this run")
    parser.add_argument("--allow-placeholder-args", action="store_true",
                         help="execute a TC even though its command arguments fell back to placeholders "
                              "(plumbing experiments only; resulting TCs are excluded from the coverage "
                              "claim) — without this flag such a TC is just skipped and the batch continues")
    # Destructive and firmware-state commands are part of the automated sweep by
    # design (the target drive's data is expendable). `--no-destructive` is here
    # for a run against a drive whose contents matter. Targets are ordered so
    # non-destructive commands run first within a batch.
    parser.add_argument("--no-destructive", action="store_true",
                         help="skip data-destructive and firmware-state opcodes (Format NVM, Sanitize, Write, "
                              "Dataset Management, Firmware Download/Commit) for this run")
    parser.add_argument("--quiet", action="store_true",
                         help="suppress per-TC progress lines (only the final summary)")
    # Coverage accumulates across runs by design (run this daily against the
    # same drive and it targets only what's still uncovered) — but nothing
    # in tc_store.json records which physical drive a result came from, so
    # swapping in a different one without this makes the new drive silently
    # inherit the old one's coverage (including drive-specific UNSUPPORTED
    # verdicts) and pick_next_targets finds nothing left to offer.
    parser.add_argument("--reset-coverage", action="store_true",
                         help="wipe accumulated coverage (tc_store.json/coverage_state.json, backed up to "
                              "data/coverage_backups/ first) before this run — use when the physical drive "
                              "under test has changed")
    args = parser.parse_args()

    with capture_to_file("tc_pipeline") as log_path:
        print(f"[전체 로그] {log_path}")
        return _run(args)


def _run(args) -> int:
    # Each TC costs 1-3 LLM calls plus an SSH round-trip (15-25s typical), so a
    # silent batch of --count 20 ran for many minutes with nothing on screen —
    # indistinguishable from a hang. on_start shows what is about to be sent
    # (scenario + Expectation, already decided by the LLM) before it goes out;
    # on_progress shows the real result once it comes back.
    on_start = None if args.quiet else _print_start
    on_progress = None if args.quiet else _print_result
    on_skip = None if args.quiet else _print_skip

    if args.reset_coverage:
        print("⚠ --reset-coverage: tc_store.json/coverage_state.json을 초기화합니다 "
              "(이전 내용은 data/coverage_backups/에 백업됨)")

    try:
        result = run_pipeline(count=args.count,
                               allow_placeholder_args=args.allow_placeholder_args,
                               allow_destructive=not args.no_destructive,
                               on_start=on_start, on_progress=on_progress, on_skip=on_skip,
                               reset_coverage=args.reset_coverage)
    except DestructiveStepBlocked as exc:
        # Defensive only — pipeline.py now catches this itself around every
        # executor.execute() call and turns it into a per-target skip, so
        # this should never actually fire. Kept as a last-resort net given
        # the stakes (a destructive command the user explicitly opted out of
        # via --no-destructive) rather than deleted outright.
        print(f"blocked: {exc}", file=sys.stderr)
        return 3

    print(f"\ngenerated={result['generated']} executed={result['executed']} "
          f"failed={result['failed']} our_bugs={result.get('our_bugs', 0)} unsupported={result.get('unsupported', 0)} "
          f"skipped={result.get('skipped', 0)}")
    cov = result["coverage"]
    print(f"요구사항 검증: {cov.get('requirements_evaluated', 0)}/{cov.get('requirements_total', 0)} 생성 요구사항"
          f" (PASS={cov.get('requirements_passed', 0)}, FAIL={cov.get('requirements_failed', 0)}, "
          f"미검증={cov.get('requirements_unverified', 0)}) — 전체 스펙 검증률 아님")
    print(f"명령 실행 이력: 연결된 조항 {cov.get('reachable_pct', 0)}% ({cov.get('reachable_covered', 0)}/{cov.get('reachable_total', 0)})"
          f" / 전체스펙 {cov['section_pct']}% ({cov['section_covered']}/{cov['section_total']}), "
          f"opcode {cov['opcode_pct']}% ({cov['opcode_covered']}/{cov['opcode_total']})")
    print(f"  명령 완료 이력 {cov.get('section_passing', 0)} / 명령 실패 이력 {cov.get('section_failing', 0)}"
          f" / 미지원 {cov.get('section_unsupported', 0)} / 집계제외 {cov.get('excluded_tc_count', 0)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
