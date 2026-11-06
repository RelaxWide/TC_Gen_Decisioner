import argparse
import sys
import textwrap
import time

from shared.run_log import capture_to_file
from tc_system.execution.expectation_checker import describe_outcome
from tc_system.verification import expected_status
from tc_system.execution.ssh_runner import DestructiveStepBlocked, passthru_cmd
from tc_system.pipeline import run_pipeline

_STATUS_LABEL = {"PASS": "PASS", "FAIL": "FAIL", "ERROR": "실행/인자 오류", "UNSUPPORTED": "미지원 응답",
                 "UNVERIFIED": "미검증"}
_PHASE_LABEL = {"setup": "사전조건", "action": "본동작", "verify": "확인"}
_tc_start_times = {}
_announced = set()  # target indexes whose header/commands were already printed


def _positive_int(text):
    value = int(text)
    if value < 1:
        raise argparse.ArgumentTypeError(f"must be 1 or more, got {value}")
    return value


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
    _announced.add(index)
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
    target_req = (tc.get("verification_contract") or {}).get("target_requirement") or {}
    if target_req:
        kind = {"abort": "거부 규칙", "variant": f"코드 변형({target_req.get('family')})"}.get(
            target_req.get("kind"), "요구사항")
        expect = f" → 기대 {target_req['expected_status']}" if target_req.get("expected_status") else ""
        _dual_label("  ", f"타겟 {kind} [{target_req.get('section_id')}]", target_req.get("text", "") + expect)

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
        if step.get("host_action"):
            label = {"controller_reset": "컨트롤러 리셋(nvme reset)",
                     "power_cycle": "PMU 전원 사이클(전원 OFF → 재인식)"}.get(step["host_action"], step["host_action"])
            print(f"        호스트 동작: {label} — 대상 호스트에서 실행")
            continue
        try:
            cmd = passthru_cmd(step)
        except ValueError as exc:
            cmd = f"(명령 생성 불가 — {exc})"
        print(f"        $ {cmd}")
        print(f"        기대 완료 상태: {expected_status(step)}")
        if step.get("constraint_overrides"):
            _dual_label("        ", "시나리오 고정값 적용", ", ".join(step["constraint_overrides"]))
        if step.get("derived_fields"):
            _dual_label("        ", "하네스 계산값 적용", ", ".join(step["derived_fields"]))

    # Checks the harness rewrote to the field their description names.
    for repair in (tc.get("verification_contract") or {}).get("check_repairs") or []:
        _dual_label("  ", f"검사식 보정(스텝 {repair['step']})",
                    f"'{repair.get('description', '')}' — {repair['problem']} → {repair['reads']}로 읽음")
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
        unsent = {r["step_index"] for r in (tc.get("execution") or {}).get("step_results", [])
                  if r.get("blocked_reason")}
        for i, step in enumerate(steps):
            step_label = ("미실행(체인 중단)" if i in unsent
                          else _STATUS_LABEL.get(step_statuses[i], step_statuses[i]))
            print(f"    [{i}] {step.get('name') or '?'}  {step_label}  cdw10={step['cdw10']} data_len={step['data_len']}")

    # Every retry decision: what triggered it, which argument values changed,
    # and what came back - or why nothing was resent. Without this the
    # command block above (printed before any retry) silently disagreed with
    # the final values, and a retry that was rejected again, or never sent,
    # left no trace at all (measured: Get Features FID 84h -> 실행/인자 오류
    # with no way to tell what the retry did).
    heads = {"args_rejected": "인자 거부 → 재시도", "replanned": "미지원 스텝 → 재계획",
             "none": "재시도 안 함"}
    for entry in tc.get("retry_log") or []:
        where = f"스텝 {entry['step_index']} {entry.get('step_name') or '?'}"
        if entry.get("trigger"):
            where += f" — 계기: {entry['trigger']}"
        _dual_label("     ", f"⚠ {heads.get(entry['kind'], entry['kind'])}", where, width=110)
        for change in entry.get("changes", []):
            _dual_label("       ", "바뀐 값", change, width=110)
        _dual_label("       ", "처리", entry.get("detail"), width=110)
        _dual_label("       ", "재시도 결과", entry.get("result"), width=110)
    if tc.get("retried"):
        print("       (위 \"실행할 명령\"은 재시도 전 값이고, 결과 줄의 cdw 값이 실제로 보낸 최종 값)")

    execution = tc.get("execution") or {}
    verification = tc.get("verification") or {}
    # What it means, why, and what happens next - in that order. A bare
    # "실행/인자 오류" + "스펙 검증: UNVERIFIED" left the reader to work out
    # whether the drive or the harness was at fault.
    outcome = describe_outcome(tc)
    _dual_label("     ", "판단", outcome["verdict"])
    _dual_label("     ", "원인", outcome["cause"], width=110)
    _dual_label("     ", "다음", outcome["next"])
    if status in ("PASS", "FAIL", "UNVERIFIED"):
        # The commands completed, so the requirement checks were evaluated.
        print(f"     스펙 검증: {verification.get('status', 'UNVERIFIED')}")
        for condition in verification.get("preconditions", []):
            results = condition.get("results", [])
            state = ("충족" if results and all(c["result"] == "satisfied" for c in results)
                     else "불충족" if any(c["result"] == "violated" for c in results) else "확인 불가")
            _dual_label("     ", f"사전조건 {state}", condition.get("description"))
            for check in results:
                if check["result"] != "satisfied":
                    _dual_label("       ", check["result"], check["detail"])
        for req in verification.get("requirements", []):
            _dual_label("     ", req["status"], req["description"])
            # One line per distinct outcome: checks on steps the chain never
            # sent all say the same thing and used to print once each.
            seen = set()
            for check in req.get("results", []):
                key = (check["result"], check["detail"])
                if key not in seen:
                    seen.add(key)
                    _dual_label("       ", check["result"], check["detail"])
    else:
        # ERROR/UNSUPPORTED: nothing was evaluated; per-check "unevaluated"
        # lines would only repeat that. Show what the TC set out to verify.
        for req in verification.get("requirements", []):
            _dual_label("     ", "검증하려던 요구사항", req["description"])
    for note in (tc.get("scenario") or {}).get("out_of_scope", []):
        _dual_label("     ", "검증 범위 밖", note)
    review = tc.get("review") or {}
    if review.get("level") in ("must", "recommend"):
        flag = "⚑ 꼭 확인" if review["level"] == "must" else "⚑ 확인 권장"
        print(f"     {flag}" + (f" (PASS 범위: {review['scope']})" if review.get("scope") else ""))
        for reason in review.get("reasons", []):
            if reason["level"] != "info":
                source = " · LLM 감사" if reason.get("source") == "llm" else ""
                _dual_label("       ", f"[{'꼭' if reason['level'] == 'must' else '권장'}{source}]", reason["text"])
    for i, r in enumerate((tc.get("execution") or {}).get("step_results", [])):
        if r.get("cleanup_skipped"):
            _dual_label("     ", f"원복 생략(스텝 {r['step_index']})", r["cleanup_skipped"])

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
    reason = reason or "(사유 미기록)"
    if index in _announced:
        # Already announced with its commands: continue that block instead of
        # a second "[i/N]" header that read as the run jumping back.
        _announced.discard(index)
        _dual_label("  ", "-> 보내지 않고 건너뜀", reason, width=110)
        return
    print(f"\n[{index}/{total}] {section['section_id']} ({opcode_entry['name']}) — 건너뜀, 다음 타겟으로 진행")
    _dual_label("  ", "사유", reason, width=110)


def build_parser():
    parser = argparse.ArgumentParser()
    how_many = parser.add_mutually_exclusive_group()
    how_many.add_argument("--count", type=_positive_int, default=None,
                          help="how many new TCs to generate+execute this run (1 or more, default 5)")
    how_many.add_argument("--all", action="store_true",
                          help="every target that can be offered, once each (~232; hours). Untried "
                               "targets come first, so an interrupted run resumes where it stopped")
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
    return parser


def main():
    args = build_parser().parse_args()

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
        result = run_pipeline(count=None if args.all else (args.count or 5),
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
    except KeyboardInterrupt:
        # Every finished TC is already stored; a long --all run stopped by hand
        # still gets a report of what it did.
        print("\n중단됨 — 지금까지 저장된 결과로 리포트를 만듭니다. 다시 실행하면 안 해 본 타겟부터 이어집니다.")
        _write_tc_report()
        return 130

    review = result.get("review") or {}
    if review:
        print(f"\n검토 요청: 꼭 확인 {review.get('must', 0)} / 확인 권장 {review.get('recommend', 0)} / "
              f"참고 {review.get('info', 0)} — 리포트 맨 위 '꼭 봐야 할 결과'에 사유와 함께 정리됨")
    print(f"\ngenerated={result['generated']} executed={result['executed']} "
          f"failed={result['failed']} our_bugs={result.get('our_bugs', 0)} unsupported={result.get('unsupported', 0)} "
          f"skipped={result.get('skipped', 0)}")
    cov = result["coverage"]
    print(f"요구사항 검증: {cov.get('requirements_evaluated', 0)}/{cov.get('requirements_total', 0)} 생성 요구사항"
          f" (PASS={cov.get('requirements_passed', 0)}, FAIL={cov.get('requirements_failed', 0)}, "
          f"미검증={cov.get('requirements_unverified', 0)}) — 전체 스펙 검증률 아님")
    if cov.get("requirements_passed_by_scope"):
        print("  PASS가 관측한 것: " + ", ".join(f"{k} {v}" for k, v in cov["requirements_passed_by_scope"].items()))
    print(f"요구사항 타겟: {cov.get('requirements_tried', 0)}/{cov.get('requirement_targets', 0)} 시도"
          f" (판정 {cov.get('requirements_judged', 0)}) / 코드 변형: {cov.get('variants_tried', 0)}/"
          f"{cov.get('variant_targets', 0)} 시도 (판정 {cov.get('variants_judged', 0)})")
    print(f"테스트 대상 조항: {cov.get('targets_tried', 0)}/{cov.get('testable_targets', 0)} 시도"
          f" / 전체스펙 {cov['section_pct']}% ({cov['section_covered']}/{cov['section_total']}), "
          f"opcode {cov['opcode_pct']}% ({cov['opcode_covered']}/{cov['opcode_total']})")
    print(f"  명령 완료 이력 {cov.get('section_passing', 0)} / 명령 실패 이력 {cov.get('section_failing', 0)}"
          f" / 미지원 {cov.get('section_unsupported', 0)} / 집계제외 {cov.get('excluded_tc_count', 0)}")
    _write_tc_report()
    return 0


def _write_tc_report():
    """Regenerated after every run. A report failure never fails the run:
    the results are already stored and `run_report.py --kind tc` rebuilds it."""
    try:
        from report.aggregator import build_tc_model
        from report.html_report import write_tc_report
        print(f"TC 리포트: {write_tc_report(build_tc_model())}")
    except Exception as exc:  # noqa: BLE001 - reporting must not mask the run's result
        print(f"⚠ TC 리포트 생성 실패(결과는 저장됨, python run_report.py --kind tc 로 다시 생성): {exc}")


if __name__ == "__main__":
    raise SystemExit(main())
