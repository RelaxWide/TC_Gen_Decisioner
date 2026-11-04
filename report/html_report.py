from pathlib import Path
import json

import config
from report import components as c
from tc_system.execution.expectation_checker import describe_outcome
from tc_system.verification import verify_tc

SOURCE_LABELS = {"qst": "QST", "pulsefz": "PULSEFZ", "tc_exec": "TC 자동생성 실행 결과"}


def _coverage_section(coverage: dict | None) -> str:
    if coverage is None:
        return '<div class="empty-state">아직 TC가 생성되지 않아 커버리지 데이터가 없습니다.</div>'
    s = coverage["summary"]
    tiles = (
        # Reachable first: it is the number that can actually reach 100%.
        c.stat_tile("명령 실행 이력이 있는 조항", f"{s.get('reachable_pct', 0)}%",
                     f"{s.get('reachable_covered', 0)}/{s.get('reachable_total', 0)} 조항 (opcode 연결됨)")
        + c.stat_tile("전체 조항 중 실행 이력", f"{s['section_pct']}%",
                       f"{s['section_covered']}/{s['section_total']} 조항 — 산문/구조 조항 포함")
        + c.stat_tile("Opcode coverage", f"{s['opcode_pct']}%", f"{s['opcode_covered']}/{s['opcode_total']} opcodes")
        + c.stat_tile("명령 완료", str(s.get("section_passing", 0)), "스펙 준수 검증과 별도")
        + c.stat_tile("명령 실패 관측", str(s.get("section_failing", 0)), "원인 분류와 별도")
        + c.stat_tile("PASS/FAIL 혼재", str(s.get("section_mixed", 0)), "재현성 확인 필요")
        + c.stat_tile("미지원 응답 관측", str(s.get("section_unsupported", 0)), "필수/선택 기능의 적합성은 별도 검증")
    )
    bars = "".join(c.progress_bar(d["pct"], d["spec_doc"]) for d in s["per_spec_doc"])
    notes = ""
    if s.get("excluded_tc_count"):
        notes = (
            f'<div class="note">집계 제외 TC {s["excluded_tc_count"]}건 — '
            "인자가 placeholder였거나, 실행이 우리 쪽 사유(INVALID_FIELD·호스트 크래시·SSH 실패)로 "
            "끝나 Spec에 대해 입증한 바가 없는 항목입니다.</div>"
        )
    verified = (
        c.stat_tile("검증식을 평가한 요구사항", str(s.get("requirements_evaluated", 0)),
                    f"생성된 요구사항 {s.get('requirements_total', 0)}개 중 — 전체 스펙 분모 아님")
        + c.stat_tile("요구사항 PASS", str(s.get("requirements_passed", 0)))
        + c.stat_tile("요구사항 FAIL / 혼재", f"{s.get('requirements_failed', 0)} / {s.get('requirements_mixed', 0)}")
        + c.stat_tile("미검증 요구사항", str(s.get("requirements_unverified", 0)))
    )
    explanation = '<p class="note">한 요구사항의 검증은 조항 전체의 검증 완료를 뜻하지 않습니다. '
    explanation += '기존 기록은 보존되며, 스펙 근거·검증식이 없으면 미검증으로 표시합니다.</p>'
    return (f'<div class="stat-row">{verified}</div>{explanation}<h3>명령 실행·지원 조사 이력</h3>'
            f'<div class="stat-row">{tiles}</div>'
            f'<div class="card" style="margin-top:16px">{bars}</div>{notes}')


def _json(value):
    return '<pre>' + c.esc(json.dumps(value, ensure_ascii=False, indent=2)) + '</pre>'


def _tc_evidence(tc):
    verification = verify_tc(tc, tc.get("execution") or {})
    contract = tc.get("verification_contract") or {}
    evidence = {e.get("evidence_id"): e for e in contract.get("evidence", [])}
    rows = []
    for req in verification["requirements"]:
        block = evidence.get(req.get("evidence_id"), {})
        rows.append([
            c.esc(block.get("section_id", "")) + '<blockquote>' + c.esc(req.get("quote", "")) + '</blockquote>',
            c.esc(req["description"]), c.esc(req["status"]),
            _json(req["results"]),
        ])
    body = '<p><strong>시나리오</strong>: ' + c.esc((tc.get("scenario") or {}).get("description", "")) + '</p>'
    outcome = describe_outcome(tc, verification)
    for label, key in (("판단", "verdict"), ("원인", "cause"), ("다음", "next")):
        if outcome.get(key):
            body += f'<p><strong>{label}</strong>: ' + c.esc(outcome[key]) + '</p>'
    retry_items = []
    for entry in tc.get("retry_log") or []:
        parts = [f"스텝 {entry.get('step_index')} {entry.get('step_name') or '?'} ({entry.get('kind')})"]
        parts += [f"계기: {entry['trigger']}"] if entry.get("trigger") else []
        parts += [f"바뀐 값: {', '.join(entry['changes'])}"] if entry.get("changes") else []
        parts += [f"처리: {entry['detail']}"] if entry.get("detail") else []
        parts += [f"재시도 결과: {entry['result']}"] if entry.get("result") else []
        retry_items.append("<li>" + "<br>".join(c.esc(x) for x in parts) + "</li>")
    if retry_items:
        body += '<p><strong>재시도 이력</strong></p><ul>' + "".join(retry_items) + '</ul>'
    notes = (tc.get("scenario") or {}).get("out_of_scope", [])
    if notes:
        body += '<p><strong>이 TC가 검증하지 않는 범위</strong></p><ul>' + "".join(
            f"<li>{c.esc(n)}</li>" for n in notes) + '</ul>'
    body += '<p><strong>스펙 검증</strong>: ' + c.esc(verification["status"]) + '</p>'
    body += _json(verification["issues"])
    if rows:
        body += c.table(["스펙 근거", "검증할 요구사항", "결과", "검증식 · 실제 관측 · 기대값"], rows)
    else:
        body += '<p>실행 가능한 검증식과 인용 근거가 없는 기록입니다. 기존 PASS는 스펙 검증 완료로 집계하지 않습니다.</p>'
    step_rows = []
    results = {r["step_index"]: r for r in (tc.get("execution") or {}).get("step_results", [])}
    for i, step in enumerate(tc.get("steps", [])):
        encoded = {k: step.get(k) for k in ("mode", "opcode", "nsid", "cdw10", "cdw11", "cdw12",
                                          "cdw13", "cdw14", "cdw15", "direction", "data_len")}
        encoded["payload"] = "명시적 hex payload" if step.get("payload_hex") else "write 시 zero-filled"
        step_rows.append([c.esc(f"{i}: {step.get('name', '')} ({step.get('phase', '')})"),
                          c.esc(step.get("role", "")), _json(step.get("field_constraints", [])),
                          _json(encoded), c.esc(step.get("expected_status", "SUCCESS")),
                          _json(results.get(i, {"missing": True}))])
    body += c.table(["단계", "계획한 목적", "고정 필드", "실제 명령 인자", "기대 상태", "실제 응답"], step_rows)
    body += '<h4>사전조건 평가</h4>' + _json(verification["preconditions"])
    body += '<h4>기존 산문 기준 / 평가 이력</h4>' + _json((tc.get("execution") or {}).get("criteria_results", []))
    if tc.get("attempts"):
        body += c.details_block("재시도 전후 명령과 원본 증거", _json(tc["attempts"]))
    body += c.details_block("스펙 근거 원문과 생성 호출 ID", _json({
        "evidence": contract.get("evidence", []), "generated_from": tc.get("generated_from"),
        "args_llm_response_ids": [s.get("args_llm_response_id") for s in tc.get("steps", [])]}))
    return c.details_block(c.esc(f"스펙 검증: {verification['status']} — 근거·명령·결과 보기"), body)


def _tc_table(tc_records: list[dict]) -> str:
    if not tc_records:
        return '<div class="empty-state">아직 생성/실행된 TC가 없습니다.</div>'
    rows = []
    for tc in sorted(tc_records, key=lambda t: t.get("updated_at", ""), reverse=True):
        status_badge = {
            "PASS": '<span class="badge" style="background:var(--status-good);color:#fff">&#9679; PASS</span>',
            "FAIL": '<span class="badge" style="background:var(--status-critical);color:#fff">&#9679; FAIL</span>',
            # The drive answered "not implemented" — a finding about an optional
            # command, not a defect and not a harness problem.
            "UNSUPPORTED": '<span class="badge" style="background:var(--series-blue);color:#fff">'
                            '&#9679; 미지원</span>',
            # ERROR here means our own bug (malformed fields or a crashed host
            # tool), so it is excluded from coverage and retried.
            "ERROR": '<span class="badge" style="background:var(--status-warning);color:#0b0b0b">&#9679; 우리버그</span>',
            "UNVERIFIED": '<span class="badge">미검증</span>',
        }.get(tc["status"], c.esc(tc["status"]))
        flags = []
        if tc.get("destructive"):
            flags.append('<span class="badge" style="background:var(--status-serious);color:#fff">&#9679; 파괴적</span>')
        if any(s.get("firmware_state") for s in tc.get("steps") or []):
            flags.append('<span class="badge" style="background:var(--status-critical);color:#fff">&#9679; 펌웨어</span>')
        # Reads the field coverage actually gates on. The old `generated_by_dummy_llm`
        # key is never written, so this badge never rendered.
        if tc.get("uses_placeholder_args"):
            flags.append('<span class="badge" style="background:var(--text-muted);color:#fff">&#9679; placeholder 인자</span>')
        rows.append([
            c.esc(tc["tc_id"]), c.esc(tc["name"]), status_badge, " ".join(flags),
            c.esc(", ".join(tc["source_section_ids"])), c.esc(", ".join(tc["source_opcodes"])),
            c.esc(tc.get("updated_at", "")),
            _tc_evidence(tc),
        ])
    return c.table(["TC ID", "Name", "저장된 결과", "Flags", "Section(s)", "Opcode(s)", "Updated", "검증 근거"], rows)


def _verdict_rows(source: str, verdicts: list[dict], fc_by_id: dict) -> list[list[str]]:
    rows = []
    for v in verdicts:
        fc = fc_by_id.get(v["failure_context_id"], {})
        signals = fc.get("signals") or {}

        post_errors = signals.get("post_failure_errors") or []
        post_block = ""
        if post_errors:
            lines = [
                f"- {e['timestamp']} [{e['error_code']}] {e['error_name']}"
                f" | opcode {(e.get('cmd') or {}).get('OPCODE', 'n/a')}"
                f" | {', '.join(e['context']) or 'teardown'}"
                for e in post_errors
            ]
            post_block = ("\n\nTC FAILED 이후 teardown 중 발생한 에러 "
                           f"({len(post_errors)}건 — 장비가 응답을 멈췄는지 판단하는 근거):\n" + "\n".join(lines))

        detail = (
            f"rationale: {v['rationale']}\n\nguidance:\n" + "\n".join(f"- {g}" for g in v.get("guidance", []))
            + post_block
            + f"\n\nsignals:\n{signals}"
            + f"\n\nprimary_log_excerpt:\n{(fc.get('primary_log_excerpt') or '')[:6000]}"
            # `or ''`, not a dict default: the key exists and is explicitly None
            # when no dmesg was correlated, which would crash the slice.
            + f"\n\ndmesg_excerpt:\n{(fc.get('dmesg_excerpt') or '')[:4000]}"
        )
        summary_bits = [c.esc(fc.get("run_id", v["failure_context_id"]))]
        if post_errors:
            summary_bits.append(f'<span class="tag">teardown 에러 {len(post_errors)}건</span>')
        if signals.get("dmesg_captured_scoped") is False:
            summary_bits.append('<span class="tag tag-warn">dmesg 범위 불확실</span>')
        details_html = c.details_block(" ".join(summary_bits), c.esc(detail))
        rows.append([
            details_html,
            c.esc(fc.get("timestamp", "")),
            c.badge(v["classification"]),
            c.esc(v["confidence"]),
        ])
    return rows


def _judgment_section(source: str, verdicts: list[dict], fc_by_id: dict) -> str:
    if not verdicts:
        return f'<div class="empty-state">{SOURCE_LABELS[source]}: 판정된 항목이 없습니다.</div>'
    rows = _verdict_rows(source, verdicts, fc_by_id)
    return c.table(["Run / Failure", "Timestamp", "Classification", "Confidence"], rows)


def render_report(model: dict) -> str:
    counts = model["counts"]
    body = [
        c.STYLE,
        "<h1>SSD 평가 모니터링 리포트</h1>",
        f'<div class="subtitle">generated_at: {c.esc(model["generated_at"])} | '
        f'QST: {counts["qst"]} | PULSEFZ: {counts["pulsefz"]} | TC 실행: {counts["tc_exec"]}</div>',

        "<h2>Spec 커버리지</h2>",
        f'<div class="section-gap">{_coverage_section(model["coverage"])}</div>',

        "<h2>TC 자동생성 현황</h2>",
        f'<div class="section-gap">{_tc_table(model["tc_records"])}</div>',
    ]
    for source in ("qst", "pulsefz", "tc_exec"):
        body.append(f"<h2>1차 판단 — {SOURCE_LABELS[source]}</h2>")
        body.append(
            f'<div class="section-gap">'
            f'{_judgment_section(source, model["verdicts_by_source"][source], model["failure_contexts_by_id"])}'
            f"</div>"
        )
    return (
        "<!DOCTYPE html><html lang='ko'><head><meta charset='utf-8'>"
        "<title>SSD 평가 모니터링 리포트</title></head><body>" + "".join(body) + "</body></html>"
    )


def write_report(model: dict, archive: bool = True) -> Path:
    html_text = render_report(model)
    config.REPORT_LATEST_PATH.write_text(html_text, encoding="utf-8")
    if archive:
        ts = model["generated_at"].replace(":", "").replace("-", "").split(".")[0]
        archive_dir = config.REPORT_OUTPUT_DIR / "archive"
        archive_dir.mkdir(parents=True, exist_ok=True)
        (archive_dir / f"report_{ts}.html").write_text(html_text, encoding="utf-8")
    return config.REPORT_LATEST_PATH
