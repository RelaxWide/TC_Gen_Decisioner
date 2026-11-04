from datetime import datetime, timedelta
from pathlib import Path

import config
from log_judge.ingest.ingest_state import is_processed, load_manifest, mark_processed, save_manifest
from log_judge.models import make_failure_context
from log_judge.parsers import dmesg_parser
from log_judge.parsers.pulsefz_parser import parse_pulsefz_log
from shared.file_store import save_json_atomic
from shared.ids import stable_id


def ingest_pulsefz(pulsefz_dir=None, force=False) -> list[dict]:
    pulsefz_dir = Path(pulsefz_dir or config.PULSEFZ_DIR)
    manifest = load_manifest(config.INGEST_STATE_PULSEFZ_PATH)
    contexts = []

    for log_path in sorted(pulsefz_dir.glob("fuzzer_*.log")):
        if not force and is_processed(manifest, log_path):
            continue

        parsed = parse_pulsefz_log(log_path)
        terminal = parsed["terminal_event"]
        if terminal is None:
            # Genuinely no crash in this run — nothing to judge.
            mark_processed(manifest, log_path)
            continue

        run_id = log_path.stem
        crash_ts = parsed["terminal_crash_ts"]
        fc_id = stable_id("fc-pulsefz", run_id, crash_ts or terminal["timestamp"])

        dmesg_file = f"dmesg_{crash_ts}.txt" if crash_ts else None
        dmesg_path = pulsefz_dir / dmesg_file if dmesg_file else None
        dmesg_window = {"lines": [], "signals": {}}
        if dmesg_path and dmesg_path.exists():
            if terminal["timestamp"]:
                center = datetime.strptime(terminal["timestamp"], "%Y-%m-%d %H:%M:%S.%f")
                dmesg_window = dmesg_parser.extract_window(
                    dmesg_path, center, before=timedelta(seconds=120), after=timedelta(seconds=30),
                )
            if not dmesg_window["lines"]:
                dmesg_window = dmesg_parser.extract_tail(dmesg_path)

        excerpt_lines = [
            f"[TIMEOUT CRASH] {terminal['cmd_name']} actual_opcode={terminal['opcode']} "
            f"timeout_group={terminal['timeout_group']}",
            *terminal["verdicts"],
        ]
        if terminal.get("fail_cmd"):
            excerpt_lines.append("[FAIL CMD] (reproduction payload)")
            excerpt_lines += [f"  {k}: {v}" for k, v in terminal["fail_cmd"].items()]
        excerpt_lines += terminal["inline_dmesg"]
        if parsed["last_stats"]:
            excerpt_lines.append(f"[Stats] {parsed['last_stats']}")
        if parsed["last_statcov"]:
            excerpt_lines.append(f"[StatCov] {parsed['last_statcov']}")

        recovered_events = [
            {"timestamp": e["timestamp"], "cmd_name": e["cmd_name"], "opcode": e["opcode"],
             "timeout_group": e["timeout_group"], "crash_ts": e["crash_ts"],
             # Keep why this one was dismissed — a triager needs the rationale,
             # not just the fact that it was filtered out.
             "verdicts": e["verdicts"], "fail_cmd": e.get("fail_cmd") or {}}
            for e in parsed["events"] if e is not terminal
        ]

        ctx = make_failure_context(
            failure_context_id=fc_id,
            source_type="PULSEFZ",
            run_id=run_id,
            timestamp=terminal["timestamp"],
            primary_log_excerpt="\n".join(excerpt_lines),
            signals={
                "cmd_name": terminal["cmd_name"],
                "opcode": terminal["opcode"],
                "timeout_group": terminal["timeout_group"],
                "crash_artifact_folder": f"crash_{crash_ts}" if crash_ts else None,
                "artifact_confirmed": parsed["artifact_confirmed"],
                "fail_cmd": terminal.get("fail_cmd") or {},
                "recovered_events": recovered_events,
                "last_stats": parsed["last_stats"],
                "last_statcov": parsed["last_statcov"],
                "dmesg_signals": dmesg_window["signals"],
            },
            dmesg_file=dmesg_file if (dmesg_path and dmesg_path.exists()) else None,
            dmesg_excerpt="\n".join(dmesg_window["lines"]),
            extraction_meta={
                "log_file": str(log_path),
                "log_line_no": terminal["line_no"],
                "extraction_method": "streaming_tag_scan",
            },
        )
        out_path = config.FAILURE_CONTEXTS_DIR / "pulsefz" / f"{fc_id}.json"
        save_json_atomic(out_path, ctx)
        contexts.append(ctx)

        mark_processed(manifest, log_path)
        # Saved per file, not once at the end: an exception on a later
        # file used to discard the marks for every file already done,
        # so the next run re-parsed them all.
        save_manifest(config.INGEST_STATE_PULSEFZ_PATH, manifest)

    save_manifest(config.INGEST_STATE_PULSEFZ_PATH, manifest)
    return contexts


if __name__ == "__main__":
    results = ingest_pulsefz()
    print(f"ingested {len(results)} PULSEFZ failure context(s)")
