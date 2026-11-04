from datetime import datetime, timedelta
from pathlib import Path

import config
from log_judge.ingest.ingest_state import is_processed, load_manifest, mark_processed, save_manifest
from log_judge.models import make_failure_context
from log_judge.parsers import dmesg_parser
from log_judge.parsers.qst_parser import parse_qst_log
from shared.file_store import save_json_atomic
from shared.ids import stable_id


def ingest_qst(qst_dir=None, force=False) -> list[dict]:
    qst_dir = Path(qst_dir or config.QST_DIR)
    manifest = load_manifest(config.INGEST_STATE_QST_PATH)
    contexts = []

    for log_path in sorted(qst_dir.glob("*_FAIL.txt")):
        if not force and is_processed(manifest, log_path):
            continue

        for rec in parse_qst_log(log_path):
            run_id = log_path.stem
            # include the FAILED line number: the same tc_name+idx can fail more
            # than once in one run (e.g. a retried TC), and would otherwise
            # silently collide onto one fc_id and overwrite its JSON on disk.
            fc_id = stable_id("fc-qst", run_id, rec["tc_name"], rec["tc_index"],
                               str(rec["extraction_meta"]["log_line_range"][1]))

            dmesg_excerpt = {"lines": [], "signals": {}}
            dmesg_fallback = None
            if rec["dmesg_file"] and rec["timestamp"]:
                dmesg_path = qst_dir / rec["dmesg_file"]
                # Span the whole failure episode — the TC's own failure through the
                # teardown errors after it. Centering on the FAILED bracket alone
                # dropped exactly the kernel-side confirmation (nvme req cancelled
                # -ETIME) that the teardown errors are evidence of.
                start = datetime.strptime(rec["timestamp"], "%Y-%m-%d %H:%M:%S.%f")
                end = start
                post_ts = [e["timestamp"] for e in rec["signals"].get("post_failure_errors", [])
                           if e.get("timestamp")]
                if post_ts:
                    end = datetime.strptime(max(post_ts), "%Y-%m-%d %H:%M:%S.%f")
                dmesg_excerpt = dmesg_parser.extract_range(dmesg_path, start, end)

                if not dmesg_excerpt["lines"]:
                    # The dump can predate the failure by over an hour (it may have
                    # been triggered by an earlier interior failure), leaving the
                    # range empty while the file is full of relevant signals. Fall
                    # back to the NVMe-relevant tail rather than reporting nothing.
                    tail = dmesg_parser.extract_tail(dmesg_path)
                    if tail["lines"]:
                        dmesg_excerpt = tail
                        dmesg_fallback = "range_empty_used_nvme_tail"

            ctx = make_failure_context(
                failure_context_id=fc_id,
                source_type="QST",
                run_id=run_id,
                timestamp=rec["timestamp"],
                primary_log_excerpt=rec["primary_log_excerpt"],
                signals={**rec["signals"], "tc_name": rec["tc_name"], "runtime_sec": rec["runtime_sec"],
                         "dmesg_signals": dmesg_excerpt["signals"],
                         "dmesg_extraction": dmesg_fallback or "failure_episode_range"},
                dmesg_file=rec["dmesg_file"],
                dmesg_excerpt="\n".join(dmesg_excerpt["lines"]),
                extraction_meta=rec["extraction_meta"],
            )
            out_path = config.FAILURE_CONTEXTS_DIR / "qst" / f"{fc_id}.json"
            save_json_atomic(out_path, ctx)
            contexts.append(ctx)

        mark_processed(manifest, log_path)
        # Saved per file, not once at the end: an exception on a later
        # file used to discard the marks for every file already done,
        # so the next run re-parsed them all.
        save_manifest(config.INGEST_STATE_QST_PATH, manifest)

    save_manifest(config.INGEST_STATE_QST_PATH, manifest)
    return contexts


if __name__ == "__main__":
    results = ingest_qst()
    print(f"ingested {len(results)} QST failure context(s)")
