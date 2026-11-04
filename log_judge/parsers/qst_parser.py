"""Parses the QST test-platform log format.

[YYYY-MM-DD HH:MM:SS.mmm][LEVEL] <MODULE> message

A run is split into TC windows by `[ <N> TC_<name> START ... ]` / `FAILED ]`
brackets. Only TCs that reach a `FAILED` bracket become FailureContexts — PASS
runs are not represented in the samples available, so that path is untested
(see plan's open assumptions).

Two failure "families" are known from real samples and parsed structurally;
anything else still gets captured via `fail_markers` (generic fallback) so no
failure type is silently dropped:
  - CMD timeout: `[-NN]SYSTEM ERROR : ... CMD Timeout` + a `CMD : { ... }` block.
  - Data miscompare: `CompareBuffer failed` + `DATA {LBA:..., ACTUAL:..., EXPECT:...}`.
"""
import re
from pathlib import Path

TIMESTAMP_RE = re.compile(
    r"^\[(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)\]\[(?P<level>\w*)\s*\]\s*<(?P<module>[^>]*)>\s?(?P<msg>.*)$"
)
TC_START_RE = re.compile(r"\[\s*<(?P<idx>\d+)>\s*(?P<name>\S+)\s+START\b")
TC_END_RE = re.compile(r"\[\s*<(?P<idx>\d+)>\s*(?P<name>\S+)\s+END\s+\[TC RunTime\s*:\s*(?P<runtime>\d+)\s*sec\]\s*\]")
TC_FAILED_RE = re.compile(r"\[\s*<(?P<idx>\d+)>\s*(?P<name>\S+)\s+FAILED\s*\]")
SYSTEM_ERROR_RE = re.compile(
    r"\[(?P<code>-?\d+)\]SYSTEM ERROR\s*:\s*(?:\[ERR\])?\s*(?P<name>[^\t]+?)\t\((?P<func>[^-]+)-\s*(?P<loc>[^)]+)\)"
)
CMD_BLOCK_RE = re.compile(
    r"CMD\s*:\s*\{(?P<fields>[^}]*)\}\s*\(nRet\s*:\s*(?P<nret>-?\d+)\)\t\((?P<func>[^-]+)-\s*(?P<loc>[^)]+)\)"
)
DATA_MISCOMPARE_RE = re.compile(
    r"DATA \{LBA:(?P<lba>0x[0-9A-Fa-f]+), ACTUAL:\s*(?P<actual>0x[0-9A-Fa-f]+), EXPECT:\s*(?P<expect>0x[0-9A-Fa-f]+)\}"
)
# Case-insensitive on the verb: real logs carry both "read Failed" and
# "CompareBuffer failed." — anchoring on capital F silently dropped the
# lowercase form, which is the one the data-miscompare path emits.
FAIL_LINE_RE = re.compile(r"(?P<subject>[\w]+) (?:failed|fail\.\.\.)", re.I)
SRC_LOC_RE = re.compile(r"\(([^()]*\.(?:cpp|h):\d+)\)")
PRINTBUFFER_RE = re.compile(r"\(PrintBuffer - ")
DUMP_LINE_RE = re.compile(r">>> Start dump: dmesg -T > .*[/\\](?P<filename>\S+_dmesg\.txt)")


def _parse_cmd_fields(fields_str: str) -> dict:
    out = {}
    for key, val in re.findall(r"(\w+):([^\s,}]+)", fields_str):
        out[key] = val
    return out


def _collapse_hex_dumps(window_lines: list[str]) -> list[str]:
    out, run = [], 0
    for line in window_lines:
        if PRINTBUFFER_RE.search(line):
            run += 1
            continue
        if run:
            out.append(f"... ({run} PrintBuffer hex-dump lines suppressed) ...")
            run = 0
        out.append(line)
    if run:
        out.append(f"... ({run} PrintBuffer hex-dump lines suppressed) ...")
    return out


def _build_post_failure_errors(lines: list[str], failed_line: int, next_start: int) -> list[dict]:
    """Errors logged after a TC's FAILED bracket, during teardown/cleanup.

    Real samples (0133/0135) keep timing out on VUC commands after the TC already
    failed — "the device stopped answering vendor commands after the miscompare"
    is exactly the firmware-vs-environment discriminator a triager wants, and it
    sits outside the TC's own [START, FAILED] window. Captured separately rather
    than by widening that window, so the TC narrative stays attributable.
    """
    errors = []
    for i in range(failed_line + 1, min(next_start, len(lines))):
        m = SYSTEM_ERROR_RE.search(lines[i])
        if not m:
            continue
        entry = {
            "line_no": i,
            "error_code": int(m.group("code")),
            "error_name": m.group("name").strip(),
            "error_source_location": m.group("loc").strip(),
            "cmd": None,
            "context": [],
        }
        ts = TIMESTAMP_RE.match(lines[i])
        entry["timestamp"] = ts.group("ts") if ts else None
        for j in range(i + 1, min(i + 8, next_start, len(lines))):
            cm = CMD_BLOCK_RE.search(lines[j])
            if cm:
                entry["cmd"] = _parse_cmd_fields(cm.group("fields"))
            fm = FAIL_LINE_RE.search(lines[j])
            if fm:
                entry["context"].append(fm.group("subject"))
        errors.append(entry)
    return errors


_MAX_RECORDED_MISCOMPARES = 32


def _build_signals(window_lines: list[str]) -> dict:
    signals = {}
    miscompares, system_errors = [], []
    for line in window_lines:
        m = SYSTEM_ERROR_RE.search(line)
        if m:
            signals["error_code"] = int(m.group("code"))
            signals["error_name"] = m.group("name").strip()
            signals["error_source_location"] = m.group("loc").strip()
            system_errors.append({"error_code": int(m.group("code")),
                                   "error_name": m.group("name").strip(),
                                   "error_source_location": m.group("loc").strip()})
        m = CMD_BLOCK_RE.search(line)
        if m:
            signals["cmd"] = _parse_cmd_fields(m.group("fields"))
        m = DATA_MISCOMPARE_RE.search(line)
        if m:
            signals["data_miscompare"] = {
                "lba": m.group("lba"), "actual": m.group("actual"), "expect": m.group("expect"),
            }
            miscompares.append(signals["data_miscompare"])

    # Keeping only the last of each discarded the shape of the failure. One real
    # sample has 8 miscompares on contiguous LBAs 0x0-0x7 all expecting the same
    # pattern — "a contiguous run returned stale data" is a far stronger
    # firmware-vs-environment signal than any single mismatched LBA.
    if miscompares:
        lbas = sorted({int(mc["lba"], 16) for mc in miscompares})
        signals["data_miscompare_summary"] = {
            "count": len(miscompares),
            "lba_first": hex(lbas[0]),
            "lba_last": hex(lbas[-1]),
            "lba_contiguous": lbas == list(range(lbas[0], lbas[0] + len(lbas))),
            "expect_values": sorted({mc["expect"] for mc in miscompares}),
        }
        signals["data_miscompares"] = miscompares[:_MAX_RECORDED_MISCOMPARES]
    if len(system_errors) > 1:
        signals["system_errors"] = system_errors
    fail_markers = [m.group("subject") for line in window_lines for m in [FAIL_LINE_RE.search(line)] if m]
    if fail_markers:
        signals["fail_markers"] = fail_markers
    src_locs = SRC_LOC_RE.findall("\n".join(window_lines))
    if src_locs:
        last = src_locs[-1]
        signals["tc_source_location"] = last.rsplit(" - ", 1)[-1].strip()
    return signals


def _find_dmesg_file(dump_candidates: list[tuple], qst_dir: Path, start_line: int, end_line: int) -> str | None:
    existing = [
        name for (line_idx, name) in dump_candidates
        if start_line <= line_idx < end_line and (qst_dir / name).exists()
    ]
    return existing[-1] if existing else None


def parse_qst_log(path) -> list[dict]:
    path = Path(path)
    qst_dir = path.parent
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()

    # idx is reused across TCs within a file (each run restarts TC indices), so
    # starts/end_runtimes must keep every occurrence, not just the latest —
    # otherwise an earlier TC's window gets resolved using a later TC's START
    # line and silently slices to an empty (or wrong) window.
    starts: dict[str, list[tuple[int, str]]] = {}
    end_runtimes_by_idx: dict[str, list[tuple[int, int]]] = {}
    start_lines_sorted: list[int] = []
    dump_candidates: list[tuple] = []
    records = []

    for i, line in enumerate(lines):
        m = DUMP_LINE_RE.search(line)
        if m:
            dump_candidates.append((i, m.group("filename")))
        m = TC_START_RE.search(line)
        if m:
            starts.setdefault(m.group("idx"), []).append((i, m.group("name")))
            start_lines_sorted.append(i)
        m = TC_END_RE.search(line)
        if m:
            end_runtimes_by_idx.setdefault(m.group("idx"), []).append((i, int(m.group("runtime"))))

    for i, line in enumerate(lines):
        m = TC_FAILED_RE.search(line)
        if not m:
            continue
        idx, name = m.group("idx"), m.group("name")
        prior_starts = [s for s in starts.get(idx, []) if s[0] < i]
        start_line, start_name = prior_starts[-1] if prior_starts else (max(0, i - 200), name)
        prior_ends = [e for e in end_runtimes_by_idx.get(idx, []) if start_line <= e[0] < i]
        runtime_sec = prior_ends[-1][1] if prior_ends else None
        next_start = next((s for s in sorted(start_lines_sorted) if s > i), len(lines))

        ts_match = TIMESTAMP_RE.match(line)
        timestamp = ts_match.group("ts") if ts_match else None

        window = lines[start_line:i + 1]
        signals = _build_signals(window)
        post_failure_errors = _build_post_failure_errors(lines, i, next_start)
        if post_failure_errors:
            signals["post_failure_errors"] = post_failure_errors
        dmesg_file = _find_dmesg_file(dump_candidates, qst_dir, start_line, next_start)

        excerpt_lines = _collapse_hex_dumps(window)
        if len(excerpt_lines) > 400:
            excerpt_lines = excerpt_lines[:150] + [f"... ({len(excerpt_lines) - 400} lines omitted) ..."] + excerpt_lines[-250:]

        records.append({
            "tc_name": name,
            "tc_index": idx,
            "timestamp": timestamp,
            "runtime_sec": runtime_sec,
            "primary_log_excerpt": "\n".join(excerpt_lines),
            "signals": signals,
            "dmesg_file": dmesg_file,
            "extraction_meta": {
                "log_file": str(path),
                "log_line_range": [start_line, i],
                "extraction_method": "tc_bracket_window",
            },
        })
    return records
