"""Streaming parser for PULSEFZ fuzzer logs (`YYYY-MM-DD HH:MM:SS.mmm [LEVEL] [TAG] msg`).

Reads the file line-by-line (never loads it whole — samples run 2MB-100MB+).
A run can report multiple `[ERROR] [TIMEOUT CRASH]` events, but only the one
whose `crash_<timestamp>` folder reference is later confirmed by an
`[ARTIFACT] ... 수집 폴더: .../crash_<timestamp>` line is "terminal" — others
got filtered out (e.g. `[UnsupChk] SKIPPED.marker`) and never produced a
paired dmesg file. Only the terminal event should drive dmesg correlation.
"""
import re
from pathlib import Path

LINE_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+) \[(?P<level>\w+)\](?: \[(?P<tag>[^\]]+)\])? ?(?P<msg>.*)$"
)
TIMEOUT_CRASH_HEADER_RE = re.compile(
    r"^(?P<cmd_name>\S+) actual_opcode=(?P<opcode>0x[0-9A-Fa-f]+) timeout_group=(?P<timeout_group>\S+)"
)
CRASH_TS_RE = re.compile(r"crash_(\d{8}_\d{6})")
NVME_CMD_RE = re.compile(
    r"opcode=(?P<opcode>0x[0-9A-Fa-f]+) nsid=(?P<nsid>\d+) timeout=(?P<timeout>\d+)ms"
)
# An inline dmesg body line starts either with the kernel's `[Day Mon ...]`
# bracket or with an ISO journal timestamp preceding it (both forms occur).
_DMESG_BODY_RE = re.compile(r"^\s*(?:\[\w{3} \w{3}|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})")
_FAIL_CMD_FIELD_RE = re.compile(r"^[\w ()]+\s*:")


def parse_pulsefz_log(path) -> dict:
    path = Path(path)
    events: list[dict] = []
    pending = None
    collecting_dmesg = collecting_fail_cmd = False
    terminal_crash_ts = None
    last_stats, last_statcov = None, None

    # newline="\n": the logs contain bare \r (progress-bar redraws), which
    # universal-newline mode would split into extra lines, inflating every
    # reported line number by hundreds.
    with path.open(encoding="utf-8", errors="replace", newline="\n") as f:
        for line_no, raw in enumerate(f):
            line = raw.rstrip("\r\n")
            m = LINE_RE.match(line)
            if not m:
                continue
            ts, level, tag, msg = m.group("ts"), m.group("level"), m.group("tag"), m.group("msg")

            if tag == "TIMEOUT CRASH":
                if pending is not None:
                    events.append(pending)
                hm = TIMEOUT_CRASH_HEADER_RE.match(msg)
                pending = {
                    "line_no": line_no,
                    "timestamp": ts,
                    "cmd_name": hm.group("cmd_name") if hm else None,
                    "opcode": hm.group("opcode") if hm else None,
                    "timeout_group": hm.group("timeout_group") if hm else None,
                    "verdicts": [],
                    "inline_dmesg": [],
                    "fail_cmd": {},
                    "crash_ts": None,
                }
                collecting_dmesg = collecting_fail_cmd = False
                continue

            if tag == "Stats":
                last_stats = msg
            elif tag == "StatCov":
                last_statcov = msg
            elif tag == "ARTIFACT" and "수집 폴더" in msg:
                cm = CRASH_TS_RE.search(msg)
                if cm:
                    terminal_crash_ts = cm.group(1)

            if pending is not None and level == "ERROR" and tag is None:
                if "판정" in msg:
                    pending["verdicts"].append(msg.strip())
                    collecting_dmesg = collecting_fail_cmd = False
                elif "dmesg" in msg and "줄" in msg:
                    collecting_dmesg, collecting_fail_cmd = True, False
                elif "FAIL CMD" in msg:
                    # The fuzzer's reproduction payload: opcode/nsid/cdw2..cdw15/
                    # data hex/mutations. QST's equivalent `CMD : {...}` block is
                    # captured, so dropping this left PULSEFZ triage with no way
                    # to reproduce the crashing command.
                    collecting_fail_cmd, collecting_dmesg = True, False
                elif collecting_dmesg and _DMESG_BODY_RE.match(msg):
                    pending["inline_dmesg"].append(msg.strip())
                elif collecting_fail_cmd and _FAIL_CMD_FIELD_RE.match(msg.strip()):
                    key, value = msg.strip().split(":", 1)
                    pending["fail_cmd"][key.strip()] = value.strip()
                elif msg.strip().startswith("="):
                    pass  # separator rule inside a block — not a block terminator
                else:
                    collecting_dmesg = collecting_fail_cmd = False

            if pending is not None and pending["crash_ts"] is None:
                cm = CRASH_TS_RE.search(line)
                if cm:
                    pending["crash_ts"] = cm.group(1)

    if pending is not None:
        events.append(pending)

    # Prefer the artifact-confirmed crash; when two events share a crash_ts the
    # later one is the terminal attempt, so match from the end.
    terminal_event = None
    # Captured before the fallback below can overwrite terminal_crash_ts —
    # otherwise `artifact_confirmed` is computed from the value the fallback
    # just invented and is always True, which is exactly the signal it exists
    # to deny: "this run had no [ARTIFACT] line".
    artifact_confirmed = False
    if terminal_crash_ts:
        terminal_event = next((e for e in reversed(events) if e["crash_ts"] == terminal_crash_ts), None)
        artifact_confirmed = terminal_event is not None
    if terminal_event is None and events:
        # No `[ARTIFACT] 수집 폴더` line — the fuzzer was killed or ran out of
        # disk before collecting. Falling through to None used to discard every
        # crash in the run silently; the last crash is still the best evidence.
        terminal_event = events[-1]
        terminal_crash_ts = terminal_event["crash_ts"]

    return {
        "events": events,
        "terminal_crash_ts": terminal_crash_ts,
        "terminal_event": terminal_event,
        "artifact_confirmed": artifact_confirmed,
        "last_stats": last_stats,
        "last_statcov": last_statcov,
    }
