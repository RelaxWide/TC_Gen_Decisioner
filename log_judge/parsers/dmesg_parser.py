"""Parses `dmesg -T` output: `[Weekday Mon DD HH:MM:SS YYYY] message`.

Timestamps are parsed by hand (not strptime) because the day field is
single/double-space-padded depending on day-of-month width, which is a known
portability trap for %d on Windows' CRT-backed strptime.
"""
import re
from datetime import datetime, timedelta
from pathlib import Path

_MONTHS = {"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
           "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12}

DMESG_LINE_RE = re.compile(r"^\[(?P<ts>\w{3} \w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2} \d{4})\]\s?(?P<msg>.*)$")


def _strip_journal_prefix(raw: str) -> str:
    """Some captures prepend a per-line ISO timestamp before the `[Day Mon ...]`
    bracket (e.g. PULSEFZ's `2026-08-25T21:01:01,928065+09:00 [Tue Aug 25 ...]`).
    Strip anything before the first `[` so DMESG_LINE_RE matches either form."""
    idx = raw.find("[")
    return raw[idx:] if idx > 0 else raw

MAX_EXCERPT_LINES = 200

NVME_SIGNAL_PATTERNS = {
    "timeout": re.compile(r"nvme_timeout|timeout, NSID|cancelled -ETIME"),
    "reset": re.compile(r"nvme_reset_ctrl|nvme_disable_ctrl|nvme_enable_ctrl|nvme_init_identify"),
    "aer": re.compile(r"\bAER:"),
    "dmar_iommu": re.compile(r"\bDMAR:|IOMMU|DMA Read NO_PASID"),
    "surprise_removal": re.compile(r"detected capacity change|Removing from iommu group"),
    "nsid_mismatch": re.compile(r"nsid \(\d+\) in cmd does not match nsid"),
}


def parse_dmesg_timestamp(ts_str: str) -> datetime:
    weekday, mon, day, hms, year = ts_str.split()
    hh, mm, ss = hms.split(":")
    return datetime(int(year), _MONTHS[mon], int(day), int(hh), int(mm), int(ss))


def _classify(msg: str, signals: dict) -> None:
    for name, pattern in NVME_SIGNAL_PATTERNS.items():
        if pattern.search(msg):
            signals.setdefault(name, 0)
            signals[name] += 1


def _has_signal(msg: str) -> bool:
    return any(p.search(msg) for p in NVME_SIGNAL_PATTERNS.values())


def _select_excerpt(candidates: list[tuple[str, str]], max_lines: int) -> list[str]:
    """Trim to `max_lines`, keeping the signal-bearing lines.

    Consumers read only the first ~2000 characters of the stored excerpt, so a
    window of thousands of routine lines buried the discriminating ones (one
    real context stored 451 KB of which the judge saw the first 2 KB). Signal
    lines are kept whole and the rest only fill whatever room is left.
    """
    if len(candidates) <= max_lines:
        return [raw for raw, _ in candidates]
    signal = [raw for raw, msg in candidates if _has_signal(msg)]
    if len(signal) >= max_lines:
        # Keep the last ones: the failure is at the end of the window.
        return signal[-max_lines:]
    room = max_lines - len(signal)
    filler = [raw for raw, msg in candidates if not _has_signal(msg)][-room:]
    kept = set(signal) | set(filler)
    return [raw for raw, _ in candidates if raw in kept]


def extract_range(dmesg_path, start_time: datetime, end_time: datetime,
                   pad_before=timedelta(seconds=60), pad_after=timedelta(seconds=30),
                   max_lines: int = MAX_EXCERPT_LINES) -> dict:
    """Return dmesg lines within [start_time-pad, end_time+pad] plus signal counts.

    A range rather than a single center point: a QST failure's evidence spans
    from the TC's own error through the teardown errors that follow it, and the
    dmesg file is a full `dmesg -T` history dump captured at an unrelated moment.

    Signals are counted over the lines actually returned, never over lines that
    were dropped — a count the evidence does not support is worse than no count.
    """
    path = Path(dmesg_path)
    if not path.exists():
        return {"lines": [], "signals": {}, "dmesg_file": None, "window": None}
    start, end = start_time - pad_before, end_time + pad_after
    candidates = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        m = DMESG_LINE_RE.match(_strip_journal_prefix(raw))
        if not m:
            continue
        try:
            ts = parse_dmesg_timestamp(m.group("ts"))
        except (ValueError, KeyError):
            continue
        if start <= ts <= end:
            candidates.append((raw, m.group("msg")))

    lines = _select_excerpt(candidates, max_lines)
    signals = classify_text("\n".join(lines))
    return {"lines": lines, "signals": signals, "dmesg_file": path.name,
            "window": [start.isoformat(), end.isoformat()],
            "lines_in_window": len(candidates), "lines_kept": len(lines)}


def extract_window(dmesg_path, center_time: datetime, before=timedelta(seconds=120),
                    after=timedelta(seconds=30)) -> dict:
    return extract_range(dmesg_path, center_time, center_time, pad_before=before, pad_after=after)


def classify_text(dmesg_text: str) -> dict:
    """For dmesg output that's already pre-scoped (e.g. captured via `dmesg -c`
    immediately before a TC batch, so it only contains that batch's messages) —
    no time-window filtering needed, just signal classification."""
    signals = {}
    for raw in dmesg_text.splitlines():
        m = DMESG_LINE_RE.match(_strip_journal_prefix(raw))
        if m:
            _classify(m.group("msg"), signals)
    return signals


def extract_tail(dmesg_path, max_lines: int = MAX_EXCERPT_LINES) -> dict:
    """Fallback when no reliable center timestamp exists: last N NVMe/AER/DMAR-relevant lines.

    Counts only what the excerpt keeps. Counting over the whole file while
    returning a truncated tail reported `reset: 779` for an excerpt containing
    155 of them — a number the evidence could not support.
    """
    path = Path(dmesg_path)
    if not path.exists():
        return {"lines": [], "signals": {}, "dmesg_file": None}
    relevant = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        m = DMESG_LINE_RE.match(_strip_journal_prefix(raw))
        if m and _has_signal(m.group("msg")):
            relevant.append(raw)
    lines = relevant[-max_lines:]
    return {"lines": lines, "signals": classify_text("\n".join(lines)),
            "dmesg_file": path.name,
            "lines_in_window": len(relevant), "lines_kept": len(lines)}
