"""Captures everything a script prints to a timestamped file under `logs/`,
in addition to the terminal. `print()` on its own is never persisted — close
the terminal, or scroll past it, and that's the only record of the run gone.
"""
import sys
from contextlib import contextmanager
from datetime import datetime, timezone

import config


class _Tee:
    """Writes to every stream given; a failure on one (e.g. the console
    raising UnicodeEncodeError under a non-UTF-8 codepage) must not stop the
    others — the file stream, opened as UTF-8, is the one that has to be
    reliable, even if the console display degrades.

    Also prefixes every line with a `[HH:MM:SS]` timestamp, on both the
    console and the file — without it, a line like "-> 실행 중..." gives no
    way to tell, while staring at it, whether the wait is normal or an actual
    multi-minute SSH hang; correlating against `ssh_commands.jsonl`'s own
    timestamps meant reopening a second file every time.
    """
    def __init__(self, *streams):
        self._streams = streams
        self._at_line_start = True

    def _stamped(self, data, at_line_start, stamp):
        """Inserts `stamp` right after every line break in `data`, plus at
        the very start if `at_line_start` is true — except where that would
        land on an empty line (the trailing split after a final "\\n", or a
        line that is itself blank), which would otherwise print as a bare,
        content-less "[HH:MM:SS]". `print()` issues a line's text and its
        trailing "\\n" as two separate write() calls, so this has to track
        line-start state across calls rather than assume one call is one
        line. Returns (stamped_data, new_at_line_start)."""
        if not data:
            return data, at_line_start
        pieces = data.split("\n")
        out = []
        for i, piece in enumerate(pieces):
            if (at_line_start if i == 0 else True) and piece:
                out.append(stamp)
            out.append(piece)
            if i < len(pieces) - 1:
                out.append("\n")
        return "".join(out), data.endswith("\n")

    def _stamp_now(self):
        return datetime.now().strftime("[%H:%M:%S] ")

    def write(self, data):
        data, self._at_line_start = self._stamped(data, self._at_line_start, self._stamp_now())
        for s in self._streams:
            try:
                s.write(data)
            except Exception:
                pass
        return len(data)

    def flush(self):
        for s in self._streams:
            try:
                s.flush()
            except Exception:
                pass

    def dual_write(self, console_data, file_data):
        """Writes `console_data` to the console and `file_data` to the file —
        one logical line, sized differently per destination (e.g. a shortened
        display line vs. the full untruncated text), instead of printing the
        line twice over two separate `write()` calls. Must go through this
        same handle, not a second one opened on the same path: a separate
        handle's own buffered write position can land in the middle of what
        this one has already written, corrupting the file instead of just
        interleaving oddly."""
        at_line_start, stamp = self._at_line_start, self._stamp_now()
        console_data, _ = self._stamped(console_data, at_line_start, stamp)
        file_data, self._at_line_start = self._stamped(file_data, at_line_start, stamp)
        streams = list(self._streams)
        if streams:
            try:
                streams[0].write(console_data)
            except Exception:
                pass
        for s in streams[1:]:
            try:
                s.write(file_data)
                s.flush()
            except Exception:
                pass


@contextmanager
def capture_to_file(prefix: str):
    """Redirects stdout/stderr to `logs/<prefix>_<timestamp>.log` for the
    duration of the `with` block, mirroring everything to the real console
    too. Yields the log file path."""
    config.LOGS_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    path = config.LOGS_DIR / f"{prefix}_{ts}.log"
    real_stdout, real_stderr = sys.stdout, sys.stderr
    with path.open("w", encoding="utf-8") as f:
        sys.stdout = _Tee(real_stdout, f)
        sys.stderr = _Tee(real_stderr, f)
        try:
            yield path
        finally:
            sys.stdout, sys.stderr = real_stdout, real_stderr
