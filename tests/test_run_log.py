"""Unit tests for shared/run_log.py — the unified per-run log file.

Before this, everything run_tc_pipeline.py printed only went to the terminal;
closing it (or just scrolling past) lost the only record of what happened.
"""
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import config
from shared.run_log import capture_to_file

_STAMP_RE = re.compile(r"^\[\d{2}:\d{2}:\d{2}\] ")


def _unstamped_lines(text):
    return [_STAMP_RE.sub("", line) for line in text.splitlines()]


class TestCaptureToFile(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self._real_logs_dir = config.LOGS_DIR
        config.LOGS_DIR = Path(self.tmp.name)

    def tearDown(self):
        config.LOGS_DIR = self._real_logs_dir
        self.tmp.cleanup()

    def test_printed_text_is_written_to_file(self):
        with capture_to_file("unit") as path:
            print("한글 테스트 라인")
            print("plain ascii line")
        self.assertEqual(
            _unstamped_lines(path.read_text(encoding="utf-8")),
            ["한글 테스트 라인", "plain ascii line"],
        )

    def test_each_line_is_prefixed_with_a_timestamp(self):
        # Without this, a line like "-> 실행 중..." gives no way to tell,
        # while staring at it, whether the wait is normal or an actual
        # multi-minute SSH hang — correlating against ssh_commands.jsonl's
        # own timestamps meant reopening a second file every time.
        with capture_to_file("unit") as path:
            print("first line")
            print("second line")
        lines = path.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 2)
        for line in lines:
            self.assertRegex(line, r"^\[\d{2}:\d{2}:\d{2}\] ")
        self.assertIn("first line", lines[0])
        self.assertIn("second line", lines[1])

    def test_a_blank_separator_line_is_not_stamped(self):
        # print(f"\n[1/10] ...") issues the leading blank line and the
        # content as part of the same write() call — the blank line itself
        # must stay genuinely blank, not a content-less "[12:00:00] ".
        with capture_to_file("unit") as path:
            print("\n[1/10] header")
        lines = path.read_text(encoding="utf-8").splitlines()
        self.assertEqual(lines[0], "")
        self.assertRegex(lines[1], r"^\[\d{2}:\d{2}:\d{2}\] \[1/10\] header$")

    def test_printed_text_still_reaches_the_real_console(self):
        real_stdout = mock.Mock()
        sys.stdout = real_stdout
        try:
            with capture_to_file("unit"):
                print("hello")
        finally:
            sys.stdout = sys.__stdout__
        written = "".join(c.args[0] for c in real_stdout.write.call_args_list)
        self.assertIn("hello", written)

    def test_stdout_and_stderr_are_restored_after_the_block(self):
        real_stdout, real_stderr = sys.stdout, sys.stderr
        with capture_to_file("unit"):
            self.assertIsNot(sys.stdout, real_stdout)
        self.assertIs(sys.stdout, real_stdout)
        self.assertIs(sys.stderr, real_stderr)

    def test_a_write_failure_on_one_stream_does_not_lose_the_others(self):
        broken = mock.Mock()
        broken.write.side_effect = UnicodeEncodeError("cp949", "x", 0, 1, "bad")
        real_stdout = sys.stdout
        sys.stdout = broken
        try:
            with capture_to_file("unit") as path:
                print("still gets to the file")
        finally:
            sys.stdout = real_stdout
        self.assertIn("still gets to the file", path.read_text(encoding="utf-8"))

    def test_dual_write_sends_different_content_to_each_destination(self):
        real_stdout = mock.Mock()
        sys.stdout = real_stdout
        try:
            with capture_to_file("unit") as path:
                sys.stdout.dual_write("short for console\n", "the full untruncated text\n")
        finally:
            sys.stdout = sys.__stdout__
        console_written = "".join(c.args[0] for c in real_stdout.write.call_args_list)
        self.assertIn("short for console", console_written)
        self.assertNotIn("full untruncated", console_written)
        file_text = path.read_text(encoding="utf-8")
        self.assertIn("the full untruncated text", file_text)
        self.assertNotIn("short for console", file_text)

    def test_dual_write_interleaves_correctly_with_printed_lines(self):
        # A second handle independently opened on the same path corrupted the
        # file (one handle's buffered write position landed in the middle of
        # what the other had already written) — dual_write must go through
        # the same handle capture_to_file already holds open, and the file's
        # version of the dual-written line must land in the right place
        # relative to the plain prints around it (replacing, not duplicating,
        # what a short-then-full two-line approach would have produced).
        with capture_to_file("unit") as path:
            print("line one")
            sys.stdout.dual_write("line two (short)\n", "line two (full)\n")
            print("line three")
        self.assertEqual(
            _unstamped_lines(path.read_text(encoding="utf-8")),
            ["line one", "line two (full)", "line three"],
        )

    def test_filename_is_prefixed_and_timestamped(self):
        with capture_to_file("tc_pipeline") as path:
            pass
        self.assertTrue(path.name.startswith("tc_pipeline_"))
        self.assertTrue(path.name.endswith(".log"))


if __name__ == "__main__":
    unittest.main()
