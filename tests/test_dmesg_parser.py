import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from log_judge.parsers import dmesg_parser

# Two timestamp forms both occur in real captures: plain `dmesg -T` and one with
# an ISO journal timestamp prefixed before the kernel bracket.
DMESG = """\
[Thu Jan 1 00:00:10 2026] nvme nvme0: nvme_reset_ctrl start
2026-01-01T00:05:00,123456+09:00 [Thu Jan 1 00:05:00 2026] nvme nvme0: I/O 1 QID 2 timeout, NSID 1 OPCODE 0x9
[Thu Jan 1 00:05:01 2026] nvme nvme0: nvme req cancelled -ETIME(-62)
[Thu Jan 1 02:00:00 2026] AER: Multiple Corrected error received
"""


class TestDmesgParser(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "d.txt"
        self.path.write_text(DMESG, encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def test_range_spans_the_whole_failure_episode(self):
        # Centering on one instant missed the teardown errors that follow the
        # initial failure; the range form must pick up both ends.
        out = dmesg_parser.extract_range(
            self.path, datetime(2026, 1, 1, 0, 0, 10), datetime(2026, 1, 1, 0, 5, 1))
        self.assertEqual(out["signals"].get("timeout"), 2)
        self.assertEqual(out["signals"].get("reset"), 1)

    def test_journal_prefixed_line_is_parsed(self):
        out = dmesg_parser.extract_range(
            self.path, datetime(2026, 1, 1, 0, 5, 0), datetime(2026, 1, 1, 0, 5, 0), )
        self.assertTrue(any("QID 2 timeout" in l for l in out["lines"]))

    def test_tail_fallback_finds_signals_outside_any_window(self):
        # Real case: a dump triggered ~83 min before the failure it is paired
        # with, so a time window around the failure returns nothing at all.
        empty = dmesg_parser.extract_range(
            self.path, datetime(2026, 1, 2, 12, 0, 0), datetime(2026, 1, 2, 12, 0, 0))
        self.assertEqual(empty["lines"], [])
        tail = dmesg_parser.extract_tail(self.path)
        self.assertTrue(tail["lines"])
        self.assertIn("timeout", tail["signals"])

    def test_missing_file_is_not_an_error(self):
        out = dmesg_parser.extract_range(
            Path(self.tmp.name) / "nope.txt", datetime(2026, 1, 1), datetime(2026, 1, 1))
        self.assertEqual(out["lines"], [])
        self.assertIsNone(out["dmesg_file"])


if __name__ == "__main__":
    unittest.main()
