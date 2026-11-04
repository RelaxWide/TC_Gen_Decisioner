import tempfile
import unittest
from pathlib import Path

from log_judge.parsers.pulsefz_parser import parse_pulsefz_log

SAMPLE_LOG = """\
2026-01-01 00:00:00.000 [INFO] [Seed] Identify (0x06): CDW10=0x00000001
2026-01-01 00:00:01.000 [ERROR] [TIMEOUT CRASH] SetFeatures actual_opcode=0x09 timeout_group=command (1000 samples)
2026-01-01 00:00:01.100 [ERROR]   [Core0] 판정: 정상 idle
2026-01-01 00:00:02.000 [WARNING] [UnsupChk] SKIPPED.marker 작성 -> crash_20260101_000001/SKIPPED.marker
2026-01-01 00:00:03.000 [ERROR] [TIMEOUT CRASH] Read actual_opcode=0x02 timeout_group=command (1000 samples)
2026-01-01 00:00:03.100 [ERROR]   [Core0] 판정: busy-wait - 0x1234 52%
2026-01-01 00:00:03.200 [ERROR]   dmesg NVMe 관련 (2줄):
2026-01-01 00:00:03.200 [ERROR]     [Thu Jan 1 00:00:02 2026] nvme nvme0: nvme_timeout triggered
2026-01-01 00:00:03.200 [ERROR]     [Thu Jan 1 00:00:02 2026] nvme nvme0: nvme req cancelled -ETIME(-62)
2026-01-01 00:00:04.000 [WARNING] [TIMEOUT] repro script -> crash_20260101_000400/
2026-01-01 00:00:05.000 [WARNING] [ARTIFACT] 수집 폴더: crash_20260101_000400
2026-01-01 00:00:06.000 [WARNING] [Stats] exec: 100 | corpus: 10(seq:0) | pcs: 20 | exec/s: 5.0
2026-01-01 00:00:06.000 [WARNING] [StatCov] BB: 1.0% (10/1000) | funcs: 2/100 (2.0%)
"""


class TestPulsefzParser(unittest.TestCase):
    def test_terminal_event_is_the_one_matching_artifact_not_the_skipped_one(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "fuzzer_sample.log"
            log_path.write_text(SAMPLE_LOG, encoding="utf-8")
            result = parse_pulsefz_log(log_path)

            self.assertEqual(len(result["events"]), 2)
            self.assertEqual(result["terminal_crash_ts"], "20260101_000400")
            self.assertIsNotNone(result["terminal_event"])
            self.assertEqual(result["terminal_event"]["cmd_name"], "Read")
            self.assertEqual(result["terminal_event"]["opcode"], "0x02")

    def test_inline_dmesg_captured(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "fuzzer_sample.log"
            log_path.write_text(SAMPLE_LOG, encoding="utf-8")
            result = parse_pulsefz_log(log_path)
            self.assertEqual(len(result["terminal_event"]["inline_dmesg"]), 2)


if __name__ == "__main__":
    unittest.main()
