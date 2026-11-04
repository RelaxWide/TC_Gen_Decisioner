import tempfile
import unittest
from pathlib import Path

from log_judge.parsers.qst_parser import parse_qst_log

SAMPLE_LOG = """\
[2026-01-01 00:00:00.000][TEST] <MAIN  > [ <0> TC_Sample START [Current Temp : 5 'C] ]
[2026-01-01 00:00:01.000][STEP] <MAIN  > >>> Start dump: dmesg -T > /some/path/run1-dump_dmesg.txt
[2026-01-01 00:00:02.000][STEP] <MAIN  > >>> Start dump: dmesg -T > /some/path/run2-dump_dmesg.txt
[2026-01-01 00:00:03.000][ERR ] <MAIN  >     [-62]SYSTEM ERROR :  [ERR]CMD Timeout\t(checkError - Engine/API/NVME/NVME_primitive.cpp:1417)
[2026-01-01 00:00:03.010][ERR ] <MAIN  >     CMD : { OPCODE:0x09, NSID:0x00000001, CDW0:0x00000009, CDW10:0x000000B1, CDW11:0x00000004, CDW12:0x00000000, CDW13:0x00000000, CDW14:0x00000000, CDW15:0x00000000, DATALEN:2848, METALEN:0, TIMEOUT:8000ms } (nRet : -1)\t(sendCmd - Engine/API/NVME/NVME_primitive.cpp:599)
[2026-01-01 00:00:03.020][ERR ] <MAIN  >     TC_Sample Failed\t(TC_Sample - TC/NVME/5_TARGET/NVMe_Sample_TC.cpp:10)
[2026-01-01 00:00:03.030][TEST] <MAIN  > [ <0> TC_Sample END [TC RunTime : 3 sec] ]
[2026-01-01 00:00:03.040][TEST] <MAIN  > [ <0> TC_Sample FAILED ]
"""


class TestQstParser(unittest.TestCase):
    def test_multi_dump_lines_picks_the_one_that_exists_on_disk(self):
        with tempfile.TemporaryDirectory() as tmp:
            qst_dir = Path(tmp)
            log_path = qst_dir / "sample_FAIL.txt"
            log_path.write_text(SAMPLE_LOG, encoding="utf-8")
            # Only the SECOND dump line's target file actually exists on disk.
            (qst_dir / "run2-dump_dmesg.txt").write_text("", encoding="utf-8")

            records = parse_qst_log(log_path)
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["dmesg_file"], "run2-dump_dmesg.txt")

    def test_signals_extracted(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "sample_FAIL.txt"
            log_path.write_text(SAMPLE_LOG, encoding="utf-8")
            records = parse_qst_log(log_path)
            signals = records[0]["signals"]
            self.assertEqual(signals["error_code"], -62)
            self.assertEqual(signals["cmd"]["OPCODE"], "0x09")
            self.assertEqual(signals["tc_source_location"], "TC/NVME/5_TARGET/NVMe_Sample_TC.cpp:10")


REUSED_IDX_LOG = """\
[2026-01-01 00:00:00.000][TEST] <MAIN  > [ <0> TC_First START [Current Temp : 5 'C] ]
[2026-01-01 00:00:01.000][ERR ] <MAIN  >     [-62]SYSTEM ERROR :  [ERR]CMD Timeout\t(checkError - Engine/API/NVME/NVME_primitive.cpp:1417)
[2026-01-01 00:00:01.010][ERR ] <MAIN  >     TC_First Failed\t(TC_First - TC/NVME/5_TARGET/NVMe_First_TC.cpp:1)
[2026-01-01 00:00:01.020][TEST] <MAIN  > [ <0> TC_First END [TC RunTime : 1 sec] ]
[2026-01-01 00:00:01.030][TEST] <MAIN  > [ <0> TC_First FAILED ]
[2026-01-01 00:00:02.000][TEST] <MAIN  > [ <0> TC_Second START [Current Temp : 5 'C] ]
[2026-01-01 00:00:03.000][ERR ] <MAIN  >     [-62]SYSTEM ERROR :  [ERR]CMD Timeout\t(checkError - Engine/API/NVME/NVME_primitive.cpp:1417)
[2026-01-01 00:00:03.010][ERR ] <MAIN  >     TC_Second Failed\t(TC_Second - TC/NVME/5_TARGET/NVMe_Second_TC.cpp:2)
[2026-01-01 00:00:03.020][TEST] <MAIN  > [ <0> TC_Second END [TC RunTime : 1 sec] ]
[2026-01-01 00:00:03.030][TEST] <MAIN  > [ <0> TC_Second FAILED ]
"""


TEARDOWN_ERROR_LOG = """\
[2026-01-01 00:00:00.000][TEST] <MAIN  > [ <0> TC_Sample START [Current Temp : 5 'C] ]
[2026-01-01 00:00:01.000][ERR ] <MAIN  >     CompareBuffer failed.\t(read - Engine/API/NVME/NVME_composition.cpp:7859)
[2026-01-01 00:00:01.010][TEST] <MAIN  > [ <0> TC_Sample END [TC RunTime : 1 sec] ]
[2026-01-01 00:00:01.020][TEST] <MAIN  > [ <0> TC_Sample FAILED ]
[2026-01-01 00:00:05.000][ERR ] <MAIN  >     [-62]SYSTEM ERROR :  CMD Timeout\t(checkError - Engine/API/NVME/NVME_primitive.cpp:1417)
[2026-01-01 00:00:05.010][ERR ] <MAIN  >     CMD : { OPCODE:0xC1, NSID:0x00000000, CDW0:0x000000C1, CDW10:0x00000004, CDW11:0x00000000, CDW12:0x00000001, CDW13:0x00000000, CDW14:0x00000000, CDW15:0x00000000, DATALEN:16, METALEN:0, TIMEOUT:8000ms } (nRet : -1)\t(sendCmd - Engine/API/NVME/NVME_primitive.cpp:599)
[2026-01-01 00:00:05.020][ERR ] <MAIN  >     refreshInjectionInfo Failed\t(refreshInjectionInfo - Engine/API/Module/QA_NVME_device.cpp:3033)
"""


class TestQstParserTeardownErrors(unittest.TestCase):
    def test_errors_after_the_failed_bracket_are_captured(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "sample_FAIL.txt"
            log_path.write_text(TEARDOWN_ERROR_LOG, encoding="utf-8")
            records = parse_qst_log(log_path)

            post = records[0]["signals"]["post_failure_errors"]
            self.assertEqual(len(post), 1)
            self.assertEqual(post[0]["error_code"], -62)
            self.assertEqual(post[0]["cmd"]["OPCODE"], "0xC1")
            self.assertIn("refreshInjectionInfo", post[0]["context"])
            # the in-window signals must stay scoped to the TC itself
            self.assertNotIn("error_code", records[0]["signals"])


MISCOMPARE_RUN_LOG = """\
[2026-01-01 00:00:00.000][TEST] <MAIN  > [ <0> TC_Sample START [Current Temp : 5 'C] ]
""" + "".join(
    f"[2026-01-01 00:00:0{i}.500][MSG ] <MAIN  > [NS 1] DATA "
    f"{{LBA:0x{i:X}, ACTUAL: 0x3F74766900000{i:03X}, EXPECT: 0x44444444}}, MAP {{IDX: 0x1, PID: 20}}\n"
    for i in range(8)
) + """\
[2026-01-01 00:00:09.000][TEST] <MAIN  > [ <0> TC_Sample END [TC RunTime : 9 sec] ]
[2026-01-01 00:00:09.010][TEST] <MAIN  > [ <0> TC_Sample FAILED ]
"""


class TestQstParserMiscompareRun(unittest.TestCase):
    def test_contiguous_miscompare_run_is_summarized_not_collapsed(self):
        # Keeping only the last miscompare hid the real shape of the failure:
        # a contiguous LBA run all expecting one pattern is the strongest
        # firmware-vs-environment discriminator available here.
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "sample_FAIL.txt"
            log_path.write_text(MISCOMPARE_RUN_LOG, encoding="utf-8")
            signals = parse_qst_log(log_path)[0]["signals"]

            summary = signals["data_miscompare_summary"]
            self.assertEqual(summary["count"], 8)
            self.assertEqual((summary["lba_first"], summary["lba_last"]), ("0x0", "0x7"))
            self.assertTrue(summary["lba_contiguous"])
            self.assertEqual(summary["expect_values"], ["0x44444444"])
            self.assertEqual(len(signals["data_miscompares"]), 8)


class TestQstParserReusedIndex(unittest.TestCase):
    def test_reused_bracket_index_does_not_steal_the_earlier_tcs_window(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "sample_FAIL.txt"
            log_path.write_text(REUSED_IDX_LOG, encoding="utf-8")
            records = parse_qst_log(log_path)

            self.assertEqual(len(records), 2)
            first = next(r for r in records if r["tc_name"] == "TC_First")
            second = next(r for r in records if r["tc_name"] == "TC_Second")
            self.assertIn("TC_First Failed", first["primary_log_excerpt"])
            self.assertNotIn("TC_Second", first["primary_log_excerpt"])
            self.assertIn("TC_Second Failed", second["primary_log_excerpt"])
            self.assertEqual(first["signals"]["tc_source_location"], "TC/NVME/5_TARGET/NVMe_First_TC.cpp:1")
            self.assertEqual(second["signals"]["tc_source_location"], "TC/NVME/5_TARGET/NVMe_Second_TC.cpp:2")


if __name__ == "__main__":
    unittest.main()
