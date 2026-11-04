import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import config
from report.html_report import render_log_report, render_tc_report
from tc_system.coverage.coverage_state import compute_coverage
from tc_system.coverage.spec_coverage_index import SpecCoverageIndexFile


def _log_model(fc):
    return {
        "generated_at": "2026-01-01T00:00:00",
        "counts": {"qst": 1, "pulsefz": 0},
        "verdicts_by_source": {
            "qst": [{
                "verdict_id": "v1", "failure_context_id": "fc1", "classification": "firmware_defect",
                "confidence": 0.9, "rationale": "r", "guidance": [], "llm_response_id": "l1",
                "judged_at": "2026-01-01T00:00:00",
            }],
            "pulsefz": [],
        },
        "failure_contexts_by_id": {"fc1": fc},
    }


def _tc_model(tc_records=(), skips=()):
    index = SpecCoverageIndexFile(config.active_coverage_index_path())
    return {"generated_at": "2026-01-01T00:00:00", "tc_records": list(tc_records), "verdicts": [],
            "failure_contexts_by_id": {}, "coverage": compute_coverage(index, list(tc_records), list(skips))}


class TestHtmlReport(unittest.TestCase):
    def test_log_excerpt_with_angle_brackets_is_escaped(self):
        html_text = render_log_report(_log_model({
            "run_id": "run1", "timestamp": "2026-01-01 00:00:00.000",
            "primary_log_excerpt": "[TEST] <MAIN  > danger", "dmesg_excerpt": "", "signals": {}}))
        self.assertNotIn("<MAIN", html_text)
        self.assertIn("&lt;MAIN", html_text)

    def test_signals_are_escaped_exactly_once(self):
        html_text = render_log_report(_log_model({
            "run_id": "run1", "timestamp": "2026-01-01 00:00:00.000",
            "primary_log_excerpt": "ok", "dmesg_excerpt": "", "signals": {"note": "a<b"}}))
        # single-escaped '<' -> "&lt;"; double-escaped would render as "&amp;lt;"
        self.assertIn("a&lt;b", html_text)
        self.assertNotIn("&amp;lt;", html_text)


class TestTheTwoFeaturesHaveSeparateReports(unittest.TestCase):
    def test_the_log_report_has_no_tc_sections(self):
        html_text = render_log_report(_log_model({"run_id": "r", "timestamp": "t", "primary_log_excerpt": "",
                                                  "dmesg_excerpt": "", "signals": {}}))
        self.assertIn("QST", html_text)
        self.assertNotIn("Spec 커버리지", html_text)
        self.assertNotIn("TC 목록", html_text)

    def test_the_tc_report_has_no_log_judgments(self):
        html_text = render_tc_report(_tc_model())
        self.assertIn("Spec 커버리지", html_text)
        self.assertNotIn("1차 판단 — QST", html_text)
        self.assertNotIn("1차 판단 — PULSEFZ", html_text)

    def test_the_tc_report_counts_against_testable_targets_and_names_exclusions(self):
        html_text = render_tc_report(_tc_model())
        self.assertIn("0/232", html_text)  # tried / testable today, not /258
        self.assertIn("Event Type", html_text)
        self.assertIn("22개", html_text)
        self.assertIn("Abort/AER", html_text)
        self.assertIn("커맨드별 현황", html_text)
        self.assertIn("Set Features", html_text)


class TestReportsAreWrittenSeparately(unittest.TestCase):
    def setUp(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(tmp, ignore_errors=True))
        for name, path in (("LOG_REPORT_PATH", tmp / "out" / "log.html"), ("TC_REPORT_PATH", tmp / "out" / "tc.html"),
                           ("TC_STORE_PATH", tmp / "tc_store.json"), ("COVERAGE_STATE_PATH", tmp / "cov.json"),
                           ("TARGET_SKIPS_PATH", tmp / "skips.json"), ("FAILURE_CONTEXTS_DIR", tmp / "fc"),
                           ("VERDICTS_DIR", tmp / "verdicts")):
            patcher = mock.patch.object(config, name, path)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.tmp = tmp

    def test_run_report_writes_the_requested_kind(self):
        import run_report
        with contextlib.redirect_stdout(io.StringIO()):
            run_report.main(["--kind", "tc"])
        self.assertTrue(config.TC_REPORT_PATH.exists())
        self.assertFalse(config.LOG_REPORT_PATH.exists())
        with contextlib.redirect_stdout(io.StringIO()):
            run_report.main([])
        self.assertTrue(config.LOG_REPORT_PATH.exists())
        self.assertTrue((self.tmp / "out" / "archive").is_dir())

    def test_a_report_failure_does_not_fail_the_tc_run(self):
        import run_tc_pipeline
        out = io.StringIO()
        with mock.patch("report.aggregator.build_tc_model", side_effect=RuntimeError("disk full")), \
             contextlib.redirect_stdout(out):
            run_tc_pipeline._write_tc_report()
        self.assertIn("TC 리포트 생성 실패", out.getvalue())
        self.assertIn("disk full", out.getvalue())


if __name__ == "__main__":
    unittest.main()
