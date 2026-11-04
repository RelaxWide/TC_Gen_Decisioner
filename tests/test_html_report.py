import unittest

from report.html_report import render_report


class TestHtmlReport(unittest.TestCase):
    def test_log_excerpt_with_angle_brackets_is_escaped(self):
        model = {
            "generated_at": "2026-01-01T00:00:00",
            "counts": {"qst": 1, "pulsefz": 0, "tc_exec": 0},
            "coverage": None,
            "tc_records": [],
            "verdicts_by_source": {
                "qst": [{
                    "verdict_id": "v1", "failure_context_id": "fc1", "classification": "firmware_defect",
                    "confidence": 0.9, "rationale": "r", "guidance": [], "llm_response_id": "l1",
                    "judged_at": "2026-01-01T00:00:00",
                }],
                "pulsefz": [], "tc_exec": [],
            },
            "failure_contexts_by_id": {
                "fc1": {
                    "run_id": "run1", "timestamp": "2026-01-01 00:00:00.000",
                    "primary_log_excerpt": "[TEST] <MAIN  > danger",
                    "dmesg_excerpt": "", "signals": {},
                }
            },
        }
        html_text = render_report(model)
        self.assertNotIn("<MAIN", html_text)
        self.assertIn("&lt;MAIN", html_text)

    def test_signals_are_escaped_exactly_once(self):
        model = {
            "generated_at": "2026-01-01T00:00:00",
            "counts": {"qst": 1, "pulsefz": 0, "tc_exec": 0},
            "coverage": None,
            "tc_records": [],
            "verdicts_by_source": {
                "qst": [{
                    "verdict_id": "v1", "failure_context_id": "fc1", "classification": "firmware_defect",
                    "confidence": 0.9, "rationale": "r", "guidance": [], "llm_response_id": "l1",
                    "judged_at": "2026-01-01T00:00:00",
                }],
                "pulsefz": [], "tc_exec": [],
            },
            "failure_contexts_by_id": {
                "fc1": {
                    "run_id": "run1", "timestamp": "2026-01-01 00:00:00.000",
                    "primary_log_excerpt": "ok",
                    "dmesg_excerpt": "", "signals": {"note": "a<b"},
                }
            },
        }
        html_text = render_report(model)
        # single-escaped '<' -> "&lt;"; double-escaped would render as "&amp;lt;"
        self.assertIn("a&lt;b", html_text)
        self.assertNotIn("&amp;lt;", html_text)


if __name__ == "__main__":
    unittest.main()
