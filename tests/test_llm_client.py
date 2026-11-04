"""Unit tests for the LLM client's parsing/normalization — no network calls.

The real LLM path is exercised by actually running `run_judge.py`; these tests
cover the fragile pure-function parts around it.
"""
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import config
from log_judge.judge import _as_confidence
from shared import llm_client
from shared.llm_client import LLMCallError, _extract_json, _schema_instruction, generate_llm_response


class TestJsonExtraction(unittest.TestCase):
    def test_plain_json(self):
        self.assertEqual(_extract_json('{"a": 1}'), {"a": 1})

    def test_fenced_json(self):
        self.assertEqual(_extract_json('```json\n{"a": 1}\n```'), {"a": 1})
        self.assertEqual(_extract_json('```\n{"a": 1}\n```'), {"a": 1})

    def test_json_wrapped_in_prose(self):
        # An otherwise-good answer shouldn't be thrown away over a stray sentence.
        self.assertEqual(_extract_json('Here you go:\n{"a": 1}\nHope that helps.'), {"a": 1})

    def test_unparseable_raises(self):
        with self.assertRaises(Exception):
            _extract_json("no json at all")

    def test_non_object_json_is_a_parse_failure(self):
        # Valid JSON that isn't an object used to be returned as-is and blow
        # up downstream as TypeError, which no caller catches.
        for text in ("[1, 2]", '"just a string"', "42"):
            with self.assertRaises(json.JSONDecodeError):
                _extract_json(text)

    def test_object_inside_an_array_is_recovered(self):
        self.assertEqual(_extract_json('[{"a": 1}]'), {"a": 1})

    def test_schema_instruction_lists_every_key(self):
        text = _schema_instruction({"classification": "one of x|y", "confidence": "0..1"})
        self.assertIn('"classification": one of x|y', text)
        self.assertIn('"confidence": 0..1', text)


class TestConfidenceNormalization(unittest.TestCase):
    def test_already_fractional(self):
        self.assertAlmostEqual(_as_confidence(0.7), 0.7)

    def test_percent_forms_are_rescaled(self):
        # Post-rules downgrade below 0.5, so a "70" meaning 70% must not read as 1.0.
        self.assertAlmostEqual(_as_confidence(70), 0.7)
        self.assertAlmostEqual(_as_confidence("70%"), 0.7)
        self.assertAlmostEqual(_as_confidence("0.7"), 0.7)

    def test_out_of_range_is_clamped(self):
        self.assertEqual(_as_confidence(500), 1.0)
        self.assertEqual(_as_confidence(-1), 0.0)

    def test_garbage_is_zero_not_crash(self):
        self.assertEqual(_as_confidence(None), 0.0)
        self.assertEqual(_as_confidence("high"), 0.0)


class _FakeCompletion:
    def __init__(self, text):
        self.choices = [mock.Mock(message=mock.Mock(content=text))]


class _FakeClient:
    def __init__(self, replies):
        self._replies = list(replies)
        self.chat = mock.Mock()
        self.chat.completions = mock.Mock()
        self.chat.completions.create = mock.Mock(
            side_effect=lambda **kw: _FakeCompletion(self._replies.pop(0)))


class TestCallLogging(unittest.TestCase):
    """Before this, the prompt and raw completion text were never written
    anywhere — the only way to see what was actually sent and actually came
    back was to re-run the pipeline and hope the behavior reproduced."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self._real_path = config.LLM_CALL_LOG_PATH
        config.LLM_CALL_LOG_PATH = Path(self.tmp.name) / "llm_calls.jsonl"
        self._real_guide = llm_client._guide
        llm_client._guide = mock.Mock(model="testmodel")

    def tearDown(self):
        config.LLM_CALL_LOG_PATH = self._real_path
        llm_client._guide = self._real_guide
        self.tmp.cleanup()

    def _lines(self):
        if not config.LLM_CALL_LOG_PATH.exists():
            return []
        return [json.loads(l) for l in config.LLM_CALL_LOG_PATH.read_text(encoding="utf-8").splitlines()]

    def test_successful_call_is_logged_with_prompt_and_response(self):
        llm_client._guide.client = _FakeClient(['{"a": "1"}'])
        generate_llm_response("my prompt", system="sys", response_schema={"a": "x"}, caller="unit-test")
        lines = self._lines()
        self.assertEqual(len(lines), 1)
        self.assertIn("my prompt", lines[0]["prompt"])
        self.assertEqual(lines[0]["system"], "sys")
        self.assertEqual(lines[0]["raw_response"], '{"a": "1"}')
        self.assertEqual(lines[0]["structured"], {"a": "1"})
        self.assertEqual(lines[0]["caller"], "unit-test")
        self.assertIsNone(lines[0]["error"])

    def test_retry_is_logged_with_both_attempts(self):
        llm_client._guide.client = _FakeClient(["not json", '{"a": "1"}'])
        generate_llm_response("p", response_schema={"a": "x"})
        line = self._lines()[0]
        self.assertEqual(line["raw_response"], "not json")
        self.assertEqual(line["retry_raw_response"], '{"a": "1"}')
        self.assertEqual(line["structured"], {"a": "1"})

    def test_missing_key_gets_one_retry_then_succeeds(self):
        # Valid JSON, just missing a declared key, used to get zero retries
        # at all and raise immediately — a transient incomplete reply from
        # the model shouldn't be treated the same as a truly broken caller.
        llm_client._guide.client = _FakeClient(['{"a": "1"}', '{"a": "1", "b": "2"}'])
        out = generate_llm_response("p", response_schema={"a": "x", "b": "y"})
        self.assertEqual(out["structured"], {"a": "1", "b": "2"})
        line = self._lines()[0]
        self.assertIn("missing required keys", line["retry_prompt"])
        self.assertIn("'b'", line["retry_prompt"])

    def test_missing_key_retry_is_skipped_if_the_json_retry_already_fired(self):
        # Only one retry total, same budget as everywhere else in this
        # project — if the JSON-parse retry already ran, a still-missing key
        # after that must raise immediately, not spend a second retry.
        llm_client._guide.client = _FakeClient(["not json", '{"a": "1"}'])
        with self.assertRaises(LLMCallError):
            generate_llm_response("p", response_schema={"a": "x", "b": "y"})
        self.assertEqual(llm_client._guide.client.chat.completions.create.call_count, 2)

    def test_still_missing_after_retry_raises(self):
        llm_client._guide.client = _FakeClient(['{"a": "1"}', '{"a": "1"}'])
        with self.assertRaises(LLMCallError):
            generate_llm_response("p", response_schema={"a": "x", "b": "y"})

    def test_failed_call_is_logged_not_silently_dropped(self):
        llm_client._guide.client = _FakeClient(["still not json", "still not json"])
        with self.assertRaises(LLMCallError):
            generate_llm_response("p", response_schema={"a": "x"})
        line = self._lines()[0]
        self.assertIsNotNone(line["error"])
        self.assertIsNone(line["structured"])

    def test_non_object_reply_is_retried_then_raises_llm_call_error(self):
        llm_client._guide.client = _FakeClient(["[1, 2]", "[3]"])
        with self.assertRaises(LLMCallError):
            generate_llm_response("p", response_schema={"a": "x"})
        self.assertEqual(llm_client._guide.client.chat.completions.create.call_count, 2)

    def test_empty_choices_is_an_llm_call_error(self):
        client = mock.Mock()
        client.chat.completions.create = mock.Mock(return_value=mock.Mock(choices=[]))
        llm_client._guide.client = client
        with self.assertRaises(LLMCallError):
            generate_llm_response("p", response_schema={"a": "x"})

    def test_each_call_appends_a_new_line(self):
        llm_client._guide.client = _FakeClient(['{"a":"1"}', '{"a":"2"}'])
        generate_llm_response("p1", response_schema={"a": "x"})
        generate_llm_response("p2", response_schema={"a": "x"})
        lines = self._lines()
        self.assertEqual(len(lines), 2)
        self.assertIn("p1", lines[0]["prompt"])
        self.assertIn("p2", lines[1]["prompt"])


if __name__ == "__main__":
    unittest.main()
