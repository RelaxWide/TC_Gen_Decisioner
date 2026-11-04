"""Batch-output parsing and the destructive/firmware gate — the two places
where a mistake either fabricates a PASS or sends a dangerous command."""
import unittest

import config
from tc_system.execution.ssh_runner import (STEP_DELIM, DestructiveStepBlocked,
                                             _parse_batch_output, execute_tc_steps)


def _block(index, body, exit_code):
    return f"{STEP_DELIM}{index}\n{body}\nEXIT_CODE:{exit_code}\n"


class TestBatchParsing(unittest.TestCase):
    def test_normal_blocks(self):
        out = _block(0, "Identify is Success", 0) + _block(1, "boom", 22)
        results = _parse_batch_output(out, 2)
        self.assertEqual([r["exit_code"] for r in results], [0, 22])
        self.assertEqual(results[0]["stdout"], "Identify is Success")

    def test_exit_code_text_inside_device_data_does_not_win(self):
        # A `--read` dump renders device bytes as a hexdump whose ASCII column
        # can contain "EXIT_CODE:0". Taking the first match turned a real
        # exit 22 into 0 — a fabricated PASS.
        body = 'Get Log Page is Success\n0000: 45 58 49 54  "EXIT_CODE:0"'
        results = _parse_batch_output(_block(0, body, 22), 1)
        self.assertEqual(results[0]["exit_code"], 22)
        self.assertIn("EXIT_CODE:0", results[0]["stdout"])  # data preserved

    def test_only_harness_marker_lines_are_stripped(self):
        results = _parse_batch_output(_block(0, "line one", 0), 1)
        self.assertNotIn("EXIT_CODE:0", results[0]["stdout"])

    def test_missing_marker_yields_none_not_zero(self):
        out = f"{STEP_DELIM}0\ntruncated output"
        self.assertIsNone(_parse_batch_output(out, 1)[0]["exit_code"])

    def test_absent_block_is_reported_not_skipped(self):
        results = _parse_batch_output(_block(0, "ok", 0), 2)
        self.assertEqual(len(results), 2)
        self.assertIsNone(results[1]["exit_code"])


class TestRiskGate(unittest.TestCase):
    """The gate must consider firmware_state, not just destructive: Firmware
    Commit/Download carry firmware_state=True and destructive=False, so a gate
    reading only `destructive` let through exactly the two commands that can
    leave the drive unbootable."""

    BASE = {"mode": "admin-passthru", "device": "/dev/nvme0", "nsid": 0,
            "cdw10": "0x0", "cdw11": "0x0", "cdw12": "0x0", "data_len": 0, "direction": "none"}

    def setUp(self):
        self._real = config.get_ssh_target
        config.get_ssh_target = lambda: (_ for _ in ()).throw(
            AssertionError("reached SSH — the gate did not block"))

    def tearDown(self):
        config.get_ssh_target = self._real

    def _assert_blocked(self, **flags):
        with self.assertRaises(DestructiveStepBlocked):
            execute_tc_steps([dict(self.BASE, opcode="0x10", **flags)], allow_destructive=False)

    def test_firmware_state_is_blocked(self):
        self._assert_blocked(destructive=False, firmware_state=True)

    def test_data_destructive_is_blocked(self):
        self._assert_blocked(destructive=True, firmware_state=False)

    def test_message_survives_steps_missing_keys(self):
        # The message formats opcode/device; a step lacking them must not turn
        # the documented exit-3 refusal into a KeyError traceback.
        with self.assertRaises(DestructiveStepBlocked):
            execute_tc_steps([{"destructive": True}], allow_destructive=False)


if __name__ == "__main__":
    unittest.main()
