import unittest

from tc_system.execution.ssh_runner import STEP_DELIM, _parse_batch_output
from tc_system.execution.expectation_checker import (check_expectation, check_step_expectations,
                                                      evaluate_criteria, field_value_unsupported,
                                                      host_tool_crash, rejected_arguments, unsupported_opcode)

TC = {
    "tc_id": "tc-1",
    "steps": [{"opcode": "0x06", "direction": "none", "data_len": 0}],
    "expectation": {"description": "d", "fail_criteria": [
        "[DUMMY LLM OUTPUT] device must not stall",  # prose — cannot be auto-evaluated
        "nvme-cli exit code != 0",                     # builtin — must not be duplicated
    ]},
}


def _exec(step_results, **kw):
    return {"step_results": step_results, **kw}


class TestExpectationChecker(unittest.TestCase):
    def test_clean_run_passes(self):
        result = _exec([{"step_index": 0, "exit_code": 0, "stdout": "ok"}])
        self.assertEqual(check_expectation(TC, result), "UNVERIFIED")

    def test_nonzero_exit_fails_and_names_the_step(self):
        result = _exec([{"step_index": 0, "exit_code": 22, "stdout": ""}])
        self.assertEqual(check_expectation(TC, result), "ERROR")
        violated = [c for c in evaluate_criteria(TC, result) if c["result"] == "violated"]
        self.assertIn("step0=22", violated[0]["detail"])

    def test_long_controller_status_text_is_not_cut_off(self):
        # Measured for real: a 200-char hard cut sliced a genuine NVMe status
        # explanation mid-sentence ("...currently in u"), and that already-
        # truncated string is what the terminal/log layer's own full-text
        # log line faithfully reproduced — no amount of fixing the display
        # layer can recover text already lost upstream.
        long_explanation = (
            "NVMe status: QID_INVALID: The creation of the I/O Completion Queue failed due to an "
            "invalid queue identifier specified as part of the command. An invalid queue identifier "
            "is one that is currently in use or is an invalid value as defined by a mandatory or "
            "optional feature."
        )
        self.assertGreater(len(long_explanation), 200)
        result = _exec([{"step_index": 0, "exit_code": 22, "stdout": long_explanation}])
        violated = [c for c in evaluate_criteria(TC, result) if c["result"] == "violated"]
        detail = next(c["detail"] for c in violated if c["criterion"] == "controller error status returned")
        self.assertIn("currently in use or is an invalid value", detail)

    def test_real_nvme_cli_error_text_is_detected(self):
        # Verbatim stderr from nvme-cli 1.16 on the target; ssh_runner folds
        # stderr into the step's stdout block, which is what makes this visible.
        result = _exec([{"step_index": 0, "exit_code": 22, "stdout":
                          "NVMe status: INVALID_FIELD: A reserved coded value or an "
                          "unsupported value in a defined field(0x2)"}])
        violated = [c["criterion"] for c in evaluate_criteria(TC, result) if c["result"] == "violated"]
        self.assertIn("controller error status returned", violated)

    def test_real_nvme_cli_success_text_is_not_flagged(self):
        result = _exec([{"step_index": 0, "exit_code": 0,
                          "stdout": "Admin Command Get Features is Success and result: 0x03030304"}])
        self.assertEqual(check_expectation(TC, result), "UNVERIFIED")

    def test_vacuous_success_is_a_fail_not_a_pass(self):
        # Measured: io-passthru 0x02 with cdw10=0 and no --data-len exits 0 while
        # transferring nothing. Counting that as a PASS would be a false
        # confirmation of spec coverage.
        tc = {**TC, "steps": [{"opcode": "0x02", "direction": "read", "data_len": 0}]}
        result = _exec([{"step_index": 0, "exit_code": 0,
                          "stdout": "IO Command Read is Success and result: 0x00000000"}])
        self.assertEqual(check_expectation(tc, result), "FAIL")
        violated = [c["criterion"] for c in evaluate_criteria(tc, result) if c["result"] == "violated"]
        self.assertIn("succeeded without transferring declared data", violated)

    def test_real_data_transfer_is_not_flagged_vacuous(self):
        tc = {**TC, "steps": [{"opcode": "0x06", "direction": "read", "data_len": 4096}]}
        result = _exec([{"step_index": 0, "exit_code": 0, "stdout": "SAMSUNG MZAMF1T0HMKB-00BL2"}])
        self.assertEqual(check_expectation(tc, result), "UNVERIFIED")

    def test_device_hang_is_a_fail_finding_not_an_error(self):
        # A wedged device is the headline finding; ERROR would get it silently
        # re-probed every run instead of recorded.
        result = _exec([{"step_index": 0, "exit_code": None, "stdout": ""}], timed_out=True)
        self.assertEqual(check_expectation(TC, result), "FAIL")

    def test_missing_exit_code_without_timeout_is_error(self):
        result = _exec([{"step_index": 0, "exit_code": None, "stdout": ""}])
        self.assertEqual(check_expectation(TC, result), "ERROR")

    def test_prose_criterion_reported_unevaluated_and_builtins_not_duplicated(self):
        criteria = evaluate_criteria(TC, _exec([{"step_index": 0, "exit_code": 0, "stdout": "ok"}]))
        prose = [c for c in criteria if c["kind"] == "prose"]
        self.assertEqual(len(prose), 1)
        self.assertEqual(prose[0]["result"], "unevaluated")
        names = [c["criterion"] for c in criteria]
        self.assertEqual(names.count("nvme-cli exit code != 0"), 1)


class TestFieldValueUnsupported(unittest.TestCase):
    """A step whose required field value (a Log Page/Feature Identifier/CNS/
    etc.) was deterministically verified in CDW10 before being sent (see
    `args_author._verify_field_values`) gets rejected for a different reason
    than an unverified step's identical-looking rejection: the value was
    confirmed correct, so the drive simply doesn't implement it — a real
    finding, not an argument-authoring mistake."""
    def _tc(self, field_value_verified, opcode="0x02"):
        return {"tc_id": "tc-1",
                "steps": [{"opcode": opcode, "direction": "none", "data_len": 0,
                            "field_value_verified": field_value_verified}],
                "expectation": {"description": "d", "fail_criteria": []}}

    def test_selector_verification_does_not_prove_support_or_other_fields(self):
        tc = self._tc(field_value_verified=True)
        result = _exec([{"step_index": 0, "exit_code": 22, "stdout":
                          "NVMe status: INVALID_LOG_PAGE: The log page indicated is invalid(0x109)"}])
        self.assertEqual(check_expectation(tc, result), "ERROR")
        self.assertIsNone(field_value_unsupported(tc, result))
        self.assertIsNotNone(rejected_arguments(result, tc))
        self.assertEqual(check_step_expectations(tc, result), ["ERROR"])

    def test_the_same_stdout_on_an_unverified_step_is_still_error(self):
        tc = self._tc(field_value_verified=False)
        result = _exec([{"step_index": 0, "exit_code": 22, "stdout":
                          "NVMe status: INVALID_LOG_PAGE: The log page indicated is invalid(0x109)"}])
        self.assertEqual(check_expectation(tc, result), "ERROR")
        self.assertIsNone(field_value_unsupported(tc, result))
        self.assertIsNotNone(rejected_arguments(result, tc))
        self.assertEqual(check_step_expectations(tc, result), ["ERROR"])

    def test_a_verified_steps_rejection_does_not_mask_a_real_error_on_a_sibling_step(self):
        # Chain: step 0 (verified, rejected -> UNSUPPORTED) and step 1
        # (unverified, rejected -> ERROR) must both be visible independently
        # in step_statuses — neither should hide the other.
        tc = {"tc_id": "tc-1",
              "steps": [{"opcode": "0x02", "direction": "none", "data_len": 0, "field_value_verified": True},
                        {"opcode": "0x09", "direction": "none", "data_len": 0, "field_value_verified": False}],
              "expectation": {"description": "d", "fail_criteria": []}}
        result = _exec([
            {"step_index": 0, "exit_code": 22, "stdout": "NVMe status: INVALID_LOG_PAGE: invalid(0x109)"},
            {"step_index": 1, "exit_code": 22, "stdout": "NVMe status: INVALID_FIELD: reserved value(0x2)"},
        ])
        self.assertEqual(check_step_expectations(tc, result), ["ERROR", "ERROR"])

    def test_no_verified_steps_means_no_field_value_finding(self):
        tc = self._tc(field_value_verified=False)
        result = _exec([{"step_index": 0, "exit_code": 0, "stdout": "Success"}])
        self.assertIsNone(field_value_unsupported(tc, result))

    def test_rejected_arguments_without_a_tc_record_is_unaffected(self):
        # Backward compatibility: existing single-argument callers (and
        # tests) must keep working exactly as before.
        result = _exec([{"step_index": 0, "exit_code": 22, "stdout":
                          "NVMe status: INVALID_LOG_PAGE: invalid(0x109)"}])
        self.assertIsNotNone(rejected_arguments(result))


class TestFirmwareCommitDummyImage(unittest.TestCase):
    """Firmware Image Download sends a zero-filled dummy buffer (no real
    signed image exists to send) — these check that Firmware Commit (0x10)
    accepting an *activating* Commit Action against that dummy is flagged as
    the real finding it is, while CA=0 (stage only, never activated) and any
    rejection stay unflagged."""
    def _tc(self, cdw10):
        return {"tc_id": "tc-1", "steps": [{"opcode": "0x10", "cdw10": cdw10, "direction": "none", "data_len": 0}],
                "expectation": {"description": "d", "fail_criteria": []}}

    def test_an_activating_commit_after_a_proven_dummy_download_is_violated(self):
        # NVMe Base Firmware Commit table: CA[5:3]=1, FS[2:0]=1.
        tc = self._tc("0x00000009")
        tc["steps"].insert(0, {"opcode": "0x11", "direction": "write", "data_len": 4})
        result = _exec([{"step_index": i, "exit_code": 0, "stdout": "Admin Command 0x10 is Success and result: 0x0"} for i in range(2)])
        names = [c["criterion"] for c in evaluate_criteria(tc, result) if c["result"] == "violated"]
        self.assertIn("firmware commit activated an unvalidated dummy image", names)
        self.assertEqual(check_step_expectations(tc, result), ["PASS", "FAIL"])

    def test_commit_action_zero_succeeding_is_not_violated(self):
        # CA=0 only stages the image into the slot — it is never activated,
        # so a real controller accepting arbitrary bytes there isn't a defect.
        tc = self._tc("0x00000001")
        result = _exec([{"step_index": 0, "exit_code": 0, "stdout": "Success"}])
        violated = [c["criterion"] for c in evaluate_criteria(tc, result) if c["result"] == "violated"]
        self.assertNotIn("firmware commit activated an unvalidated dummy image", violated)

    def test_an_activating_commit_action_that_is_rejected_is_not_violated(self):
        # The expected, desired outcome: the controller validated the dummy
        # image and refused to activate it. The exact rejection text isn't
        # load-bearing here — only that it wasn't accepted (exit_code != 0).
        tc = self._tc("0x00000019")  # CA=3, FS=1: activate immediately
        result = _exec([{"step_index": 0, "exit_code": 7, "stdout": "NVMe status: FW_INVALID_IMAGE"}])
        violated = [c["criterion"] for c in evaluate_criteria(tc, result) if c["result"] == "violated"]
        self.assertNotIn("firmware commit activated an unvalidated dummy image", violated)

    def test_a_different_opcode_is_never_flagged(self):
        tc = {**TC, "steps": [{"opcode": "0x11", "cdw10": "0x00000003", "direction": "write", "data_len": 512}]}
        result = _exec([{"step_index": 0, "exit_code": 0, "stdout": "Success"}])
        violated = [c["criterion"] for c in evaluate_criteria(tc, result) if c["result"] == "violated"]
        self.assertNotIn("firmware commit activated an unvalidated dummy image", violated)


class TestOurBugsVsRealFindings(unittest.TestCase):
    """The three ways a command can come back wrong must not be conflated:
    an unimplemented optional command is a finding, a malformed field is our
    bug, and a crashed host tool is our bug with no device evidence at all."""

    def test_invalid_opcode_is_a_finding_not_our_bug(self):
        result = _exec([{"step_index": 0, "exit_code": 22, "stdout":
                          "NVMe status: INVALID_OPCODE: The associated command opcode field is not valid(0x1)"}])
        self.assertEqual(check_expectation(TC, result), "UNSUPPORTED")
        self.assertIsNotNone(unsupported_opcode(result))
        # Must not be mistaken for an argument problem, or it gets retried forever.
        self.assertIsNone(rejected_arguments(result))

    def test_invalid_field_is_our_bug_and_retryable(self):
        result = _exec([{"step_index": 0, "exit_code": 22, "stdout":
                          "NVMe status: INVALID_FIELD: A reserved coded value or an "
                          "unsupported value in a defined field(0x2)"}])
        self.assertEqual(check_expectation(TC, result), "ERROR")
        self.assertIsNotNone(rejected_arguments(result))
        self.assertIsNone(unsupported_opcode(result))

    def test_long_unsupported_and_rejection_text_is_not_cut_off(self):
        long_unsupported = ("NVMe status: INVALID_OPCODE: The associated command opcode field is not "
                             "valid as defined by the applicable command set specification for this "
                             "controller and namespace combination(0x1)")
        long_rejection = ("NVMe status: INVALID_FIELD: A reserved coded value or an unsupported value "
                           "in a defined field was specified for this particular command variant(0x2)")
        self.assertGreater(len(long_unsupported), 100)
        self.assertGreater(len(long_rejection), 100)
        self.assertIn("controller and namespace combination",
                      unsupported_opcode(_exec([{"step_index": 0, "exit_code": 22, "stdout": long_unsupported}])))
        _, reason = rejected_arguments(_exec([{"step_index": 0, "exit_code": 22, "stdout": long_rejection}]))
        self.assertIn("this particular command variant", reason)

    def test_rejected_arguments_returns_the_step_index_that_was_rejected(self):
        # pipeline.py needs to know which step to reauthor (or whether it's
        # safe to patch locally vs. needing a full replan) — a bare string
        # can't carry that.
        result = _exec([
            {"step_index": 0, "exit_code": 0, "stdout": "Admin Command Write is Success and result: 0x0"},
            {"step_index": 1, "exit_code": 22, "stdout":
             "NVMe status: INVALID_FIELD: A reserved coded value(0x2)"},
        ])
        rejection = rejected_arguments(result)
        self.assertEqual(rejection[0], 1)
        self.assertIn("INVALID_FIELD", rejection[1])

    def test_other_invalid_statuses_are_also_our_bug(self):
        # Observed: the model placed Get Log Page's LID in the wrong bits, so
        # the drive answered INVALID_LOG_PAGE. Matching only INVALID_FIELD let
        # that through as a firmware FAIL that also counted as coverage.
        for status in ("INVALID_LOG_PAGE: The log page indicated is invalid(0x109)",
                        "INVALID_NS: The namespace or the format of that namespace is invalid(0xb)",
                        "INVALID_QUEUE_IDENTIFIER: The creation of the I/O queue failed(0x100)"):
            result = _exec([{"step_index": 0, "exit_code": 22, "stdout": f"NVMe status: {status}"}])
            self.assertEqual(check_expectation(TC, result), "ERROR", status)
            self.assertIsNotNone(rejected_arguments(result), status)

    def test_host_tool_crash_is_error_not_firmware_fail(self):
        # Observed for real: authored args requested more dwords than the
        # allocated buffer, so nvme-cli died instead of reporting a status.
        result = _exec([{"step_index": 0, "exit_code": 134,
                          "stdout": "Admin Command Get Log Page is Success and result: 0x00000000\n"
                                    "malloc(): corrupted top size"}])
        self.assertEqual(check_expectation(TC, result), "ERROR")
        self.assertIn("dword count", host_tool_crash(result))

    def test_clean_success_is_unaffected(self):
        result = _exec([{"step_index": 0, "exit_code": 0,
                          "stdout": "Admin Command Identify is Success and result: 0x00000000"}])
        self.assertEqual(check_expectation(TC, result), "UNVERIFIED")
        self.assertIsNone(unsupported_opcode(result))
        self.assertIsNone(rejected_arguments(result))
        self.assertIsNone(host_tool_crash(result))


class TestCheckStepExpectations(unittest.TestCase):
    """The whole-TC `check_expectation` scalar stays worst-of-all-steps (for
    routing/judging), but coverage needs each step's own independent
    verdict so one bad step in a chain doesn't erase evidence that an
    earlier, unrelated step in the same TC actually passed."""

    TWO_STEP_TC = {
        "tc_id": "tc-1",
        "steps": [
            {"opcode": "0x01", "direction": "write", "data_len": 512},
            {"opcode": "0x02", "direction": "read", "data_len": 512},
        ],
        "expectation": {"description": "d", "fail_criteria": []},
    }

    def test_all_steps_pass_independently(self):
        result = _exec([
            {"step_index": 0, "exit_code": 0, "stdout": "IO Command Write is Success"},
            {"step_index": 1, "exit_code": 0, "stdout": "IO Command Read is Success"},
        ])
        self.assertEqual(check_step_expectations(self.TWO_STEP_TC, result), ["PASS", "PASS"])

    def test_first_step_passes_second_is_unsupported(self):
        # The whole-TC scalar would read UNSUPPORTED for this execution, but
        # step 0 (Write) genuinely ran and should still be creditable.
        result = _exec([
            {"step_index": 0, "exit_code": 0, "stdout": "IO Command Write is Success"},
            {"step_index": 1, "exit_code": 22, "stdout":
             "NVMe status: INVALID_OPCODE: The associated command opcode field is not valid(0x1)"},
        ])
        self.assertEqual(check_expectation(self.TWO_STEP_TC, result), "UNSUPPORTED")
        self.assertEqual(check_step_expectations(self.TWO_STEP_TC, result), ["PASS", "UNSUPPORTED"])

    def test_first_step_passes_second_is_rejected(self):
        result = _exec([
            {"step_index": 0, "exit_code": 0, "stdout": "IO Command Write is Success"},
            {"step_index": 1, "exit_code": 22, "stdout":
             "NVMe status: INVALID_FIELD: A reserved coded value(0x2)"},
        ])
        self.assertEqual(check_step_expectations(self.TWO_STEP_TC, result), ["PASS", "ERROR"])

    def test_a_step_never_executed_after_a_hang_is_error_not_fail(self):
        # Step 0 hung (timed_out) and the batch was killed before step 1 ever
        # ran. The hung step itself is FAIL — that's the headline finding. But
        # step 1 never reached the device, and FAIL counts toward coverage, so
        # marking it FAIL (as this once did) credited its clause as "covered"
        # without ever sending it. ERROR keeps it out and re-offers it.
        result = _exec([{"step_index": 0, "exit_code": None, "stdout": "partial"}], timed_out=True)
        self.assertEqual(check_step_expectations(self.TWO_STEP_TC, result), ["FAIL", "ERROR"])
        self.assertEqual(check_expectation(self.TWO_STEP_TC, result), "FAIL")  # the TC itself is still a hang

    def test_parsed_batch_output_marks_steps_whose_delimiter_never_appeared(self):
        # The real shape: _parse_batch_output always returns one entry per
        # step, so "never ran" has to come from whether its delimiter was
        # echoed, not from a missing entry.
        stdout = f"{STEP_DELIM}0\nIO Command Write is Success\nEXIT_CODE:0\n{STEP_DELIM}1\n"
        three_step_tc = {**self.TWO_STEP_TC, "steps": self.TWO_STEP_TC["steps"] + [
            {"opcode": "0x02", "direction": "read", "data_len": 512}]}
        result = _exec(_parse_batch_output(stdout, 3), timed_out=True)
        self.assertEqual([r["started"] for r in result["step_results"]], [True, True, False])
        self.assertEqual(check_step_expectations(three_step_tc, result), ["PASS", "FAIL", "ERROR"])


class TestScalarStatusFollowsTheActionStep(unittest.TestCase):
    """`check_expectation` used to return UNSUPPORTED as soon as *any* step
    said INVALID_OPCODE — so an unimplemented setup command relabeled a real
    FAIL (or a hang) of the action step as UNSUPPORTED, and UNSUPPORTED TCs
    are never judged."""

    @staticmethod
    def _tc(*phases):
        return {"tc_id": "tc-1", "expectation": {"description": "d", "fail_criteria": []},
                "steps": [{"opcode": "0x06", "direction": "none", "data_len": 0, "phase": p} for p in phases]}

    UNSUPPORTED_OUT = "NVMe status: INVALID_OPCODE: The associated command opcode field is not valid(0x1)"

    def test_unsupported_setup_does_not_mask_an_action_hang(self):
        stdout = f"{STEP_DELIM}0\n{self.UNSUPPORTED_OUT}\nEXIT_CODE:1\n{STEP_DELIM}1\n"
        result = _exec(_parse_batch_output(stdout, 3), timed_out=True)
        self.assertEqual(check_expectation(self._tc("setup", "action", "verify"), result), "FAIL")

    def test_unsupported_setup_does_not_mask_an_action_fail(self):
        result = _exec([
            {"step_index": 0, "exit_code": 1, "stdout": self.UNSUPPORTED_OUT},
            {"step_index": 1, "exit_code": 1, "stdout": "NVMe status: INTERNAL: internal controller error"},
        ])
        self.assertEqual(check_expectation(self._tc("setup", "action"), result), "FAIL")

    def test_unsupported_setup_with_a_passing_action_is_pass(self):
        # The setup step's own non-zero exit isn't a firmware misbehavior
        # either, so it must not turn the TC into a FAIL instead.
        result = _exec([
            {"step_index": 0, "exit_code": 1, "stdout": self.UNSUPPORTED_OUT},
            {"step_index": 1, "exit_code": 0, "stdout": "Admin Command Identify is Success"},
        ])
        tc = self._tc("setup", "action")
        self.assertEqual(check_expectation(tc, result), "UNVERIFIED")
        self.assertEqual(check_step_expectations(tc, result), ["UNSUPPORTED", "PASS"])

    def test_unsupported_action_is_still_unsupported(self):
        result = _exec([
            {"step_index": 0, "exit_code": 0, "stdout": "Admin Command Identify is Success"},
            {"step_index": 1, "exit_code": 1, "stdout": self.UNSUPPORTED_OUT},
        ])
        self.assertEqual(check_expectation(self._tc("setup", "action"), result), "UNSUPPORTED")


class TestCheckStepExpectationsContinued(unittest.TestCase):
    TWO_STEP_TC = TestCheckStepExpectations.TWO_STEP_TC

    def test_vacuous_success_is_per_step(self):
        tc = {**self.TWO_STEP_TC, "steps": [
            {"opcode": "0x01", "direction": "write", "data_len": 512},
            {"opcode": "0x02", "direction": "read", "data_len": 0},  # declares read, moves nothing
        ]}
        result = _exec([
            {"step_index": 0, "exit_code": 0, "stdout": "IO Command Write is Success"},
            {"step_index": 1, "exit_code": 0, "stdout": "IO Command Read is Success"},
        ])
        self.assertEqual(check_step_expectations(tc, result), ["PASS", "FAIL"])

    def test_single_step_tc_matches_the_whole_tc_scalar(self):
        result = _exec([{"step_index": 0, "exit_code": 0, "stdout": "ok"}])
        self.assertEqual(check_step_expectations(TC, result), ["PASS"])
        self.assertEqual(check_expectation(TC, result), "UNVERIFIED")


if __name__ == "__main__":
    unittest.main()
