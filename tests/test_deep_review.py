"""Regression tests for the 2026-11-05 deep review (docs/reviews/2026-11-05-deep-review).

Each test is one reviewer counterexample (R01..R11) or one of the ten earlier
findings it lists, asserting the invariant the review demanded: what the
drive ends up holding, what was (not) sent, what the result says. A mock
device stands in for the SSD; nothing reaches SSH, an LLM or real files.
"""
import json
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from unittest import mock

import config
from shared.file_store import load_json, save_json_atomic
from tc_system import pipeline
from tc_system.execution import ssh_runner
from tc_system.execution.expectation_checker import check_expectation, describe_outcome
from tc_system.execution.tc_executor import SSHTCExecutor
from tc_system.generation import tc_writer
from tc_system.review import downgrade_verdict, review_tc
from tc_system.verification import evaluate_check, validate_plan_contract, verify_tc

QUOTE = "This synthetic requirement shall observe the completion of the command."


def step(**overrides):
    s = dict(name="Set Features", phase="action", mode="admin-passthru", device="/dev/nvme0", opcode="0x09",
             nsid=1, cdw10="0x04", cdw11="0x12c", cdw12="0x0", cdw13="0x0", cdw14="0x0", cdw15="0x0", data_len=0,
             direction="none", expected_status="SUCCESS", args_source="authored", field_constraints=[],
             test_intent={}, destructive=False, firmware_state=False, lockout_risk=False, shared_facts={})
    s.update(overrides)
    return s


def reply(value=0, data=None, error=None):
    r = dict(step_index=0, started=True, exit_code=22 if error else 0,
             stdout=(f"NVMe status: {error}: synthetic rejection" if error else
                     "Admin Command Synthetic is Success" + (f" and result: 0x{value:08x}" if value is not None else "")))
    if data is not None:
        r["data_hex"] = data.hex()
    return r


def tc_for(steps, **contract):
    i = next(i for i, s in enumerate(steps) if s["phase"] == "action")
    c = dict(version=2, precondition_checks=[], evidence=[dict(evidence_id="e", text=QUOTE)],
             requirements=[dict(requirement_id="r", section_id="s", evidence_id="e", quote=QUOTE,
                                description="completion", checks=[dict(kind="completion", step=i)])])
    c.update(contract)
    return dict(tc_id="t", name="t", steps=steps, uses_placeholder_args=False, scenario=dict(preconditions=[]),
                verification_contract=c)


def run(tc, device, host=None, raise_at=None):
    sent = []

    def wire(batch, **kw):
        s = deepcopy(batch[0])
        sent.append(s)
        if raise_at is not None and len(sent) == raise_at:
            raise KeyboardInterrupt
        return dict(step_results=[device(s)], batch_stderr="", timed_out=False, dmesg_captured_scoped=True)

    with mock.patch.object(ssh_runner, "execute_tc_steps", side_effect=wire), \
         mock.patch.object(ssh_runner, "clear_dmesg", return_value=True), \
         mock.patch.object(ssh_runner, "capture_dmesg", return_value=""), \
         mock.patch.object(ssh_runner, "run_host_action", side_effect=host or AssertionError("no host step")):
        execution = SSHTCExecutor(allow_destructive=True).execute(tc)
    return execution, sent


def with_restore(*actions):
    snaps, cleanups = tc_writer.plan_state_restore(list(actions), "/dev/nvme0", "/dev/nvme0n1")
    return tc_for(snaps + list(actions) + cleanups)


class TestRestoreContract(unittest.TestCase):
    def test_R01_an_irreversible_write_protection_is_never_sent(self):
        tc = with_restore(step(cdw10="0x84", cdw11="0x3"))
        with self.assertRaisesRegex(ValueError, "되돌릴 수 없는"):
            pipeline._preflight(tc, allow_destructive=False)  # the wire validation refuses it
        state = {"wps": 0}

        def device(s):
            if int(s["opcode"], 16) == 0x09:
                state["wps"] = int(s["cdw11"], 16) & 7
            return reply(state["wps"])

        with mock.patch.object(ssh_runner, "passthru_cmd"):
            execution, sent = run(tc, device)
        self.assertEqual(state["wps"], 0)
        self.assertNotIn("Set Features", [s["name"] for s in sent])
        self.assertNotEqual(check_expectation(tc, execution), "PASS")

    def _register_feature(self, fid, initial, changed, length=0):
        tc = with_restore(step(cdw10=hex(fid), cdw11="0x1", cdw12=hex(changed), data_len=length,
                               direction="write" if length else "none"))
        state = {"value": initial}

        def device(s):
            if int(s["opcode"], 16) == 0x09:
                state["value"] = int(s["cdw12"], 16)
            return reply(state["value"])

        execution, sent = run(tc, device)
        return tc, execution, sent, state

    def test_R02abc_features_without_a_known_restore_encoding_are_not_changed(self):
        for fid, initial, changed, length in ((0x13, 1, 0, 512), (0x14, 2, 1, 0), (0x12, 7, 3, 0)):
            tc, execution, sent, state = self._register_feature(fid, initial, changed, length)
            self.assertEqual(state["value"], initial, hex(fid))
            self.assertEqual(sent, [], hex(fid))  # neither the change nor a guessed restore
            self.assertIn("되돌리는 방법", execution["step_results"][0]["blocked_reason"])
            self.assertNotEqual(check_expectation(tc, execution), "PASS")

    def test_R02d_timestamp_reserved_bytes_are_sent_as_zero(self):
        tc = with_restore(step(cdw10="0x0e", data_len=8, direction="write"))
        got = bytes.fromhex("0100000000000200")  # Origin attribute in byte 6

        def device(s):
            return reply(0, got) if int(s["opcode"], 16) == 0x0A else reply()

        _, sent = run(tc, device)
        restore = [s for s in sent if s.get("harness") == "restore"][0]
        self.assertEqual(bytes.fromhex(restore["payload_hex"])[6:8], b"\0\0")

    def test_R03a_no_captured_original_value_means_no_change(self):
        tc = with_restore(step(cdw10="0x04", cdw11="0x12c"))
        writes = []

        def device(s):
            if int(s["opcode"], 16) == 0x0A:
                return reply(None)  # SUCCESS line, no CQE DW0
            writes.append(s["cdw11"])
            return reply()

        execution, _ = run(tc, device)
        self.assertEqual(writes, [])  # never "restored" to 0
        self.assertIn("Dword 0", execution["step_results"][1]["blocked_reason"])

    def test_R03b_a_short_original_buffer_means_no_change(self):
        tc = with_restore(step(cdw10="0x0c", cdw11="0x0", data_len=256, direction="write"))
        writes = []

        def device(s):
            if int(s["opcode"], 16) == 0x0A:
                return reply(1, b"\xab")  # 1 of 256 bytes
            writes.append(s)
            return reply()

        execution, _ = run(tc, device)
        self.assertEqual(writes, [])
        self.assertIn("1/256", execution["step_results"][1]["blocked_reason"])

    def _retry_identity(self, authored):
        original = step(cdw10="0x05", cdw11="0x12c")
        op = {"name": "Set Features", "command_set": "ADMIN", "raw_opcode": "0x09", "opcode": "0x09a"}
        section = {"section_id": "s", "spec_doc": "x"}
        with mock.patch.object(tc_writer, "author_args", return_value=dict(
                cdw10="0x05", cdw11="0x12c", cdw12="0x0", nsid=1, data_len=0, direction="none", shared_facts={},
                field_breakdown="x")):
            first = tc_writer._command_step(section, op, "/dev/nvme0", "/dev/nvme0n1", 1, phase="action",
                                            test_intent={"field_constraints": [{"field": "cdw10", "mask": "0xFF",
                                                                                "value": "0x05"}]})
        tc = with_restore(first)
        resolved = [dict(section=section, opcode_entry=dict(op, name=s["name"]), phase=s["phase"],
                         harness=bool(s.get("harness"))) for s in tc["steps"]]
        with mock.patch.object(tc_writer, "author_args", return_value=dict(authored, shared_facts={},
                                                                           field_breakdown="retry")):
            tc["steps"] = tc_writer.reauthor_steps(tc, resolved, {"step_index": 1, "reason": "x"}, 1)
        return tc, original

    def test_R04a_a_retry_cannot_move_the_change_to_all_namespaces(self):
        tc, _ = self._retry_identity(dict(cdw10="0x05", cdw11="0x12c", cdw12="0x0", nsid=0xFFFFFFFF, data_len=0,
                                          direction="none"))
        action = tc["steps"][1]
        # The NSID is pinned from the first authoring: a reply that moves it
        # violates the pin, so the retry is a placeholder and is never sent.
        self.assertEqual(action["args_source"], "placeholder")
        self.assertIn("nsid", action["args_error"])

    def test_R04b_a_retry_cannot_turn_on_save(self):
        tc, _ = self._retry_identity(dict(cdw10="0x80000005", cdw11="0x12c", cdw12="0x0", nsid=1, data_len=0,
                                          direction="none"))
        action = tc["steps"][1]
        self.assertEqual(action["args_source"], "placeholder")
        self.assertIn("cdw10", action["args_error"])

    def test_an_identity_changed_anyway_is_refused_at_send_time(self):
        tc = with_restore(step(cdw10="0x05", cdw11="0x12c", nsid=1))
        tc["steps"][1] = dict(tc["steps"][1], nsid=0xFFFFFFFF)  # changed behind the planner's back
        execution, sent = run(tc, lambda s: reply(5))
        self.assertNotIn("Set Features", [s["name"] for s in sent if s["phase"] == "action"])
        self.assertIn("원복 대상", execution["step_results"][1]["blocked_reason"])

    def test_sv1_saves_and_restores_both_the_saved_and_the_current_value(self):
        tc = with_restore(step(cdw10="0x80000004", cdw11="0x12c"))
        state = {"current": 100, "saved": 150}

        def device(s):
            c10 = int(s["cdw10"], 16)
            if int(s["opcode"], 16) == 0x0A:
                return reply(state["saved" if (c10 >> 8) & 7 == 2 else "current"])
            state["current"] = int(s["cdw11"], 16) & 0xFFFF
            if c10 >> 31:
                state["saved"] = state["current"]
            return reply()

        run(tc, device)
        self.assertEqual(state, {"current": 100, "saved": 150})

    def test_host_identifier_is_not_treated_as_restorable(self):
        # Follow-up F03: once non-zero, Set Features of the Host Identifier is
        # refused with Command Sequence Error, so Set cannot put it back.
        snaps, cleanups = tc_writer.plan_state_restore(
            [step(cdw10="0x81", cdw11="0x1", nsid=0, data_len=16, direction="write")], "/dev/nvme0", "/dev/nvme0n1")
        self.assertEqual(snaps, [])
        self.assertFalse(cleanups[0]["restorable"])

    def test_write_zeroes_is_not_sent_when_write_uncorrectable_was_not(self):
        wu = step(name="Write Uncorrectable", mode="io-passthru", device="/dev/nvme0n1", opcode="0x04", nsid=1,
                  cdw10="0x1000", cdw11="0x0", cdw12="0x7")
        setup = step(name="Get Features", phase="setup", opcode="0x0A", cdw10="0x01", cdw11="0x0")
        tc = with_restore(setup, wu)
        execution, sent = run(tc, lambda s: reply(error="INVALID_FIELD") if s["name"] == "Get Features" else reply())
        self.assertEqual([s["name"] for s in sent], ["Get Features"])
        self.assertTrue(execution["step_results"][-1]["cleanup_not_needed"])

    def test_cleanup_runs_when_the_run_is_interrupted(self):
        tc = with_restore(step(cdw10="0x04", cdw11="0x12c"),
                          step(name="Get Features", phase="verify", opcode="0x0A", cdw10="0x04", cdw11="0x0"))
        state = {"value": 100}

        def device(s):
            if int(s["opcode"], 16) == 0x09:
                state["value"] = int(s["cdw11"], 16) & 0xFFFF
            return reply(state["value"])

        sent = []

        def wire(batch, **kw):
            sent.append(batch[0])
            if len(sent) == 3:  # the verify step: Ctrl+C
                raise KeyboardInterrupt
            return dict(step_results=[device(batch[0])], batch_stderr="", timed_out=False, dmesg_captured_scoped=True)

        with mock.patch.object(ssh_runner, "execute_tc_steps", side_effect=wire), \
             mock.patch.object(ssh_runner, "clear_dmesg", return_value=True), \
             mock.patch.object(ssh_runner, "capture_dmesg", return_value=""):
            with self.assertRaises(KeyboardInterrupt):
                SSHTCExecutor(allow_destructive=True).execute(tc)
        self.assertEqual(state["value"], 100)

    def test_a_restore_that_did_not_take_is_flagged(self):
        tc = with_restore(step(cdw10="0x04", cdw11="0x12c"))
        state = {"value": 100}

        def device(s):
            if int(s["opcode"], 16) == 0x09 and s["phase"] == "action":
                state["value"] = 300  # the restore "succeeds" but changes nothing
            return reply(state["value"])

        execution, _ = run(tc, device)
        tc = dict(tc, execution=execution, status=check_expectation(tc, execution), step_statuses=[])
        self.assertFalse(execution["step_results"][-1]["restore_verified"])
        self.assertEqual(review_tc(tc)["level"], "must")


class TestJudgmentContract(unittest.TestCase):
    def test_R05_the_log_boundary_is_before_a_first_host_step(self):
        tc = tc_for([step(name="Controller Reset", phase="setup", mode="host", host_action="controller_reset",
                          opcode="host"), step(name="Get Features", opcode="0x0A", cdw10="0x01", cdw11="0x0")])
        order = []
        with mock.patch.object(ssh_runner, "clear_dmesg", side_effect=lambda **k: order.append("clear") or True), \
             mock.patch.object(ssh_runner, "run_host_action", side_effect=lambda *a, **k: order.append("reset") or
                               {"exit_code": 0, "stdout": "ok", "batch_stderr": "", "timed_out": False}), \
             mock.patch.object(ssh_runner, "execute_tc_steps", side_effect=lambda b, **k: order.append("cmd") or dict(
                 step_results=[reply()], batch_stderr="", timed_out=False, dmesg_captured_scoped=True)), \
             mock.patch.object(ssh_runner, "capture_dmesg", return_value=""), \
             mock.patch.object(ssh_runner, "passthru_cmd"):
            SSHTCExecutor(allow_destructive=True).execute(tc)
        self.assertEqual(order, ["clear", "reset", "cmd"])

    def test_R05_a_failed_clear_is_not_reported_as_scoped(self):
        tc = tc_for([step(name="Get Features", opcode="0x0A", cdw10="0x01", cdw11="0x0")])
        with mock.patch.object(ssh_runner, "clear_dmesg", return_value=False), \
             mock.patch.object(ssh_runner, "execute_tc_steps", return_value=dict(
                 step_results=[reply()], batch_stderr="", timed_out=False, dmesg_captured_scoped=True)), \
             mock.patch.object(ssh_runner, "capture_dmesg", return_value="boot log"):
            execution = SSHTCExecutor(allow_destructive=True).execute(tc)
        self.assertFalse(execution["dmesg_captured_scoped"])

    def test_R06_judge_normalization_does_not_strengthen_bad_replies(self):
        from log_judge.judge import _as_classification, _as_confidence
        self.assertEqual(_as_classification("not a firmware defect"), "needs_engineer_review")
        self.assertEqual(_as_classification("Firmware Defect"), "firmware_defect")
        self.assertEqual(_as_confidence("NaN"), 0.0)
        self.assertEqual(_as_confidence(float("inf")), 0.0)

    def test_R07_an_unmeasured_premise_is_not_a_fail_and_holds_a_defect_verdict(self):
        action = step(name="Get Log Page", opcode="0x02", cdw10="0x7e", data_len=4, direction="read",
                      expected_status="INVALID_FIELD")
        tc = tc_for([action], unmeasured_preconditions=["the controller is a Discovery controller"])
        execution = dict(step_results=[reply(data=bytes(4))], timed_out=False, dmesg_text="")
        status = check_expectation(tc, execution)
        self.assertEqual(status, "UNVERIFIED")
        tc = dict(tc, execution=execution, status="FAIL", verification=verify_tc(tc, execution), step_statuses=["FAIL"])
        held = downgrade_verdict({"classification": "firmware_defect", "rationale": "r"}, review_tc(tc))
        self.assertEqual(held["classification"], "needs_engineer_review")

    def _retention_plan(self, steps):
        from tc_system.execution.host_actions import host_action_entries
        ops = [{"name": "Get Features", "raw_opcode": "0x0A", "command_set": "ADMIN", "opcode": "0x0Aa"},
               {"name": "Set Features", "raw_opcode": "0x09", "command_set": "ADMIN", "opcode": "0x09a"}] \
            + host_action_entries(None)
        target = {"requirement_id": "t", "section_id": "s", "kind": "shall", "text": QUOTE,
                  "host_actions": ["controller_reset", "power_cycle"], "host_steps": ["Controller Reset"]}
        last = len(steps) - 1
        plan = {"description": "d", "preconditions": [], "steps_plan": steps, "out_of_scope": [],
                "requirements": [{"description": "d", "evidence_id": "e", "quote": QUOTE,
                                  "checks": [{"kind": "completion", "step": last}]}], "precondition_checks": []}
        return lambda: validate_plan_contract(plan, [{"evidence_id": "e", "text": QUOTE}], "s", ops,
                                              target_requirement=target)

    def test_reset_then_set_then_get_is_not_retention(self):
        fix = [{"field": "cdw10", "mask": "0x7FF", "value": "0x02"}]
        steps = [{"opcode_name": "Controller Reset", "phase": "setup"},
                 {"opcode_name": "Set Features", "phase": "setup", "field_constraints": fix},
                 {"opcode_name": "Get Features", "phase": "action", "expected_status": "SUCCESS", "field_constraints": fix}]
        with self.assertRaisesRegex(ValueError, "BEFORE the host step|after the event"):
            self._retention_plan(steps)()
        ok = [{"opcode_name": "Set Features", "phase": "setup", "field_constraints": fix},
              {"opcode_name": "Controller Reset", "phase": "setup"},
              {"opcode_name": "Get Features", "phase": "action", "expected_status": "SUCCESS", "field_constraints": fix}]
        self._retention_plan(ok)()

    def test_measured_unsupported_but_accepted_stays_a_fail(self):
        quote = "If a controller does not support the specified CNS value, then the controller shall abort the command"
        action = step(name="Identify", opcode="0x06", cdw10="0x410", data_len=4096, direction="read",
                      expected_status="INVALID_FIELD", selector_support=False)
        tc = tc_for([action], evidence=[dict(evidence_id="e", text=quote)],
                    requirements=[dict(requirement_id="r", section_id="s", evidence_id="e", quote=quote,
                                       description="d", checks=[dict(kind="completion", step=0)])])
        self.assertEqual(check_expectation(tc, dict(step_results=[reply()])), "FAIL")

    def test_data_equal_needs_both_whole_buffers(self):
        read = step(name="Read", mode="io-passthru", opcode="0x02", data_len=512, direction="read", device="/dev/nvme0n1")
        check = {"kind": "data_equal", "step": 1, "other_step": 0}
        results = {0: dict(reply(data=b"\0"), step_index=0), 1: dict(reply(data=b"\0"), step_index=1)}
        self.assertEqual(evaluate_check(check, [read, dict(read)], results)["result"], "unevaluated")

    def test_dulbe_unwritten_block_is_accepted_for_an_in_range_read_variant(self):
        from tc_system.verification import matches_expected
        s = step(name="Read", mode="io-passthru", opcode="0x02", expected_status="SUCCESS", also_accept=["UNWRITTEN_BLOCK"])
        self.assertTrue(matches_expected(s, reply(error="UNWRITTEN_BLOCK") | {
            "stdout": "NVMe status: UNWRITTEN_BLOCK: deallocated(0x2287)"}))

    def test_R10_a_refused_fid_is_not_described_as_an_unimplemented_command(self):
        s = step(name="Get Features", opcode="0x0A", cdw10="0x11", selector_support=False)
        tc = tc_for([s])
        execution = dict(step_results=[reply(error="INVALID_FIELD")])
        tc.update(execution=execution, status=check_expectation(tc, execution), verification=verify_tc(tc, execution))
        text = describe_outcome(tc)["verdict"]
        self.assertEqual(tc["status"], "UNSUPPORTED")
        self.assertNotIn("INVALID_OPCODE", text)
        self.assertIn("FID", text)


class TestInputAndHistoryContracts(unittest.TestCase):
    OPS = [{"name": "Get Log Page", "raw_opcode": "0x02", "command_set": "ADMIN", "opcode": "0x02a"}]

    def _plan(self, **extra):
        plan = {"description": "d", "preconditions": [], "out_of_scope": [], "precondition_checks": [],
                "steps_plan": [{"opcode_name": "Get Log Page", "phase": "action", "expected_status": "SUCCESS",
                                "field_constraints": [{"field": "cdw10", "mask": "0xFF", "value": "0x02"}]}],
                "requirements": [{"description": "d", "evidence_id": "e", "quote": QUOTE,
                                  "checks": [{"kind": "completion", "step": 0}]}]}
        plan.update(extra)
        return plan

    def test_R08a_a_string_where_a_check_group_belongs_is_a_plan_error(self):
        with self.assertRaisesRegex(ValueError, "precondition_checks"):
            validate_plan_contract(self._plan(precondition_checks=["some condition"]),
                                   [{"evidence_id": "e", "text": QUOTE}], "s", self.OPS,
                                   device_support={"lids": {0x02: True}, "fids": {}})

    def test_R08b_an_unreadable_precondition_is_not_dropped(self):
        with self.assertRaisesRegex(ValueError, "preconditions"):
            validate_plan_contract(self._plan(preconditions=[{"condition": "Discovery controller"}]),
                                   [{"evidence_id": "e", "text": QUOTE}], "s", self.OPS)

    def test_R09_a_rejudged_verdict_is_linked_to_its_tc(self):
        import run_judge
        from log_judge.models import make_failure_context
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            fc = make_failure_context(failure_context_id="fc-1", source_type="TC_EXEC", run_id="t",
                                      timestamp="x", primary_log_excerpt="x", signals={})
            save_json_atomic(temp / "failure_contexts" / "tc_exec" / "fc.json", fc)
            save_json_atomic(temp / "tc_store.json", [dict(tc_for([step()]), failure_context_id="fc-1",
                                                           verdict_id=None, status="FAIL")])
            verdict = dict(verdict_id="v-1", failure_context_id="fc-1", classification="firmware_defect",
                           confidence=0.9, rationale="r")
            with mock.patch.object(config, "FAILURE_CONTEXTS_DIR", temp / "failure_contexts"), \
                 mock.patch.object(config, "VERDICTS_DIR", temp / "verdicts"), \
                 mock.patch.object(config, "TC_STORE_PATH", temp / "tc_store.json"), \
                 mock.patch.object(run_judge, "judge_failure_context", return_value=verdict):
                run_judge.judge_source("tc_exec")
            tc = load_json(temp / "tc_store.json")[0]
            self.assertEqual(tc["verdict_id"], "v-1")
            self.assertIn("review", tc)

    def test_R11_different_replies_get_different_ids(self):
        from shared import llm_client
        a, b = json.dumps({"text": "x" * 250 + "first"}), json.dumps({"text": "x" * 250 + "second"})
        with mock.patch.object(llm_client, "_load_guide", return_value=object()), \
             mock.patch.object(llm_client, "_complete", side_effect=[a, b]), \
             mock.patch.object(llm_client, "_append_log"):
            r1 = llm_client.generate_llm_response("p", response_schema={"text": "string"})
            r2 = llm_client.generate_llm_response("p", response_schema={"text": "string"})
        self.assertNotEqual(r1["response_id"], r2["response_id"])

    def test_scope_is_per_requirement(self):
        from tc_system.review import requirement_scope
        set_ = step(cdw10="0x04")
        get = step(name="Get Features", phase="verify", opcode="0x0A", cdw10="0x04", cdw11="0x0")
        tc = tc_for([set_, get])
        self.assertEqual(requirement_scope(tc, {"checks": [{"kind": "completion", "step": 0}]}), "완료 상태만 확인")
        self.assertEqual(requirement_scope(tc, {"checks": [{"kind": "result_bits", "step": 1, "mask": "0xFFFF",
                                                            "value": "0x12c"}]}), "설정 왕복(저장된 값만 확인)")

    def test_progress_counts_only_this_runs_skips(self):
        from report.html_report import _progress_section
        html = _progress_section([dict(tc_for([step()]), run_id="r2", status="PASS")],
                                 [{"run_id": "r1"}, {"run_id": "r1"}, {"run_id": "r2"}], "r2")
        self.assertIn('<div class="stat-value">1</div><div class="stat-sub">생성·인자', html)


class TestFollowUpReview(unittest.TestCase):
    """docs/reviews/2026-11-05-followup-review (F01..F05) and the code review after it."""

    def test_F01_an_interrupt_during_the_change_still_restores(self):
        tc = with_restore(step(cdw10="0x04", cdw11="0x12c"))
        state = {"value": 360}

        def device(s):
            if int(s["opcode"], 16) == 0x0A:
                return reply(state["value"])
            state["value"] = int(s["cdw11"], 16) & 0xFFFF
            if s["phase"] == "action":
                raise KeyboardInterrupt  # applied, but the call never returned
            return reply()

        with self.assertRaises(KeyboardInterrupt):
            run(tc, device)
        self.assertEqual(state["value"], 360)

    def test_a_rejected_change_is_not_restored_or_flagged(self):
        tc = with_restore(step(cdw10="0x04", cdw11="0x12c", expected_status="INVALID_FIELD"))
        execution, sent = run(tc, lambda s: reply(5) if int(s["opcode"], 16) == 0x0A else reply(error="INVALID_FIELD"))
        self.assertEqual([s["phase"] for s in sent], ["setup", "action"])  # no restore, no read-back
        self.assertTrue(execution["step_results"][-1]["cleanup_not_needed"])
        tc = dict(tc, execution=execution, status=check_expectation(tc, execution), step_statuses=[])
        self.assertNotIn("cleanup_skipped", [r["code"] for r in review_tc(tc)["reasons"]])

    def test_F02_another_lids_support_does_not_measure_this_premise(self):
        q = ("If a Get Log Page command specifies a Log Page Identifier that is not supported, then the "
             "controller shall abort the command with a status code of Invalid Log Page.")
        ops = [{"name": "Get Log Page", "raw_opcode": "0x02", "command_set": "ADMIN", "opcode": "0x02a"}]

        def plan(index, value):
            return {"description": "d", "preconditions": ["support"], "out_of_scope": [],
                    "precondition_checks": [{"description": "support", "checks": [
                        {"kind": "data_field", "step": 0, "field": "LSUPP", "index": index, "value": value}]}],
                    "steps_plan": [{"opcode_name": "Get Log Page", "phase": "setup", "expected_status": "SUCCESS",
                                    "field_constraints": [{"field": "cdw10", "mask": "0xff", "value": "0x00"}]},
                                   {"opcode_name": "Get Log Page", "phase": "action", "expected_status": "INVALID_LOG_PAGE",
                                    "field_constraints": [{"field": "cdw10", "mask": "0xff", "value": "0x7e"}]}],
                    "requirements": [{"description": "d", "quote": q, "evidence_id": "e",
                                      "checks": [{"kind": "completion", "step": 1}]}]}

        unrelated = plan(0, 1)
        validate_plan_contract(unrelated, [{"evidence_id": "e", "text": q}], "s", ops,
                               device_support={"lids": {0: True}, "fids": {}})
        self.assertTrue(any("7Eh" in n for n in unrelated["unmeasured_preconditions"]))
        own = plan(0x7E, 0)
        validate_plan_contract(own, [{"evidence_id": "e", "text": q}], "s", ops,
                               device_support={"lids": {0: True}, "fids": {}})
        self.assertEqual(own["unmeasured_preconditions"], [])

    def test_F03_host_identifier_is_not_changed_expecting_success(self):
        tc = with_restore(step(cdw10="0x81", cdw11="0x0", nsid=0, data_len=8, direction="write", payload_hex="ab"))
        execution, sent = run(tc, lambda s: reply(0, bytes(8)))
        self.assertEqual(sent, [])

    def test_F04_a_failed_read_back_asks_for_review(self):
        tc = with_restore(step(cdw10="0x04", cdw11="0x12c"))
        reads = {"n": 0}

        def device(s):
            if int(s["opcode"], 16) == 0x0A:
                reads["n"] += 1
                return reply(360) if reads["n"] == 1 else reply(error="INTERNAL")
            return reply()

        execution, _ = run(tc, device)
        tc = dict(tc, execution=execution, status=check_expectation(tc, execution), verification=verify_tc(tc, execution),
                  step_statuses=[])
        self.assertIn(review_tc(tc)["level"], ("recommend", "must"))

    def test_F05_the_latest_run_is_shown_even_with_no_tc(self):
        from report.aggregator import build_tc_model
        from report.html_report import _progress_section
        old, latest = "20261105T010000Z", "20261105T020000Z"
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp)
            save_json_atomic(p / "tc_store.json", [dict(tc_for([step()]), run_id=old, status="PASS",
                                                        execution={"step_results": [reply()]})])
            save_json_atomic(p / "target_skips.json", [{"run_id": latest, "section_id": "s", "opcode": "x", "reason": "r"}])
            save_json_atomic(p / "manifests" / f"{latest}.json", {"run_id": latest})
            with mock.patch.multiple(config, TC_STORE_PATH=p / "tc_store.json", TARGET_SKIPS_PATH=p / "target_skips.json",
                                     COVERAGE_STATE_PATH=p / "c.json", FAILURE_CONTEXTS_DIR=p / "fc",
                                     VERDICTS_DIR=p / "v", RUN_MANIFESTS_DIR=p / "manifests"), \
                 mock.patch.object(config, "active_coverage_index_path", return_value=p / "none.json"):
                model = build_tc_model()
        self.assertEqual(model["run_id"], latest)
        html = _progress_section(model["tc_records"], model["skips"], model["run_id"])
        self.assertIn('<div class="stat-value">0</div><div class="stat-sub">실행', html)
        self.assertIn('<div class="stat-value">1</div><div class="stat-sub">생성·인자', html)

    def test_relabelling_the_action_keeps_a_cleanup_step(self):
        from tc_system.generation.scenario_generator import _validate_steps_plan
        ops = [{"name": n, "raw_opcode": r, "command_set": "ADMIN"} for n, r in
               (("Set Features", "0x09"), ("Get Features", "0x0A"))]
        plan = [{"opcode_name": "Set Features", "phase": "action"}, {"opcode_name": "Get Features", "phase": "verify"},
                {"opcode_name": "Set Features", "phase": "cleanup"}]
        out = _validate_steps_plan(plan, ops[1], ops)
        self.assertEqual([s["phase"] for s in out], ["setup", "action", "cleanup"])

    def test_a_selector_pinned_from_the_role_satisfies_the_action_rule(self):
        q = "The controller shall return the log page requested by the Log Page Identifier field."
        plan = {"description": "d", "preconditions": [], "out_of_scope": [], "precondition_checks": [],
                "steps_plan": [{"opcode_name": "Get Log Page", "phase": "action", "role": "LID 02h 조회",
                                "expected_status": "SUCCESS"}],
                "requirements": [{"description": "d", "quote": q, "evidence_id": "e",
                                  "checks": [{"kind": "completion", "step": 0}]}]}
        validate_plan_contract(plan, [{"evidence_id": "e", "text": q}], "s",
                               [{"name": "Get Log Page", "raw_opcode": "0x02", "command_set": "ADMIN", "opcode": "0x02a"}])
        self.assertEqual(plan["steps_plan"][0]["field_constraints"][0]["value"], "0x2")

    def test_tc_ids_differ_per_requirement_at_the_same_instant(self):
        captured = []
        section = {"section_id": "s", "target_requirement": {"requirement_id": "r1", "kind": "shall", "text": QUOTE}}
        op = {"name": "Get Log Page", "raw_opcode": "0x02", "command_set": "ADMIN", "opcode": "0x02a"}
        ctx = {"existing": [], "available_opcodes": [op], "allow_destructive": True, "allow_placeholder_args": False,
               "target": {"nvme_ctrl": "/dev/nvme0", "nvme_ns": "/dev/nvme0n1"}, "active_nsid": 1, "lba_bytes": 512,
               "device_facts": None, "device_support": None, "index": None}
        fixed = pipeline.datetime(2026, 11, 5, tzinfo=pipeline.timezone.utc)
        with mock.patch.object(pipeline, "datetime") as clock, \
             mock.patch.object(pipeline, "generate_scenario", side_effect=ValueError("stop")):
            clock.now.return_value = fixed
            for rid in ("r1", "r2"):
                with mock.patch.object(pipeline, "stable_id", side_effect=lambda *a: captured.append(a) or "id"):
                    pipeline._prepare_target(dict(section, target_requirement=dict(section["target_requirement"],
                                                                                    requirement_id=rid)), op, ctx)
        self.assertNotEqual(captured[0], captured[1])

    def test_run_judge_survives_an_attribute_error_from_a_reply(self):
        import run_judge
        from log_judge.models import make_failure_context
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            fc = make_failure_context(failure_context_id="fc-1", source_type="TC_EXEC", run_id="t",
                                      timestamp="x", primary_log_excerpt="x", signals={})
            save_json_atomic(temp / "failure_contexts" / "tc_exec" / "fc.json", fc)
            with mock.patch.object(config, "FAILURE_CONTEXTS_DIR", temp / "failure_contexts"), \
                 mock.patch.object(config, "VERDICTS_DIR", temp / "verdicts"), \
                 mock.patch.object(config, "TC_STORE_PATH", temp / "tc_store.json"), \
                 mock.patch.object(run_judge, "judge_failure_context", side_effect=AttributeError("bad reply")):
                new, _, failures = run_judge.judge_source("tc_exec")
        self.assertEqual((new, len(failures)), ([], 1))


class TestReview1106(unittest.TestCase):
    """docs/reviews/2026-11-06-review (N01..N03) and the code review before it."""

    def test_N01_a_failure_while_processing_still_restores(self):
        tc = with_restore(step(cdw10="0x04", cdw11="0x12c"))
        state = {"value": 360}

        def device(s):
            if int(s["opcode"], 16) == 0x0A:
                return reply(state["value"])
            state["value"] = int(s["cdw11"], 16) & 0xFFFF
            return reply(error="INTERNAL") if s["phase"] == "action" else reply()

        execution, sent = run(tc, device)
        self.assertEqual(state["value"], 360)
        self.assertEqual([s["phase"] for s in sent], ["setup", "action", "cleanup", "setup"])
        self.assertTrue(execution["step_results"][-1]["restore_verified"])

    def _fid_plan(self, description):
        from tc_system.generation.variants import RULES
        q = RULES["reserved_fid"][1]
        ops = [{"name": "Get Log Page", "raw_opcode": "0x02", "command_set": "ADMIN", "opcode": "0x02a"},
               {"name": "Get Features", "raw_opcode": "0x0A", "command_set": "ADMIN", "opcode": "0x0Aa"}]
        plan = {"description": "d", "preconditions": [description], "out_of_scope": [],
                "precondition_checks": [{"description": description, "checks": [
                    {"kind": "data_field", "step": 0, "field": "FSUPP", "index": "7Fh", "value": 0}]}],
                "steps_plan": [{"opcode_name": "Get Log Page", "phase": "setup", "expected_status": "SUCCESS",
                                "field_constraints": [{"field": "cdw10", "mask": "0xff", "value": "0x12"}]},
                               {"opcode_name": "Get Features", "phase": "action", "expected_status": "INVALID_FIELD",
                                "field_constraints": [{"field": "cdw10", "mask": "0x7ff", "value": "0x7f"}]}],
                "requirements": [{"description": "d", "quote": q, "evidence_id": "e",
                                  "checks": [{"kind": "completion", "step": 1}]}]}
        validate_plan_contract(plan, [{"evidence_id": "e", "text": q}], "s", ops,
                               device_support={"lids": {}, "fids": {1: True}})
        return plan, q

    def test_N02_a_fid_measured_unsupported_in_the_tc_is_measured(self):
        plan, q = self._fid_plan("FID 7Fh 미지원")
        self.assertEqual(plan["unmeasured_preconditions"], [])
        setup = step(name="Get Log Page", phase="setup", opcode="0x02", cdw10="0x00ff0012", cdw11="0x0",
                     data_len=1024, direction="read")
        action = step(name="Get Features", opcode="0x0A", cdw10="0x7f", cdw11="0x0", data_len=0,
                      direction="none", expected_status="INVALID_FIELD")
        tc = tc_for([setup, action], requirements=plan["requirements"],
                    precondition_checks=plan["precondition_checks"], evidence=[{"evidence_id": "e", "text": q}],
                    unmeasured_preconditions=plan["unmeasured_preconditions"])
        tc["scenario"]["preconditions"] = plan["preconditions"]
        execution = {"step_results": [dict(reply(data=bytes(1024)), step_index=0), dict(reply(), step_index=1)]}
        self.assertEqual(check_expectation(tc, execution), "FAIL")  # FSUPP=0 measured, yet accepted

    def test_N03_unsupported_is_not_read_as_supported(self):
        from tc_system.verification import _bit_polarity
        for text, want in (("FID 7Fh is unsupported", "clear"), ("LID 7Eh is not supported", "clear"),
                           ("the controller does not support FID 7Fh", "clear"), ("FID 7Fh 미지원함", "clear"),
                           ("FID 7Fh is supported", "set"), ("지원됨", "set"), ("FSUPP", None)):
            self.assertEqual(_bit_polarity(text), want, text)
        plan, _ = self._fid_plan("FID 7Fh is unsupported")
        self.assertEqual(int(str(plan["precondition_checks"][0]["checks"][0]["value"]), 0), 0)
        self.assertFalse(plan.get("check_repairs"))

    def test_a_named_check_that_contradicts_its_description_is_not_flipped(self):
        with self.assertRaisesRegex(ValueError, "make them agree"):
            self._fid_plan("FID 7Fh is supported")

    def test_clause_rotation_keeps_less_tried_requirements_first(self):
        from tc_system.coverage import coverage_state
        op = {"name": "Get Log Page", "opcode": "0x02a", "raw_opcode": "0x02", "command_set": "ADMIN"}
        a, b = {"section_id": "base:1", "title": "A"}, {"section_id": "base:2", "title": "B"}
        triples = [(a, op, {"requirement_id": "A1"}), (a, op, {"requirement_id": "A2"}),
                   (b, op, {"requirement_id": "B1"})]
        tried = [{"section_id": "base:2", "opcode": "0x02a", "requirement_id": "B1", "reason": "x"}] * 2
        with mock.patch.object(coverage_state, "requirement_targets", return_value=triples):
            index = mock.Mock(list_opcodes=lambda: [], list_sections=lambda: [])
            picked = coverage_state.pick_next_targets(index, [], 3, skip_records=tried)
        self.assertEqual([s["target_requirement"]["requirement_id"] for s, _ in picked], ["A1", "A2", "B1"])


if __name__ == "__main__":
    unittest.main()
