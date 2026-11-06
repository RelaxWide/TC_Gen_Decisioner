"""Regression tests for the 2026-11-06 --all run (642 of 1,631 targets).

Each test pins one thing that run showed: a probe value read in only one
output format, mechanical slips in scenario contracts that skipped targets,
a command measured unsupported by a precondition but generated again and
again, review flags raised on code variants and on registers the auditor
decoded wrongly, a status compared by name only, and a pending firmware
activation read as a Sanitize defect. No SSH, LLM or real files.
"""
import unittest
from copy import deepcopy
from unittest import mock

import config
from tc_system import review, spec_fields
from tc_system.coverage.spec_coverage_index import SpecCoverageIndexFile
from tc_system.generation import device_capabilities
from tc_system.verification import (_normalize_contract, _resolve_structure_checks, command_support_measured_absent,
                                    firmware_activation_pending, status_matches, validate_plan_contract, verify_tc)


def step(**overrides):
    s = dict(name="Get Log Page", phase="action", mode="admin-passthru", device="/dev/nvme0", opcode="0x02",
             nsid=0, cdw10="0x0", cdw11="0x0", cdw12="0x0", cdw13="0x0", cdw14="0x0", cdw15="0x0", data_len=0,
             direction="none", expected_status="SUCCESS", args_source="authored", field_constraints=[])
    s.update(overrides)
    return s


class TestProbeFormats(unittest.TestCase):
    def test_plain_id_ns_lba_size_is_read(self):
        # The probe sends `nvme id-ns` without -H: only "lbads:N" is printed.
        text = "nsze : 0x3b9e12b0\nlbaf  0 : ms:0   lbads:9  rp:0x2 (in use)\nlbaf  1 : ms:0   lbads:12 rp:0x1\n"
        self.assertEqual(device_capabilities.in_use_lba_bytes({"id_ns": text}), 512)
        self.assertIn("섹터 크기=512", device_capabilities.summarize_device_capabilities({"id_ns": text}))

    def test_pending_firmware_activation_is_read(self):
        raw = {"fw_log": "Firmware Log for device:nvme0\nafi  : 0x11\nfrs1 : 0x374d5852 (7MXR)\n"}
        self.assertEqual(device_capabilities.firmware_activation_pending(raw), 0x11)
        self.assertIsNone(device_capabilities.firmware_activation_pending({"fw_log": "afi  : 0x1\n"}))
        self.assertIn("펌웨어 활성화 대기", device_capabilities.summarize_device_capabilities(raw))


class TestMechanicalContractSlips(unittest.TestCase):
    def test_slips_are_undone_and_recorded(self):
        structured = {
            "steps_plan": [{"opcode_name": "Identify", "phase": "setup", "field_constraints": [
                {"field": "nsid", "value": "1"}, {"field": "cdw11", "mask": "0x0", "value": "0x0"},
                {"field": "cdw1", "mask": "0xFFFFFFFF", "value": "0x1"}]}],
            "requirements": [{"description": "d", "checks": [
                {"kind": "offset", "step": 0, "offset": 4, "width": 1, "mask": "0xFF", "value": 1},
                {"kind": "data_field", "step": 0, "offset": 8, "width": 2, "value": 3},
                {"kind": "data_field", "step": 0, "field": "GENCTR@0+8", "value": 1, "operator": "ne"}]}]}
        _normalize_contract(structured)
        constraints = structured["steps_plan"][0]["field_constraints"]
        self.assertEqual(constraints, [{"field": "nsid", "value": "1", "mask": "0xFFFFFFFF"},
                                       {"field": "nsid", "mask": "0xFFFFFFFF", "value": "0x1"}])
        checks = structured["requirements"][0]["checks"]
        self.assertEqual(checks[0]["kind"], "data_field")
        self.assertEqual(checks[1]["mask"], "0xffff")
        self.assertEqual((checks[2]["offset"], checks[2]["width"], checks[2]["label"], checks[2]["mask"]),
                         (0, 8, "GENCTR", hex((1 << 64) - 1)))
        self.assertNotIn("field", checks[2])
        self.assertEqual(len(structured["check_repairs"]), 7)

    def test_a_named_offset_check_on_a_structure_without_names_is_a_label(self):
        # Sanitize Status (LID 81h) was fixed; the error said "LID is not fixed".
        by_name = {"Get Log Page": {"command_set": "ADMIN", "raw_opcode": "0x02", "name": "Get Log Page"}}
        plan = [{"opcode_name": "Get Log Page", "phase": "setup",
                 "field_constraints": [{"field": "cdw10", "mask": "0xFF", "value": "0x81"}]}]
        structured = {"requirements": [{"description": "d", "checks": [
            {"kind": "data_field", "step": 0, "field": "SSTAT", "offset": 0, "width": 2, "mask": "0x7", "value": 1}]}]}
        _resolve_structure_checks(structured, plan, by_name)
        check = structured["requirements"][0]["checks"][0]
        self.assertEqual(check.get("label"), "SSTAT")
        self.assertNotIn("field", check)
        # Without an offset the message names the real problem, not the LID.
        structured["requirements"][0]["checks"] = [{"kind": "data_field", "step": 0, "field": "SSTAT", "value": 1}]
        with self.assertRaisesRegex(ValueError, r"LID 81h data has no named fields"):
            _resolve_structure_checks(structured, plan, by_name)


class TestStatusNames(unittest.TestCase):
    def test_spec_spellings_resolve_to_codes(self):
        out = {"started": True, "exit_code": 5,
               "stdout": "NVMe status: READ_ERROR: The read data could not be recovered from the media(0x2281)"}
        self.assertTrue(status_matches("UNRECOVERED_ERROR", out))
        self.assertEqual(spec_fields.status_code_of_name("INVALID_PROT_INFO"), (1, 0x81))
        self.assertEqual(spec_fields.status_code_of_name("ASYMMETRIC_ACCESS_INACCESSIBLE"), (3, 0x02))
        self.assertEqual(spec_fields.status_code_of_name("SANITIZE_PROHIBITED_WHILE_PERSISTENT_MEMORY_REGION_IS_ENABLED"),
                         (1, 0x23))

    def test_an_unknown_expected_status_is_refused_with_suggestions(self):
        index = SpecCoverageIndexFile(config.active_coverage_index_path())
        structured = {"steps_plan": [{"opcode_name": "Identify", "phase": "action",
                                      "expected_status": "INVALID_COMMAND_ID", "field_constraints": [
                                          {"field": "cdw10", "mask": "0xFF", "value": "0x1"}]}],
                      "requirements": [], "preconditions": [], "precondition_checks": []}
        with self.assertRaisesRegex(ValueError, r"not a status code this harness knows.*did you mean"):
            validate_plan_contract(structured, [], "base:5.2.13", index.list_opcodes())


class TestCommandMeasuredUnsupported(unittest.TestCase):
    def _tc(self, check, observed, structure_step):
        steps = [structure_step, step(name="Copy", mode="io-passthru", opcode="0x19", phase="action",
                                      device="/dev/nvme0n1", nsid=1)]
        return {"steps": steps,
                "execution": {"step_results": [{"step_index": 0, "started": True, "exit_code": 0, "stdout": "ok"},
                                               {"step_index": 1, "started": False, "blocked_reason": "precondition"}]},
                "verification": {"preconditions": [{"description": "Copy 지원", "results": [
                    {"check": check, "result": "violated", "observed": observed}]}]}}

    def test_its_own_oncs_bit_or_csupp_marks_the_command(self):
        identify = step(name="Identify", opcode="0x06", cdw10="0x1", phase="setup", data_len=4096)
        oncs = {"kind": "data_field", "step": 0, "offset": 520, "width": 2, "mask": "0x100", "value": "0x100"}
        self.assertIn("ONCS.NVMCPYS=0", command_support_measured_absent(self._tc(oncs, 0, identify)))
        cse_step = step(cdw10="0x05", phase="setup", data_len=4096)
        csupp = {"kind": "data_field", "step": 0, "offset": 1024 + 0x19 * 4, "width": 4, "mask": "0x1", "value": "0x1"}
        self.assertIn("CSUPP=0", command_support_measured_absent(self._tc(csupp, 0, cse_step)))

    def test_another_bit_or_a_sent_action_does_not(self):
        identify = step(name="Identify", opcode="0x06", cdw10="0x1", phase="setup", data_len=4096)
        compare_bit = {"kind": "data_field", "step": 0, "offset": 520, "width": 2, "mask": "0x1", "value": "0x1"}
        self.assertIsNone(command_support_measured_absent(self._tc(compare_bit, 0, identify)))
        oncs = {"kind": "data_field", "step": 0, "offset": 520, "width": 2, "mask": "0x100", "value": "0x100"}
        tc = self._tc(oncs, 0, identify)
        tc["execution"]["step_results"][1] = {"step_index": 1, "started": True, "exit_code": 0, "stdout": "ok"}
        self.assertIsNone(command_support_measured_absent(tc))


class TestFirmwareActivationPending(unittest.TestCase):
    def test_a_sanitize_refused_for_pending_activation_is_not_judged(self):
        steps = [step(name="Sanitize", opcode="0x84", cdw10="0x102")]
        results = {0: {"step_index": 0, "started": True, "exit_code": 5,
                       "stdout": "NVMe status: FW_NEEDS_RESET: synthetic(0x111)"}}
        self.assertIn("펌웨어 활성화 대기", firmware_activation_pending(steps, results))
        # Firmware Commit itself answering so is the expected outcome.
        self.assertIsNone(firmware_activation_pending([step(name="Firmware Commit", opcode="0x10")], results))
        tc = {"status": "FAIL", "steps": steps,
              "verification_contract": {"version": 2, "requirements": [
                  {"description": "d", "quote": "q", "evidence_id": "e", "checks": [{"kind": "completion", "step": 0}]}]}}
        verification = verify_tc(tc, {"step_results": list(results.values())})
        self.assertNotEqual(verification["status"], "FAIL")
        tc["verification"] = verification
        reasons = review.code_review(tc)
        self.assertIn("fw_activation_pending", {r["code"] for r in reasons if r["level"] == "must"})


class TestReviewOfVariantsAndRegisters(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tc_system.generation.variants import variant_targets
        cls.index = SpecCoverageIndexFile(config.active_coverage_index_path())
        cls.ops = {o["name"]: o for o in cls.index.list_opcodes()}
        cls.variants = variant_targets(cls.index, nsze=0x1000, lba_bytes=512)

    def _passed(self, family, support=None):
        from tc_system.generation.variants import build_variant_tc
        variant = next(v for v in self.variants if v["family"] == family)
        tc = build_variant_tc("t", variant, self.ops[variant["command"]], "/dev/nvme0", "/dev/nvme0n1", 1, 512,
                              support)
        tc["status"] = "PASS"
        return tc

    def test_a_reserved_lid_variant_carries_the_probe_answer(self):
        tc = self._passed("reserved_lid", {"lids": {i: False for i in range(256)}, "fids": {}})
        self.assertIs(tc["steps"][0]["selector_support"], False)
        self.assertNotIn("support_unknown", {r["code"] for r in review.code_review(tc)})

    def test_a_reserved_fid_variant_is_a_note_and_not_audited(self):
        tc = self._passed("reserved_fid")
        notes = [r for r in review.code_review(tc) if r["code"] == "support_unknown"]
        self.assertEqual([r["level"] for r in notes], ["info"])
        with mock.patch.object(review, "llm_audit", side_effect=AssertionError("audited")):
            self.assertEqual(review.review_tc(tc, use_llm=True)["level"], "info")

    def test_the_auditor_sees_decoded_registers_and_sent_values(self):
        self.assertEqual(review.decode_command(step(cdw10="0x007F0000"))["LID"], "0x0")
        self.assertEqual(review.decode_command(step(opcode="0x10", cdw10="0x19"))["CA"], "0x3")
        wz = review.decode_command(step(mode="io-passthru", opcode="0x08", cdw12="0x01800001"))
        self.assertEqual((wz["NSZ"], wz["STC"], wz["DEAC"]), ("0x1", "0x1", "0x0"))
        restore = step(phase="cleanup", opcode="0x09", cdw10="0x1", cdw11="0x0", harness="restore")
        tc = {"status": "FAIL", "name": "t", "steps": [restore],
              "execution": {"step_results": [{"step_index": 0, "started": True, "exit_code": 0, "stdout": "ok",
                                              "sent": {"cdw10": "0x1", "cdw11": "0x01020300", "data_len": 0}}]}}
        prompt = review._audit_prompt(tc, [])
        self.assertIn('"cdw11": "0x01020300"', prompt)
        self.assertIn('"decoded": {"FID": "0x1", "SV": "0x0"}', prompt)


class TestMidrunReview(unittest.TestCase):
    """docs/reviews/2026-11-06-midrun: counterexamples against the code above."""

    def test_a_refusal_does_not_judge_a_data_rule(self):
        # §2: the DSLBA rule "passed" on INVALID_OPCODE and counted as judged.
        from tc_system.coverage.coverage_state import judged_target_requirements
        from tc_system.verification import VERSION, _bind_target_requirement
        quote = ("The Descriptor Starting LBA (DSLBA) field in the first LBA Status Descriptor Entry returned in the "
                 "LBA Status Descriptor List shall contain the lowest numbered LBA that is greater than or equal to "
                 "the value specified in the Starting LBA field in the Get LBA Status command.")
        req = {"description": "d", "quote": quote, "evidence_id": "e", "checks": [{"kind": "completion", "step": 0}]}
        target = {"kind": "shall", "requirement_id": "t-dslba", "text": quote}
        contract = {"version": VERSION, "requirements": [req], "precondition_checks": [],
                    "evidence": [{"evidence_id": "e", "text": quote}], "target_requirement": target}
        _bind_target_requirement(contract, [{"opcode_name": "Get LBA Status"}], 0, target)
        tc = {"uses_placeholder_args": False, "scenario": {"preconditions": []}, "verification_contract": contract,
              "steps": [{"name": "Get LBA Status", "phase": "action", "expected_status": "INVALID_OPCODE"}]}
        execution = {"step_results": [{"step_index": 0, "exit_code": 1,
                                       "stdout": "NVMe status: INVALID_OPCODE: Invalid Command Opcode(0x1)"}]}
        tc["execution"] = execution
        tc["verification"] = verification = verify_tc(tc, execution)
        self.assertEqual(verification["status"], "UNVERIFIED")
        self.assertTrue(verification["requirements"][0]["unobserved"])
        self.assertEqual(judged_target_requirements([tc]), set())
        self.assertIn("target_unobserved", {r["code"] for r in review.code_review(dict(tc, status="PASS"))})
        # A sentence that is itself about refusing stays judged by the refusal.
        rule = "If the command is not supported, then the controller shall abort the command with Invalid Opcode."
        contract["target_requirement"] = dict(target, text=rule)
        req.update(quote=rule)
        contract["evidence"][0]["text"] = rule
        self.assertEqual(verify_tc(tc, execution)["status"], "PASS")

    def test_a_comparison_without_the_lba_size_is_not_made(self):
        # §3: NLB=3 with a 4096-byte buffer; the device moved 2048 bytes.
        from tc_system.verification import evaluate_check
        def io(opcode, direction):
            return step(name="X", mode="io-passthru", device="/dev/nvme0n1", opcode=opcode, nsid=1, cdw12="0x3",
                        data_len=4096, direction=direction, payload_hex="A55A", phase="setup" if opcode == "0x01" else "verify")
        dump = "\n".join(f"{o:04x}: " + " ".join("a5 5a" for _ in range(8)) for o in range(0, 4096, 16))
        results = {i: {"step_index": i, "started": True, "exit_code": 0, "stdout": f"IO Command X is Success and result: 0x00000000\n{dump}"}
                   for i in (0, 1)}
        outcome = evaluate_check({"kind": "data_matches_write", "step": 1, "other_step": 0},
                                 [io("0x01", "write"), io("0x02", "read")], results)
        self.assertEqual(outcome["result"], "unevaluated")
        self.assertIn("LBA 크기", outcome["detail"])

    def _plan(self, steps, checks):
        index = SpecCoverageIndexFile(config.active_coverage_index_path())
        structured = {"steps_plan": steps, "preconditions": [], "precondition_checks": [],
                      "requirements": [{"description": "d", "quote": "q" * 30, "evidence_id": "e", "checks": checks}]}
        return lambda: validate_plan_contract(structured, [], "base:5.2.26", index.list_opcodes())

    def test_reserved_completion_bits_and_capabilities_layout_are_refused(self):
        # §5: Arbitration low byte compared with 8 (AB is bits 2:0).
        get = {"opcode_name": "Get Features", "phase": "verify", "role": "FID 01h",
               "field_constraints": [{"field": "cdw10", "mask": "0x7FF", "value": "0x001"}]}
        set_ = {"opcode_name": "Set Features", "phase": "action", "expected_status": "SUCCESS", "role": "FID 01h",
                "field_constraints": [{"field": "cdw10", "mask": "0xFF", "value": "0x01"}]}
        with self.assertRaisesRegex(ValueError, r"reads bits 0xf8 .*reserved"):
            self._plan([set_, get], [{"kind": "result_bits", "step": 1, "mask": "0xFF", "value": 8}])()
        # §7: a current-value bit read from the SEL=011b capabilities DW0.
        caps = dict(get, phase="setup", role="FID 05h capabilities",
                    field_constraints=[{"field": "cdw10", "mask": "0x7FF", "value": "0x305"}])
        with self.assertRaisesRegex(ValueError, r"SEL=011b capabilities"):
            self._plan([caps, set_], [{"kind": "result_bits", "step": 0, "mask": "0x10000", "value": 0}])()

    def test_a_whole_firmware_slot_log_is_not_compared(self):
        # §6: AFI 0x11 -> 0x01 after the reset is the pending slot clearing.
        log = {"opcode_name": "Get Log Page", "phase": "setup", "role": "LID 03h",
               "field_constraints": [{"field": "cdw10", "mask": "0xFF", "value": "0x03"}]}
        commit = {"opcode_name": "Firmware Commit", "phase": "action", "expected_status": "SUCCESS",
                  "field_constraints": [{"field": "cdw10", "mask": "0x3F", "value": "0x11"}]}
        with self.assertRaisesRegex(ValueError, r"LID 03h log .*change by design"):
            self._plan([log, commit, dict(log, phase="verify")],
                       [{"kind": "data_equal", "step": 2, "other_step": 0}])()

    def test_role_and_encoding_must_agree(self):
        # §4: role said DEAC=1, CDW12=0x01800001 sent DEAC=0 and STC=1.
        from tc_system.command_fields import role_field_mismatch
        wrong = role_field_mismatch("NVM", 0x08, {"cdw12": "0x01800001"}, "Write Zeroes NSZ=1, DEAC=1로 전체 클리어")
        self.assertIn("DEAC=1 (encoded DEAC=0)", wrong)
        self.assertIsNone(role_field_mismatch("NVM", 0x08, {"cdw12": "0x02800000"}, "NSZ=1, DEAC=1"))
        self.assertIn("CA=2", role_field_mismatch("ADMIN", 0x10, {"cdw10": "0x19"}, "CA=010b, FS=1 커밋") or "")
        self.assertIsNone(role_field_mismatch("ADMIN", 0x10, {"cdw10": "0x19"}, "CA=011b, FS=1"))

    def test_set_features_reserved_bits_are_refused_when_success_is_expected(self):
        from tc_system.generation import args_author
        reply = {"structured": {"cdw10": "0x1", "cdw11": "0x01020308", "cdw12": "0x0", "cdw13": "0x0",
                                "cdw14": "0x0", "cdw15": "0x0", "data_len": 0, "direction": "none", "nsid": 0},
                 "response_id": "r"}
        op = {"name": "Set Features", "command_set": "ADMIN", "raw_opcode": "0x09"}
        with mock.patch.object(args_author, "generate_llm_response", return_value=reply):
            with self.assertRaisesRegex(args_author.ArgsAuthoringError, r"reserved bits 0x8"):
                args_author._author_once("p", op, 1, test_intent={"expected_status": "SUCCESS", "role": "FID 01h"})

    def test_the_auditor_alone_does_not_make_a_must(self):
        llm_must = [{"level": "must", "code": "llm_audit", "source": "llm", "text": "x"}]
        alone = review.escalation({"status": "PASS"}, [], llm_must)
        self.assertEqual((alone[0]["level"], alone[0]["llm_level"]), ("recommend", "must"))
        self.assertTrue(alone[0]["text"].startswith("(LLM 단독 의견)"))
        corroborating = [{"level": "recommend", "code": "actor", "source": "code", "text": "y"}]
        self.assertEqual(review.escalation({"status": "PASS"}, corroborating, llm_must)[0]["level"], "must")
        self.assertEqual(review.escalation({"status": "FAIL"}, [], llm_must)[0]["level"], "must")
        # The judge is an LLM too: it does not corroborate the auditor.
        judge = [{"level": "recommend", "code": "verdict_review", "source": "code", "text": "z"}]
        self.assertEqual(review.escalation({"status": "PASS"}, judge, llm_must)[0]["level"], "recommend")

    def test_judge_review_on_a_held_error_and_an_unsupported_cleanup_are_recommend(self):
        tc = {"status": "ERROR", "steps": [step(name="Capacity Management", opcode="0x20", phase="cleanup")],
              "execution": {"step_results": [{"step_index": 0, "started": True, "exit_code": 1,
                                              "stdout": "NVMe status: INVALID_OPCODE: x(0x1)"}]}}
        reasons = {r["code"]: r["level"] for r in review.code_review(tc, {"classification": "needs_engineer_review"})}
        self.assertEqual(reasons["verdict_review"], "recommend")
        self.assertEqual(reasons["cleanup_failed"], "recommend")
        self.assertEqual({r["code"]: r["level"] for r in review.code_review(dict(tc, status="FAIL"), {
            "classification": "needs_engineer_review"})}["verdict_review"], "must")

    def test_nszs_is_bit_12(self):
        check = spec_fields.resolve_named_check({"field": "ONCS.NSZS", "value": 1}, "id_ctrl")
        self.assertEqual((check["offset"], check["mask"]), (520, hex(1 << 12)))


class TestPowerCycleOffer(unittest.TestCase):
    """2026-11-06: no PMU was configured, the prompt still listed power_cycle,
    the model planned "Power Cycle (PMU)" and the plan was refused."""

    def test_the_prompt_lists_only_what_the_run_offers(self):
        from tc_system.execution.host_actions import host_action_entries
        from tc_system.generation.scenario_generator import run_capabilities
        self.assertNotIn("power_cycle", run_capabilities(host_action_entries(None)))
        self.assertIn("controller_reset", run_capabilities(host_action_entries(None)))
        self.assertIn("power_cycle", run_capabilities(host_action_entries({"script": "/x/pmu_4_1.py"})))

    def test_a_planned_power_cycle_without_a_pmu_says_why(self):
        from tc_system.execution.host_actions import host_action_entries
        from tc_system.generation.scenario_generator import _validate_steps_plan
        ops = [{"name": "Flush", "command_set": "NVM", "raw_opcode": "0x00", "opcode": "nvm:0x00"}]
        plan = [{"opcode_name": "Flush", "phase": "action"}, {"opcode_name": "Power Cycle (PMU)", "phase": "verify"}]
        with self.assertRaisesRegex(ValueError, "no PMU board"):
            _validate_steps_plan(plan, ops[0], ops + host_action_entries(None))

    def test_the_probe_checks_the_script_on_the_target(self):
        from tc_system.execution import ssh_runner

        class Proc:
            returncode, stdout, stderr = 0, "PMU_SCRIPT_MISSING", ""
        with mock.patch.object(ssh_runner, "_plink", return_value=Proc()) as plink, \
                mock.patch.object(ssh_runner, "_append_ssh_log"), \
                mock.patch.object(config, "get_ssh_target", return_value={"host": "h", "user": "u", "password": "p"}):
            out = ssh_runner.probe_device_capabilities("/dev/nvme0", "/dev/nvme0n1", "/opt/pmu dir/pmu_4_1.py")
        self.assertEqual(out["pmu_script"], "PMU_SCRIPT_MISSING")
        self.assertIn("'/opt/pmu dir/pmu_4_1.py'", plink.call_args_list[-1].args[1])


if __name__ == "__main__":
    unittest.main()
