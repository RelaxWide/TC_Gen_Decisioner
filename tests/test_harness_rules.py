"""Regression fixtures from the 2026-11-05 --all run (191 TCs) and its audit.

Each case is the smallest synthetic reproduction of something that produced a
wrong result for real: a false FAIL, a precondition blocking a command the
drive supports, state left changed, a crash. No device, SSH or LLM; values
are written out here, never copied from a drive dump (no serial numbers).
"""
import json
import re
import unittest
from pathlib import Path
from unittest import mock

import config
from tc_system import spec_fields
from tc_system.execution.expectation_checker import (check_execution, check_expectation, check_step_expectations,
                                                      error_cause, rejected_arguments)
from tc_system.execution.tc_executor import SSHTCExecutor
from tc_system.generation.tc_writer import _shift_checks, plan_state_restore
from tc_system.review import code_review, review_tc
from tc_system.verification import (evaluate_check, status_matches, validate_check, validate_plan_contract,
                                    verify_tc)

# Identify Controller of a drive like the one in the run: OACS=0x0017
# (Security, Format, Firmware, Self-test), ONCS=0x00DF, SANICAP=0x60000002.
ID_CTRL = bytearray(4096)
ID_CTRL[111] = 1
ID_CTRL[256:258] = (0x0017).to_bytes(2, "little")
ID_CTRL[260] = 0x16
ID_CTRL[261] = 0x3F
ID_CTRL[263] = 4
ID_CTRL[328:332] = (0x60000002).to_bytes(4, "little")
ID_CTRL[516:520] = (1).to_bytes(4, "little")
ID_CTRL[520:522] = (0x00DF).to_bytes(2, "little")
ID_CTRL[525] = 0x07


def _dump(data):
    rows = [f"{i:04x}: " + " ".join(f"{b:02x}" for b in data[i:i + 16]) for i in range(0, len(data), 16)]
    return "Admin Command Identify is Success and result: 0x00000000\n" + "\n".join(rows)


def _identify_step(phase="setup"):
    return {"name": "Identify", "phase": phase, "mode": "admin-passthru", "device": "/dev/nvme0", "opcode": "0x06",
            "nsid": 0, "cdw10": "0x00000001", "cdw11": "0x0", "cdw12": "0x0", "cdw13": "0x0",
            "data_len": 4096, "direction": "read", "expected_status": "SUCCESS"}


def _result(i, stdout, code=0, **kw):
    return dict({"step_index": i, "exit_code": code, "stdout": stdout, "started": True}, **kw)


SPEC_CHUNKS = config.RAG_INDEX_DIR / "v20260922_172200" / "chunks.jsonl"
# Registry entries whose row or bit the local text does not render as a table
# row we can match (split across pages / OCR). Listed so a new entry must be
# confirmed against the spec or added here on purpose.
UNCONFIRMED = {"OAES.NSAN", "CTRATT.FDPS", "FRMW.SLOT1RO", "LPA.SMARTS", "LPA.CSES", "LPA.LPEDS", "LPA.TS",
               "LPA.PELS", "HCTMA.HCTMS", "SANICAP.NODMMAS", "ONCS.TSS", "ONCS.NVMVFYS", "ONCS.NVMCPYS", "ONCS.NSZS",
               "VWC.VWCP", "NMIC.SHRNS"}
UNCONFIRMED_ROWS = {"HMMAXD", "SGLS", "LBAF0"}


@unittest.skipUnless(SPEC_CHUNKS.exists(), "local spec chunks not present")
class TestRegistryMatchesTheLocalSpec(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = "\n".join(json.loads(l).get("content", "") for l in SPEC_CHUNKS.open(encoding="utf-8"))

    def test_every_byte_range_and_bit_is_in_the_spec_or_listed_as_unconfirmed(self):
        missing = []
        for table in (spec_fields.ID_CTRL, spec_fields.ID_NS):
            for name, field in table.items():
                lo, hi = field["offset"], field["offset"] + field["width"] - 1
                labels = {f"{hi}:{lo}" if hi != lo else str(lo), f"{hi:02d}:{lo:02d}" if hi != lo else f"{lo:02d}"}
                found = any(re.search(r"(?<![0-9:])" + re.escape(label) + r"(?![0-9:]).{0,300}?\(" + re.escape(name)
                                      + r"\)", self.text) for label in labels)
                if not found and name not in UNCONFIRMED_ROWS:
                    missing.append(f"{name}@{sorted(labels)[0]}")
                for bit_name, bit in field["bits"].items():
                    b = bit["bits"]
                    blabel = f"{b[1]}:{b[0]}" if isinstance(b, tuple) else str(b)
                    found = re.search(r"<td>0?" + re.escape(blabel) + r"</td><td>[^<]{0,90}\(" + re.escape(bit_name) + r"\)",
                                      self.text)
                    if not found and f"{name}.{bit_name}" not in UNCONFIRMED:
                        missing.append(f"{name}.{bit_name}@bit {blabel}")
        self.assertEqual(missing, [])

    def test_status_codes_match_the_spec_tables(self):
        for name, (sct, sc) in {"Invalid Queue Identifier": (1, 0x01), "Invalid Log Page": (1, 0x09),
                                "Unrecovered Read Error": (2, 0x81), "Compare Failure": (2, 0x85)}.items():
            self.assertIn(f"<td>{sc:02X}h</td><td>{name}", self.text)
            self.assertEqual(spec_fields.status_code_of_name(name), (sct, sc))


class TestStatusIsComparedByCode(unittest.TestCase):
    """Four correct rejections became FAILs over spelling (F03)."""
    CASES = [("COMPARE_FAILURE", "NVMe status: COMPARE_FAILED: The command failed due to a miscompare(0x2285)"),
             ("UNRECOVERED_READ_ERROR", "NVMe status: READ_ERROR: The read data could not be recovered(0x6281)"),
             ("INVALID_QUEUE_IDENTIFIER", "NVMe status: QID_INVALID: invalid queue identifier(0x101)")]

    def test_spec_names_match_nvme_cli_tokens(self):
        for expected, out in self.CASES:
            self.assertTrue(status_matches(expected, {"exit_code": 22, "stdout": out, "started": True}), expected)

    def test_a_different_code_still_does_not_match(self):
        out = "NVMe status: INVALID_FIELD: A reserved coded value(0x2)"
        self.assertFalse(status_matches("INVALID_LOG_PAGE", {"exit_code": 22, "stdout": out, "started": True}))

    def test_more_and_dnr_bits_are_not_part_of_the_code(self):
        self.assertEqual(spec_fields.status_code_in_output("NVMe status: READ_ERROR: x(0x6281)"), (2, 0x81))


class TestNamedFieldChecks(unittest.TestCase):
    """At least 17 TCs were stopped by checks reading the wrong bytes (F06)."""

    def test_a_named_bit_becomes_the_spec_offset_and_mask(self):
        out = spec_fields.resolve_named_check({"kind": "data_field", "step": 0, "field": "OACS.NMS", "value": 1},
                                              "id_ctrl")
        self.assertEqual((out["offset"], out["width"], int(out["mask"], 16), int(out["value"], 16)), (256, 2, 0x8, 0x8))

    def test_the_hi_lo_notation_read_as_an_offset_is_caught(self):
        # "OACS 257:256" written as offset 257, width 2: reads OACS high byte + ACL.
        problem = spec_fields.check_matches_description(
            {"offset": 257, "width": 2, "mask": "0x0008", "value": "0x0008"}, "id_ctrl",
            "컨트롤러가 Security Send/Receive를 지원해야 한다(OACS 비트로 확인)")
        self.assertIn("여러 필드", problem)

    def test_a_bit_that_is_not_the_named_one_is_caught(self):
        # Directives checked with mask 0x10 (Device Self-test).
        problem = spec_fields.check_matches_description(
            {"offset": 256, "width": 2, "mask": "0x0010", "value": "0x0000"}, "id_ctrl",
            "컨트롤러가 Directives를 지원하지 않는다(OACS의 DIRS 비트가 0)")
        self.assertIn("DIRS", problem)
        self.assertIn("DSTS", problem)

    def test_a_correct_check_passes_and_reads_the_drive_value(self):
        check = {"kind": "data_field", "step": 0, "offset": 256, "width": 2, "mask": "0x0004", "value": "0x0004"}
        self.assertIsNone(spec_fields.check_matches_description(check, "id_ctrl", "Firmware Download 지원(FWDS)"))
        outcome = evaluate_check(check, [_identify_step()], {0: _result(0, _dump(ID_CTRL))})
        self.assertEqual(outcome["result"], "satisfied")

    def test_supported_log_entry_is_lid_times_four(self):
        # Measured: "LID 25h 지원" was checked at offset 4 mask 0x20.
        problem = spec_fields.check_matches_description(
            {"offset": 4, "width": 1, "mask": "0x20", "value": "0x20"}, "supported_logs",
            "Supported Log Pages(LID 00h)에서 LID 25h가 지원됨")
        self.assertIn("offset 148", problem)

    def test_a_namespace_field_named_on_a_controller_structure_is_caught(self):
        problem = spec_fields.check_matches_description(
            {"offset": 516, "width": 4, "mask": "0xFFFFFFFF", "value": "1"}, "id_ns",
            "NSID 1이 존재해야 한다(Identify Namespace data의 NN 필드가 1 이상)")
        self.assertIn("NN", problem)


def _plan(steps, requirements, precondition_checks=(), preconditions=()):
    return {"description": "d", "preconditions": list(preconditions), "steps_plan": steps,
            "requirements": requirements, "precondition_checks": list(precondition_checks), "out_of_scope": []}


EVIDENCE = [{"evidence_id": "e", "text": "The controller shall abort the command with a status code of Invalid "
                                         "Field in Command if the value is not supported by the controller. "
                                         "If a Get Log Page command is processed that specifies a Log Page "
                                         "Identifier that is not supported, then the controller shall abort the "
                                         "command with a status code of Invalid Log Page."}]
QUOTE_FIELD = "The controller shall abort the command with a status code of Invalid Field in Command"
QUOTE_LOG = "specifies a Log Page Identifier that is not supported, then the controller shall abort"
OPS = [{"name": "Identify", "raw_opcode": "0x06", "command_set": "ADMIN", "opcode": "0x06a"},
       {"name": "Get Features", "raw_opcode": "0x0A", "command_set": "ADMIN", "opcode": "0x0Aa"},
       {"name": "Set Features", "raw_opcode": "0x09", "command_set": "ADMIN", "opcode": "0x09a"},
       {"name": "Get Log Page", "raw_opcode": "0x02", "command_set": "ADMIN", "opcode": "0x02a"},
       {"name": "Create I/O Completion Queue", "raw_opcode": "0x05", "command_set": "ADMIN", "opcode": "0x05a"}]


class TestPlanRules(unittest.TestCase):
    def _validate(self, plan, **kw):
        validate_plan_contract(plan, EVIDENCE, "base:x", OPS, **kw)
        return plan

    def test_a_role_naming_another_fid_than_the_fixed_one_is_rejected(self):
        # Measured: "PLM Config FID 13h" sent as CDW10=0x20D (HMB FID 0Dh, SEL 2).
        steps = [{"opcode_name": "Get Features", "phase": "setup", "role": "PLM Config FID 13h 조회",
                  "field_constraints": [{"field": "cdw10", "mask": "0x7FF", "value": "0x20D"}]},
                 {"opcode_name": "Set Features", "phase": "action", "expected_status": "INVALID_FIELD",
                  "field_constraints": [{"field": "cdw10", "mask": "0xFF", "value": "0x13"}]}]
        req = [{"description": "d", "evidence_id": "e", "quote": QUOTE_FIELD, "checks": [{"kind": "completion", "step": 1}]}]
        with self.assertRaisesRegex(ValueError, "role says FID 13h"):
            self._validate(_plan(steps, req))

    def test_a_support_table_step_is_not_pinned_to_the_id_it_looks_up(self):
        steps = [{"opcode_name": "Get Log Page", "phase": "setup",
                  "role": "Supported Log Pages(LID 00h)에서 LID 7Eh 지원 여부 확인",
                  "field_constraints": [{"field": "cdw10", "mask": "0xFF", "value": "0x00"}]},
                 {"opcode_name": "Get Log Page", "phase": "action", "expected_status": "INVALID_LOG_PAGE",
                  "field_constraints": [{"field": "cdw10", "mask": "0xFF", "value": "0x7E"}]}]
        req = [{"description": "d", "evidence_id": "e", "quote": QUOTE_LOG, "checks": [{"kind": "completion", "step": 1}]}]
        plan = self._validate(_plan(steps, req))
        self.assertEqual([c["value"] for c in plan["steps_plan"][0]["field_constraints"]], ["0x00"])

    def test_data_length_is_dropped_and_alone_it_is_rejected(self):
        steps = [{"opcode_name": "Get Log Page", "phase": "action", "expected_status": "INVALID_LOG_PAGE",
                  "field_constraints": [{"field": "cdw10", "mask": "0xFF", "value": "0x7E"}]}]
        mixed = [{"description": "d", "evidence_id": "e", "quote": QUOTE_LOG,
                  "checks": [{"kind": "completion", "step": 0}, {"kind": "data_length", "step": 0, "bytes": 64}]}]
        plan = self._validate(_plan(steps, mixed))
        self.assertEqual([c["kind"] for c in plan["requirements"][0]["checks"]], ["completion"])
        only = [{"description": "d", "evidence_id": "e", "quote": QUOTE_LOG,
                 "checks": [{"kind": "data_length", "step": 0, "value": 4096}]}]  # "integer required: None" before
        with self.assertRaisesRegex(ValueError, "data_length"):
            self._validate(_plan(steps, only))

    def test_an_always_true_check_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "always true"):
            validate_check({"kind": "data_field", "step": 0, "offset": 0, "width": 1, "mask": "0x70",
                            "value": "0x70", "operator": "le"}, 1)

    def test_a_named_field_check_on_a_controller_identify_is_resolved(self):
        steps = [{"opcode_name": "Identify", "phase": "setup", "role": "Identify Controller로 OACS 측정"},
                 {"opcode_name": "Get Log Page", "phase": "action", "expected_status": "INVALID_LOG_PAGE",
                  "field_constraints": [{"field": "cdw10", "mask": "0xFF", "value": "0x7E"}]}]
        req = [{"description": "d", "evidence_id": "e", "quote": QUOTE_LOG, "checks": [{"kind": "completion", "step": 1}]}]
        pre = [{"description": "Firmware Download 지원", "checks": [{"kind": "data_field", "step": 0,
                                                                   "field": "OACS.FWDS", "value": 1}]}]
        plan = self._validate(_plan(steps, req, pre, ["Firmware Download 지원"]))
        check = plan["precondition_checks"][0]["checks"][0]
        self.assertEqual((check["offset"], check["width"], int(check["mask"], 16)), (256, 2, 0x4))
        self.assertEqual(plan["steps_plan"][0]["field_constraints"][0]["value"], "0x1")  # CNS from the role

    def test_an_inverted_bit_condition_is_rewritten_from_the_description(self):
        # "Save/Select 지원 비트가 1" written as (x & 0x10) != 0x10.
        steps = [{"opcode_name": "Identify", "phase": "setup", "role": "Identify Controller",
                  "field_constraints": [{"field": "cdw10", "mask": "0xFF", "value": "0x01"}]},
                 {"opcode_name": "Set Features", "phase": "action", "expected_status": "INVALID_FIELD",
                  "field_constraints": [{"field": "cdw10", "mask": "0xFF", "value": "0x01"}]}]
        req = [{"description": "d", "evidence_id": "e", "quote": QUOTE_FIELD, "checks": [{"kind": "completion", "step": 1}]}]
        pre = [{"description": "Save and Select Feature Support 비트가 1", "checks": [
            {"kind": "data_field", "step": 0, "offset": 520, "width": 2, "mask": "0x10", "value": "0x10",
             "operator": "ne"}]}]
        plan = self._validate(_plan(steps, req, pre, ["Save and Select Feature Support 비트가 1"]))
        check = plan["precondition_checks"][0]["checks"][0]
        self.assertEqual((check["mask"], check["value"], check["operator"]), ("0x10", "0x10", "eq"))
        self.assertIn("1인 조건", plan["check_repairs"][0]["problem"])

    def test_expecting_invalid_log_page_for_a_supported_lid_is_rejected(self):
        steps = [{"opcode_name": "Get Log Page", "phase": "action", "expected_status": "INVALID_LOG_PAGE",
                  "field_constraints": [{"field": "cdw10", "mask": "0xFF", "value": "0x09"}]}]
        req = [{"description": "d", "evidence_id": "e", "quote": QUOTE_LOG, "checks": [{"kind": "completion", "step": 0}]}]
        with self.assertRaisesRegex(ValueError, "false premise"):
            self._validate(_plan(steps, req), device_support={"lids": {0x09: True}, "fids": {}})
        plan = self._validate(_plan(steps, req), device_support={"lids": {}, "fids": {0x01: True}})
        self.assertTrue(any("LID 09h" in n for n in plan["unmeasured_preconditions"]))

    def test_a_queue_create_on_a_driver_qid_is_rejected_before_anything_is_sent(self):
        steps = [{"opcode_name": "Create I/O Completion Queue", "phase": "action", "expected_status": "QID_INVALID",
                  "field_constraints": [{"field": "cdw10", "mask": "0xFFFF", "value": "0x2"}]}]
        req = [{"description": "d", "evidence_id": "e", "quote": QUOTE_FIELD, "checks": [{"kind": "completion", "step": 0}]}]
        with self.assertRaisesRegex(ValueError, "QID=2"):
            self._validate(_plan(steps, req))

    def test_setting_the_host_memory_buffer_is_rejected(self):
        steps = [{"opcode_name": "Set Features", "phase": "action", "expected_status": "SUCCESS",
                  "field_constraints": [{"field": "cdw10", "mask": "0xFF", "value": "0x0D"}]}]
        req = [{"description": "d", "evidence_id": "e", "quote": QUOTE_FIELD, "checks": [{"kind": "completion", "step": 0}]}]
        with self.assertRaisesRegex(ValueError, "Host Memory Buffer"):
            self._validate(_plan(steps, req))


def _negative_tc(quote, stdout, opcode="0x06", cdw10="0x00000410"):
    step = {"name": "Identify", "phase": "action", "mode": "admin-passthru", "device": "/dev/nvme0", "opcode": opcode,
            "nsid": 0, "cdw10": cdw10, "cdw11": "0x0", "data_len": 4096, "direction": "read",
            "expected_status": "INVALID_FIELD"}
    tc = {"tc_id": "t", "status": None, "steps": [step], "scenario": {"preconditions": []},
          "verification_contract": {"version": 2, "precondition_checks": [], "evidence": [{"evidence_id": "e", "text": quote}],
                                    "requirements": [{"requirement_id": "r", "evidence_id": "e", "quote": quote,
                                                      "description": "d", "checks": [{"kind": "completion", "step": 0}]}]}}
    return tc, {"step_results": [_result(0, stdout, 0)]}


class TestPremises(unittest.TestCase):
    def test_success_on_an_unsupported_premise_is_not_a_fail(self):
        # CNS 10h and LID 09h "must be unsupported" - the drive supported them.
        quote = "If a controller does not support the specified CNS value, then the controller shall abort the command"
        tc, execution = _negative_tc(quote, "Admin Command Identify is Success and result: 0x00000000")
        self.assertEqual(check_expectation(tc, execution), "UNVERIFIED")
        self.assertTrue(any("반증" in i for i in verify_tc(tc, execution)["issues"]))

    def test_accepting_a_value_the_spec_reserves_is_still_a_fail(self):
        quote = "The controller shall abort the command with a status code of Invalid Field in Command if a reserved value is used"
        tc, execution = _negative_tc(quote, "Admin Command Identify is Success and result: 0x00000000")
        self.assertEqual(check_expectation(tc, execution), "FAIL")


class TestSetupFailuresAndUnsupportedFeatures(unittest.TestCase):
    def test_a_refused_setup_step_is_error_not_a_device_fail(self):
        # Create I/O CQ (setup) -> QID_INVALID made Delete CQ a "FAIL" though it never ran.
        setup = {"name": "Create I/O Completion Queue", "phase": "setup", "mode": "admin-passthru", "opcode": "0x05",
                 "expected_status": "SUCCESS", "direction": "none", "data_len": 0}
        action = dict(setup, name="Delete I/O Completion Queue", phase="action", opcode="0x04")
        tc = {"steps": [setup, action], "verification_contract": {}}
        execution = {"step_results": [_result(0, "NVMe status: QID_INVALID: x(0x101)", 22),
                                      {"step_index": 1, "exit_code": None, "stdout": "", "started": False,
                                       "blocked_reason": "stopped"}]}
        self.assertEqual(check_execution(tc, execution), "ERROR")
        self.assertEqual(error_cause(tc, execution)["kind"], "사전 상태")

    def test_a_probed_unsupported_fid_is_unsupported_not_our_argument_error(self):
        step = {"name": "Get Features", "phase": "action", "mode": "admin-passthru", "opcode": "0x0A",
                "cdw10": "0x00000013", "expected_status": "SUCCESS", "direction": "none", "data_len": 0,
                "selector_support": False}
        tc = {"steps": [step], "verification_contract": {}}
        execution = {"step_results": [_result(0, "NVMe status: INVALID_FIELD: x(0x2)", 22)]}
        self.assertEqual(check_step_expectations(tc, execution), ["UNSUPPORTED"])
        self.assertIsNone(rejected_arguments(execution, tc))
        self.assertEqual(check_execution(tc, execution), "UNSUPPORTED")


class TestStateIsRestored(unittest.TestCase):
    def _set_step(self, fid=0x04, cdw11=0x0000012C, save=False):
        return {"name": "Set Features", "phase": "action", "mode": "admin-passthru", "device": "/dev/nvme0",
                "opcode": "0x09", "nsid": 0, "cdw10": f"0x{fid | (save << 31):08X}", "cdw11": f"0x{cdw11:08X}",
                "cdw12": "0x0", "cdw13": "0x0", "cdw14": "0x0", "cdw15": "0x0", "data_len": 0, "direction": "none",
                "expected_status": "SUCCESS", "args_source": "authored"}

    def test_set_features_gets_a_snapshot_and_a_restore(self):
        snaps, cleanups = plan_state_restore([self._set_step()], "/dev/nvme0", "/dev/nvme0n1")
        self.assertEqual((len(snaps), len(cleanups)), (1, 1))
        self.assertEqual((snaps[0]["opcode"], snaps[0]["cdw10"]), ("0x0A", "0x00000004"))
        self.assertEqual(cleanups[0]["phase"], "cleanup")

    def test_write_uncorrectable_is_rewritten_afterwards(self):
        wu = {"name": "Write Uncorrectable", "phase": "action", "mode": "io-passthru", "device": "/dev/nvme0n1",
              "opcode": "0x04", "nsid": 1, "cdw10": "0x00001000", "cdw11": "0x0", "cdw12": "0x00000007"}
        _, cleanups = plan_state_restore([wu], "/dev/nvme0", "/dev/nvme0n1")
        self.assertEqual((cleanups[0]["name"], cleanups[0]["cdw10"], cleanups[0]["cdw12"]),
                         ("Write Zeroes", "0x00001000", "0x00000007"))

    def test_check_indexes_follow_the_inserted_snapshot(self):
        groups = [{"checks": [{"kind": "data_equal", "step": 2, "other_step": 0}]}]
        self.assertEqual(_shift_checks(groups, 1)[0]["checks"][0], {"kind": "data_equal", "step": 3, "other_step": 1})
        self.assertEqual(groups[0]["checks"][0]["step"], 2)  # the scenario itself is untouched

    def test_cleanup_runs_after_the_chain_stops_with_the_value_read_before(self):
        snaps, cleanups = plan_state_restore([self._set_step()], "/dev/nvme0", "/dev/nvme0n1")
        verify = dict(self._set_step(), name="Get Features", phase="verify", opcode="0x0A", cdw11="0x0")
        after = dict(verify)
        steps = snaps + [self._set_step(), verify, after] + cleanups
        tc = {"tc_id": "t", "steps": steps, "verification_contract": {"version": 2, "precondition_checks": []}}
        replies = iter([
            {"step_results": [_result(0, "Admin Command Get Features is Success and result: 0x0000015d")]},
            {"step_results": [_result(0, "Admin Command Set Features is Success and result: 0x0")]},  # changed
            {"step_results": [_result(0, "NVMe status: INTERNAL: x(0x6)", 22)]},   # verify fails: chain stops
            {"step_results": [_result(0, "Admin Command Set Features is Success and result: 0x0")]},  # restore
            {"step_results": [_result(0, "Admin Command Get Features is Success and result: 0x0000015d")]},  # read-back
        ])
        sent = []

        def wire(batch, **kw):
            sent.append(dict(batch[0]))
            return dict(next(replies), batch_stderr="", timed_out=False, dmesg_captured_scoped=True)

        with mock.patch("tc_system.execution.ssh_runner.passthru_cmd"), \
             mock.patch("tc_system.execution.ssh_runner.execute_tc_steps", side_effect=wire), \
             mock.patch("tc_system.execution.ssh_runner.capture_dmesg", return_value=""):
            result = SSHTCExecutor(allow_destructive=True).execute(tc)
        by_index = {r["step_index"]: r for r in result["step_results"]}
        self.assertTrue(by_index[3].get("blocked_reason"))         # the step after the failure is not sent
        self.assertEqual(sent[-2]["cdw11"], "0x0000015D")            # restore used the snapshot value
        self.assertEqual(by_index[4]["sent"]["cdw11"], "0x0000015D")
        self.assertEqual(sent[-1]["name"], "Get Features")          # then read back
        self.assertTrue(by_index[4]["restore_verified"])
        self.assertEqual(check_execution(tc, result), "FAIL")       # the verify decides; the restore is not counted


class TestRestoreReviewFindings(unittest.TestCase):
    """Second review of the harness (P1/P2 findings)."""

    def _set(self, cdw11, fid=0x04, nsid=0, expected="SUCCESS"):
        return {"name": "Set Features", "phase": "action", "mode": "admin-passthru", "device": "/dev/nvme0",
                "opcode": "0x09", "nsid": nsid, "cdw10": f"0x{fid:08X}", "cdw11": f"0x{cdw11:08X}", "cdw12": "0x0",
                "cdw13": "0x0", "cdw14": "0x0", "cdw15": "0x0", "data_len": 0, "direction": "none",
                "expected_status": expected, "args_source": "authored"}

    def test_a_tc_with_a_set_features_step_builds(self):
        # P1: harness entries had no raw_opcode -> KeyError in build_tc, every such TC skipped.
        from tc_system.generation import tc_writer
        section = {"section_id": "base:5.2.26", "spec_doc": "x"}
        op = {"name": "Set Features", "raw_opcode": "0x09", "command_set": "ADMIN", "opcode": "0x09a"}
        get = {"name": "Get Features", "raw_opcode": "0x0A", "command_set": "ADMIN", "opcode": "0x0Aa"}
        resolved = [{"section": section, "opcode_entry": op, "phase": "action", "role": "r",
                     "field_constraints": [{"field": "cdw10", "mask": "0xFF", "value": "0x04"}]},
                    {"section": section, "opcode_entry": get, "phase": "verify", "role": "r",
                     "field_constraints": [{"field": "cdw10", "mask": "0x7FF", "value": "0x04"}]}]
        scenario = {"description": "d", "preconditions": [], "fail_criteria": [], "chain_summary": "c",
                    "rag_response_id": "r", "llm_response_id": "l",
                    "requirements": [{"description": "d", "quote": "q", "checks": [{"kind": "completion", "step": 1}]}]}
        reply = {"cdw10": "0x00000004", "cdw11": "0x0000012C", "cdw12": "0x0", "nsid": 0, "data_len": 0,
                 "direction": "none", "shared_facts": {}, "field_breakdown": "x"}
        with mock.patch.object(tc_writer, "author_args", return_value=dict(reply)):
            tc = tc_writer.build_tc("t", resolved, scenario, "/dev/nvme0", "/dev/nvme0n1", 1)
        self.assertEqual([s["name"] for s in tc["steps"]], ["Get Features", "Set Features", "Get Features", "Set Features"])
        self.assertEqual([s.get("harness") for s in tc["steps"]], ["snapshot", None, None, "restore"])
        self.assertEqual(tc["step_section_ids"], [None, "base:5.2.26", "base:5.2.26", None])
        self.assertEqual(tc["verification_contract"]["requirements"][0]["checks"][0]["step"], 2)  # shifted by 1
        self.assertEqual(len(resolved), 4)  # aligned with tc["steps"] for retries

    def test_two_temperature_sensors_are_two_values(self):
        # P2: (FID, SV) alone restored one sensor.
        snaps, cleanups = plan_state_restore([self._set(0x0001012C), self._set(0x0002012C)], "/dev/nvme0", "/dev/nvme0n1")
        self.assertEqual(len(snaps), 2)
        self.assertEqual(sorted(c["cdw11"] for c in cleanups), ["0x00010000", "0x00020000"])
        same, _ = plan_state_restore([self._set(0x0001012C), self._set(0x00010100)], "/dev/nvme0", "/dev/nvme0n1")
        self.assertEqual(len(same), 1)  # same sensor twice: one original value
        per_ns, _ = plan_state_restore([self._set(0x1, fid=0x05, nsid=1)], "/dev/nvme0", "/dev/nvme0n1")
        self.assertEqual(per_ns[0]["nsid"], 1)  # read back from the namespace it is set on

    def _run(self, steps, replies):
        tc = {"tc_id": "t", "steps": steps, "verification_contract": {"version": 2, "precondition_checks": []}}
        replies, sent = iter(replies), []

        def wire(batch, **kw):
            sent.append(dict(batch[0]))
            return dict({"step_results": [next(replies)]}, batch_stderr="", timed_out=False, dmesg_captured_scoped=True)

        with mock.patch("tc_system.execution.ssh_runner.passthru_cmd"), \
             mock.patch("tc_system.execution.ssh_runner.execute_tc_steps", side_effect=wire), \
             mock.patch("tc_system.execution.ssh_runner.capture_dmesg", return_value=""):
            result = SSHTCExecutor(allow_destructive=True).execute(tc)
        return tc, result, sent

    def test_a_change_whose_original_value_was_not_read_is_not_sent(self):
        # P1: Get Features failed, Set Features succeeded, restore skipped, PASS.
        snaps, cleanups = plan_state_restore([self._set(0x12C)], "/dev/nvme0", "/dev/nvme0n1")
        tc, result, sent = self._run(snaps + [self._set(0x12C)] + cleanups,
                                     [_result(0, "NVMe status: INTERNAL: x(0x6)", 22)])
        self.assertEqual([s["name"] for s in sent], ["Get Features"])  # Set never sent
        by_index = {r["step_index"]: r for r in result["step_results"]}
        self.assertIn("원복 불가", by_index[1]["blocked_reason"])
        self.assertTrue(by_index[2]["cleanup_not_needed"])  # nothing changed, nothing to restore
        self.assertNotEqual(check_expectation(tc, result), "PASS")

    def test_a_negative_test_is_still_sent_and_an_unexpected_change_is_flagged(self):
        snaps, cleanups = plan_state_restore([self._set(0x12C, expected="INVALID_FIELD")], "/dev/nvme0", "/dev/nvme0n1")
        steps = snaps + [self._set(0x12C, expected="INVALID_FIELD")] + cleanups
        tc, result, sent = self._run(steps, [_result(0, "NVMe status: INVALID_FIELD: x(0x2)", 22),
                                             _result(0, "Admin Command Set Features is Success and result: 0x0")])
        self.assertEqual([s["name"] for s in sent], ["Get Features", "Set Features"])
        tc = dict(tc, status=check_expectation(tc, result), execution=result,
                  step_statuses=check_step_expectations(tc, result))
        self.assertEqual(tc["status"], "FAIL")  # accepted what it should have rejected
        self.assertTrue(any(r["code"] == "cleanup_skipped" for r in code_review(tc)))

    def test_data_all_needs_the_whole_buffer(self):
        # P2: one captured zero byte for a 512-byte read was "all zero".
        read = {"name": "Read", "phase": "action", "mode": "io-passthru", "opcode": "0x02", "data_len": 512,
                "direction": "read", "expected_status": "SUCCESS"}
        short = _result(0, "IO Command Read is Success and result: 0x0\n0000: 00")
        full = _result(0, "IO Command Read is Success and result: 0x0\n"
                       + "\n".join(f"{i:04x}: " + " ".join(["00"] * 16) for i in range(0, 512, 16)))
        check = {"kind": "data_all", "step": 0, "value": 0}
        self.assertEqual(evaluate_check(check, [read], {0: short})["result"], "unevaluated")
        self.assertEqual(evaluate_check(check, [read], {0: full})["result"], "satisfied")


class TestFollowUpFixes(unittest.TestCase):
    def test_a_check_on_the_wrong_bytes_is_rewritten_to_the_named_field(self):
        # 106 of 215 Identify checks in the run read another field than their
        # description; rejecting them would skip the targets.
        steps = [{"opcode_name": "Identify", "phase": "setup", "role": "Identify Controller",
                  "field_constraints": [{"field": "cdw10", "mask": "0xFF", "value": "0x01"}]},
                 {"opcode_name": "Get Log Page", "phase": "action", "expected_status": "INVALID_LOG_PAGE",
                  "field_constraints": [{"field": "cdw10", "mask": "0xFF", "value": "0x7E"}]}]
        req = [{"description": "d", "evidence_id": "e", "quote": QUOTE_LOG, "checks": [{"kind": "completion", "step": 1}]}]
        desc = "컨트롤러가 Security Send/Receive를 지원해야 한다(SSRS)"
        pre = [{"description": desc, "checks": [{"kind": "data_field", "step": 0, "offset": 257, "width": 2,
                                                 "mask": "0x0008", "value": "0x0008"}]}]
        plan = _plan(steps, req, pre, [desc])
        validate_plan_contract(plan, EVIDENCE, "base:x", OPS)
        check = plan["precondition_checks"][0]["checks"][0]
        self.assertEqual((check["offset"], check["width"], check["mask"], check["value"]), (256, 2, "0x1", "0x1"))
        self.assertEqual(plan["check_repairs"][0]["reads"], "OACS bit 0 (SSRS)")
        outcome = evaluate_check(check, [_identify_step()], {0: _result(0, _dump(ID_CTRL))})
        self.assertEqual(outcome["result"], "satisfied")  # the drive supports it: no longer blocked

    def test_an_ambiguous_description_is_still_rejected(self):
        steps = [{"opcode_name": "Identify", "phase": "setup", "role": "Identify Controller",
                  "field_constraints": [{"field": "cdw10", "mask": "0xFF", "value": "0x01"}]},
                 {"opcode_name": "Get Log Page", "phase": "action", "expected_status": "INVALID_LOG_PAGE",
                  "field_constraints": [{"field": "cdw10", "mask": "0xFF", "value": "0x7E"}]}]
        req = [{"description": "d", "evidence_id": "e", "quote": QUOTE_LOG, "checks": [{"kind": "completion", "step": 1}]}]
        desc = "OACS 비트로 지원 여부 확인"  # names the field, not which bit
        pre = [{"description": desc, "checks": [{"kind": "data_field", "step": 0, "offset": 257, "width": 2,
                                                 "mask": "0x0008", "value": "0x0008"}]}]
        with self.assertRaisesRegex(ValueError, "named check"):
            validate_plan_contract(_plan(steps, req, pre, [desc]), EVIDENCE, "base:x", OPS)

    def test_a_namespace_feature_is_not_called_unsupported_from_nsid_0(self):
        from tc_system.generation.device_capabilities import device_support
        raw = {"id_ctrl": "oncs      : 0xdf\n",
               "fid_support": "FID=01\nok\nRC=0\n"
                              "FID=03\nNVMe status: INVALID_FIELD: x(0x2)\nNSID_RETRY\nget-feature:0x03 ok\nRC=0\n"
                              "FID=13\nNVMe status: INVALID_FIELD: x(0x2)\nNSID_RETRY\nNVMe status: INVALID_FIELD: x(0x2)\nRC=2\n"}
        self.assertEqual(device_support(raw)["fids"], {0x01: True, 0x03: True, 0x13: False})

    def test_the_feature_instance_is_pinned_for_retries(self):
        from tc_system.generation import tc_writer
        reply = {"cdw10": "0x00000004", "cdw11": "0x0002012C", "cdw12": "0x0", "nsid": 0, "data_len": 0,
                 "direction": "none", "shared_facts": {}, "field_breakdown": "x"}
        op = {"name": "Set Features", "raw_opcode": "0x09", "command_set": "ADMIN", "opcode": "0x09a"}
        with mock.patch.object(tc_writer, "author_args", return_value=dict(reply)):
            step = tc_writer._command_step({"section_id": "s"}, op, "/dev/nvme0", "/dev/nvme0n1", 1, phase="action",
                                           test_intent={"field_constraints": [{"field": "cdw10", "mask": "0xFF",
                                                                               "value": "0x04"}]})
        pinned = [c for c in step["test_intent"]["field_constraints"] if c["field"] == "cdw11"]
        self.assertEqual((pinned[0]["mask"], pinned[0]["value"]), ("0x3f0000", "0x20000"))  # TMPSEL/THSEL of sensor 2

    def test_a_pass_counts_as_covered_with_what_it_observed(self):
        from tc_system.coverage.coverage_state import requirement_coverage
        step = {"name": "Namespace Management", "phase": "action", "mode": "admin-passthru", "opcode": "0x0D",
                "cdw10": "0x0", "expected_status": "INVALID_OPCODE", "direction": "none", "data_len": 0}
        quote = "Commands that are not supported shall be aborted with a status of Invalid Command Opcode"
        tc = {"tc_id": "t", "uses_placeholder_args": False, "steps": [step], "scenario": {"preconditions": []},
              "verification_contract": {"version": 2, "precondition_checks": [], "evidence": [{"evidence_id": "e", "text": quote}],
                                        "requirements": [{"requirement_id": "r", "section_id": "s", "evidence_id": "e",
                                                          "quote": quote, "description": "d",
                                                          "checks": [{"kind": "completion", "step": 0}]}]},
              "execution": {"step_results": [_result(0, "NVMe status: INVALID_OPCODE: x(0x1)", 22)]}}
        rows, summary = requirement_coverage([tc])
        self.assertEqual((rows[0]["status"], rows[0]["scope"]), ("PASS", "미지원 응답 확인"))
        self.assertEqual(summary["requirements_passed_by_scope"], {"미지원 응답 확인": 1})

    def test_judge_and_audit_prompts_stay_bounded_on_a_large_chain(self):
        from log_judge.judge import _build_prompt
        from tc_system.pipeline import _build_tc_exec_failure_context
        from tc_system.review import _audit_prompt
        from tc_system.execution.expectation_checker import evaluate_criteria
        steps = [_identify_step() for _ in range(3)] + [dict(_identify_step("action"), cdw10="0x00000002")]
        quote = "A list of 1,024 namespace IDs is returned to the host containing active NSIDs"
        reqs = [{"requirement_id": f"r{i}", "section_id": "s", "evidence_id": "e", "quote": quote, "description": "d",
                 "checks": [{"kind": "data_equal", "step": 3, "other_step": i}]} for i in range(3)]
        tc = {"tc_id": "t", "name": "TC_big", "steps": steps, "status": "FAIL", "source_opcodes": ["0x06a"],
              "expectation": {"description": "x" * 500}, "scenario": {"preconditions": [], "description": "d"},
              "verification_contract": {"version": 2, "precondition_checks": [], "requirements": reqs,
                                        "evidence": [{"evidence_id": "e", "text": quote}]}}
        execution = {"executed_at": "x", "dmesg_text": "", "step_results": [_result(i, _dump(ID_CTRL)) for i in range(4)]}
        tc["verification"] = verify_tc(tc, execution)
        tc["execution"] = dict(execution, criteria_results=evaluate_criteria(tc, execution))
        judge_prompt = _build_prompt(_build_tc_exec_failure_context(tc, execution))[0]
        self.assertLess(len(judge_prompt), 25000)  # + spec_context (14,000): under the old 95,847
        self.assertIn("step 3 Identify (action)", judge_prompt[:12000])  # the action's output comes first
        self.assertLess(len(_audit_prompt(tc, code_review(tc))), 30000)


class TestReviewReasons(unittest.TestCase):
    def _pass_tc(self, steps, requirements, results, status="PASS"):
        return {"name": "t", "status": status, "steps": steps, "step_statuses": ["PASS"] * len(steps),
                "verification_contract": {"requirements": requirements, "precondition_checks": []},
                "verification": {"requirements": requirements, "issues": []},
                "execution": {"step_results": results}}

    def test_a_timestamp_check_contradicting_the_written_payload_is_flagged(self):
        set_ = {"name": "Set Features", "phase": "action", "mode": "admin-passthru", "opcode": "0x09",
                "cdw10": "0x0000000E", "direction": "write", "data_len": 8, "payload_hex": "0000100000000000"}
        get = {"name": "Get Features", "phase": "verify", "mode": "admin-passthru", "opcode": "0x0A",
               "cdw10": "0x0000000E", "direction": "read", "data_len": 8}
        req = [{"description": "timestamp", "quote": "q", "checks": [
            {"kind": "data_field", "step": 1, "offset": 0, "width": 6, "mask": "0xFFFFFFFFFFFF", "value": 4194304,
             "operator": "ge"}]}]
        reasons = code_review(self._pass_tc([set_, get], req, [], status="FAIL"))
        self.assertTrue(any(r["code"] == "roundtrip_expectation" and "1048576" in r["text"] for r in reasons))

    def test_an_unsupported_only_pass_is_marked(self):
        step = {"name": "Namespace Management", "phase": "action", "mode": "admin-passthru", "opcode": "0x0D",
                "cdw10": "0x0", "expected_status": "INVALID_OPCODE"}
        review = review_tc(self._pass_tc([step], [{"description": "d", "quote": "q", "checks": []}], []))
        self.assertEqual(review["scope"], "미지원 응답 확인")
        self.assertEqual(review["level"], "recommend")

    def test_a_fail_with_a_name_only_status_mismatch_names_the_code(self):
        step = {"name": "Compare", "phase": "action", "mode": "io-passthru", "opcode": "0x05",
                "expected_status": "COMPARE_FAILURE"}
        req = [{"description": "d", "quote": "q", "checks": [{"kind": "completion", "step": 0}],
                "results": [{"check": {"kind": "completion", "step": 0}, "result": "violated",
                             "observed": "COMPARE_FAILED", "expected": "COMPARE_FAILURE"}]}]
        tc = self._pass_tc([step], req, [_result(0, "NVMe status: COMPARE_FAILED: x(0x2285)", 22)], status="FAIL")
        reasons = code_review(tc)
        self.assertTrue(any(r["code"] == "status_alias" for r in reasons))
        self.assertEqual(review_tc(tc)["level"], "must")

    def test_a_defect_verdict_over_a_contradictory_contract_is_held(self):
        from tc_system.review import downgrade_verdict
        verdict = downgrade_verdict({"classification": "firmware_defect", "rationale": "r"},
                                    {"reasons": [{"code": "wrong_field", "source": "code", "text": "x"}]})
        self.assertEqual(verdict["classification"], "needs_engineer_review")


class TestSupportProbe(unittest.TestCase):
    def _raw(self, oncs):
        rows = ["%04x: " % i + " ".join("01" if (i + k) % 4 == 0 and (i + k) // 4 in (0, 2, 5) else "00"
                                        for k in range(16)) for i in range(0, 1024, 16)]
        return {"supported_logs": "Device:nvme0 log_id:0x00\n" + "\n".join(rows),
                "fid_support": "FID=01\nget-feature:0x01, Current value:0x4\nRC=0\n"
                               "FID=13\nNVMe status: INVALID_FIELD: x(0x2)\nRC=2\n",
                "id_ctrl": f"oncs      : {oncs}\n"}

    def test_lids_and_fids_are_read_from_the_probe(self):
        from tc_system.generation.device_capabilities import device_support
        support = device_support(self._raw("0xdf"))
        self.assertEqual(sorted(k for k, v in support["lids"].items() if v), [0, 2, 5])
        self.assertEqual(support["fids"], {0x01: True, 0x13: False})

    def test_without_save_select_the_fid_probe_proves_nothing(self):
        from tc_system.generation.device_capabilities import device_support
        self.assertEqual(device_support(self._raw("0x0f"))["fids"], {})


class TestReplay(unittest.TestCase):
    def test_a_stored_alias_fail_replays_as_not_fail(self):
        from tc_system.replay import replay
        step = {"name": "Compare", "phase": "action", "mode": "io-passthru", "opcode": "0x05",
                "expected_status": "COMPARE_FAILURE", "direction": "write", "data_len": 512}
        tc = {"tc_id": "t", "name": "TC_Compare", "status": "FAIL", "steps": [step],
              "scenario": {"preconditions": []},
              "verification_contract": {"version": 2, "precondition_checks": [],
                                        "evidence": [{"evidence_id": "e", "text": "Compare shall fail with Compare Failure status"}],
                                        "requirements": [{"requirement_id": "r", "evidence_id": "e",
                                                          "quote": "Compare shall fail with Compare Failure status",
                                                          "description": "d", "checks": [{"kind": "completion", "step": 0}]}]},
              "execution": {"step_results": [_result(0, "NVMe status: COMPARE_FAILED: x(0x2285)", 22)]}}
        rows, skips = replay([tc], [{"section_id": "s", "reason": "payload_hex pattern of 43 bytes does not evenly fill"}])
        self.assertEqual((rows[0]["old"], rows[0]["new"]), ("FAIL", "PASS"))
        self.assertTrue(skips[0]["fixed_by"])


if __name__ == "__main__":
    unittest.main()
