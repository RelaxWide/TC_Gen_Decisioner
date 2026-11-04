"""Offline contract regressions; responses model nvme-cli's actual output format."""
import copy
import unittest
from unittest.mock import patch

from unittest import mock

import config
from log_judge import judge
from shared import spec_evidence
from shared.rag_client import generate_rag_response
from tc_system.coverage.spec_coverage_index import SpecCoverageIndexFile
from tc_system.verification import (verify_tc, validate_fixed_fields, decode_payload, payload_bytes,
                                    validate_plan_contract)
from tc_system.command_fields import validate_transfer, verify_selectors
from tc_system.execution.expectation_checker import (check_expectation, check_execution, rejected_arguments,
                                                      check_step_expectations, device_hung)
from tc_system.execution.tc_executor import SSHTCExecutor
from tc_system.generation import args_author, scenario_generator
from shared.spec_evidence import section_evidence
from report.html_report import _tc_evidence

QUOTE = 'The controller shall return the supported capabilities in Dword 0.'


def fixture():
    step = {'name': 'Get Features', 'phase': 'action', 'opcode': '0x0a',
            'command_set': 'ADMIN', 'expected_status': 'SUCCESS', 'cdw10': '0x37d',
            'field_constraints': [{'field': 'cdw10', 'mask': '0x7ff', 'value': '0x37d'}],
            'direction': 'none', 'data_len': 0}
    tc = {'tc_id': 'regression', 'steps': [step], 'scenario': {'preconditions': []},
          'verification_contract': {'version': 2, 'precondition_checks': [],
            'evidence': [{'evidence_id': 'source', 'section_id': 'base:5.2.11', 'text': QUOTE}],
            'requirements': [{'requirement_id': 'req', 'section_id': 'base:5.2.11', 'evidence_id': 'source', 'quote': QUOTE,
                'description': 'Check supported capabilities',
                'checks': [{'kind': 'result_bits', 'step': 0, 'mask': 7, 'value': 5}]}]}}
    execution = {'step_results': [{'step_index': 0, 'exit_code': 0,
                   'stdout': 'Admin Command Get Features is Success and result: 0x00000005'}]}
    return tc, execution


class TestEvidenceContract(unittest.TestCase):
    def test_observed_bits_pass_and_wrong_bits_fail(self):
        tc, result = fixture()
        self.assertEqual(verify_tc(tc, result)['status'], 'PASS')
        result['step_results'][0]['stdout'] = 'Admin Command Get Features is Success and result: 0x00000004'
        self.assertEqual(verify_tc(tc, result)['status'], 'FAIL')

    def test_exit_zero_alone_cannot_verify_spec(self):
        tc, result = fixture()
        result['step_results'][0]['stdout'] = 'ok'
        self.assertEqual(verify_tc(tc, result)['status'], 'UNVERIFIED')

    def test_expected_negative_completion_passes_without_reauthor(self):
        tc, result = fixture()
        tc['steps'][0]['expected_status'] = 'INVALID_FIELD'
        tc['verification_contract']['requirements'][0]['checks'] = [{'kind': 'completion', 'step': 0}]
        result['step_results'][0].update(exit_code=22, stdout='NVMe status: INVALID_FIELD: invalid field (0x2)')
        self.assertEqual(check_expectation(tc, result), 'PASS')
        self.assertIsNone(rejected_arguments(result, tc))

    def test_host_error_and_fabricated_quote_cannot_verify(self):
        tc, result = fixture()
        result['step_results'][0].update(exit_code=1, stdout='Permission denied')
        self.assertEqual(check_expectation(tc, result), 'ERROR')
        self.assertEqual(verify_tc(tc, result)['status'], 'UNVERIFIED')
        tc, result = fixture()
        tc['verification_contract']['requirements'][0]['quote'] = 'An invented normative sentence that is absent from the source.'
        self.assertEqual(verify_tc(tc, result)['status'], 'UNVERIFIED')

    def test_unobserved_precondition_prevents_pass(self):
        tc, result = fixture()
        tc['scenario']['preconditions'] = ['Controller supports this feature']
        self.assertEqual(verify_tc(tc, result)['status'], 'UNVERIFIED')

    def test_retry_cannot_change_feature_or_selector(self):
        tc, _ = fixture()
        for value in ('0x302', '0x07d'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_fixed_fields({'cdw10': value}, tc['steps'][0]['field_constraints'])

    def test_hex_payload_requires_contiguous_offsets(self):
        self.assertEqual(decode_payload({'stdout': '0000: 01 02 03 04 ....'}), b'\x01\x02\x03\x04')
        self.assertIsNone(decode_payload({'stdout': '0010: 01 02 03 04'}))

    def test_report_exposes_observation_and_escapes_source(self):
        tc, result = fixture()
        tc['execution'] = result
        tc['scenario']['description'] = '<script>alert(1)</script>'
        html = _tc_evidence(tc)
        self.assertIn('observed', html)
        self.assertIn('expected', html)
        self.assertNotIn('<script>', html)
        self.assertIn('&lt;script&gt;', html)
        self.assertIn('UNVERIFIED', _tc_evidence({'steps': []}))


class TestWireSemantics(unittest.TestCase):
    def test_log_page_zero_based_numd_matches_buffer(self):
        opcode = {'command_set': 'ADMIN', 'raw_opcode': '0x02', 'name': 'Get Log Page'}
        for numd, length in ((128, 512), (127, 508)):
            with self.subTest(numd=numd), self.assertRaises(ValueError):
                validate_transfer({'cdw10': hex(numd << 16 | 2), 'cdw11': '0x0',
                                   'data_len': length, 'direction': 'read'}, opcode)
        validate_transfer({'cdw10': '0x007f0002', 'cdw11': '0x0', 'data_len': 512, 'direction': 'read'}, opcode)

    def test_directive_and_action_selectors_use_their_own_registers(self):
        self.assertTrue(verify_selectors({'cdw11': '0x102'},
            {'command_set': 'ADMIN', 'raw_opcode': '0x19'},
            [{'field_name': 'Directive Type', 'hex_value': '0x01'},
             {'field_name': 'Directive Operation', 'hex_value': '0x02'}]))
        self.assertTrue(verify_selectors({'cdw13': '0x02000000'},
            {'command_set': 'ADMIN', 'raw_opcode': '0x86'},
            [{'field_name': 'Action Type', 'hex_value': '0x02'}]))

    def test_firmware_action_bits_and_download_provenance(self):
        for cdw10, downloaded, expected in ((1, True, 'PASS'), (8, True, 'FAIL'),
                (9, True, 'FAIL'), (17, True, 'PASS'), (25, True, 'FAIL'), (9, False, 'PASS')):
            with self.subTest(cdw10=cdw10, downloaded=downloaded):
                steps = [{'opcode': '0x11', 'direction': 'write', 'data_len': 4}] if downloaded else []
                steps.append({'opcode': '0x10', 'direction': 'none', 'data_len': 0, 'cdw10': hex(cdw10)})
                result = {'step_results': [{'step_index': i, 'exit_code': 0,
                           'stdout': 'Admin Command 0x10 is Success and result: 0x0'} for i in range(len(steps))]}
                self.assertEqual(check_step_expectations({'steps': steps}, result)[-1], expected)

    def test_failed_precondition_blocks_action(self):
        tc, execution = fixture()
        tc['steps'].insert(0, dict(tc['steps'][0], phase='setup'))
        tc['verification_contract']['precondition_checks'] = [{'description': 'capability',
            'checks': [{'kind': 'result_bits', 'step': '0', 'mask': 7, 'value': 6}]}]
        response = dict(execution, dmesg_text='', batch_stderr='', timed_out=False, dmesg_captured_scoped=True)
        with patch('tc_system.execution.ssh_runner.passthru_cmd'), patch(
                'tc_system.execution.ssh_runner.execute_tc_steps', return_value=response) as wire, patch(
                'tc_system.execution.ssh_runner.capture_dmesg', return_value=''):
            result = SSHTCExecutor().execute(tc)
        self.assertEqual(wire.call_count, 1)
        self.assertFalse(result['step_results'][1]['started'])

    def test_invalid_later_step_is_rejected_before_any_ssh(self):
        tc, _ = fixture()
        tc['steps'].append(copy.deepcopy(tc['steps'][0]))
        with patch('tc_system.execution.ssh_runner.passthru_cmd', side_effect=['ok', ValueError('bad fields')]), patch(
                'tc_system.execution.ssh_runner.execute_tc_steps') as wire:
            with self.assertRaises(ValueError):
                SSHTCExecutor().execute(tc)
        wire.assert_not_called()


class TestLocalSpecEvidence(unittest.TestCase):
    def test_exact_clause_and_cross_document_command_are_present(self):
        evidence = section_evidence({'section_id': 'base:5.2.19'}, command_name='NVMe-MI Send')
        sections = {b['section_id'] for b in evidence['chunks']}
        self.assertIn('base:5.2.19', sections)
        self.assertIn('mi:4.3.1', sections)
        self.assertTrue(all(b['evidence_id'] and b['chunk_ids'] for b in evidence['chunks']))
        self.assertTrue(any(len(b['text']) > 2000 for b in evidence['chunks']))


class TestRequirementCoverage(unittest.TestCase):
    def test_legacy_pass_and_placeholders_do_not_verify_requirements(self):
        from tc_system.coverage.coverage_state import requirement_coverage
        tc, execution = fixture()
        tc.update(execution=execution, uses_placeholder_args=True)
        rows, summary = requirement_coverage([tc, {'status': 'PASS', 'uses_placeholder_args': False}])
        self.assertEqual(rows, [])
        self.assertEqual(summary['requirements_evaluated'], 0)

    def test_mixed_observations_and_host_error_remain_distinct(self):
        from tc_system.coverage.coverage_state import requirement_coverage
        tc, execution = fixture()
        tc.update(execution=execution, uses_placeholder_args=False)
        failed = copy.deepcopy(tc)
        failed['execution']['step_results'][0]['stdout'] = 'Admin Command Get Features is Success and result: 0x4'
        host_error = copy.deepcopy(tc)
        host_error['execution']['step_results'][0].update(exit_code=1, stdout='Permission denied')
        rows, summary = requirement_coverage([tc, failed, host_error])
        self.assertEqual(rows[0]['status'], 'MIXED')
        self.assertEqual(rows[0]['observations'][-1]['status'], 'UNVERIFIED')
        self.assertEqual(summary['requirements_evaluated'], 1)

    def test_numeric_cdw_is_not_reinterpreted_as_hex_digits(self):
        from tc_system.generation.args_author import _normalize_hex, ArgsAuthoringError
        self.assertEqual(_normalize_hex(125, 'cdw10'), '0x0000007D')
        with self.assertRaises(ArgsAuthoringError):
            _normalize_hex(True, 'cdw10')


# --- Regressions from the 2026-11-04 review of the spec-verification rewrite ---

OK = "Admin Command Get Features is Success and result: 0x00000000"
INTERNAL = "NVMe status: INTERNAL: The command was not completed successfully due to an internal error(0x6)"


def _step(phase, expected="SUCCESS"):
    return {"phase": phase, "opcode": "0x0a", "mode": "admin-passthru", "direction": "none",
            "data_len": 0, "expected_status": expected, "cdw10": "0x0"}


def _result(i, stdout, code=22, **kw):
    return dict({"step_index": i, "exit_code": code, "stdout": stdout, "started": True}, **kw)


def _blocked(i):
    return {"step_index": i, "exit_code": None, "stdout": "", "started": False,
            "blocked_reason": "step 1 did not complete with the expected status"}


class TestActionResultIsNotHiddenByBlockedSteps(unittest.TestCase):
    def test_action_fail_with_a_blocked_verify_step_is_fail(self):
        tc = {"steps": [_step("setup"), _step("action"), _step("verify")]}
        execution = {"step_results": [_result(0, OK, 0), _result(1, INTERNAL), _blocked(2)]}
        self.assertEqual(check_step_expectations(tc, execution), ["PASS", "FAIL", "ERROR"])
        self.assertEqual(check_execution(tc, execution), "FAIL")

    def test_setup_error_before_the_action_still_wins(self):
        # The action ran without its precondition: its FAIL may be ours.
        tc = {"steps": [_step("setup"), _step("action")]}
        execution = {"step_results": [_result(0, "NVMe status: INVALID_FIELD: x(0x2)"), _result(1, INTERNAL)]}
        self.assertEqual(check_execution(tc, execution), "ERROR")

    def test_precondition_stop_with_nothing_failed_is_unverified(self):
        tc = {"steps": [_step("setup"), _step("action")]}
        execution = {"step_results": [_result(0, OK, 0), _blocked(1)]}
        self.assertEqual(check_execution(tc, execution), "UNVERIFIED")

    def test_never_started_without_a_block_reason_is_still_error(self):
        # SSH dropped mid-batch: nothing about the device was learned.
        tc = {"steps": [_step("action"), _step("verify")]}
        execution = {"step_results": [_result(0, OK, 0),
                                      {"step_index": 1, "exit_code": None, "stdout": "", "started": False}]}
        self.assertEqual(check_execution(tc, execution), "ERROR")


class TestKernelCancelledCommandIsAHang(unittest.TestCase):
    def test_eintr_is_fail_and_triggers_the_hang_handling(self):
        tc = {"steps": [_step("action"), _step("verify")]}
        execution = {"step_results": [_result(0, "passthru: Interrupted system call"), _blocked(1)],
                     "timed_out": False}
        self.assertEqual(check_step_expectations(tc, execution)[0], "FAIL")
        self.assertTrue(device_hung(execution))
        self.assertEqual(check_execution(tc, execution), "FAIL")

    def test_eagain_stays_a_host_error(self):
        tc = {"steps": [_step("action")]}
        execution = {"step_results": [_result(0, "/dev/nvme0: Resource temporarily unavailable")]}
        self.assertEqual(check_step_expectations(tc, execution), ["ERROR"])
        self.assertFalse(device_hung(execution))


class TestNegativeTestOutcomes(unittest.TestCase):
    def test_a_different_rejection_is_requeued_not_judged(self):
        tc = {"steps": [_step("action", expected="INVALID_FIELD")]}
        execution = {"step_results": [_result(0, "NVMe status: INVALID_NS: x(0xb)")]}
        self.assertEqual(check_step_expectations(tc, execution), ["ERROR"])

    def test_accepting_the_invalid_request_is_a_finding(self):
        tc = {"steps": [_step("action", expected="INVALID_FIELD")]}
        execution = {"step_results": [_result(0, OK, 0)]}
        self.assertEqual(check_step_expectations(tc, execution), ["FAIL"])


class TestPayloadHex(unittest.TestCase):
    def test_prefix_and_whitespace_are_tolerated(self):
        self.assertEqual(payload_bytes("0xA5 5A\n00"), b"\xa5\x5a\x00")

    def test_non_hex_payload_is_a_contract_error(self):
        plan = {"steps_plan": [{"opcode_name": "Write", "phase": "action", "expected_status": "SUCCESS",
                                "field_constraints": [], "payload_hex": "not hex"}]}
        with self.assertRaisesRegex(ValueError, "payload_hex"):
            validate_plan_contract(plan, [], "nvm:3.3.6", [{"name": "Write", "raw_opcode": "0x01",
                                                           "command_set": "NVM"}])

    def test_pattern_that_does_not_fill_the_buffer_goes_through_the_args_retry(self):
        write = {"name": "Write", "raw_opcode": "0x01", "command_set": "NVM"}
        reply = {"cdw10": "0x0", "cdw11": "0x0", "cdw12": "0x0", "nsid": 1, "data_len": 512,
                 "direction": "write", "shared_facts": {}, "field_breakdown": "x"}
        llm = mock.Mock(return_value={"structured": reply, "response_id": "l"})
        with mock.patch.object(args_author, "generate_rag_response",
                               return_value={"chunks": [{"text": "spec"}], "response_id": "r"}), \
             mock.patch.object(args_author, "generate_llm_response", llm):
            with self.assertRaisesRegex(args_author.ArgsAuthoringError, "payload_hex"):
                args_author.author_args({"section_id": "nvm:3.3.6", "spec_doc": "x"}, write, 1,
                                        test_intent={"payload_hex": "A55A5A"})  # 3 B into 512 B
        self.assertEqual(llm.call_count, 2)  # first try + the one retry


class TestContractExecutorSshRoundTrips(unittest.TestCase):
    def test_dmesg_is_cleared_once_and_dumped_once(self):
        steps = [dict(_step("setup"), name="a"), dict(_step("action"), name="b")]
        tc = {"tc_id": "t", "steps": steps, "verification_contract": {"version": 2, "precondition_checks": []}}
        reply = {"step_results": [_result(0, OK, 0)], "batch_stderr": "", "timed_out": False,
                 "dmesg_captured_scoped": True, "dmesg_text": ""}
        with mock.patch("tc_system.execution.ssh_runner.passthru_cmd"), \
             mock.patch("tc_system.execution.ssh_runner.execute_tc_steps", return_value=reply) as wire, \
             mock.patch("tc_system.execution.ssh_runner.capture_dmesg", return_value="dmesg") as dump:
            result = SSHTCExecutor().execute(tc)
        self.assertEqual([c.kwargs["clear_dmesg"] for c in wire.call_args_list], [True, False])
        self.assertTrue(all(c.kwargs["dump_dmesg"] is False for c in wire.call_args_list))
        self.assertEqual([c.kwargs["step_index"] for c in wire.call_args_list], [0, 1])
        dump.assert_called_once()
        self.assertEqual(result["dmesg_text"], "dmesg")


class TestPromptBudget(unittest.TestCase):
    """Every real target, measured: keeps each prompt well under ~10K tokens."""
    MAX_CHARS = 30000  # ~8K tokens at 3.5-4 chars/token, before device facts

    @classmethod
    def setUpClass(cls):
        cls.index = SpecCoverageIndexFile(config.active_coverage_index_path())
        cls.targets = [(s, self_ops[0]) for s in cls.index.list_sections()
                       for self_ops in [cls.index.opcodes_for_section(s)] if self_ops]

    def _measure(self, module, call):
        sizes = []

        def fake(prompt, system=None, response_schema=None, caller=None):
            sizes.append(len(prompt) + len(system or ""))
            raise RuntimeError("stop")

        with mock.patch.object(module, "generate_llm_response", fake):
            for section, opcode in self.targets:
                with self.subTest(section=section["section_id"]):
                    with self.assertRaises(RuntimeError):
                        call(section, opcode)
        return sizes

    def test_scenario_prompts(self):
        sizes = self._measure(scenario_generator, lambda s, o: scenario_generator.generate_scenario(s, o, [o]))
        self.assertEqual(len(sizes), len(self.targets))
        self.assertLessEqual(max(sizes), self.MAX_CHARS)

    def test_args_prompts(self):
        sizes = self._measure(args_author, lambda s, o: args_author.author_args(s, o, 1))
        self.assertEqual(len(sizes), len(self.targets))
        self.assertLessEqual(max(sizes), self.MAX_CHARS)

    def test_judge_sends_the_contract_evidence_once_and_capped(self):
        evidence = [{"evidence_id": f"e{i}", "section_id": "base:5.2.13", "chunk_id": "c",
                     "text": f"EVIDENCE-{i} " + "x " * 5000} for i in range(6)]
        fc = {"failure_context_id": "fc", "source_type": "TC_EXEC", "run_id": "r", "timestamp": "t",
              "primary_log_excerpt": "", "dmesg_excerpt": "",
              "signals": {"cmd_name": "Identify", "opcode": "0x06",
                          "test_definition": {"contract": {"evidence": evidence, "requirements": []},
                                              "steps": [{"name": "Identify", "test_intent": {"scenario": "dup"}}]}}}
        prompts = []

        def fake(prompt, system=None, response_schema=None, caller=None):
            prompts.append(prompt)
            raise RuntimeError("stop")

        with mock.patch.object(judge, "generate_llm_response", fake):
            with self.assertRaises(RuntimeError):
                judge.judge_failure_context(fc)
        prompt = prompts[0]
        self.assertEqual(prompt.count("EVIDENCE-0"), 1)
        self.assertNotIn("test_intent", prompt)
        self.assertLessEqual(len(prompt), spec_evidence.JUDGE_EVIDENCE_CHARS + 4000)


class TestEvidenceForEncoding(unittest.TestCase):
    def test_leaf_value_clause_gets_the_commands_dword_layout(self):
        # "Return Allocated LBAs (Action Type 02h)" names the value but not the
        # register; the args prompt must carry Get LBA Status's CDW13 figure.
        section = {"section_id": "nvm:4.2.1.1.1"}
        evidence = generate_rag_response("q", section=section, command_name="Get LBA Status",
                                         layout_ref="nvm:4.2.1", purpose="args")
        roles = [c["role"] for c in evidence["chunks"]]
        self.assertEqual(roles[0], "command_layout")
        self.assertIn("target", roles)
        self.assertIn("Command Dword 13", evidence["chunks"][0]["text"])

    def test_oversized_target_is_excerpted_by_whole_rows_and_marked(self):
        evidence = spec_evidence.section_evidence({"section_id": "base:5.2.13.2.1"}, "Identify",
                                                  max_chars=5000)
        target = evidence["chunks"][0]
        self.assertTrue(target["truncated"])
        self.assertLessEqual(len(target["text"]), 5000)
        self.assertIn("base:5.2.13.2.1", evidence["truncated_sections"])
        self.assertFalse(evidence["complete"])
        full = spec_evidence.clause_catalog()["base:5.2.13.2.1"]["text"]
        self.assertTrue(full.startswith(target["text"]))
        self.assertNotEqual(target["evidence_id"], spec_evidence.clause_catalog()["base:5.2.13.2.1"]["evidence_id"])

    def test_tables_are_compacted_without_markup(self):
        text = spec_evidence.clause_catalog()["nvm:4.2.1"]["text"]
        self.assertNotIn("<td", text)
        self.assertIn("| 31:24 |", text)



# --- Regressions from the follow-up review: NVM transfer size, compared LBAs ---

NVM_READ = {"command_set": "NVM", "name": "Read", "raw_opcode": "0x02"}
NVM_OPS = [{"name": "Write", "raw_opcode": "0x01", "command_set": "NVM"}, NVM_READ]


def _io(opcode, slba=0, nlb0=0, data_len=512, direction="read", payload=None, nsid=1, phase="action"):
    step = {"mode": "io-passthru", "device": "/dev/nvme0n1", "opcode": opcode, "nsid": nsid, "phase": phase,
            "cdw10": hex(slba & 0xFFFFFFFF), "cdw11": hex(slba >> 32), "cdw12": hex(nlb0),
            "data_len": data_len, "direction": direction, "expected_status": "SUCCESS"}
    if payload is not None:
        step["payload_hex"] = payload
    return step


def _io_ok(name, data=None):
    out = f"IO Command {name} is Success and result: 0x00000000"
    if data is not None:
        rows = [f"{off:04x}: " + " ".join(f"{b:02x}" for b in data[off:off + 16]) for off in range(0, len(data), 16)]
        out += "\n" + "\n".join(rows)
    return {"exit_code": 0, "stdout": out, "started": True}


class TestNvmTransferLength(unittest.TestCase):
    def test_huge_nlb_into_a_one_byte_buffer_is_rejected(self):
        fields = {"cdw12": "0xFFFF", "data_len": 1, "direction": "read"}
        for lba in (None, 512):
            with self.subTest(lba=lba), self.assertRaisesRegex(ValueError, "NLB=65536"):
                validate_transfer(fields, NVM_READ, lba_bytes=lba)

    def test_buffer_must_be_nlb_times_the_measured_lba_size(self):
        fields = {"cdw12": "0x7", "data_len": 4096, "direction": "read"}
        validate_transfer(fields, NVM_READ, lba_bytes=512)  # 8 x 512
        with self.assertRaises(ValueError):
            validate_transfer(fields, NVM_READ, lba_bytes=4096)  # would need 32 KiB
        validate_transfer(fields, NVM_READ)  # size unknown: 8 x 512 is still plausible

    def test_direction_follows_the_command(self):
        with self.assertRaises(ValueError):
            validate_transfer({"cdw12": "0x0", "data_len": 512, "direction": "none"}, NVM_READ, lba_bytes=512)
        with self.assertRaises(ValueError):
            validate_transfer({"cdw12": "0x0", "data_len": 512, "direction": "read"}, NVM_OPS[0], lba_bytes=512)

    def test_no_data_lba_commands_move_no_buffer(self):
        with self.assertRaises(ValueError):
            validate_transfer({"cdw12": "0x0", "data_len": 512, "direction": "write"},
                              {"command_set": "NVM", "name": "Write Zeroes", "raw_opcode": "0x08"})

    def test_the_wire_gate_checks_it_too(self):
        from tc_system.execution.ssh_runner import passthru_cmd
        step = dict(_io("0x02", nlb0=0xFFFF, data_len=1), args_source="authored", lba_bytes=512)
        with self.assertRaisesRegex(ValueError, "NLB=65536"):
            passthru_cmd(step)


def _fixed(slba, nlb0):
    return [{"field": "cdw10", "mask": "0xFFFFFFFF", "value": hex(slba & 0xFFFFFFFF)},
            {"field": "cdw11", "mask": "0xFFFFFFFF", "value": hex(slba >> 32)},
            {"field": "cdw12", "mask": "0xFFFF", "value": hex(nlb0)}]


def _write_then_read_plan(write_slba, read_slba, payload="A55A"):
    return {"steps_plan": [
                {"opcode_name": "Write", "phase": "setup", "expected_status": "SUCCESS",
                 "field_constraints": _fixed(write_slba, 0), "payload_hex": payload},
                {"opcode_name": "Read", "phase": "action", "expected_status": "SUCCESS",
                 "field_constraints": _fixed(read_slba, 0)}],
            "requirements": [{"evidence_id": "e", "quote": "x" * 30, "description": "d",
                              "checks": [{"kind": "data_matches_write", "step": 1, "other_step": 0}]}]}


class TestComparedDataIsTheSameData(unittest.TestCase):
    def test_plan_reading_a_different_lba_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "not inside"):
            validate_plan_contract(_write_then_read_plan(0, 8), [], "nvm:3.3.4", NVM_OPS)

    def test_plan_with_a_zero_payload_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "non-zero payload_hex"):
            validate_plan_contract(_write_then_read_plan(0, 0, payload="0000"), [], "nvm:3.3.4", NVM_OPS)

    def test_plan_reading_the_written_lba_passes_this_check(self):
        # Fails later, on the (deliberately absent) evidence, not on the LBAs.
        with self.assertRaisesRegex(ValueError, "quote"):
            validate_plan_contract(_write_then_read_plan(0, 0), [], "nvm:3.3.4", NVM_OPS)

    def _evaluate(self, read_step, write_payload="A55A"):
        from tc_system.verification import evaluate_check
        write = _io("0x01", slba=0, nlb0=1, data_len=1024, direction="write", payload=write_payload, phase="setup")
        steps = [write, read_step]
        pattern = bytes.fromhex(write_payload) if write_payload else b"\0"
        results = {0: dict(_io_ok("Write"), step_index=0),
                   1: dict(_io_ok("Read", (pattern * 512)[:read_step["data_len"]]), step_index=1)}
        return evaluate_check({"kind": "data_matches_write", "step": 1, "other_step": 0}, steps, results)

    def test_a_read_inside_the_written_range_is_compared_block_for_block(self):
        self.assertEqual(self._evaluate(_io("0x02", slba=1))["result"], "satisfied")

    def test_a_read_elsewhere_is_never_satisfied(self):
        outcome = self._evaluate(_io("0x02", slba=8))
        self.assertEqual(outcome["result"], "unevaluated")
        self.assertIn("not inside", outcome["detail"])

    def test_another_namespace_is_never_satisfied(self):
        self.assertEqual(self._evaluate(_io("0x02", slba=0, nsid=2))["result"], "unevaluated")

    def test_a_zero_filled_write_is_never_satisfied(self):
        self.assertEqual(self._evaluate(_io("0x02", slba=0), write_payload=None)["result"], "unevaluated")
