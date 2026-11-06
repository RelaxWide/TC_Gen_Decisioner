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
                                    payload_for_step, validate_plan_contract)
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

    def test_a_structure_payload_is_zero_padded_not_repeated(self):
        # Measured: 8 targets skipped because a 43-byte management structure
        # did not divide 4096. Repeating it would write garbage into reserved
        # fields; reserved is zero.
        step = {"direction": "write", "data_len": 8, "payload_hex": "0102030405"}
        self.assertEqual(payload_for_step(step), bytes([1, 2, 3, 4, 5, 0, 0, 0]))
        self.assertEqual(payload_for_step(dict(step, payload_hex="A55A")), bytes.fromhex("A55AA55AA55AA55A"))

    def test_payload_longer_than_the_buffer_goes_through_the_args_retry(self):
        write = {"name": "Write", "raw_opcode": "0x01", "command_set": "NVM"}
        reply = {"cdw10": "0x0", "cdw11": "0x0", "cdw12": "0x0", "nsid": 1, "data_len": 512,
                 "direction": "write", "shared_facts": {}, "field_breakdown": "x"}
        llm = mock.Mock(return_value={"structured": reply, "response_id": "l"})
        with mock.patch.object(args_author, "generate_rag_response",
                               return_value={"chunks": [{"text": "spec"}], "response_id": "r"}), \
             mock.patch.object(args_author, "generate_llm_response", llm):
            with self.assertRaisesRegex(args_author.ArgsAuthoringError, "payload_hex"):
                args_author.author_args({"section_id": "nvm:3.3.6", "spec_doc": "x"}, write, 1,
                                        test_intent={"payload_hex": "A5" * 513})  # 513 B into 512 B
        self.assertEqual(llm.call_count, 2)  # first try + the one retry


class TestContractExecutorSshRoundTrips(unittest.TestCase):
    def test_dmesg_is_cleared_once_and_dumped_once(self):
        steps = [dict(_step("setup"), name="a"), dict(_step("action"), name="b")]
        tc = {"tc_id": "t", "steps": steps, "verification_contract": {"version": 2, "precondition_checks": []}}
        reply = {"step_results": [_result(0, OK, 0)], "batch_stderr": "", "timed_out": False,
                 "dmesg_captured_scoped": True, "dmesg_text": ""}
        with mock.patch("tc_system.execution.ssh_runner.passthru_cmd"), \
             mock.patch("tc_system.execution.ssh_runner.clear_dmesg", return_value=True) as clear, \
             mock.patch("tc_system.execution.ssh_runner.execute_tc_steps", return_value=reply) as wire, \
             mock.patch("tc_system.execution.ssh_runner.capture_dmesg", return_value="dmesg") as dump:
            result = SSHTCExecutor().execute(tc)
        # Cleared once before the first step of any kind (review R05), never per step.
        clear.assert_called_once()
        self.assertEqual([c.kwargs["clear_dmesg"] for c in wire.call_args_list], [False, False])
        self.assertTrue(result["dmesg_captured_scoped"])
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
        # Every requirement target, with its sentence added when the budget left it out.
        from tc_system.coverage.coverage_state import pick_next_targets
        targets = pick_next_targets(self.index, [], 10**9)
        sizes, saved = [], self.targets
        self.targets = targets
        try:
            sizes = self._measure(scenario_generator, lambda s, o: scenario_generator.generate_scenario(s, o, [o]))
        finally:
            self.targets = saved
        self.assertEqual(len(sizes), len(targets))
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



# --- Quote provenance: same words in order, not byte-identical formatting ---

class TestQuoteMatching(unittest.TestCase):
    def setUp(self):
        self.text = spec_evidence.clause_catalog()["nvm:4.2.1"]["text"]

    def test_ocr_latex_and_table_pipes_do_not_break_a_faithful_quote(self):
        from tc_system.verification import quote_in
        self.assertIn("LBA $ _{s} $", self.text)  # what the evidence really contains
        self.assertTrue(quote_in("Return tracked allocated LBAs in the specified range", self.text))
        self.assertTrue(quote_in("MNDW: This is a 0\u2019s based value \u2013 in dwords.",
                                 "MNDW: This is a 0's based value - in dwords."))

    def test_translation_or_paraphrase_still_fails(self):
        from tc_system.verification import quote_in
        self.assertFalse(quote_in("지정된 범위에서 추적된 할당 LBA를 반환한다", self.text))
        self.assertFalse(quote_in("Returns the allocated LBAs that are tracked in a range", self.text))

    def test_pieces_joined_with_an_ellipsis_must_appear_in_order(self):
        from tc_system.verification import quote_in
        self.assertTrue(quote_in("The Get LBA Status command requests ... the LBA Status Descriptor List", self.text))
        self.assertFalse(quote_in("the LBA Status Descriptor List ... The Get LBA Status command requests", self.text))
        self.assertFalse(quote_in("Get LBA Status ... is", self.text))  # tiny pieces prove nothing

    def test_a_mislabelled_evidence_id_is_corrected_not_rejected(self):
        tc, _ = fixture()
        evidence = [{"evidence_id": "other", "text": "unrelated text " * 5},
                    {"evidence_id": "source", "text": QUOTE}]
        structured = {"steps_plan": [{"opcode_name": "Get Features", "phase": "action", "expected_status": "SUCCESS",
                                      "field_constraints": [{"field": "cdw10", "mask": "0x7ff", "value": "0x37d"}]}],
                      "requirements": [{"evidence_id": "other", "quote": QUOTE, "description": "d",
                                        "checks": [{"kind": "completion", "step": 0}]}],
                      "preconditions": [], "precondition_checks": []}
        ops = [{"name": "Get Features", "raw_opcode": "0x0a", "command_set": "ADMIN"}]
        validate_plan_contract(structured, evidence, "base:5.2.11", ops)
        self.assertEqual(structured["requirements"][0]["evidence_id"], "source")

    def test_an_unfound_quote_names_itself_so_the_retry_can_fix_it(self):
        structured = {"steps_plan": [{"opcode_name": "Get Features", "phase": "action", "expected_status": "SUCCESS",
                                      "field_constraints": [{"field": "cdw10", "mask": "0x7ff", "value": "0x37d"}]}],
                      "requirements": [{"evidence_id": "source", "quote": "An invented sentence absent from it.",
                                        "description": "d", "checks": [{"kind": "completion", "step": 0}]}]}
        ops = [{"name": "Get Features", "raw_opcode": "0x0a", "command_set": "ADMIN"}]
        with self.assertRaisesRegex(ValueError, r"requirements\[0\]\.quote .*An invented sentence"):
            validate_plan_contract(structured, [{"evidence_id": "source", "text": QUOTE}], "base:5.2.11", ops)



class TestSetupOnlyRequirementBecomesAPrecondition(unittest.TestCase):
    OPS = [{"name": "Identify", "raw_opcode": "0x06", "command_set": "ADMIN"},
           {"name": "Get Features", "raw_opcode": "0x0a", "command_set": "ADMIN"}]

    def _plan(self, steps_checked):
        steps = [{"opcode_name": "Identify", "phase": "setup", "expected_status": "SUCCESS",
                  "field_constraints": [{"field": "cdw10", "mask": "0xff", "value": "0x1"}]},
                 {"opcode_name": "Get Features", "phase": "action", "expected_status": "SUCCESS",
                  "field_constraints": [{"field": "cdw10", "mask": "0x7ff", "value": "0x84"}]}]
        reqs = [{"evidence_id": "source", "quote": QUOTE, "description": f"requirement on step {s}",
                 "checks": [{"kind": "completion", "step": s}]} for s in steps_checked]
        return {"steps_plan": steps, "requirements": reqs, "preconditions": [], "precondition_checks": []}

    def test_it_is_moved_when_another_requirement_checks_the_action(self):
        plan = self._plan([0, 1])
        validate_plan_contract(plan, [{"evidence_id": "source", "text": QUOTE}], "base:5.2.11", self.OPS)
        self.assertEqual([r["description"] for r in plan["requirements"]], ["requirement on step 1"])
        self.assertEqual(plan["preconditions"], ["requirement on step 0"])
        self.assertEqual(plan["precondition_checks"][0]["checks"], [{"kind": "completion", "step": 0}])

    def test_with_no_check_on_the_action_the_error_names_the_action_index(self):
        with self.assertRaisesRegex(ValueError, r"steps_plan\[1\] \(Get Features\).*\"step\": 1"):
            validate_plan_contract(self._plan([0]), [{"evidence_id": "source", "text": QUOTE}],
                                   "base:5.2.11", self.OPS)



class TestQuoteOperatorsKeepTheirMeaning(unittest.TestCase):
    def setUp(self):
        self.text = "\n".join(b["text"] for b in spec_evidence.clause_catalog().values())

    def test_a_flipped_inequality_is_not_the_same_requirement(self):
        from tc_system.verification import quote_in
        self.assertIn("≥ NAWUN and ≥ AWUN", self.text)
        self.assertTrue(quote_in("Namespace Atomic Boundary Size Normal (NABSN) = NAWUN", self.text))
        self.assertTrue(quote_in("and = NABSPF | ≥ NAWUN and ≥ AWUN", self.text))
        self.assertFalse(quote_in("and = NABSPF | ≤ NAWUN and ≤ AWUN", self.text))

    def test_latex_unicode_and_ascii_spellings_of_one_operator_are_equal(self):
        from tc_system.verification import quote_in
        self.assertIn("$ \\geq $ AWUN", self.text)  # OCR'd LaTeX in the real evidence
        source = "Namespace Atomic Write Unit Normal (NAWUN) | $ \\geq $ AWUN"
        for spelling in ("≥", ">=", "$\\geq$"):
            with self.subTest(spelling=spelling):
                self.assertTrue(quote_in(f"Namespace Atomic Write Unit Normal (NAWUN) {spelling} AWUN", source))
        self.assertFalse(quote_in("Namespace Atomic Write Unit Normal (NAWUN) <= AWUN", source))

    def test_decimal_points_and_minus_signs_are_kept(self):
        from tc_system.verification import quote_in
        self.assertFalse(quote_in("the maximum value is 15 seconds for this field", "the maximum value is 1.5 seconds for this field"))
        self.assertFalse(quote_in("the number of logical blocks is NLB + 1 for this command",
                                  "the number of logical blocks is NLB - 1 for this command"))
        self.assertTrue(quote_in("a zero filled buffer is transferred to the host", "a zero-filled buffer is transferred to the host"))


class TestReportDoesNotCallALegacyPassVerified(unittest.TestCase):
    def test_a_stored_pass_without_a_contract_is_described_from_the_recomputed_status(self):
        from tc_system.execution.expectation_checker import describe_outcome
        legacy = {"status": "PASS", "steps": [], "execution": {"step_results": []}}
        recomputed = verify_tc(legacy, legacy["execution"])
        self.assertEqual(recomputed["status"], "UNVERIFIED")
        outcome = describe_outcome(legacy, recomputed)
        self.assertNotIn("통과", outcome["verdict"])
        self.assertIn("입증하지 못함", outcome["verdict"])
        html = _tc_evidence(legacy)
        self.assertNotIn("스펙 요구사항 검증 통과", html)

    def test_a_verified_pass_is_still_described_as_passed(self):
        from tc_system.execution.expectation_checker import describe_outcome
        tc, execution = fixture()
        tc.update(status="PASS", execution=execution)
        self.assertEqual(describe_outcome(tc, verify_tc(tc, execution))["verdict"], "스펙 요구사항 검증 통과")



class TestExpectedStatusUsesNvmeCliTokens(unittest.TestCase):
    """Measured: a Directive Receive scenario expected the drive to reject the
    unsupported command, wrote the spec's name for it, and was reported as
    "미지원 응답" instead of the PASS it had designed for."""
    OUT = "NVMe status: INVALID_OPCODE: The associated command opcode field is not valid(0x1)"

    def _tc(self, expected):
        step = {"name": "Directive Receive", "phase": "action", "opcode": "0x1a", "direction": "read",
                "data_len": 4096, "expected_status": expected}
        tc = {"tc_id": "t", "steps": [step], "scenario": {"preconditions": []},
              "verification_contract": {"version": 2, "precondition_checks": [],
                  "evidence": [{"evidence_id": "source", "text": QUOTE}],
                  "requirements": [{"requirement_id": "r", "section_id": "base:5.2.7", "evidence_id": "source",
                                    "quote": QUOTE, "description": "unsupported -> Invalid Command Opcode",
                                    "checks": [{"kind": "completion", "step": 0}]}]}}
        return tc, {"step_results": [{"step_index": 0, "exit_code": 22, "stdout": self.OUT, "started": True}]}

    def test_spec_names_are_mapped_to_nvme_cli_tokens(self):
        from tc_system.verification import canonical_status
        for name, token in (("INVALID_COMMAND_OPCODE", "INVALID_OPCODE"), ("Invalid Command Opcode", "INVALID_OPCODE"),
                            ("Invalid Field in Command", "INVALID_FIELD"), ("INVALID_NAMESPACE_OR_FORMAT", "INVALID_NS"),
                            ("SUCCESS", "SUCCESS"), ("INVALID_OPCODE", "INVALID_OPCODE")):
            with self.subTest(name=name):
                self.assertEqual(canonical_status(name), token)

    def test_an_expected_rejection_written_with_the_spec_name_is_the_intended_pass(self):
        for expected in ("INVALID_OPCODE", "INVALID_COMMAND_OPCODE", "Invalid Command Opcode"):
            with self.subTest(expected=expected):
                tc, execution = self._tc(expected)
                self.assertEqual(check_step_expectations(tc, execution), ["PASS"])
                self.assertEqual(check_expectation(tc, execution), "PASS")

    def test_without_that_expectation_it_is_still_unsupported(self):
        tc, execution = self._tc("SUCCESS")
        self.assertEqual(check_expectation(tc, execution), "UNSUPPORTED")

    def test_the_plan_stores_the_token(self):
        plan = {"steps_plan": [{"opcode_name": "Directive Receive", "phase": "action",
                                "expected_status": "Invalid Command Opcode",
                                "field_constraints": [{"field": "cdw11", "mask": "0xffff", "value": "0x0101"}]}],
                "requirements": [{"evidence_id": "source", "quote": QUOTE, "description": "d",
                                  "checks": [{"kind": "completion", "step": 0}]}],
                "preconditions": [], "precondition_checks": []}
        ops = [{"name": "Directive Receive", "raw_opcode": "0x1a", "command_set": "ADMIN"}]
        validate_plan_contract(plan, [{"evidence_id": "source", "text": QUOTE}], "base:5.2.7", ops)
        self.assertEqual(plan["steps_plan"][0]["expected_status"], "INVALID_OPCODE")

    def test_an_unexpected_unsupported_says_what_was_expected(self):
        from tc_system.execution.expectation_checker import describe_outcome
        tc, _ = self._tc("INVALID_FIELD")
        tc["status"] = "UNSUPPORTED"
        self.assertIn("기대 INVALID_FIELD", describe_outcome(tc)["cause"])



class TestPreconditionsThatCannotBeMeasuredAreNotes(unittest.TestCase):
    """Measured: base:5.4.6/5.4.7 (Fabric Zoning Receive/Send) were skipped with
    "preconditions must be observable before the action" every run."""
    OPS = [{"name": "Identify", "raw_opcode": "0x06", "command_set": "ADMIN"},
           {"name": "Fabric Zoning Receive", "raw_opcode": "0x56", "command_set": "ADMIN"}]

    def _plan(self, steps, preconditions, precondition_checks):
        return {"steps_plan": steps, "preconditions": preconditions, "precondition_checks": precondition_checks,
                "out_of_scope": [],
                "requirements": [{"evidence_id": "source", "quote": QUOTE, "description": "FZR completion",
                                  "checks": [{"kind": "completion", "step": len(steps) - 1}]}]}

    def _validate(self, plan):
        validate_plan_contract(plan, [{"evidence_id": "source", "text": QUOTE}], "base:5.4.6", self.OPS)
        return plan

    ACTION = {"opcode_name": "Fabric Zoning Receive", "phase": "action", "expected_status": "SUCCESS",
              "field_constraints": []}
    IDENTIFY = {"opcode_name": "Identify", "phase": "setup", "expected_status": "SUCCESS",
                "field_constraints": [{"field": "cdw10", "mask": "0xff", "value": "0x1"}]}

    def test_a_precondition_checked_on_the_action_itself_becomes_a_note(self):
        plan = self._validate(self._plan([self.ACTION], ["Discovery controller"],
                                         [{"description": "Discovery controller",
                                           "checks": [{"kind": "completion", "step": 0}]}]))
        self.assertEqual(plan["preconditions"], [])
        self.assertEqual(plan["precondition_checks"], [])
        self.assertTrue(any("사전조건 미측정" in n and "Discovery controller" in n for n in plan["out_of_scope"]))

    def test_unchecked_or_unmatched_preconditions_become_notes_too(self):
        early = {"kind": "data_field", "step": 0, "offset": 111, "width": 1, "mask": "0xff", "value": "0x2"}
        plan = self._validate(self._plan([self.IDENTIFY, self.ACTION], ["A", "CNTRLTYPE is 2h"],
                                         [{"description": "CNTRLTYPE = 2h", "checks": [early]}]))
        self.assertEqual(plan["preconditions"], ["CNTRLTYPE = 2h"])  # the measured one, as the check names it
        notes = " ".join(plan["out_of_scope"])
        self.assertIn(": A", notes)
        self.assertIn("CNTRLTYPE is 2h", notes)

    def test_checks_after_the_action_are_dropped_and_earlier_ones_kept(self):
        early = {"kind": "data_field", "step": 0, "offset": 111, "width": 1, "mask": "0xff", "value": "0x2"}
        plan = self._validate(self._plan([self.IDENTIFY, self.ACTION], ["Discovery controller"],
                                         [{"description": "Discovery controller",
                                           "checks": [early, {"kind": "completion", "step": 1}]}]))
        self.assertEqual(plan["precondition_checks"][0]["checks"], [early])
        self.assertEqual(plan["out_of_scope"], [])

    def _tc_from(self, plan):
        return {"steps": [dict(self.ACTION, name="Fabric Zoning Receive", opcode="0x56", direction="none", data_len=0)],
                "scenario": {"preconditions": plan["preconditions"]},
                "verification_contract": {"version": 2, "precondition_checks": plan["precondition_checks"],
                                          "unmeasured_preconditions": plan["unmeasured_preconditions"],
                                          "evidence": [{"evidence_id": "source", "text": QUOTE}],
                                          "requirements": plan["requirements"]}}

    EXECUTION = {"step_results": [{"step_index": 0, "exit_code": 0, "started": True,
                                   "stdout": "Admin Command Fabric Zoning Receive is Success and result: 0x0"}]}

    def test_an_unmeasured_precondition_still_gates_the_verdict(self):
        # Review: a "Discovery controller" scenario that never checked the
        # controller type ended as PASS and counted as a requirement PASS.
        plan = self._validate(self._plan([self.ACTION], ["Discovery controller"], []))
        self.assertEqual(plan["unmeasured_preconditions"], ["Discovery controller"])
        result = verify_tc(self._tc_from(plan), self.EXECUTION)
        self.assertEqual(result["status"], "UNVERIFIED")
        self.assertEqual({r["status"] for r in result["requirements"]}, {"UNVERIFIED"})
        self.assertTrue(any("사전조건 미측정" in i and "Discovery controller" in i for i in result["issues"]))

    def test_with_every_precondition_measured_the_verdict_is_given(self):
        plan = self._validate(self._plan([self.ACTION], [], []))
        self.assertEqual(plan["unmeasured_preconditions"], [])
        self.assertEqual(verify_tc(self._tc_from(plan), self.EXECUTION)["status"], "PASS")



class TestContractLeniencyForSupportingSteps(unittest.TestCase):
    """The five scenario-contract rules relaxed after listing every skip path."""
    OPS = [{"name": "Identify", "raw_opcode": "0x06", "command_set": "ADMIN"},
           {"name": "Get Features", "raw_opcode": "0x0a", "command_set": "ADMIN"}]
    ACTION_FIXED = [{"field": "cdw10", "mask": "0x7ff", "value": "0x84"}]

    def _plan(self, setup=None, action=None, **extra):
        setup = {"opcode_name": "Identify", "phase": "setup", **(setup or {})}
        action = {"opcode_name": "Get Features", "phase": "action", "expected_status": "SUCCESS",
                  "field_constraints": self.ACTION_FIXED, **(action or {})}
        plan = {"steps_plan": [setup, action], "preconditions": [], "precondition_checks": [], "out_of_scope": [],
                "requirements": [{"evidence_id": "source", "quote": QUOTE, "description": "d",
                                  "checks": [{"kind": "completion", "step": 1}]}]}
        plan.update(extra)
        return plan

    def _validate(self, plan):
        validate_plan_contract(plan, [{"evidence_id": "source", "text": QUOTE}], "base:5.2.11", self.OPS)
        return plan

    def test_unknown_capability_names_are_noted_not_rejected(self):
        plan = self._validate(self._plan(required_capabilities=["sequential", "feature_readback"]))
        self.assertTrue(any("feature_readback" in n for n in plan["out_of_scope"]))

    def test_a_supporting_step_without_expected_status_expects_success(self):
        plan = self._validate(self._plan())
        self.assertEqual(plan["steps_plan"][0]["expected_status"], "SUCCESS")

    def test_the_action_must_still_declare_its_expected_status(self):
        with self.assertRaisesRegex(ValueError, r"steps_plan\[1\] \(the action\)"):
            self._validate(self._plan(action={"expected_status": None}))

    def test_missing_field_constraints_mean_none(self):
        plan = self._validate(self._plan())
        self.assertEqual(plan["steps_plan"][0]["field_constraints"], [])

    def test_spec_hex_notation_is_accepted(self):
        from tc_system.verification import integer
        self.assertEqual((integer("84h"), integer("0084H"), integer("0x84"), integer("10")), (0x84, 0x84, 0x84, 10))
        plan = self._validate(self._plan(action={"field_constraints": [{"field": "cdw10", "mask": "7FFh",
                                                                         "value": "84h"}]}))
        self.assertEqual(plan["steps_plan"][1]["field_constraints"][0]["value"], "84h")

    def test_only_the_action_must_fix_its_selectors(self):
        self._validate(self._plan())  # setup Identify with CNS open: accepted
        with self.assertRaisesRegex(ValueError, r"steps_plan\[1\] Get Features \(the action\).*cdw10: 0x7ff"):
            self._validate(self._plan(action={"field_constraints": []}))

    def test_an_open_setup_selector_is_frozen_from_its_first_authoring(self):
        from tc_system.generation import tc_writer
        authored = {"cdw10": "0x00000001", "cdw11": "0x0", "cdw12": "0x0", "nsid": 0, "data_len": 4096,
                    "direction": "read", "shared_facts": {}, "field_breakdown": "CNS=1"}
        identify = {"name": "Identify", "raw_opcode": "0x06", "command_set": "ADMIN", "opcode": "a06"}
        intent = {"field_constraints": [], "expected_status": "SUCCESS"}
        with mock.patch.object(tc_writer, "author_args", return_value=authored):
            setup = tc_writer._command_step({"section_id": "s"}, identify, "/dev/nvme0", "/dev/nvme0n1", 1,
                                            phase="setup", test_intent=dict(intent))
            action = tc_writer._command_step({"section_id": "s"}, identify, "/dev/nvme0", "/dev/nvme0n1", 1,
                                             phase="action", test_intent=dict(intent))
        frozen = [c for c in setup["field_constraints"] if c.get("frozen_from_first_authoring")]
        self.assertEqual([(c["field"], c["mask"], c["value"]) for c in frozen], [("cdw10", "0xff", "0x1")])
        self.assertEqual(setup["test_intent"]["field_constraints"], setup["field_constraints"])  # reauthor keeps it
        self.assertEqual(action["field_constraints"], [])  # the action's selectors come from the scenario



class TestAStoppedChainSaysWhy(unittest.TestCase):
    """Measured: UNVERIFIED with "unevaluated: step did not complete" printed
    once per check and "재시도 안 함: 스텝 1 Set Features" blaming the
    environment, when the chain had stopped on an unmet precondition."""

    def _tc(self):
        get = {"name": "Get Features", "phase": "setup", "opcode": "0x0a", "direction": "none", "data_len": 0,
               "expected_status": "SUCCESS", "cdw10": "0x2"}
        set_ = dict(get, name="Set Features", phase="action", opcode="0x09")
        verify = dict(get, phase="verify")
        return {"tc_id": "t", "steps": [get, set_, verify], "verification_contract": {
            "version": 2, "precondition_checks": [{"description": "Power State 0 is current",
                                                   "checks": [{"kind": "result_bits", "step": 0,
                                                               "mask": "0x1f", "value": "0x0"}]}]}}

    def _run(self, replies):
        reply = iter(replies)

        def wire(steps, **kw):
            return {"step_results": [dict(next(reply), step_index=0)], "batch_stderr": "",
                    "timed_out": False, "dmesg_captured_scoped": True, "dmesg_text": ""}

        with mock.patch("tc_system.execution.ssh_runner.passthru_cmd"), \
             mock.patch("tc_system.execution.ssh_runner.execute_tc_steps", side_effect=wire), \
             mock.patch("tc_system.execution.ssh_runner.capture_dmesg", return_value=""):
            return SSHTCExecutor().execute(self._tc())

    def test_an_unmet_precondition_names_the_condition_and_the_observed_value(self):
        result = self._run([{"exit_code": 0, "started": True,
                             "stdout": "Admin Command Get Features is Success and result: 0x00000002"}])
        reason = result["step_results"][1]["blocked_reason"]
        self.assertIn("Power State 0 is current", reason)
        self.assertIn("불충족", reason)
        self.assertIn("2 eq 0", reason)
        self.assertEqual(result["step_results"][2]["blocked_reason"], reason)

    def test_an_unexpected_completion_names_expected_and_actual(self):
        result = self._run([{"exit_code": 22, "started": True,
                             "stdout": "NVMe status: INVALID_FIELD: x(0x2)"}])
        reason = result["step_results"][1]["blocked_reason"]
        self.assertIn("기대 완료 상태 SUCCESS", reason)
        self.assertIn("INVALID_FIELD", reason)

    def test_checks_on_unsent_steps_say_not_run(self):
        from tc_system.verification import evaluate_check
        tc = self._tc()
        results = {1: {"step_index": 1, "started": False, "exit_code": None, "stdout": "", "blocked_reason": "x"}}
        outcome = evaluate_check({"kind": "completion", "step": 1}, tc["steps"], results)
        self.assertEqual(outcome["detail"], "step 1 not run (chain stopped earlier)")



class TestHostStepsInAChain(unittest.TestCase):
    def _tc(self, host_result):
        set_f = {"name": "Set Features", "phase": "setup", "opcode": "0x09", "mode": "admin-passthru",
                 "direction": "none", "data_len": 0, "expected_status": "SUCCESS", "cdw10": "0x2"}
        cycle = {"name": "Power Cycle (PMU)", "phase": "setup", "host_action": "power_cycle", "mode": "host",
                 "device": "/dev/nvme0", "expected_status": "SUCCESS"}
        get_f = dict(set_f, name="Get Features", phase="action", opcode="0x0a")
        ok = {"exit_code": 0, "started": True, "stdout": "Admin Command X is Success and result: 0x0"}
        tc = {"steps": [set_f, cycle, get_f]}
        execution = {"step_results": [dict(ok, step_index=0), dict(host_result, step_index=1, started=True,
                                                                   host_action="power_cycle"),
                                      dict(ok, step_index=2)]}
        return tc, execution

    def test_a_completed_power_cycle_is_a_passing_step(self):
        tc, execution = self._tc({"exit_code": 0, "stdout": "POWER_ON_RC=0\nREADY_AFTER_SEC=5"})
        self.assertEqual(check_step_expectations(tc, execution), ["PASS", "PASS", "PASS"])

    def test_a_controller_that_never_comes_back_is_a_finding(self):
        tc, execution = self._tc({"exit_code": 98, "stdout": "NOT_READY_AFTER_SEC=30"})
        self.assertEqual(check_step_expectations(tc, execution)[1], "FAIL")

    def test_a_pmu_failure_is_the_host_side(self):
        tc, execution = self._tc({"exit_code": 2, "stdout": "pmu: device not found"})
        self.assertEqual(check_step_expectations(tc, execution)[1], "ERROR")

    def test_the_contract_executor_sends_host_steps_through_ssh_not_nvme_cli(self):
        tc, _ = self._tc({})
        tc.update(tc_id="t", verification_contract={"version": 2, "precondition_checks": []})
        nvme_reply = {"step_results": [{"step_index": 0, "exit_code": 0, "started": True,
                                        "stdout": "Admin Command X is Success and result: 0x0"}],
                      "batch_stderr": "", "timed_out": False, "dmesg_captured_scoped": True, "dmesg_text": ""}
        host_reply = {"exit_code": 0, "stdout": "READY_AFTER_SEC=4", "batch_stderr": "", "timed_out": False}
        with mock.patch("tc_system.execution.ssh_runner.passthru_cmd"), \
             mock.patch("tc_system.execution.ssh_runner.execute_tc_steps", return_value=nvme_reply) as wire, \
             mock.patch("tc_system.execution.ssh_runner.run_host_action", return_value=host_reply) as host, \
             mock.patch("tc_system.execution.ssh_runner.capture_dmesg", return_value=""):
            result = SSHTCExecutor(allow_destructive=True).execute(tc)
        self.assertEqual(wire.call_count, 2)
        host.assert_called_once()
        self.assertEqual(result["step_results"][1]["host_action"], "power_cycle")



class TestTargetRequirementBinding(unittest.TestCase):
    OPS = [{"name": "Get Log Page", "raw_opcode": "0x02", "command_set": "ADMIN"}]
    RULE = {"requirement_id": "sreq-1", "section_id": "base:5.2.12", "kind": "abort",
            "expected_status": "INVALID_FIELD",
            "text": "If a Get Log Page command is processed that specifies a Log Page Identifier that is not "
                    "supported, then the controller should abort the command with a status code of Invalid "
                    "Field in Command."}

    def _plan(self, quote, expected="INVALID_FIELD"):
        return {"steps_plan": [{"opcode_name": "Get Log Page", "phase": "action", "expected_status": expected,
                                "field_constraints": [{"field": "cdw10", "mask": "0xff", "value": "0xEE"}]}],
                "requirements": [{"evidence_id": "e", "quote": quote, "description": "d",
                                  "checks": [{"kind": "completion", "step": 0}]}],
                "preconditions": [], "precondition_checks": []}

    def _validate(self, plan):
        validate_plan_contract(plan, [{"evidence_id": "e", "text": self.RULE["text"]
                                       + " An unrelated sentence that sits in the same evidence block."}],
                               "base:5.2.12", self.OPS, target_requirement=self.RULE)
        return plan

    def test_the_requirement_quoting_the_target_is_linked(self):
        plan = self._validate(self._plan("specifies a Log Page Identifier that is not supported"))
        self.assertEqual(plan["requirements"][0]["target_requirement_id"], "sreq-1")

    def test_a_scenario_that_tests_something_else_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "TARGET_REQUIREMENT is not tested"):
            self._validate(self._plan("An unrelated sentence that sits in the same evidence block."))

    def test_an_abort_rule_needs_the_action_to_expect_its_status(self):
        with self.assertRaisesRegex(ValueError, "must provoke its condition and expect INVALID_FIELD"):
            self._validate(self._plan("specifies a Log Page Identifier that is not supported", expected="SUCCESS"))



class TestHostEventTargets(unittest.TestCase):
    """"retained across power cycles and resets" is not tested by one Get Log Page."""
    from tc_system.execution.host_actions import host_action_entries as _entries
    OPS = [{"name": "Get Log Page", "raw_opcode": "0x02", "command_set": "ADMIN"}] + _entries(None)
    TEXT = "The information in this log page shall be retained across power cycles and resets."
    TARGET = {"requirement_id": "sreq-h", "section_id": "base:5.2.12.1.14", "kind": "shall", "expected_status": None,
              "text": TEXT, "host_actions": ["controller_reset", "power_cycle"], "host_steps": ["Controller Reset"]}
    LID = [{"field": "cdw10", "mask": "0xff", "value": "0x0D"}]

    def _plan(self, steps, check_step):
        return {"steps_plan": steps,
                "requirements": [{"evidence_id": "e", "quote": self.TEXT, "description": "d",
                                  "checks": [{"kind": "completion", "step": check_step}]}],
                "preconditions": [], "precondition_checks": []}

    def _validate(self, plan):
        validate_plan_contract(plan, [{"evidence_id": "e", "text": self.TEXT}], "base:5.2.12.1.14", self.OPS,
                               target_requirement=self.TARGET)
        return plan

    def _log(self, phase):
        return {"opcode_name": "Get Log Page", "phase": phase, "expected_status": "SUCCESS",
                "field_constraints": self.LID}

    def test_a_single_read_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "across a reset/power cycle.*'Controller Reset'"):
            self._validate(self._plan([self._log("action")], 0))

    def test_a_reset_after_the_observed_step_is_rejected(self):
        plan = self._plan([self._log("action"), {"opcode_name": "Controller Reset", "phase": "verify"}], 0)
        with self.assertRaisesRegex(ValueError, "host steps now at \\[1\\]"):
            self._validate(plan)

    def test_record_reset_read_back_is_accepted(self):
        plan = self._plan([self._log("setup"), {"opcode_name": "Controller Reset", "phase": "setup"},
                           self._log("action")], 2)
        self.assertEqual(self._validate(plan)["requirements"][0]["target_requirement_id"], "sreq-h")

    def test_the_prompt_tells_the_model_to_use_it(self):
        from tc_system.generation.scenario_generator import _target_block
        self.assertIn("MUST perform it with a 'Controller Reset' step", _target_block(self.TARGET))
