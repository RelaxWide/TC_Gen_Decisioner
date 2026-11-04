"""Integration-style tests for the multi-step retry/replan decision tree in
`pipeline.run_pipeline`. No network: `generate_scenario` and `author_args` are
replaced with controllable fakes, and the SSH executor is injected (the
function already accepts one), so only the branching logic under test runs
for real.
"""
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import config
from shared.file_store import save_json_atomic
from shared.llm_client import LLMCallError
from tc_system import pipeline
from tc_system.execution.ssh_runner import DestructiveStepBlocked
from tc_system.generation import tc_writer
from tc_system.generation.args_author import ArgsAuthoringError
from tc_system.pipeline import _resolve_steps_plan
from tc_system.store import tc_store

SECTION_READ = {"section_id": "nvm:1.1", "spec_doc": "NVM-Express-NVM-Command-Set-Specification",
                 "spec_doc_label": "x", "doc": "nvm", "clause": "1.1", "title": "Read command",
                 "related_opcodes": ["0x02n"], "chunk_ids": [], "covers_commands": []}
SECTION_WRITE = {"section_id": "nvm:1.2", "spec_doc": "NVM-Express-NVM-Command-Set-Specification",
                  "spec_doc_label": "x", "doc": "nvm", "clause": "1.2", "title": "Write command",
                  "related_opcodes": ["0x01n"], "chunk_ids": [], "covers_commands": []}
OPCODE_READ = {"opcode": "0x02n", "raw_opcode": "0x02", "name": "Read", "command_set": "NVM",
               "spec_doc": "NVM-Express-NVM-Command-Set-Specification", "spec_doc_label": "x",
               "section_ref": "nvm:1.1", "direction": "read", "destructive": False,
               "firmware_state": False, "lockout_risk": False, "risk_class": 0, "source": "test"}
OPCODE_WRITE = {"opcode": "0x01n", "raw_opcode": "0x01", "name": "Write", "command_set": "NVM",
                "spec_doc": "NVM-Express-NVM-Command-Set-Specification", "spec_doc_label": "x",
                "section_ref": "nvm:1.2", "direction": "write", "destructive": True,
                "firmware_state": False, "lockout_risk": False, "risk_class": 2, "source": "test"}

INDEX_JSON = {
    "schema_version": 2, "source": "test", "rag_index_version": "test", "excluded_docs": [],
    "sections": [SECTION_READ, SECTION_WRITE], "opcodes": [OPCODE_READ, OPCODE_WRITE],
}


def _authored(opcode_entry, prior_steps=None, rejected=None, shared_facts=None):
    return {"cdw10": "0x00000000", "cdw11": "0x00000000", "cdw12": "0x00000000", "data_len": 512,
            "direction": "read" if opcode_entry["name"] == "Read" else "write", "nsid": 1,
            "shared_facts": shared_facts or {}, "field_breakdown": "stub"}


def _two_step_scenario(section, opcode_entry, available_opcodes, feedback=None, device_facts=None):
    """Write(setup) -> <target>(action). If replanned (feedback given),
    drops the setup step entirely."""
    steps_plan = [{"opcode_name": opcode_entry["name"], "role": "primary", "phase": "action"}]
    if not feedback:
        steps_plan = [{"opcode_name": "Write", "role": "setup", "phase": "setup"}] + steps_plan
    return {"description": "d", "preconditions": [], "fail_criteria": [], "steps_plan": steps_plan,
            "chain_summary": "chain", "rag_response_id": "r", "llm_response_id": "l"}


class _FakeExecutor:
    """Returns one canned execution result per call, in order."""
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def execute(self, tc):
        self.calls.append([dict(s) for s in tc["steps"]])
        step_results = self.responses.pop(0)
        return {"executor": "FakeExecutor", "executed_at": "2026-01-01T00:00:00+00:00",
                "step_results": step_results, "dmesg_text": "", "batch_stderr": "",
                "timed_out": False, "dmesg_captured_scoped": True}


def _ok(i, text="Success"):
    return {"step_index": i, "exit_code": 0, "stdout": text}


def _rejected(i, reason="NVMe status: INVALID_FIELD: reserved value(0x2)"):
    return {"step_index": i, "exit_code": 22, "stdout": reason}


def _unsupported(i):
    return {"step_index": i, "exit_code": 22,
            "stdout": "NVMe status: INVALID_OPCODE: The associated command opcode field is not valid(0x1)"}


def _plain_fail(i):
    # Nonzero exit, no INVALID_* text — a real firmware misbehavior, not a
    # rejected argument or an unsupported opcode, so this reaches judging.
    return {"step_index": i, "exit_code": 1, "stdout": "unexpected failure, no further detail"}


class _FakeIndex:
    """Just enough of SpecCoverageIndex for _resolve_steps_plan: a lookup
    from section_id to section dict."""
    def __init__(self, sections):
        self._by_id = {s["section_id"]: s for s in sections}

    def get_section(self, section_id):
        return self._by_id.get(section_id)


# A section whose own id differs from the opcode's generic section_ref — the
# shape that broke coverage for real (measured: 43 of 103 reachable sections,
# e.g. "base:5.2.17.1" vs Migration Send's section_ref "base:5.2.17").
SECTION_READ_SUBCLAUSE = {"section_id": "nvm:1.1.2", "spec_doc": "NVM-Express-NVM-Command-Set-Specification",
                           "spec_doc_label": "x", "doc": "nvm", "clause": "1.1.2",
                           "title": "Read — Deallocated LBA handling",
                           "related_opcodes": ["0x02n"], "chunk_ids": [], "covers_commands": []}


class TestResolveStepsPlanActionKeepsItsOwnSection(unittest.TestCase):
    def setUp(self):
        self.index = _FakeIndex([SECTION_READ, SECTION_READ_SUBCLAUSE, SECTION_WRITE])
        self.steps_plan = [
            {"opcode_name": "Write", "phase": "setup", "role": "write a known pattern"},
            {"opcode_name": "Read", "phase": "action", "role": "read it back"},
        ]

    def test_action_step_keeps_the_originally_targeted_sub_clause(self):
        # pick_next_targets picked the sub-clause (nvm:1.1.2), not Read's
        # generic section_ref (nvm:1.1) — the action step must credit
        # coverage to the one actually picked, or that sub-clause can never
        # be marked covered and gets offered again forever.
        resolved = _resolve_steps_plan(self.index, self.steps_plan, [OPCODE_READ, OPCODE_WRITE],
                                        SECTION_READ_SUBCLAUSE)
        action = next(r for r in resolved if r["phase"] == "action")
        self.assertEqual(action["section"]["section_id"], "nvm:1.1.2")

    def test_setup_step_resolves_via_its_own_opcodes_section_ref(self):
        # Setup/verify steps have no pre-assigned target (the LLM chose them
        # freely), so they still resolve to their own command's real section.
        resolved = _resolve_steps_plan(self.index, self.steps_plan, [OPCODE_READ, OPCODE_WRITE],
                                        SECTION_READ_SUBCLAUSE)
        setup = next(r for r in resolved if r["phase"] == "setup")
        self.assertEqual(setup["section"]["section_id"], "nvm:1.2")


class PipelineTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        tmp_path = Path(self.tmp.name)
        index_path = tmp_path / "index.json"
        index_path.write_text(json.dumps(INDEX_JSON), encoding="utf-8")

        self._patches = [
            mock.patch.object(config, "active_coverage_index_path", lambda: index_path),
            mock.patch.object(config, "TC_STORE_PATH", tmp_path / "tc_store.json"),
            mock.patch.object(config, "COVERAGE_STATE_PATH", tmp_path / "coverage_state.json"),
            mock.patch.object(config, "FAILURE_CONTEXTS_DIR", tmp_path / "failure_contexts"),
            mock.patch.object(config, "VERDICTS_DIR", tmp_path / "verdicts"),
            mock.patch.object(config, "get_ssh_target", lambda: {
                "host": "h", "user": "u", "password": "p",
                "nvme_ctrl": "/dev/nvme0", "nvme_ns": "/dev/nvme0n1"}),
            mock.patch.object(pipeline, "probe_device_capabilities", return_value={}),
            mock.patch.object(pipeline, "device_responsive", return_value=(True, "")),
            mock.patch.object(pipeline, "generate_scenario", side_effect=_two_step_scenario),
            mock.patch.object(tc_writer, "author_args",
                               side_effect=lambda *a, **k: _authored(a[1], **{
                                   kk: vv for kk, vv in k.items() if kk in ("prior_steps", "rejected")})),
            mock.patch.object(pipeline, "judge_failure_context",
                               return_value={"verdict_id": "v-1", "classification": "needs_engineer_review"}),
        ]
        for p in self._patches:
            p.start()
            self.addCleanup(p.stop)
        (tmp_path / "failure_contexts" / "tc_exec").mkdir(parents=True)
        (tmp_path / "verdicts").mkdir(parents=True)
        self.addCleanup(self.tmp.cleanup)

    def _run(self, executor):
        return pipeline.run_pipeline(count=1, executor=executor, allow_destructive=True)


class TestTcExecJudgmentsResetEachRun(PipelineTestCase):
    def test_old_verdicts_and_failure_contexts_are_wiped_and_stale_tc_refs_cleared(self):
        # data/verdicts/tc_exec.json otherwise only ever grows across every
        # invocation that was ever run. tc_store.json's status/steps stay —
        # only the judgment trail and any now-dangling reference to it reset.
        old_fc_dir = Path(config.FAILURE_CONTEXTS_DIR) / "tc_exec"
        old_fc_dir.mkdir(parents=True, exist_ok=True)
        (old_fc_dir / "fc-old-1.json").write_text("{}", encoding="utf-8")
        save_json_atomic(Path(config.VERDICTS_DIR) / "tc_exec.json",
                          [{"verdict_id": "verdict-old", "failure_context_id": "fc-old-1"}])
        tc_store.save_all([{"tc_id": "tc-old", "status": "FAIL", "steps": [],
                             "verdict_id": "verdict-old", "failure_context_id": "fc-old-1"}])

        executor = _FakeExecutor([[_ok(0)]])

        def _single_step_scenario(section, opcode_entry, available_opcodes, feedback=None, device_facts=None):
            return {"description": "d", "preconditions": [], "fail_criteria": [],
                    "steps_plan": [{"opcode_name": opcode_entry["name"], "role": "primary", "phase": "action"}],
                    "chain_summary": "", "rag_response_id": "r", "llm_response_id": "l"}

        with mock.patch.object(pipeline, "generate_scenario", side_effect=_single_step_scenario):
            pipeline.run_pipeline(count=1, executor=executor, allow_destructive=True)

        self.assertFalse((old_fc_dir / "fc-old-1.json").exists())
        verdicts = json.loads((Path(config.VERDICTS_DIR) / "tc_exec.json").read_text(encoding="utf-8"))
        self.assertEqual([v for v in verdicts if v.get("verdict_id") == "verdict-old"], [])

        old_tc = next(tc for tc in tc_store.load_all() if tc["tc_id"] == "tc-old")
        self.assertNotIn("verdict_id", old_tc)
        self.assertNotIn("failure_context_id", old_tc)
        self.assertEqual(old_tc["status"], "FAIL")  # coverage-relevant fields untouched


class TestResetCoverageFlag(PipelineTestCase):
    """`--reset-coverage` is for when the physical drive under test changed —
    without it, a new drive silently inherits the old one's accumulated
    coverage (including drive-specific UNSUPPORTED verdicts)."""
    def test_reset_coverage_wipes_tc_store_and_backs_it_up_first(self):
        tc_store.save_all([{"tc_id": "tc-old-device", "status": "FAIL", "steps": []}])
        save_json_atomic(config.COVERAGE_STATE_PATH, {"summary": {"reachable_pct": 100.0}})

        executor = _FakeExecutor([[_ok(0)]])
        with mock.patch.object(pipeline, "generate_scenario", side_effect=_single_step_scenario):
            pipeline.run_pipeline(count=1, executor=executor, allow_destructive=True, reset_coverage=True)

        stored_ids = [tc["tc_id"] for tc in tc_store.load_all()]
        self.assertNotIn("tc-old-device", stored_ids)  # wiped, not accumulated onto

        backups = list((Path(config.TC_STORE_PATH).parent / "coverage_backups").iterdir())
        self.assertEqual(len(backups), 1)
        backed_up = json.loads((backups[0] / "tc_store.json").read_text(encoding="utf-8"))
        self.assertEqual(backed_up[0]["tc_id"], "tc-old-device")  # old content preserved, not lost

    def test_without_the_flag_old_coverage_survives(self):
        tc_store.save_all([{"tc_id": "tc-old-device", "status": "FAIL", "steps": []}])
        executor = _FakeExecutor([[_ok(0)]])
        with mock.patch.object(pipeline, "generate_scenario", side_effect=_single_step_scenario):
            pipeline.run_pipeline(count=1, executor=executor, allow_destructive=True)
        stored_ids = [tc["tc_id"] for tc in tc_store.load_all()]
        self.assertIn("tc-old-device", stored_ids)


class TestCleanRun(PipelineTestCase):
    def test_all_steps_pass_straight_through(self):
        executor = _FakeExecutor([[_ok(0), _ok(1)]])
        result = self._run(executor)
        self.assertEqual(len(executor.calls), 1)
        self.assertEqual(result["failed"], 0)


class TestRejectionCascade(PipelineTestCase):
    def test_a_rejected_setup_step_triggers_cascading_reauthor_not_replan(self):
        # step 0 (Write, setup) rejected; step 1 (Read, action) was already
        # built assuming step 0's original facts. reauthor_steps should
        # rebuild both, and generate_scenario must NOT be called a second
        # time (this is a local fix, not a structural replan).
        executor = _FakeExecutor([
            [_rejected(0), _ok(1)],
            [_ok(0), _ok(1)],
        ])
        with mock.patch.object(pipeline, "generate_scenario", side_effect=_two_step_scenario) as gen:
            result = self._run(executor)
            self.assertEqual(gen.call_count, 1)  # only the initial plan, no replan
        self.assertEqual(len(executor.calls), 2)  # original attempt + one retry
        self.assertEqual(result["failed"], 0)

    def test_a_retry_is_recorded_so_the_terminal_can_flag_the_stale_printed_command(self):
        # Without this marker, run_tc_pipeline.py's "실행할 명령" block (printed
        # before any retry) can silently disagree with the final cdw10 printed
        # after, with nothing on screen explaining why.
        executor = _FakeExecutor([
            [_rejected(0), _ok(1)],
            [_ok(0), _ok(1)],
        ])
        with mock.patch.object(pipeline, "generate_scenario", side_effect=_two_step_scenario):
            self._run(executor)
        stored = json.loads(Path(config.TC_STORE_PATH).read_text(encoding="utf-8"))
        self.assertEqual(stored[0]["retried"]["kind"], "args_rejected")
        self.assertEqual(stored[0]["retried"]["step_index"], 0)

    def test_rejection_on_the_last_step_still_works(self):
        # A single-step TC (no setup step at all, so nothing destructive
        # could possibly precede the rejected step) — this is the original,
        # pre-multistep reauthor behavior as a special case of the same code
        # path, not a separate one.
        def _single_step_scenario(section, opcode_entry, available_opcodes, feedback=None, device_facts=None):
            return {"description": "d", "preconditions": [], "fail_criteria": [],
                    "steps_plan": [{"opcode_name": opcode_entry["name"], "role": "primary", "phase": "action"}],
                    "chain_summary": "", "rag_response_id": "r", "llm_response_id": "l"}

        executor = _FakeExecutor([
            [_rejected(0)],
            [_ok(0)],
        ])
        with mock.patch.object(pipeline, "generate_scenario", side_effect=_single_step_scenario):
            result = self._run(executor)
        self.assertEqual(len(executor.calls), 2)
        self.assertEqual(result["failed"], 0)


class TestUnsupportedNonActionStepReplans(PipelineTestCase):
    def test_unsupported_setup_step_triggers_a_replan(self):
        # step 0 (Write, setup) is UNSUPPORTED on this drive — no argument
        # fix helps, so this must go through generate_scenario with
        # feedback, which (per _two_step_scenario) drops the setup step.
        executor = _FakeExecutor([
            [_unsupported(0), _ok(1)],
            [_ok(0)],  # the replanned single-step attempt
        ])
        with mock.patch.object(pipeline, "generate_scenario", side_effect=_two_step_scenario) as gen:
            result = self._run(executor)
            self.assertEqual(gen.call_count, 2)  # initial plan + one replan
            self.assertIn("feedback", gen.call_args.kwargs)
        self.assertEqual(len(executor.calls), 2)
        self.assertEqual(len(executor.calls[1]), 1)  # replanned TC has only the action step
        self.assertEqual(result["failed"], 0)

    def test_a_replan_is_recorded_so_the_terminal_can_flag_the_stale_printed_command(self):
        executor = _FakeExecutor([
            [_unsupported(0), _ok(1)],
            [_ok(0)],
        ])
        with mock.patch.object(pipeline, "generate_scenario", side_effect=_two_step_scenario):
            self._run(executor)
        stored = json.loads(Path(config.TC_STORE_PATH).read_text(encoding="utf-8"))
        self.assertEqual(stored[0]["retried"]["kind"], "replanned")
        self.assertEqual(stored[0]["retried"]["step_index"], 0)


class TestUnsupportedActionStepIsNeverRetried(PipelineTestCase):
    def test_unsupported_action_step_is_accepted_as_is(self):
        # The action step itself (the fixed primary target) is UNSUPPORTED —
        # no plan change can avoid testing it, so this must NOT replan or
        # reauthor at all; it's recorded as UNSUPPORTED and left alone.
        executor = _FakeExecutor([[_ok(0), _unsupported(1)]])
        with mock.patch.object(pipeline, "generate_scenario", side_effect=_two_step_scenario) as gen:
            result = self._run(executor)
            self.assertEqual(gen.call_count, 1)  # no replan attempted
        self.assertEqual(len(executor.calls), 1)  # no retry executed
        self.assertEqual(result["unsupported"], 1)


class TestJudgedTcRecordsBothIds(PipelineTestCase):
    def test_a_judged_fail_stores_both_verdict_id_and_failure_context_id(self):
        # Before this, the terminal only ever printed verdict_id (and only
        # for FAIL, not ERROR) — finding the matching FailureContext file
        # required a manual two-hop lookup through data/verdicts/tc_exec.json.
        def _single_step_scenario(section, opcode_entry, available_opcodes, feedback=None, device_facts=None):
            return {"description": "d", "preconditions": [], "fail_criteria": [],
                    "steps_plan": [{"opcode_name": opcode_entry["name"], "role": "primary", "phase": "action"}],
                    "chain_summary": "", "rag_response_id": "r", "llm_response_id": "l"}

        executor = _FakeExecutor([[_plain_fail(0)]])
        with mock.patch.object(pipeline, "generate_scenario", side_effect=_single_step_scenario):
            self._run(executor)

        stored = json.loads((Path(config.TC_STORE_PATH)).read_text(encoding="utf-8"))
        self.assertEqual(len(stored), 1)
        tc = stored[0]
        self.assertEqual(tc["status"], "FAIL")
        self.assertIsNotNone(tc.get("verdict_id"))
        self.assertIsNotNone(tc.get("failure_context_id"))

        fc_path = Path(config.FAILURE_CONTEXTS_DIR) / "tc_exec" / f"{tc['failure_context_id']}.json"
        self.assertTrue(fc_path.exists())


class TestScenarioGenerationFailureIsNotFatal(PipelineTestCase):
    def test_a_failed_scenario_generation_is_skipped_not_fatal(self):
        # Measured for real: one target's scenario response came back
        # missing a declared key, and with no try/except around the call,
        # that crashed the whole --count batch — losing every other,
        # unrelated target queued after it. The failing target must instead
        # just be skipped (nothing was built or sent to the device, so it's
        # offered again next run) while the rest of the batch proceeds.
        calls = {"n": 0}

        def _flaky_scenario(section, opcode_entry, available_opcodes, feedback=None, device_facts=None):
            calls["n"] += 1
            if calls["n"] == 1:
                raise LLMCallError("LLM response missing required keys: ['fail_criteria']")
            return {"description": "d", "preconditions": [], "fail_criteria": [],
                    "steps_plan": [{"opcode_name": opcode_entry["name"], "role": "primary", "phase": "action"}],
                    "chain_summary": "", "rag_response_id": "r", "llm_response_id": "l"}

        executor = _FakeExecutor([[_ok(0)]])  # only the second (successful) target ever executes
        with mock.patch.object(pipeline, "generate_scenario", side_effect=_flaky_scenario):
            result = pipeline.run_pipeline(count=2, executor=executor, allow_destructive=True)
        self.assertEqual(calls["n"], 2)  # both targets were attempted
        self.assertEqual(result["skipped"], 1)
        self.assertEqual(len(executor.calls), 1)  # the skipped target never reached execution


class TestDeviceFactsReachGeneration(PipelineTestCase):
    def test_probed_capabilities_are_passed_to_scenario_and_arg_generation(self):
        # The probe runs once per batch (not once per TC) so generation can
        # avoid proposing commands/values already known unsupported, instead
        # of spending an LLM call plus an SSH round trip per target to
        # rediscover the same answer.
        author_calls = []

        def _capturing_author_args(*a, **k):
            author_calls.append(k.get("device_facts"))
            return _authored(a[1])

        executor = _FakeExecutor([[_ok(0), _ok(1)]])
        with mock.patch.object(pipeline, "probe_device_capabilities",
                                return_value={"id_ctrl": "oacs    : 0x17\n"}), \
             mock.patch.object(pipeline, "generate_scenario", side_effect=_two_step_scenario) as gen, \
             mock.patch.object(tc_writer, "author_args", side_effect=_capturing_author_args):
            self._run(executor)
        self.assertIn("Format NVM", gen.call_args.kwargs["device_facts"])
        self.assertTrue(all("Format NVM" in facts for facts in author_calls))

    def test_a_probe_failure_degrades_to_no_hint_instead_of_failing_the_run(self):
        executor = _FakeExecutor([[_ok(0), _ok(1)]])
        with mock.patch.object(pipeline, "probe_device_capabilities",
                                side_effect=RuntimeError("unreachable")), \
             mock.patch.object(pipeline, "generate_scenario", side_effect=_two_step_scenario) as gen:
            result = self._run(executor)
        self.assertIsNone(gen.call_args.kwargs["device_facts"])
        self.assertEqual(result["failed"], 0)


class TestDestructivePrecedentBlocksRetry(PipelineTestCase):
    def test_no_retry_after_a_destructive_step_already_ran(self):
        # step 0 (Write, destructive) already succeeded; step 1 being
        # rejected must not trigger any retry, since that would resend the
        # already-executed destructive step purely to fix something after it.
        executor = _FakeExecutor([[_ok(0), _rejected(1)]])
        with mock.patch.object(pipeline, "generate_scenario", side_effect=_two_step_scenario) as gen:
            result = self._run(executor)
            self.assertEqual(gen.call_count, 1)
        self.assertEqual(len(executor.calls), 1)  # no retry executed at all
        self.assertEqual(result["our_bugs"], 1)


def _single_step_scenario(section, opcode_entry, available_opcodes, feedback=None, device_facts=None):
    return {"description": "d", "preconditions": [], "fail_criteria": [],
            "steps_plan": [{"opcode_name": opcode_entry["name"], "role": "primary", "phase": "action"}],
            "chain_summary": "", "rag_response_id": "r", "llm_response_id": "l"}


class TestPlaceholderArgsIsSkippedNotFatal(PipelineTestCase):
    # Measured for real: a batch of --count 10 stopped dead at target 4
    # because one command's args fell back to a placeholder — nine unrelated
    # targets after it were lost. Nothing was ever sent to the device for
    # this target, so it must be skipped (offered again next run) like any
    # other per-target generation failure, not take the whole batch down.
    def test_placeholder_args_is_skipped_not_fatal(self):
        def _always_placeholder(*a, **k):
            raise ArgsAuthoringError("no spec context found")

        executor = _FakeExecutor([])  # never reached
        with mock.patch.object(pipeline, "generate_scenario", side_effect=_single_step_scenario), \
             mock.patch.object(tc_writer, "author_args", side_effect=_always_placeholder):
            result = pipeline.run_pipeline(count=1, executor=executor, allow_destructive=True)
        self.assertEqual(result["skipped"], 1)
        self.assertEqual(result["executed"], 0)
        self.assertEqual(len(executor.calls), 0)

    def test_on_skip_fires_with_the_target_and_reason(self):
        def _always_placeholder(*a, **k):
            raise ArgsAuthoringError("no spec context found")

        skips = []

        def _on_skip(i, total, section, opcode_entry, reason):
            skips.append((i, total, section["section_id"], opcode_entry["name"], reason))

        executor = _FakeExecutor([])
        with mock.patch.object(pipeline, "generate_scenario", side_effect=_single_step_scenario), \
             mock.patch.object(tc_writer, "author_args", side_effect=_always_placeholder):
            pipeline.run_pipeline(count=1, executor=executor, allow_destructive=True, on_skip=_on_skip)
        self.assertEqual(len(skips), 1)
        i, total, section_id, opcode_name, reason = skips[0]
        self.assertEqual((i, total, section_id, opcode_name), (1, 1, "nvm:1.1", "Read"))
        self.assertIn("placeholder", reason)

    def test_allow_placeholder_args_still_executes_it_anyway(self):
        # The opt-in flag's meaning is unchanged by this fix — only the
        # no-flag default changed from "halt the batch" to "skip".
        executor = _FakeExecutor([[_ok(0)]])
        with mock.patch.object(pipeline, "generate_scenario", side_effect=_single_step_scenario), \
             mock.patch.object(tc_writer, "author_args", side_effect=ArgsAuthoringError("no spec context found")):
            result = pipeline.run_pipeline(count=1, executor=executor, allow_placeholder_args=True,
                                            allow_destructive=True)
        self.assertEqual(result["skipped"], 0)
        self.assertEqual(len(executor.calls), 1)


class TestDestructiveBlockIsSkippedNotFatal(PipelineTestCase):
    class _BlockingExecutor:
        def execute(self, tc):
            raise DestructiveStepBlocked("refusing opcode 0x01 (data-destructive) on /dev/nvme0n1")

    def test_destructive_block_on_the_first_execute_is_skipped_not_fatal(self):
        # A chain the model built on its own (here, the action opcode itself)
        # hit the --no-destructive gate — unrelated to this target's own
        # correctness, so the rest of the batch must still run.
        with mock.patch.object(pipeline, "generate_scenario", side_effect=_single_step_scenario):
            result = pipeline.run_pipeline(count=1, executor=self._BlockingExecutor(), allow_destructive=False)
        self.assertEqual(result["skipped"], 1)
        self.assertEqual(result["executed"], 0)

    def test_on_skip_fires_for_a_destructive_block(self):
        skips = []

        def _on_skip(i, total, section, opcode_entry, reason):
            skips.append(reason)

        with mock.patch.object(pipeline, "generate_scenario", side_effect=_single_step_scenario):
            pipeline.run_pipeline(count=1, executor=self._BlockingExecutor(), allow_destructive=False,
                                   on_skip=_on_skip)
        self.assertEqual(len(skips), 1)
        self.assertIn("0x01", skips[0])


# Write sorts first (risk_class 0) so the destructive TC runs before the
# second target, letting the health check's effect on "what's left" be
# observed — in real runs risk_class instead pushes destructive commands
# toward the end, but the health-check logic itself doesn't care which
# target was destructive, only what comes after it.
WRITE_FIRST_INDEX_JSON = {
    "schema_version": 2, "source": "test", "rag_index_version": "test", "excluded_docs": [],
    "sections": [SECTION_WRITE, SECTION_READ],
    "opcodes": [dict(OPCODE_WRITE, risk_class=0), dict(OPCODE_READ, risk_class=1)],
}


class TestDeviceHealthCheckAfterRiskySteps(PipelineTestCase):
    def setUp(self):
        super().setUp()
        self.skips = []
        index_path = Path(self.tmp.name) / "write_first_index.json"
        index_path.write_text(json.dumps(WRITE_FIRST_INDEX_JSON), encoding="utf-8")
        self._index_patch = mock.patch.object(config, "active_coverage_index_path", lambda: index_path)
        self._index_patch.start()
        self.addCleanup(self._index_patch.stop)

    def _on_skip(self, i, total, section, opcode_entry, reason):
        self.skips.append((i, total, section["section_id"], reason))

    def test_a_dead_device_after_a_destructive_tc_stops_the_rest_of_the_batch(self):
        # Measured for real: a later TC's Write/Read failed with "No such
        # file or directory" because an earlier destructive TC in the same
        # batch had already changed the device/namespace state — grinding
        # through the remaining targets anyway would just repeat the same
        # failure for each one.
        executor = _FakeExecutor([[_ok(0)]])  # only the Write TC ever executes
        with mock.patch.object(pipeline, "generate_scenario", side_effect=_single_step_scenario), \
             mock.patch.object(pipeline, "device_responsive",
                                return_value=(False, "id-ctrl exit code 22: No such file or directory")):
            result = pipeline.run_pipeline(count=2, executor=executor, allow_destructive=True,
                                            on_skip=self._on_skip)
        self.assertEqual(len(executor.calls), 1)  # Read's TC never ran
        self.assertEqual(result["skipped"], 1)
        self.assertEqual(len(self.skips), 1)
        self.assertEqual(self.skips[0][2], "nvm:1.1")  # the skipped target is Read's section
        self.assertIn("No such file or directory", self.skips[0][3])

    def test_a_healthy_device_after_a_destructive_tc_continues_the_batch(self):
        executor = _FakeExecutor([[_ok(0)], [_ok(0)]])
        with mock.patch.object(pipeline, "generate_scenario", side_effect=_single_step_scenario), \
             mock.patch.object(pipeline, "device_responsive", return_value=(True, "")) as probe:
            result = pipeline.run_pipeline(count=2, executor=executor, allow_destructive=True,
                                            on_skip=self._on_skip)
        self.assertEqual(len(executor.calls), 2)  # both targets ran
        self.assertEqual(result["skipped"], 0)
        self.assertEqual(probe.call_count, 1)  # only after the destructive TC, not after Read's

    def test_no_health_check_when_nothing_risky_ran(self):
        swapped = {
            "schema_version": 2, "source": "test", "rag_index_version": "test", "excluded_docs": [],
            "sections": [SECTION_READ], "opcodes": [OPCODE_READ],
        }
        index_path = Path(self.tmp.name) / "read_only_index.json"
        index_path.write_text(json.dumps(swapped), encoding="utf-8")
        executor = _FakeExecutor([[_ok(0)]])
        with mock.patch.object(config, "active_coverage_index_path", lambda: index_path), \
             mock.patch.object(pipeline, "generate_scenario", side_effect=_single_step_scenario), \
             mock.patch.object(pipeline, "device_responsive") as probe:
            pipeline.run_pipeline(count=1, executor=executor, allow_destructive=True)
        probe.assert_not_called()


class TestReplanLlmFailureFallsBackToOriginal(PipelineTestCase):
    def test_a_failed_replan_keeps_the_original_result_instead_of_crashing(self):
        # Same failure mode that once crashed scenario generation for a
        # fresh target (TestScenarioGenerationFailureIsNotFatal) can happen
        # during a replan too — it must fall back to the already-executed
        # original result (step 0 UNSUPPORTED, step 1 PASS) rather than
        # propagate and take the rest of the batch down.
        calls = {"n": 0}

        def _flaky_replan(section, opcode_entry, available_opcodes, feedback=None, device_facts=None):
            calls["n"] += 1
            if feedback:
                raise LLMCallError("replan response missing required keys")
            return _two_step_scenario(section, opcode_entry, available_opcodes, feedback=feedback,
                                       device_facts=device_facts)

        executor = _FakeExecutor([[_unsupported(0), _ok(1)]])  # setup UNSUPPORTED, action PASS
        with mock.patch.object(pipeline, "generate_scenario", side_effect=_flaky_replan) as gen:
            result = self._run(executor)
            self.assertEqual(gen.call_count, 2)  # initial plan + attempted (failed) replan
        self.assertEqual(len(executor.calls), 1)  # no re-execution — replan failed, kept the original
        self.assertEqual(result["skipped"], 0)  # not skipped — the original result is still usable
        # The overall status follows the action step (PASS), not the
        # unimplemented setup step — the per-step view keeps both.
        self.assertEqual(result["unsupported"], 0)
        stored = json.loads(Path(config.TC_STORE_PATH).read_text(encoding="utf-8"))
        self.assertEqual(stored[0]["status"], "PASS")
        self.assertEqual(stored[0]["step_statuses"], ["UNSUPPORTED", "PASS"])


class TestJudgeFailureIsNotFatal(PipelineTestCase):
    def test_a_failed_judge_call_still_records_the_tc_without_a_verdict(self):
        # The device-side FAIL is real regardless of whether judging
        # succeeds — an LLM hiccup in judge_failure_context must not crash
        # the batch over a result that already happened on the device.
        executor = _FakeExecutor([[_plain_fail(0)]])
        with mock.patch.object(pipeline, "generate_scenario", side_effect=_single_step_scenario), \
             mock.patch.object(pipeline, "judge_failure_context",
                                side_effect=LLMCallError("judge call failed")):
            result = self._run(executor)
        self.assertEqual(result["failed"], 1)
        stored = json.loads(Path(config.TC_STORE_PATH).read_text(encoding="utf-8"))
        tc = stored[0]
        self.assertEqual(tc["status"], "FAIL")
        self.assertIsNone(tc.get("verdict_id"))
        self.assertIsNone(tc.get("failure_context_id"))


class _TimingOutExecutor(_FakeExecutor):
    def execute(self, tc):
        result = super().execute(tc)
        result["timed_out"] = True
        return result


def _hung(i):
    return {"step_index": i, "exit_code": None, "stdout": "", "started": True}


class TestPlaceholderRetryDoesNotOverwriteExecutedSteps(PipelineTestCase):
    def test_a_retry_that_falls_back_to_placeholder_keeps_the_steps_that_actually_ran(self):
        # The reauthor came back as placeholder, so nothing was re-sent. The
        # stored steps must still be the ones that produced the stored
        # results — not never-sent placeholder steps — and no "retried"
        # marker may claim a retry that didn't happen.
        calls = {"n": 0}

        def _author_then_fail(*a, **k):
            calls["n"] += 1
            if calls["n"] > 2:  # the two original steps succeed; the reauthor fails
                raise ArgsAuthoringError("no spec context found")
            return _authored(a[1])

        executor = _FakeExecutor([[_rejected(0), _ok(1)]])
        with mock.patch.object(tc_writer, "author_args", side_effect=_author_then_fail):
            self._run(executor)
        self.assertEqual(len(executor.calls), 1)
        stored = json.loads(Path(config.TC_STORE_PATH).read_text(encoding="utf-8"))[0]
        self.assertEqual([s["args_source"] for s in stored["steps"]], ["authored", "authored"])
        self.assertEqual(stored["steps"], executor.calls[0])
        self.assertNotIn("retried", stored)


class TestReplanBlockedByDestructiveGateFallsBackToOriginal(PipelineTestCase):
    class _BlockSecondExecute(_FakeExecutor):
        def execute(self, tc):
            if self.calls:
                raise DestructiveStepBlocked("refusing opcode 0x01 (data-destructive) on /dev/nvme0n1")
            return super().execute(tc)

    def test_the_already_executed_original_is_kept_not_skipped(self):
        # The original chain already ran on the device; the gate only blocks
        # the *replanned* one, before anything is sent. Skipping the target
        # (as this once did) threw away that real execution.
        executor = self._BlockSecondExecute([[_unsupported(0), _ok(1)]])
        result = self._run(executor)
        self.assertEqual(result["skipped"], 0)
        self.assertEqual(result["executed"], 1)
        stored = json.loads(Path(config.TC_STORE_PATH).read_text(encoding="utf-8"))
        self.assertEqual(len(stored), 1)
        self.assertEqual(stored[0]["step_statuses"], ["UNSUPPORTED", "PASS"])
        self.assertNotIn("retried", stored[0])


class TestMalformedLlmReplyIsNotFatal(PipelineTestCase):
    # run_judge.py has always caught (LLMCallError, ValueError, KeyError,
    # TypeError) around the same judge call; the TC pipeline caught only
    # LLMCallError, so the same malformed reply killed the whole batch here.
    def test_a_type_error_from_judging_still_records_the_tc(self):
        executor = _FakeExecutor([[_plain_fail(0)]])
        with mock.patch.object(pipeline, "generate_scenario", side_effect=_single_step_scenario), \
             mock.patch.object(pipeline, "judge_failure_context", side_effect=TypeError("list indices")):
            result = self._run(executor)
        self.assertEqual(result["failed"], 1)
        stored = json.loads(Path(config.TC_STORE_PATH).read_text(encoding="utf-8"))
        self.assertEqual(stored[0]["status"], "FAIL")

    def test_a_type_error_from_generation_skips_just_that_target(self):
        executor = _FakeExecutor([])
        with mock.patch.object(pipeline, "generate_scenario", side_effect=TypeError("bad reply shape")):
            result = self._run(executor)
        self.assertEqual(result["skipped"], 1)
        self.assertEqual(len(executor.calls), 0)


class TestTimeoutIsAFindingNotARetryTrigger(PipelineTestCase):
    def test_a_hang_is_not_retried_and_triggers_a_health_check(self):
        # Read is not destructive, so before this nothing checked the device
        # after its hang — and a retry would have overwritten the hang.
        executor = _TimingOutExecutor([[_hung(0)]])
        with mock.patch.object(pipeline, "generate_scenario", side_effect=_single_step_scenario), \
             mock.patch.object(pipeline, "device_responsive", return_value=(True, "")) as probe:
            self._run(executor)
        self.assertEqual(len(executor.calls), 1)
        probe.assert_called_once()
        stored = json.loads(Path(config.TC_STORE_PATH).read_text(encoding="utf-8"))
        self.assertEqual(stored[0]["status"], "FAIL")

    def test_a_dead_device_after_a_hang_stops_the_batch(self):
        skips = []
        executor = _TimingOutExecutor([[_hung(0)]])
        with mock.patch.object(pipeline, "generate_scenario", side_effect=_single_step_scenario), \
             mock.patch.object(pipeline, "device_responsive",
                                return_value=(False, "device did not respond within 15s")):
            result = pipeline.run_pipeline(count=2, executor=executor, allow_destructive=True,
                                            on_skip=lambda *a: skips.append(a[-1]))
        self.assertEqual(len(executor.calls), 1)
        self.assertEqual(result["skipped"], 1)
        self.assertIn("타임아웃", skips[0])


class TestJudgeIsGroundedOnTheActionStep(PipelineTestCase):
    def test_failure_context_names_the_action_not_the_first_setup_step(self):
        # source_opcodes[0] is the Write setup step; judging a Write->Read TC
        # against Write's spec text grounded it on the wrong command.
        executor = _FakeExecutor([[_ok(0), _plain_fail(1)]])
        with mock.patch.object(pipeline, "judge_failure_context",
                                return_value={"verdict_id": "v-1", "classification": "needs_engineer_review"}) as judge:
            self._run(executor)
        fc = judge.call_args.args[0]
        self.assertEqual(fc["signals"]["cmd_name"], "Read")
        self.assertEqual(fc["signals"]["opcode"], "0x02")


SECTION_LOG_PAGE_LID = {
    "section_id": "base:5.2.12.1.2", "spec_doc": "NVM-Express-Base-Specification",
    "spec_doc_label": "x", "doc": "base", "clause": "5.2.12.1.2",
    "title": "Error Information (Log Page Identifier 01h)",
    "related_opcodes": ["0x02a"], "chunk_ids": [], "covers_commands": [],
    "field_values": [{"field_name": "Log Page Identifier", "hex_value": "0x01"}],
}
OPCODE_GET_LOG_PAGE = {
    "opcode": "0x02a", "raw_opcode": "0x02", "name": "Get Log Page", "command_set": "ADMIN",
    "spec_doc": "NVM-Express-Base-Specification", "spec_doc_label": "x",
    "section_ref": "base:5.2.12", "direction": "read", "destructive": False,
    "firmware_state": False, "lockout_risk": False, "risk_class": 0, "source": "test",
}
FIELD_VALUE_INDEX_JSON = {
    "schema_version": 3, "source": "test", "rag_index_version": "test", "excluded_docs": [],
    "sections": [SECTION_LOG_PAGE_LID], "opcodes": [OPCODE_GET_LOG_PAGE],
}


class TestFieldValueTargetIsUnsupportedNotError(PipelineTestCase):
    def test_a_verified_rejection_counts_as_unsupported_not_our_bug(self):
        # End-to-end: a target whose section requires a specific Log Page
        # Identifier, correctly placed in CDW10 (field_value_verified=True),
        # gets rejected by the (stub) controller — this must land as
        # UNSUPPORTED (a real finding, counted toward coverage) rather than
        # ERROR (skipped as "our bug" and offered again next run).
        index_path = Path(self.tmp.name) / "field_value_index.json"
        index_path.write_text(json.dumps(FIELD_VALUE_INDEX_JSON), encoding="utf-8")

        def _single_step_for(section, opcode_entry, available_opcodes, feedback=None, device_facts=None):
            return {"description": "d", "preconditions": [], "fail_criteria": [],
                    "steps_plan": [{"opcode_name": opcode_entry["name"], "role": "primary", "phase": "action"}],
                    "chain_summary": "", "rag_response_id": "r", "llm_response_id": "l"}

        def _verified_author_args(section, opcode_entry, active_nsid, **kwargs):
            return {"cdw10": "0x00000001", "cdw11": "0x00000000", "cdw12": "0x00000000", "data_len": 0,
                    "direction": "none", "nsid": 0, "shared_facts": {}, "field_breakdown": "LID=01h",
                    "field_value_verified": True}

        executor = _FakeExecutor([[{"step_index": 0, "exit_code": 22, "stdout":
                                     "NVMe status: INVALID_LOG_PAGE: The log page indicated is invalid(0x109)"}]])
        with mock.patch.object(config, "active_coverage_index_path", lambda: index_path), \
             mock.patch.object(pipeline, "generate_scenario", side_effect=_single_step_for), \
             mock.patch.object(tc_writer, "author_args", side_effect=_verified_author_args):
            result = pipeline.run_pipeline(count=1, executor=executor, allow_destructive=True)

        self.assertEqual(result["unsupported"], 1)
        self.assertEqual(result["our_bugs"], 0)
        self.assertEqual(result["skipped"], 0)
        stored = json.loads(Path(config.TC_STORE_PATH).read_text(encoding="utf-8"))
        self.assertEqual(stored[0]["status"], "UNSUPPORTED")


if __name__ == "__main__":
    unittest.main()
