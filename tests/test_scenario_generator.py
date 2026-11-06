"""Validation tests for multi-step scenario planning.

No network: `generate_scenario` is exercised through a stubbed LLM so the
steps_plan validation/fallback logic is covered without calling out.
"""
from copy import deepcopy
import unittest
from unittest import mock

from tc_system.generation import scenario_generator
from tc_system.generation.scenario_generator import generate_scenario

SECTION = {"section_id": "nvm:3.3.4", "spec_doc": "NVM-Express-NVM-Command-Set-Specification",
           "title": "Read command"}
OPCODE = {"name": "Read", "raw_opcode": "0x02", "command_set": "NVM", "risk_class": 0}

AVAILABLE_OPCODES = [
    OPCODE,
    {"name": "Write", "raw_opcode": "0x01", "command_set": "NVM", "risk_class": 2},
    {"name": "Compare", "raw_opcode": "0x05", "command_set": "NVM", "risk_class": 0},
    {"name": "Set Features", "raw_opcode": "0x09", "command_set": "ADMIN", "risk_class": 1},
    {"name": "Get Features", "raw_opcode": "0x0A", "command_set": "ADMIN", "risk_class": 0},
    {"name": "Format NVM", "raw_opcode": "0x80", "command_set": "ADMIN", "risk_class": 2},
]

GOOD_STRUCTURED = {
    "description": "Verify Read returns the deallocated status for an unwritten LBA.",
    "preconditions": [],
    "fail_criteria": ["Read does not return the deallocated status"],
    "steps_plan": [{"opcode_name": "Read", "role": "primary clause behavior", "phase": "action"}],
    "chain_summary": "Read an unwritten LBA and check the deallocated status.",
}


EVIDENCE = {"evidence_id": "spec-fixture", "section_id": SECTION["section_id"],
            "role": "target", "text": "The Read command shall return the requested data to the host."}


def prepared(structured):
    structured = deepcopy(structured)
    plan = structured["steps_plan"]
    for step in plan:
        if not isinstance(step, dict):
            continue
        step.setdefault("expected_status", "SUCCESS")
        # Set Features on Power Management (02h): a feature the harness can
        # restore (a successful Set of an unknown FID is refused).
        step.setdefault("field_constraints", [{"field": f"cdw{i}", "mask": "0xFFFFFFFF",
                                               "value": 2 if i == 10 and step.get("opcode_name") == "Set Features"
                                               else 0} for i in (10, 11, 12)])
    action = next((i for i, p in enumerate(plan) if isinstance(p, dict) and p.get("phase") == "action"), 0)
    structured.setdefault("requirements", [{"description": "Read completion", "evidence_id": "spec-fixture",
                                              "quote": EVIDENCE["text"],
                                              "checks": [{"kind": "completion", "step": action}]}])
    structured.setdefault("precondition_checks", [])
    structured.setdefault("required_capabilities", ["sequential", "completion_status"])
    structured.setdefault("out_of_scope", [])
    return structured


def _run(structured, available_opcodes=AVAILABLE_OPCODES, feedback=None, opcode=OPCODE):
    with mock.patch.object(scenario_generator, "generate_rag_response",
                            return_value={"chunks": [EVIDENCE], "response_id": "r"}), \
         mock.patch.object(scenario_generator, "generate_llm_response",
                            return_value={"structured": prepared(structured), "response_id": "l"}):
        return generate_scenario(SECTION, opcode, available_opcodes, feedback=feedback)


class TestStepsPlanValidation(unittest.TestCase):
    def test_non_object_entry_is_rejected(self):
        # A bare string entry used to raise AttributeError, which nothing
        # upstream caught — one malformed reply ended the whole batch.
        with self.assertRaises(ValueError):
            _run(dict(GOOD_STRUCTURED, steps_plan=[
                "Write", {"opcode_name": "Read", "role": "primary", "phase": "action"}]))

    def test_single_action_step_passes_through(self):
        out = _run(dict(GOOD_STRUCTURED))
        self.assertEqual(out["steps_plan"], prepared(GOOD_STRUCTURED)["steps_plan"])
        self.assertEqual(out["chain_summary"], GOOD_STRUCTURED["chain_summary"])

    def test_scope_notes_are_recorded_not_a_reason_to_skip(self):
        # Measured: honest notes such as "other LIDs are not covered by this
        # single-action TC" used to reject every scenario (all targets skipped).
        notes = ["지원하지 않는 LID에 대한 동작은 이 TC에서 검증하지 않음"]
        for key in ("out_of_scope", "unverified_conditions"):  # the older key too
            with self.subTest(key=key):
                out = _run(dict(GOOD_STRUCTURED, **{key: notes}))
                self.assertEqual(out["out_of_scope"], notes)

    def test_scope_notes_must_be_strings(self):
        with self.assertRaisesRegex(ValueError, "out_of_scope"):
            _run(dict(GOOD_STRUCTURED, out_of_scope="not a list"))

    def test_setup_before_action_and_verify_after_is_accepted(self):
        plan = [
            {"opcode_name": "Write", "role": "write a known pattern", "phase": "setup"},
            {"opcode_name": "Read", "role": "primary clause behavior", "phase": "action"},
            {"opcode_name": "Compare", "role": "confirm the data matches", "phase": "verify"},
        ]
        out = _run(dict(GOOD_STRUCTURED, steps_plan=plan))
        self.assertEqual(out["steps_plan"], prepared(dict(GOOD_STRUCTURED, steps_plan=plan))["steps_plan"])

    def test_multiple_setup_steps_are_allowed(self):
        # PM-state-transition-style scenarios need more than one precondition
        # step — the design explicitly rejects a fixed step-count cap.
        plan = [
            {"opcode_name": "Set Features", "role": "enter state A", "phase": "setup"},
            {"opcode_name": "Set Features", "role": "enter state B", "phase": "setup"},
            {"opcode_name": "Read", "role": "primary clause behavior", "phase": "action"},
        ]
        out = _run(dict(GOOD_STRUCTURED, steps_plan=plan))
        self.assertEqual(out["steps_plan"], prepared(dict(GOOD_STRUCTURED, steps_plan=plan))["steps_plan"])

    def test_missing_action_step_is_rejected(self):
        plan = [{"opcode_name": "Write", "role": "oops", "phase": "setup"}]
        with self.assertRaises(ValueError):
            _run(dict(GOOD_STRUCTURED, steps_plan=plan))

    def test_action_step_naming_a_different_command_is_rejected(self):
        plan = [{"opcode_name": "Write", "role": "wrong target", "phase": "action"}]
        with self.assertRaises(ValueError):
            _run(dict(GOOD_STRUCTURED, steps_plan=plan))

    def test_invented_command_name_is_rejected(self):
        plan = [
            {"opcode_name": "Totally Made Up Command", "role": "setup", "phase": "setup"},
            {"opcode_name": "Read", "role": "primary clause behavior", "phase": "action"},
        ]
        with self.assertRaises(ValueError):
            _run(dict(GOOD_STRUCTURED, steps_plan=plan))

    def test_setup_after_action_is_rejected(self):
        plan = [
            {"opcode_name": "Read", "role": "primary clause behavior", "phase": "action"},
            {"opcode_name": "Write", "role": "misordered", "phase": "setup"},
        ]
        with self.assertRaises(ValueError):
            _run(dict(GOOD_STRUCTURED, steps_plan=plan))

    def test_verify_before_action_is_rejected(self):
        plan = [
            {"opcode_name": "Compare", "role": "misordered", "phase": "verify"},
            {"opcode_name": "Read", "role": "primary clause behavior", "phase": "action"},
        ]
        with self.assertRaises(ValueError):
            _run(dict(GOOD_STRUCTURED, steps_plan=plan))

    def test_a_destructive_setup_step_riskier_than_the_action_is_accepted(self):
        # The canonical case: Write (risk_class 2, destructive) setting up
        # data for a Read (risk_class 0) action to verify. risk_class is a
        # batch-ordering preference, not a safety gate — the real safety
        # boundary is execute_tc_steps's DestructiveStepBlocked, which scans
        # every step regardless of phase, so steps_plan validation must not
        # reject this.
        plan = [
            {"opcode_name": "Format NVM", "role": "reset to a known state", "phase": "setup"},
            {"opcode_name": "Read", "role": "primary clause behavior", "phase": "action"},
        ]
        out = _run(dict(GOOD_STRUCTURED, steps_plan=plan))
        self.assertEqual(out["steps_plan"], prepared(dict(GOOD_STRUCTURED, steps_plan=plan))["steps_plan"])

    def test_two_action_steps_is_rejected(self):
        plan = [
            {"opcode_name": "Read", "role": "primary clause behavior", "phase": "action"},
            {"opcode_name": "Write", "role": "also action?", "phase": "action"},
        ]
        with self.assertRaises(ValueError):
            _run(dict(GOOD_STRUCTURED, steps_plan=plan))

    def test_admin_and_nvm_commands_can_mix_in_one_plan(self):
        plan = [
            {"opcode_name": "Set Features", "role": "enable a caching behavior", "phase": "setup"},
            {"opcode_name": "Read", "role": "primary clause behavior", "phase": "action"},
        ]
        out = _run(dict(GOOD_STRUCTURED, steps_plan=plan))
        self.assertEqual(out["steps_plan"], prepared(dict(GOOD_STRUCTURED, steps_plan=plan))["steps_plan"])


    def test_a_trigger_then_target_plan_is_relabelled_not_rejected(self):
        # Measured (base:5.2.12.1.14.2.11): "Set Features (action) -> Get Log
        # Page (verify)" for a Get Log Page clause. Right order, wrong label.
        plan = [{"opcode_name": "Write", "role": "trigger", "phase": "action"},
                {"opcode_name": "Read", "role": "observe", "phase": "verify"}]
        requirements = [{"description": "Read completion", "evidence_id": "spec-fixture",
                         "quote": EVIDENCE["text"], "checks": [{"kind": "completion", "step": 1}]}]
        out = _run(dict(GOOD_STRUCTURED, steps_plan=plan, requirements=requirements))
        self.assertEqual([s["phase"] for s in out["steps_plan"]], ["setup", "action"])

    def test_a_plan_without_the_target_command_is_still_rejected(self):
        plan = [{"opcode_name": "Write", "role": "x", "phase": "action"}]
        with self.assertRaisesRegex(ValueError, "not in steps_plan"):
            _run(dict(GOOD_STRUCTURED, steps_plan=plan))

class TestReplanFeedback(unittest.TestCase):
    def test_feedback_reaches_the_prompt(self):
        captured = {}

        def _capture(prompt, **kwargs):
            captured["prompt"] = prompt
            return {"structured": prepared(GOOD_STRUCTURED), "response_id": "l"}

        with mock.patch.object(scenario_generator, "generate_rag_response",
                                return_value={"chunks": [EVIDENCE], "response_id": "r"}), \
             mock.patch.object(scenario_generator, "generate_llm_response", _capture):
            generate_scenario(SECTION, OPCODE, AVAILABLE_OPCODES,
                               feedback="step 0 (Write) was rejected: NVMe status: INVALID_FIELD")
        self.assertIn("did not work out", captured["prompt"])
        self.assertIn("INVALID_FIELD", captured["prompt"])

    def test_no_feedback_means_no_extra_prompt_text(self):
        captured = {}

        def _capture(prompt, **kwargs):
            captured["prompt"] = prompt
            return {"structured": prepared(GOOD_STRUCTURED), "response_id": "l"}

        with mock.patch.object(scenario_generator, "generate_rag_response",
                                return_value={"chunks": [EVIDENCE], "response_id": "r"}), \
             mock.patch.object(scenario_generator, "generate_llm_response", _capture):
            generate_scenario(SECTION, OPCODE, AVAILABLE_OPCODES)
        self.assertNotIn("did not work out", captured["prompt"])


class TestDeviceFacts(unittest.TestCase):
    def test_device_facts_reaches_the_prompt(self):
        captured = {}

        def _capture(prompt, **kwargs):
            captured["prompt"] = prompt
            return {"structured": prepared(GOOD_STRUCTURED), "response_id": "l"}

        with mock.patch.object(scenario_generator, "generate_rag_response",
                                return_value={"chunks": [EVIDENCE], "response_id": "r"}), \
             mock.patch.object(scenario_generator, "generate_llm_response", _capture):
            generate_scenario(SECTION, OPCODE, AVAILABLE_OPCODES,
                               device_facts="지원하는 optional admin 커맨드(OACS): Format NVM")
        self.assertIn("device_facts", captured["prompt"])
        self.assertIn("Format NVM", captured["prompt"])

    def test_no_device_facts_means_no_extra_prompt_text(self):
        captured = {}

        def _capture(prompt, **kwargs):
            captured["prompt"] = prompt
            return {"structured": prepared(GOOD_STRUCTURED), "response_id": "l"}

        with mock.patch.object(scenario_generator, "generate_rag_response",
                                return_value={"chunks": [EVIDENCE], "response_id": "r"}), \
             mock.patch.object(scenario_generator, "generate_llm_response", _capture):
            generate_scenario(SECTION, OPCODE, AVAILABLE_OPCODES)
        self.assertNotIn("device_facts", captured["prompt"])


if __name__ == "__main__":
    unittest.main()
