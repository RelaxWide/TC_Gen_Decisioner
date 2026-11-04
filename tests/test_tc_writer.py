import unittest
from unittest import mock

from tc_system.generation import tc_writer
from tc_system.generation.tc_writer import build_tc, namespace_id_from_device_path, reauthor_steps

SECTION_READ = {"section_id": "nvm:3.3.4", "spec_doc": "NVM-Express-NVM-Command-Set-Specification",
                 "title": "Read command"}
OPCODE_READ = {"opcode": "0x02n", "raw_opcode": "0x02", "name": "Read", "command_set": "NVM",
               "destructive": False, "firmware_state": False}
SECTION_WRITE = {"section_id": "nvm:3.3.6", "spec_doc": "NVM-Express-NVM-Command-Set-Specification",
                  "title": "Write command"}
OPCODE_WRITE = {"opcode": "0x01n", "raw_opcode": "0x01", "name": "Write", "command_set": "NVM",
                "destructive": True, "firmware_state": False}

SCENARIO = {"description": "Write a pattern then read it back.", "preconditions": [], "fail_criteria": [],
            "rag_response_id": "r", "llm_response_id": "l", "chain_summary": "Write then read back."}

ACTIVE_NSID = 1
NVME_CTRL, NVME_NS = "/dev/nvme0", "/dev/nvme0n1"

ACTION_ONLY = [{"section": SECTION_READ, "opcode_entry": OPCODE_READ, "phase": "action", "role": "primary"}]
WRITE_THEN_READ = [
    {"section": SECTION_WRITE, "opcode_entry": OPCODE_WRITE, "phase": "setup", "role": "write a known pattern"},
    {"section": SECTION_READ, "opcode_entry": OPCODE_READ, "phase": "action", "role": "read it back"},
]

SECTION_COMPARE = {"section_id": "nvm:3.3.1", "spec_doc": "NVM-Express-NVM-Command-Set-Specification",
                    "title": "Compare command"}
OPCODE_COMPARE = {"opcode": "0x05n", "raw_opcode": "0x05", "name": "Compare", "command_set": "NVM",
                   "destructive": False, "firmware_state": False}
WRITE_READ_COMPARE = WRITE_THEN_READ + [
    {"section": SECTION_COMPARE, "opcode_entry": OPCODE_COMPARE, "phase": "verify", "role": "confirm it matches"},
]


def _authored(opcode_entry, shared_facts=None):
    return {"cdw10": "0x00000000", "cdw11": "0x00000000", "cdw12": "0x00000000", "data_len": 512,
            "direction": "read" if opcode_entry["name"] == "Read" else "write", "nsid": ACTIVE_NSID,
            "shared_facts": shared_facts or {}, "field_breakdown": "stub"}


class TestNamespaceIdFromDevicePath(unittest.TestCase):
    def test_parses_the_trailing_namespace_number(self):
        self.assertEqual(namespace_id_from_device_path("/dev/nvme0n1"), 1)

    def test_handles_multi_digit_and_multi_namespace_drives(self):
        self.assertEqual(namespace_id_from_device_path("/dev/nvme1n23"), 23)

    def test_a_controller_only_path_has_no_namespace_to_derive(self):
        # Passing the controller device (no "n<N>" suffix) here instead of
        # the namespace device is a config mistake — it must fail loudly
        # rather than silently guessing a namespace id.
        with self.assertRaises(ValueError):
            namespace_id_from_device_path("/dev/nvme0")


class TestBuildTcSingleStep(unittest.TestCase):
    """Regression guard: a single-action-step TC must look byte-identical to
    what build_tc produced before multi-step chains existed."""

    def setUp(self):
        patcher = mock.patch.object(tc_writer, "author_args", side_effect=lambda *a, **k: _authored(a[1]))
        self.addCleanup(patcher.stop)
        patcher.start()

    def test_name_and_expectation_match_the_pre_multistep_format(self):
        tc = build_tc("tc-1", ACTION_ONLY, SCENARIO, NVME_CTRL, NVME_NS, ACTIVE_NSID)
        self.assertEqual(tc["name"], "TC_Read_nvm_3_3_4")
        self.assertEqual(tc["expectation"]["description"],
                          "Opcode 0x02 (Read) completes without controller-reported error and within its timeout.")
        self.assertEqual(tc["chain_summary"], "")
        self.assertEqual(tc["source_section_ids"], ["nvm:3.3.4"])
        self.assertEqual(tc["source_opcodes"], ["0x02n"])
        self.assertEqual(tc["step_section_ids"], ["nvm:3.3.4"])
        self.assertEqual(tc["step_opcodes"], ["0x02n"])
        self.assertFalse(tc["destructive"])
        self.assertEqual(len(tc["steps"]), 1)


SECTION_READ_WITH_FIELD_VALUE = dict(SECTION_READ, field_values=[{"field_name": "CNS", "hex_value": "0x01"}])


class TestFieldValueThreading(unittest.TestCase):
    """A target section's own `field_values` (see build_spec_index.py's
    `link_field_values`) must reach `author_args` as `required_field_values`,
    and whatever it reports back must be stamped onto the step — this is
    what lets expectation_checker later tell "this drive doesn't implement
    this specific value" apart from "we authored a malformed argument"."""
    def test_section_field_values_reach_author_args_and_get_stamped(self):
        captured = {}

        def _fake_author_args(section, opcode_entry, active_nsid, **kwargs):
            captured["required_field_values"] = kwargs.get("required_field_values")
            return dict(_authored(opcode_entry), field_value_verified=True)

        with mock.patch.object(tc_writer, "author_args", side_effect=_fake_author_args):
            action_only = [{"section": SECTION_READ_WITH_FIELD_VALUE, "opcode_entry": OPCODE_READ,
                             "phase": "action", "role": "primary"}]
            tc = build_tc("tc-1", action_only, SCENARIO, NVME_CTRL, NVME_NS, ACTIVE_NSID)
        self.assertEqual(captured["required_field_values"], [{"field_name": "CNS", "hex_value": "0x01"}])
        self.assertTrue(tc["steps"][0]["field_value_verified"])

    def test_a_section_without_field_values_passes_none_and_stamps_false(self):
        captured = {}

        def _fake_author_args(section, opcode_entry, active_nsid, **kwargs):
            captured["required_field_values"] = kwargs.get("required_field_values")
            return _authored(opcode_entry)  # no field_value_verified key at all

        with mock.patch.object(tc_writer, "author_args", side_effect=_fake_author_args):
            tc = build_tc("tc-1", ACTION_ONLY, SCENARIO, NVME_CTRL, NVME_NS, ACTIVE_NSID)
        self.assertIsNone(captured["required_field_values"])
        self.assertFalse(tc["steps"][0]["field_value_verified"])

    def test_placeholder_fallback_still_has_the_key(self):
        from tc_system.generation.args_author import ArgsAuthoringError
        with mock.patch.object(tc_writer, "author_args", side_effect=ArgsAuthoringError("no spec context")):
            tc = build_tc("tc-1", ACTION_ONLY, SCENARIO, NVME_CTRL, NVME_NS, ACTIVE_NSID)
        self.assertFalse(tc["steps"][0]["field_value_verified"])


class TestBuildTcMultiStep(unittest.TestCase):
    def setUp(self):
        self.calls = []

        def _fake_author_args(section, opcode_entry, active_nsid, prior_steps=None, rejected=None,
                               device_facts=None, required_field_values=None, test_intent=None):
            self.calls.append({"opcode_entry": opcode_entry, "prior_steps": prior_steps})
            facts = {"lba": "0x5", "nlb": "0"} if opcode_entry["name"] == "Write" else {}
            return _authored(opcode_entry, shared_facts=facts)

        patcher = mock.patch.object(tc_writer, "author_args", side_effect=_fake_author_args)
        self.addCleanup(patcher.stop)
        patcher.start()

    def test_name_is_based_on_the_action_step_only(self):
        tc = build_tc("tc-1", WRITE_THEN_READ, SCENARIO, NVME_CTRL, NVME_NS, ACTIVE_NSID)
        # Not "TC_Write_then_Read_..." — the name stays exactly as short and
        # stable as a single-step TC's, regardless of chain length.
        self.assertEqual(tc["name"], "TC_Read_nvm_3_3_4")

    def test_chain_summary_and_expectation_describe_the_whole_sequence(self):
        tc = build_tc("tc-1", WRITE_THEN_READ, SCENARIO, NVME_CTRL, NVME_NS, ACTIVE_NSID)
        self.assertEqual(tc["chain_summary"], "Write then read back.")
        self.assertIn("0x01 (Write)", tc["expectation"]["description"])
        self.assertIn("0x02 (Read)", tc["expectation"]["description"])

    def test_each_step_carries_its_own_name_phase_and_role_for_display(self):
        tc = build_tc("tc-1", WRITE_THEN_READ, SCENARIO, NVME_CTRL, NVME_NS, ACTIVE_NSID)
        self.assertEqual(tc["steps"][0]["name"], "Write")
        self.assertEqual(tc["steps"][0]["phase"], "setup")
        self.assertEqual(tc["steps"][0]["role"], "write a known pattern")
        self.assertEqual(tc["steps"][1]["name"], "Read")
        self.assertEqual(tc["steps"][1]["phase"], "action")
        self.assertEqual(tc["steps"][1]["role"], "read it back")

    def test_destructive_is_true_if_any_step_is(self):
        tc = build_tc("tc-1", WRITE_THEN_READ, SCENARIO, NVME_CTRL, NVME_NS, ACTIVE_NSID)
        self.assertTrue(tc["destructive"])

    def test_step_arrays_are_not_deduped_and_align_with_steps(self):
        tc = build_tc("tc-1", WRITE_THEN_READ, SCENARIO, NVME_CTRL, NVME_NS, ACTIVE_NSID)
        self.assertEqual(tc["step_section_ids"], ["nvm:3.3.6", "nvm:3.3.4"])
        self.assertEqual(tc["step_opcodes"], ["0x01n", "0x02n"])
        self.assertEqual(len(tc["steps"]), 2)

    def test_later_steps_see_earlier_steps_shared_facts(self):
        build_tc("tc-1", WRITE_THEN_READ, SCENARIO, NVME_CTRL, NVME_NS, ACTIVE_NSID)
        write_call, read_call = self.calls
        self.assertEqual(write_call["prior_steps"], [])  # nothing precedes the first step
        self.assertEqual(len(read_call["prior_steps"]), 1)
        self.assertEqual(read_call["prior_steps"][0]["opcode_name"], "Write")
        self.assertEqual(read_call["prior_steps"][0]["facts"], {"lba": "0x5", "nlb": "0"})


class TestReauthorSteps(unittest.TestCase):
    def test_only_the_rejected_step_is_rebuilt(self):
        with mock.patch.object(tc_writer, "author_args", side_effect=lambda *a, **k: _authored(a[1])):
            tc = build_tc("tc-1", WRITE_THEN_READ, SCENARIO, NVME_CTRL, NVME_NS, ACTIVE_NSID)
        original_step0 = dict(tc["steps"][0])

        with mock.patch.object(tc_writer, "author_args",
                                side_effect=lambda *a, **k: _authored(a[1], shared_facts={"lba": "0x9", "nlb": "0"})):
            new_steps = reauthor_steps(tc, WRITE_THEN_READ, {"step_index": 1, "reason": "INVALID_FIELD"},
                                        ACTIVE_NSID)
        self.assertEqual(new_steps[0], original_step0)
        self.assertEqual(new_steps[1]["shared_facts"], {"lba": "0x9", "nlb": "0"})

    def test_rejection_not_on_the_last_step_cascades_to_everything_after_it(self):
        # Reject step 0 (Write) in a 3-step chain — steps 1 (Read) and 2
        # (Compare) were already authored assuming Write's original
        # shared_facts, so leaving them untouched would leave them pointing
        # at a location Write no longer actually wrote to.
        with mock.patch.object(tc_writer, "author_args", side_effect=lambda *a, **k: _authored(
                a[1], shared_facts={"lba": "0x5", "nlb": "0"} if a[1]["name"] == "Write" else {})):
            tc = build_tc("tc-1", WRITE_READ_COMPARE, SCENARIO, NVME_CTRL, NVME_NS, ACTIVE_NSID)

        calls = []

        def _capture(section, opcode_entry, active_nsid, prior_steps=None, rejected=None, device_facts=None,
                     required_field_values=None, test_intent=None):
            calls.append({"opcode_entry": opcode_entry, "prior_steps": prior_steps, "rejected": rejected})
            facts = {"lba": "0x9", "nlb": "0"} if opcode_entry["name"] == "Write" else {}
            return _authored(opcode_entry, shared_facts=facts)

        with mock.patch.object(tc_writer, "author_args", side_effect=_capture):
            new_steps = reauthor_steps(tc, WRITE_READ_COMPARE, {"step_index": 0, "reason": "INVALID_FIELD"},
                                        ACTIVE_NSID)
        self.assertEqual(len(calls), 3)  # all three steps rebuilt, not just step 0
        self.assertEqual(calls[0]["rejected"]["reason"], "INVALID_FIELD")
        self.assertIsNone(calls[1]["rejected"])
        self.assertIsNone(calls[2]["rejected"])
        # step 1 (Read) and step 2 (Compare) must see Write's NEW lba (0x9),
        # not the stale 0x5 it was originally authored against.
        self.assertEqual(calls[1]["prior_steps"][0]["facts"], {"lba": "0x9", "nlb": "0"})
        self.assertEqual(calls[2]["prior_steps"][0]["facts"], {"lba": "0x9", "nlb": "0"})
        self.assertEqual(len(new_steps), 3)

    def test_rebuild_still_sees_earlier_steps_facts(self):
        with mock.patch.object(tc_writer, "author_args", side_effect=lambda *a, **k: _authored(
                a[1], shared_facts={"lba": "0x5", "nlb": "0"} if a[1]["name"] == "Write" else {})):
            tc = build_tc("tc-1", WRITE_THEN_READ, SCENARIO, NVME_CTRL, NVME_NS, ACTIVE_NSID)

        captured = {}

        def _capture(section, opcode_entry, active_nsid, prior_steps=None, rejected=None, device_facts=None,
                     required_field_values=None, test_intent=None):
            captured["prior_steps"] = prior_steps
            return _authored(opcode_entry)

        with mock.patch.object(tc_writer, "author_args", side_effect=_capture):
            reauthor_steps(tc, WRITE_THEN_READ, {"step_index": 1, "reason": "INVALID_FIELD"}, ACTIVE_NSID)
        self.assertEqual(captured["prior_steps"][0]["facts"], {"lba": "0x5", "nlb": "0"})


if __name__ == "__main__":
    unittest.main()
