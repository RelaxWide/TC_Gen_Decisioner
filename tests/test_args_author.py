"""Validation tests for the module that authors values sent to real hardware.

No network: `author_args` is exercised through a stubbed LLM so the validation
and rejection logic is covered without calling out.
"""
import unittest
from unittest import mock

from tc_system.generation import args_author
from tc_system.generation.args_author import ArgsAuthoringError, _normalize_hex, author_args

SECTION = {"section_id": "base:5.2.13", "spec_doc": "NVM-Express-Base-Specification",
           "title": "Identify command"}
OPCODE = {"name": "Identify", "raw_opcode": "0x06", "command_set": "ADMIN"}
ACTIVE_NSID = 1  # the one namespace this fixture's "target" is configured to test

GOOD = {"cdw10": "0x00000001", "cdw11": "0x0", "cdw12": "0x0", "nsid": ACTIVE_NSID,
        "data_len": 4096, "direction": "read", "shared_facts": {}, "field_breakdown": "CNS=1"}


def _run(structured, opcode=OPCODE):
    with mock.patch.object(args_author, "generate_rag_response",
                            return_value={"chunks": [{"text": "spec text"}], "response_id": "r"}), \
         mock.patch.object(args_author, "generate_llm_response",
                            return_value={"structured": structured, "response_id": "l"}):
        return author_args(SECTION, opcode, ACTIVE_NSID)


class TestNormalizeHex(unittest.TestCase):
    def test_accepts_and_pads(self):
        self.assertEqual(_normalize_hex("0x1", "cdw10"), "0x00000001")
        self.assertEqual(_normalize_hex("1", "cdw10"), "0x00000001")
        self.assertEqual(_normalize_hex("0XABCD", "cdw10"), "0x0000ABCD")

    def test_rejects_junk(self):
        for bad in ("", "0xZZ", "0x123456789", "; rm -rf /", None):
            with self.assertRaises(ArgsAuthoringError):
                _normalize_hex(bad, "cdw10")


class TestAuthorArgs(unittest.TestCase):
    def test_good_args_pass_through_normalized(self):
        out = _run(dict(GOOD))
        self.assertEqual(out["cdw10"], "0x00000001")
        self.assertEqual(out["cdw11"], "0x00000000")
        self.assertEqual(out["data_len"], 4096)
        self.assertEqual(out["direction"], "read")
        self.assertEqual(out["nsid"], ACTIVE_NSID)

    def test_direction_with_zero_length_is_rejected_not_coerced(self):
        # Coercing to "none" here used to hide the case from
        # _vacuous_success, letting a no-op command register as a PASS and
        # count as real spec coverage.
        with self.assertRaises(ArgsAuthoringError) as ctx:
            _run(dict(GOOD, data_len=0))
        self.assertIn("transfers nothing", str(ctx.exception))

    def test_length_without_direction_is_rejected(self):
        with self.assertRaises(ArgsAuthoringError):
            _run(dict(GOOD, direction="none", data_len=512))

    def test_bad_direction_is_rejected(self):
        with self.assertRaises(ArgsAuthoringError):
            _run(dict(GOOD, direction="both"))

    def test_absurd_length_is_rejected(self):
        with self.assertRaises(ArgsAuthoringError):
            _run(dict(GOOD, data_len=1 << 30))

    def test_non_integer_length_is_rejected(self):
        with self.assertRaises(ArgsAuthoringError):
            _run(dict(GOOD, data_len="lots"))

    def test_missing_spec_context_is_rejected(self):
        with mock.patch.object(args_author, "generate_rag_response",
                                return_value={"chunks": [], "response_id": "r"}):
            with self.assertRaises(ArgsAuthoringError):
                author_args(SECTION, OPCODE, ACTIVE_NSID)

    def test_direction_conflicting_with_opcode_bits_is_rejected(self):
        # Measured on real hardware: opcode 0x2A's bits 1:0 encode
        # controller-to-host ("read"), but a TC authored direction="write".
        # nvme-cli warned and sent it anyway, and the command never
        # completed — a ~125s SSH batch timeout for a request that was
        # malformed before it left this host.
        opcode = dict(OPCODE, name="Create Exported NVM Subsystem", raw_opcode="0x2A")
        with mock.patch.object(args_author, "generate_rag_response",
                                return_value={"chunks": [{"text": "spec text"}], "response_id": "r"}), \
             mock.patch.object(args_author, "generate_llm_response",
                                return_value={"structured": dict(GOOD, direction="write"), "response_id": "l"}):
            with self.assertRaises(ArgsAuthoringError) as ctx:
                author_args(SECTION, opcode, ACTIVE_NSID)
        self.assertIn("conflicts", str(ctx.exception))

    def test_direction_mismatch_is_retried_once_with_feedback_before_giving_up(self):
        # The mistake is the LLM's own and never reached the device, so it
        # gets one chance to see what it got wrong and fix it itself — the
        # same corrective pattern already used for controller rejections —
        # instead of immediately falling back to a placeholder probe.
        attempts = []

        def _capture(prompt, **kwargs):
            attempts.append(prompt)
            direction = "write" if len(attempts) == 1 else "read"  # OPCODE 0x06 expects "read"
            return {"structured": dict(GOOD, direction=direction), "response_id": f"l{len(attempts)}"}

        with mock.patch.object(args_author, "generate_rag_response",
                                return_value={"chunks": [{"text": "spec text"}], "response_id": "r"}), \
             mock.patch.object(args_author, "generate_llm_response", _capture):
            out = author_args(SECTION, OPCODE, ACTIVE_NSID)
        self.assertEqual(len(attempts), 2)
        self.assertIn("INVALID", attempts[1])
        self.assertIn("conflicts", attempts[1])
        self.assertEqual(out["direction"], "read")

    def test_two_consecutive_bad_attempts_still_raise(self):
        opcode = dict(OPCODE, name="Create Exported NVM Subsystem", raw_opcode="0x2A")
        attempts = []

        def _capture(prompt, **kwargs):
            attempts.append(prompt)
            return {"structured": dict(GOOD, direction="write"), "response_id": "l"}  # wrong both times

        with mock.patch.object(args_author, "generate_rag_response",
                                return_value={"chunks": [{"text": "spec text"}], "response_id": "r"}), \
             mock.patch.object(args_author, "generate_llm_response", _capture):
            with self.assertRaises(ArgsAuthoringError):
                author_args(SECTION, opcode, ACTIVE_NSID)
        self.assertEqual(len(attempts), 2)

    def test_none_direction_is_exempt_from_the_opcode_bit_check(self):
        # Many read-capable commands (Get Features returning its value in
        # CDW0) legitimately move no buffer at all — that zero-length choice
        # was measured accepted (PASS) on real hardware and must stay legal
        # even though opcode 0x06's bits nominally allow a "read" transfer.
        out = _run(dict(GOOD, direction="none", data_len=0),
                   opcode={"name": "Get Features", "raw_opcode": "0x0A", "command_set": "ADMIN"})
        self.assertEqual(out["direction"], "none")

    def test_bidirectional_opcode_bits_allow_either_direction(self):
        opcode = dict(OPCODE, raw_opcode="0x03")  # bits 1:0 = 11b = bidirectional
        with mock.patch.object(args_author, "generate_rag_response",
                                return_value={"chunks": [{"text": "spec text"}], "response_id": "r"}), \
             mock.patch.object(args_author, "generate_llm_response",
                                return_value={"structured": dict(GOOD, direction="write"), "response_id": "l"}):
            out = author_args(SECTION, opcode, ACTIVE_NSID)
        self.assertEqual(out["direction"], "write")

    def test_nsid_zero_is_accepted_for_a_controller_wide_command(self):
        out = _run(dict(GOOD, nsid=0))
        self.assertEqual(out["nsid"], 0)

    def test_nsid_broadcast_is_accepted(self):
        out = _run(dict(GOOD, nsid=0xFFFFFFFF))
        self.assertEqual(out["nsid"], 0xFFFFFFFF)

    def test_invented_nsid_is_rejected(self):
        # Hardcoding nsid=0 for every admin command used to make any
        # namespace-scoped CNS/LID fail with INVALID_NS no matter how many
        # times the other fields were retried — but accepting whatever
        # namespace id the model invents is just as wrong: this harness has
        # exactly one real target, so a made-up id of 7 would hit a
        # *different* drive-reported error for an unrelated reason.
        with self.assertRaises(ArgsAuthoringError) as ctx:
            _run(dict(GOOD, nsid=7))
        self.assertIn("nsid=7", str(ctx.exception))

    def test_nsid_mismatch_is_retried_once_with_feedback_before_giving_up(self):
        attempts = []

        def _capture(prompt, **kwargs):
            attempts.append(prompt)
            nsid = 7 if len(attempts) == 1 else ACTIVE_NSID
            return {"structured": dict(GOOD, nsid=nsid), "response_id": f"l{len(attempts)}"}

        with mock.patch.object(args_author, "generate_rag_response",
                                return_value={"chunks": [{"text": "spec text"}], "response_id": "r"}), \
             mock.patch.object(args_author, "generate_llm_response", _capture):
            out = author_args(SECTION, OPCODE, ACTIVE_NSID)
        self.assertEqual(len(attempts), 2)
        self.assertIn("INVALID", attempts[1])
        self.assertEqual(out["nsid"], ACTIVE_NSID)

    def test_active_nsid_reaches_the_prompt(self):
        captured = {}

        def _capture(prompt, **kwargs):
            captured["prompt"] = prompt
            return {"structured": dict(GOOD), "response_id": "l"}

        with mock.patch.object(args_author, "generate_rag_response",
                                return_value={"chunks": [{"text": "spec"}], "response_id": "r"}), \
             mock.patch.object(args_author, "generate_llm_response", _capture):
            author_args(SECTION, OPCODE, ACTIVE_NSID)
        self.assertIn(f"active_nsid={ACTIVE_NSID}", captured["prompt"])

    def test_shared_facts_are_returned(self):
        out = _run(dict(GOOD, shared_facts={"lba": "0x5", "nlb": "0"}))
        self.assertEqual(out["shared_facts"], {"lba": "0x5", "nlb": "0"})

    def test_missing_shared_facts_defaults_to_empty(self):
        structured = dict(GOOD)
        del structured["shared_facts"]
        out = _run(structured)
        self.assertEqual(out["shared_facts"], {})

    def test_non_object_shared_facts_is_rejected(self):
        with self.assertRaises(ArgsAuthoringError):
            _run(dict(GOOD, shared_facts="lba=0x5"))

    def test_prior_steps_reach_the_prompt_as_a_list_not_a_merged_dict(self):
        # A flat dict merge would let a later step's value for the same key
        # (e.g. a power-state transition) silently overwrite an earlier
        # step's — keeping the per-step list preserves that history.
        captured = {}

        def _capture(prompt, **kwargs):
            captured["prompt"] = prompt
            return {"structured": dict(GOOD), "response_id": "l"}

        prior_steps = [
            {"step": 0, "phase": "setup", "opcode_name": "Write", "facts": {"lba": "0x5", "nlb": "0"}},
            {"step": 1, "phase": "setup", "opcode_name": "Set Features", "facts": {"feature_id": "0x0A"}},
        ]
        with mock.patch.object(args_author, "generate_rag_response",
                                return_value={"chunks": [{"text": "spec"}], "response_id": "r"}), \
             mock.patch.object(args_author, "generate_llm_response", _capture):
            author_args(SECTION, OPCODE, ACTIVE_NSID, prior_steps=prior_steps)
        self.assertIn("step0(setup, Write)", captured["prompt"])
        self.assertIn("step1(setup, Set Features)", captured["prompt"])
        self.assertIn("lba", captured["prompt"])
        self.assertIn("feature_id", captured["prompt"])

    def test_prior_steps_with_no_facts_are_skipped_silently(self):
        captured = {}

        def _capture(prompt, **kwargs):
            captured["prompt"] = prompt
            return {"structured": dict(GOOD), "response_id": "l"}

        prior_steps = [{"step": 0, "phase": "action", "opcode_name": "Device Self-test", "facts": {}}]
        with mock.patch.object(args_author, "generate_rag_response",
                                return_value={"chunks": [{"text": "spec"}], "response_id": "r"}), \
             mock.patch.object(args_author, "generate_llm_response", _capture):
            author_args(SECTION, OPCODE, ACTIVE_NSID, prior_steps=prior_steps)
        self.assertNotIn("prior_steps", captured["prompt"])

    def test_device_facts_reaches_the_prompt(self):
        captured = {}

        def _capture(prompt, **kwargs):
            captured["prompt"] = prompt
            return {"structured": dict(GOOD), "response_id": "l"}

        with mock.patch.object(args_author, "generate_rag_response",
                                return_value={"chunks": [{"text": "spec"}], "response_id": "r"}), \
             mock.patch.object(args_author, "generate_llm_response", _capture):
            author_args(SECTION, OPCODE, ACTIVE_NSID,
                        device_facts="네임스페이스 크기(NSZE)=0x3A7E2B0 LBA")
        self.assertIn("device_facts", captured["prompt"])
        self.assertIn("0x3A7E2B0", captured["prompt"])

    def test_no_device_facts_means_no_extra_prompt_text(self):
        captured = {}

        def _capture(prompt, **kwargs):
            captured["prompt"] = prompt
            return {"structured": dict(GOOD), "response_id": "l"}

        with mock.patch.object(args_author, "generate_rag_response",
                                return_value={"chunks": [{"text": "spec"}], "response_id": "r"}), \
             mock.patch.object(args_author, "generate_llm_response", _capture):
            author_args(SECTION, OPCODE, ACTIVE_NSID)
        self.assertNotIn("device_facts", captured["prompt"])

    def test_required_field_value_matching_cdw10_is_verified(self):
        # GOOD's cdw10=0x00000001 -> byte 0x01, matching CNS=0x01.
        with mock.patch.object(args_author, "generate_rag_response",
                                return_value={"chunks": [{"text": "spec"}], "response_id": "r"}), \
             mock.patch.object(args_author, "generate_llm_response",
                                return_value={"structured": dict(GOOD), "response_id": "l"}):
            out = author_args(SECTION, OPCODE, ACTIVE_NSID,
                               required_field_values=[{"field_name": "CNS", "hex_value": "0x01"}])
        self.assertTrue(out["field_value_verified"])

    def test_required_field_value_mismatch_is_retried_then_raises(self):
        attempts = []

        def _capture(prompt, **kwargs):
            attempts.append(prompt)
            return {"structured": dict(GOOD), "response_id": f"l{len(attempts)}"}  # cdw10 byte=0x01 both times

        with mock.patch.object(args_author, "generate_rag_response",
                                return_value={"chunks": [{"text": "spec"}], "response_id": "r"}), \
             mock.patch.object(args_author, "generate_llm_response", _capture):
            with self.assertRaises(ArgsAuthoringError) as ctx:
                author_args(SECTION, OPCODE, ACTIVE_NSID,
                            required_field_values=[{"field_name": "CNS", "hex_value": "0x02"}])
        self.assertEqual(len(attempts), 2)
        self.assertIn("CNS=0x02", str(ctx.exception))
        self.assertIn("INVALID", attempts[1])

    def test_field_name_outside_the_allowlist_is_not_hard_checked(self):
        # Event Type is response-side-only (discovered by parsing a returned
        # log, not something the host writes into CDW10) — can't be
        # deterministically verified, so this must not raise even though
        # cdw10's byte doesn't match the given hex_value, and the result must
        # not claim verification happened.
        with mock.patch.object(args_author, "generate_rag_response",
                                return_value={"chunks": [{"text": "spec"}], "response_id": "r"}), \
             mock.patch.object(args_author, "generate_llm_response",
                                return_value={"structured": dict(GOOD), "response_id": "l"}):
            out = author_args(SECTION, OPCODE, ACTIVE_NSID,
                               required_field_values=[{"field_name": "Event Type", "hex_value": "0x99"}])
        self.assertFalse(out["field_value_verified"])

    def test_action_type_is_not_checked_against_cdw10(self):
        # Get LBA Status's ATYPE lives in CDW13 bits 31:24 (CDW10 is the low
        # half of SLBA). Checking it against CDW10 bits 7:0 rejected every
        # correctly-authored command and pushed the model to overwrite SLBA.
        get_lba_status = {"name": "Get LBA Status", "raw_opcode": "0x86", "command_set": "ADMIN"}
        with mock.patch.object(args_author, "generate_rag_response",
                                return_value={"chunks": [{"text": "spec"}], "response_id": "r"}), \
             mock.patch.object(args_author, "generate_llm_response",
                                return_value={"structured": dict(GOOD, cdw10="0x00000000", cdw13="0x02000000"),
                                              "response_id": "l"}):
            out = author_args(SECTION, get_lba_status, ACTIVE_NSID,
                               required_field_values=[{"field_name": "Action Type", "hex_value": "0x02"}])
        self.assertEqual(out["cdw10"], "0x00000000")
        self.assertEqual(out["cdw13"], "0x02000000")
        self.assertTrue(out["field_value_verified"])

    def test_no_required_field_values_is_not_verified(self):
        out = _run(dict(GOOD))
        self.assertFalse(out["field_value_verified"])

    def test_required_field_value_reaches_the_prompt(self):
        captured = {}

        def _capture(prompt, **kwargs):
            captured["prompt"] = prompt
            return {"structured": dict(GOOD), "response_id": "l"}

        with mock.patch.object(args_author, "generate_rag_response",
                                return_value={"chunks": [{"text": "spec"}], "response_id": "r"}), \
             mock.patch.object(args_author, "generate_llm_response", _capture):
            author_args(SECTION, OPCODE, ACTIVE_NSID,
                        required_field_values=[{"field_name": "CNS", "hex_value": "0x01"}])
        self.assertIn("required_field_value=CNS=0x01", captured["prompt"])

    def test_rejection_feedback_reaches_the_prompt(self):
        captured = {}

        def _capture(prompt, **kwargs):
            captured["prompt"] = prompt
            return {"structured": dict(GOOD), "response_id": "l"}

        with mock.patch.object(args_author, "generate_rag_response",
                                return_value={"chunks": [{"text": "spec"}], "response_id": "r"}), \
             mock.patch.object(args_author, "generate_llm_response", _capture):
            author_args(SECTION, OPCODE, ACTIVE_NSID, rejected={
                "step": {"cdw10": "0x00000000", "cdw11": "0x0", "cdw12": "0x0",
                          "nsid": 0, "data_len": 0, "direction": "none"},
                "reason": "NVMe status: INVALID_FIELD",
            })
        self.assertIn("REJECTED", captured["prompt"])
        self.assertIn("INVALID_FIELD", captured["prompt"])
        self.assertIn("0x00000000", captured["prompt"])


if __name__ == "__main__":
    unittest.main()
