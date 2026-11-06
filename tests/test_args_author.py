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
        # count as real spec coverage. Get Features has no length field the
        # harness could compute the buffer from, so it is still rejected.
        with self.assertRaises(ArgsAuthoringError) as ctx:
            _run(dict(GOOD, cdw10="0x0000007D", data_len=0),  # FID 7Dh: buffer size not in the table
                 opcode=dict(OPCODE, name="Get Features", raw_opcode="0x0A"))
        self.assertIn("transfers nothing", str(ctx.exception))

    def test_identify_always_moves_its_4096_byte_structure(self):
        out = _run(dict(GOOD, data_len=0, direction="none"))
        self.assertEqual((out["data_len"], out["direction"]), (4096, "read"))
        self.assertTrue(out["derived_fields"])
    def test_length_without_direction_is_rejected(self):
        # opcode bits 00 (no data transfer): a buffer is the author's mistake
        with self.assertRaises(ArgsAuthoringError):
            _run(dict(GOOD, direction="none", data_len=512), opcode=dict(OPCODE, name="Abort", raw_opcode="0x08"))
    def test_bad_direction_is_rejected(self):
        with self.assertRaises(ArgsAuthoringError):
            _run(dict(GOOD, direction="both"))

    def test_absurd_length_is_rejected(self):
        with self.assertRaises(ArgsAuthoringError):
            _run(dict(GOOD, cdw10="0x0000007D", data_len=1 << 30),
                 opcode=dict(OPCODE, name="Get Features", raw_opcode="0x0A"))

    def test_a_feature_buffer_is_its_spec_structure_size(self):
        # Measured: HMB (FID 0Dh) Get Features with a 4-byte buffer crashed
        # nvme-cli (malloc assertion, exit 134); the structure is 4096 bytes.
        out = _run(dict(GOOD, cdw10="0x0000000D", data_len=4), opcode=dict(OPCODE, name="Get Features", raw_opcode="0x0A"))
        self.assertEqual((out["data_len"], out["direction"]), (4096, "read"))
        out = _run(dict(GOOD, cdw10="0x00000001", data_len=4), opcode=dict(OPCODE, name="Get Features", raw_opcode="0x0A"))
        self.assertEqual((out["data_len"], out["direction"]), (0, "none"))  # Arbitration: value in DW0

    def test_host_owned_feature_cannot_be_set(self):
        with self.assertRaisesRegex(ArgsAuthoringError, "Host Memory Buffer"):
            _run(dict(GOOD, cdw10="0x0000000D", data_len=0, direction="none"),
                 opcode=dict(OPCODE, name="Set Features", raw_opcode="0x09"))

    def test_io_command_nsid_must_be_the_namespace_device(self):
        # Kernel: "nsid (0) in cmd does not match nsid (1) of namespace".
        read = {"name": "Read", "raw_opcode": "0x02", "command_set": "NVM"}
        with self.assertRaisesRegex(ArgsAuthoringError, "kernel"):
            _run(dict(GOOD, cdw10="0x0", nsid=0, data_len=512, direction="read"), opcode=read)

    def test_a_queue_command_on_a_driver_qid_is_refused(self):
        create_cq = {"name": "Create I/O Completion Queue", "raw_opcode": "0x05", "command_set": "ADMIN"}
        with self.assertRaisesRegex(ArgsAuthoringError, "큐"):
            _run(dict(GOOD, cdw10="0x00030002", nsid=0, data_len=0, direction="none"), opcode=create_cq)
    def test_non_integer_length_is_rejected(self):
        with self.assertRaises(ArgsAuthoringError):
            _run(dict(GOOD, data_len="lots"))

    def test_missing_spec_context_is_rejected(self):
        with mock.patch.object(args_author, "generate_rag_response",
                                return_value={"chunks": [], "response_id": "r"}):
            with self.assertRaises(ArgsAuthoringError):
                author_args(SECTION, OPCODE, ACTIVE_NSID)

    def test_direction_is_taken_from_the_opcode_bits(self):
        # Measured on real hardware: opcode 0x2A's bits 1:0 encode
        # controller-to-host ("read"), but a TC authored direction="write".
        # nvme-cli warned and sent it anyway, and the command never
        # completed — a ~125s SSH batch timeout. The bits decide it now.
        opcode = dict(OPCODE, name="Create Exported NVM Subsystem", raw_opcode="0x2A")
        out = _run(dict(GOOD, direction="write"), opcode=opcode)
        self.assertEqual(out["direction"], "read")
        self.assertIn("opcode 비트", out["derived_fields"][0])
    def test_an_invalid_reply_is_retried_once_with_feedback_before_giving_up(self):
        # The mistake is the LLM's own and never reached the device, so it
        # gets one chance to see what it got wrong and fix it itself — the
        # same corrective pattern already used for controller rejections —
        # instead of immediately falling back to a placeholder probe.
        attempts = []

        def _capture(prompt, **kwargs):
            attempts.append(prompt)
            nsid = 7 if len(attempts) == 1 else ACTIVE_NSID  # 7 is not a namespace of this target
            return {"structured": dict(GOOD, nsid=nsid), "response_id": f"l{len(attempts)}"}

        with mock.patch.object(args_author, "generate_rag_response",
                                return_value={"chunks": [{"text": "spec text"}], "response_id": "r"}), \
             mock.patch.object(args_author, "generate_llm_response", _capture):
            out = author_args(SECTION, OPCODE, ACTIVE_NSID)
        self.assertEqual(len(attempts), 2)
        self.assertIn("INVALID", attempts[1])
        self.assertIn("nsid=7", attempts[1])
        self.assertEqual(out["nsid"], ACTIVE_NSID)
    def test_two_consecutive_bad_attempts_still_raise(self):
        attempts = []

        def _capture(prompt, **kwargs):
            attempts.append(prompt)
            return {"structured": dict(GOOD, nsid=7), "response_id": "l"}  # wrong both times

        with mock.patch.object(args_author, "generate_rag_response",
                                return_value={"chunks": [{"text": "spec text"}], "response_id": "r"}), \
             mock.patch.object(args_author, "generate_llm_response", _capture):
            with self.assertRaises(ArgsAuthoringError):
                author_args(SECTION, OPCODE, ACTIVE_NSID)
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

    def test_the_clause_selector_is_written_by_the_harness(self):
        # The index knows the clause's CNS/LID/FID: written, not checked.
        # Measured: "clause requires LID=0x15, got 0xF" skipped targets after
        # the retry repeated the same slip.
        llm = mock.Mock(return_value={"structured": dict(GOOD), "response_id": "l"})  # CNS 01h
        with mock.patch.object(args_author, "generate_rag_response",
                                return_value={"chunks": [{"text": "spec"}], "response_id": "r"}),              mock.patch.object(args_author, "generate_llm_response", llm):
            out = author_args(SECTION, OPCODE, ACTIVE_NSID,
                              required_field_values=[{"field_name": "CNS", "hex_value": "0x02"}])
        self.assertEqual(llm.call_count, 1)
        self.assertEqual(int(out["cdw10"], 16) & 0xFF, 0x02)
        self.assertTrue(out["field_value_verified"])
        self.assertTrue(any("조항 선택자" in c for c in out["constraint_overrides"]))

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



class TestPersistentEventLogCasesFromTheField(unittest.TestCase):
    """The three skips reported for base:5.2.12.1.14 / 5.2.12.1.14.2.1."""
    GLP = {"name": "Get Log Page", "raw_opcode": "0x02", "command_set": "ADMIN"}
    SECTION = {"section_id": "base:5.2.12.1.14", "spec_doc": "NVM-Express-Base-Specification"}

    def _author(self, replies, constraints):
        llm = mock.Mock(side_effect=[{"structured": r, "response_id": f"l{n}"} for n, r in enumerate(replies)])
        with mock.patch.object(args_author, "generate_rag_response",
                               return_value={"chunks": [{"text": "spec"}], "response_id": "r"}), \
             mock.patch.object(args_author, "generate_llm_response", llm):
            try:
                return author_args(self.SECTION, self.GLP, ACTIVE_NSID,
                                   test_intent={"field_constraints": constraints}), llm
            except ArgsAuthoringError as exc:
                return exc, llm

    @staticmethod
    def _reply(cdw10, cdw11="0x0", data_len=512):
        return {"cdw10": cdw10, "cdw11": cdw11, "cdw12": "0x0", "nsid": 0, "data_len": data_len,
                "direction": "read", "shared_facts": {}, "field_breakdown": "x"}

    def test_a_fixed_action_field_is_applied_not_a_reason_to_skip(self):
        # Scenario: ACT (CDW10[9:8]) = 11b "Establish Context and Read 512 Bytes
        # of Header"; the author wrote 10b "Release Context".
        result, llm = self._author([self._reply("0x007F020D")],
                                   [{"field": "cdw10", "mask": "0x3FF", "value": "0x30D"}])
        self.assertEqual(result["cdw10"], "0x007F030D")
        self.assertEqual(result["constraint_overrides"], ["cdw10 0x007F020D -> 0x007F030D"])
        self.assertEqual(llm.call_count, 1)

    def test_numdl_in_the_wrong_register_is_rewritten_from_data_len(self):
        # 0x7F written into CDW11 (NUMDU): 32 MB requested into 512 bytes.
        # The harness writes NUMD from the buffer size: no retry needed.
        result, llm = self._author([self._reply("0x0000000D", cdw11="0x7F")], [])
        self.assertEqual((result["cdw10"], result["cdw11"], result["data_len"]),
                         ("0x007F000D", "0x00000000", 512))
        self.assertEqual(llm.call_count, 1)
        self.assertIn("NUMDL", result["derived_fields"][0])
    def test_a_fixed_numd_sets_the_matching_length(self):
        # NUMDL pinned by the scenario: the buffer follows it, not the reverse.
        constraints = [{"field": "cdw10", "mask": "0xFFFF00FF", "value": "0x4000000D"}]
        result, llm = self._author([self._reply("0x03FF000D", data_len=4096)], constraints)
        self.assertEqual((result["cdw10"], result["data_len"]), ("0x4000000D", 65540))
        self.assertEqual(llm.call_count, 1)


class TestDeriveTransfer(unittest.TestCase):
    """The fields the spec ties together are computed, not checked."""

    def _derive(self, op, constraints=None, lba_bytes=None, **fields):
        from tc_system.command_fields import derive_transfer
        base = {f"cdw{i}": "0x00000000" for i in range(10, 16)}
        base.update(nsid=1, data_len=0, direction="none")
        base.update(fields)
        changes = derive_transfer(base, op, lba_bytes=lba_bytes, constraints=constraints)
        return base, changes

    def test_directive_receive_numd_follows_the_buffer(self):
        out, _ = self._derive({"command_set": "ADMIN", "raw_opcode": "0x1A", "name": "Directive Receive"},
                              data_len=4096, direction="read", cdw10="0x00000001")
        self.assertEqual(out["cdw10"], "0x000003FF")

    def test_nvm_read_buffer_follows_nlb(self):
        out, _ = self._derive({"command_set": "NVM", "raw_opcode": "0x02", "name": "Read"}, lba_bytes=4096,
                              data_len=512, direction="write", cdw12="0x00000001")
        self.assertEqual((out["data_len"], out["direction"]), (8192, "read"))

    def test_write_zeroes_moves_no_buffer(self):
        out, _ = self._derive({"command_set": "NVM", "raw_opcode": "0x08", "name": "Write Zeroes"},
                              data_len=512, direction="write")
        self.assertEqual((out["data_len"], out["direction"]), (0, "none"))

    def test_two_pinned_sides_that_disagree_are_left_for_validation(self):
        from tc_system.command_fields import validate_transfer
        op = {"command_set": "ADMIN", "raw_opcode": "0x02", "name": "Get Log Page"}
        pins = [{"field": "cdw10", "mask": "0xFFFF0000", "value": "0x00FF0000"},
                {"field": "data_len", "mask": "0xFFFFFFFF", "value": "512"}]
        out, changes = self._derive(op, pins, data_len=512, direction="read", cdw10="0x00FF0002")
        self.assertEqual([c for c in changes if not c.startswith("direction")], [])
        with self.assertRaises(ValueError):
            validate_transfer(out, op)


if __name__ == "__main__":
    unittest.main()
