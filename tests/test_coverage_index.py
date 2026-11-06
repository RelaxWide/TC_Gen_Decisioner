import unittest

from unittest import mock

import config
from tc_system.coverage.coverage_state import _needs_unverifiable_value
from tc_system.verification import UNEXECUTABLE_COMMANDS, verify_tc
from tc_system.coverage.coverage_state import (UNRESOLVED_ATTEMPT_LIMIT, compute_coverage,
                                              pick_next_targets)
from tc_system.coverage.spec_coverage_index import SpecCoverageIndexFile


class TestCoverageIndex(unittest.TestCase):
    def setUp(self):
        self.index = SpecCoverageIndexFile(config.active_coverage_index_path())
        # Most clauses in the real index are explanatory and carry no opcode;
        # only the testable ones can stand in for a covered section here.
        self.testable = [s for s in self.index.list_sections()
                         if self.index.opcodes_for_section(s)]
        self.assertGreater(len(self.testable), 2, "index has too few testable sections")

    def _tc(self, n, status, **kw):
        section = self.testable[n]
        opcode = self.index.opcodes_for_section(section)[0]
        return {"tc_id": f"tc-{n}", "status": status, "uses_placeholder_args": False,
                "source_section_ids": [section["section_id"]],
                "source_opcodes": [opcode["opcode"]], **kw}

    def test_empty_tc_records_gives_zero_coverage(self):
        coverage = compute_coverage(self.index, [])
        self.assertEqual(coverage["summary"]["section_covered"], 0)
        self.assertEqual(coverage["summary"]["section_pct"], 0.0)

    def test_one_tc_covers_its_section_and_opcode(self):
        sections = self.testable
        coverage = compute_coverage(self.index, [self._tc(0, "PASS")])
        self.assertEqual(coverage["summary"]["section_covered"], 1)
        covered_ids = [s["covering_tc_ids"] for s in coverage["section_coverage"]
                       if s["section_id"] == sections[0]["section_id"]][0]
        self.assertEqual(covered_ids, ["tc-0"])

    def test_failed_tc_still_counts_as_covered_but_is_marked_failing(self):
        # A FAIL exercised the spec path, so it counts — but must be
        # distinguishable from a PASS, which actually confirmed the behavior.
        coverage = compute_coverage(self.index, [self._tc(0, "PASS"), self._tc(1, "FAIL")])
        self.assertEqual(coverage["summary"]["section_covered"], 2)
        self.assertEqual(coverage["summary"]["section_passing"], 1)
        self.assertEqual(coverage["summary"]["section_failing"], 1)

    def test_errored_and_dummy_tcs_are_excluded_from_coverage(self):
        records = [self._tc(0, "ERROR"), self._tc(1, "PASS", uses_placeholder_args=True)]
        coverage = compute_coverage(self.index, records)
        self.assertEqual(coverage["summary"]["section_covered"], 0)
        self.assertEqual(coverage["summary"]["excluded_tc_count"], 2)

    def test_excluded_sections_are_offered_again_as_targets(self):
        sections = self.testable
        targets = pick_next_targets(self.index, [self._tc(0, "ERROR")], count=10000)
        self.assertIn(sections[0]["section_id"], [s["section_id"] for s, _ in targets])

    def test_exposure_does_not_permanently_exclude_a_spec_section(self):
        sections = self.testable
        targets = pick_next_targets(self.index, [self._tc(0, "PASS")], count=10000)
        target_ids = [s["section_id"] for s, _ in targets]
        self.assertIn(sections[0]["section_id"], target_ids)

    def test_legacy_record_without_the_field_is_excluded(self):
        # Records predating `uses_placeholder_args` must not silently count —
        # wrongly claiming coverage is worse than under-counting.
        legacy = self._tc(0, "PASS")
        del legacy["uses_placeholder_args"]
        coverage = compute_coverage(self.index, [legacy])
        self.assertEqual(coverage["summary"]["section_covered"], 0)
        self.assertEqual(coverage["summary"]["excluded_tc_count"], 1)

    def test_section_with_both_pass_and_fail_is_counted_as_mixed_only(self):
        # Reporting "passing" would hide the failure; folding it into "failing"
        # (as this once did) hides that it also passed once — a flapping
        # section needs to be visible as its own thing.
        same_section = dict(self._tc(0, "FAIL"), tc_id="tc-0b")
        coverage = compute_coverage(self.index, [self._tc(0, "PASS"), same_section])
        entry = next(s for s in coverage["section_coverage"]
                     if s["section_id"] == self.testable[0]["section_id"])
        self.assertEqual(entry["outcome"], "mixed")
        summary = coverage["summary"]
        self.assertEqual(summary["section_mixed"], 1)
        self.assertEqual(summary["section_passing"], 0)
        self.assertEqual(summary["section_failing"], 0)

    def test_unsupported_counts_as_covered_with_its_own_outcome(self):
        coverage = compute_coverage(self.index, [self._tc(0, "UNSUPPORTED")])
        self.assertEqual(coverage["summary"]["section_covered"], 1)
        self.assertEqual(coverage["summary"]["section_unsupported"], 1)
        self.assertEqual(coverage["summary"]["section_passing"], 0)

    def _multi_tc(self, n, m, status_n, status_m, **kw):
        """A 2-step TC whose steps independently cover testable[n] and
        testable[m] — the per-step arrays that drive multi-step crediting."""
        sections = [self.testable[n], self.testable[m]]
        opcodes = [self.index.opcodes_for_section(s)[0] for s in sections]
        overall = "ERROR" if "ERROR" in (status_n, status_m) else status_n
        return {
            "tc_id": f"tc-multi-{n}-{m}", "status": overall, "uses_placeholder_args": False,
            "source_section_ids": [s["section_id"] for s in sections],
            "source_opcodes": [o["opcode"] for o in opcodes],
            "step_section_ids": [s["section_id"] for s in sections],
            "step_opcodes": [o["opcode"] for o in opcodes],
            "step_statuses": [status_n, status_m],
            **kw,
        }

    def test_an_early_pass_step_is_credited_even_when_a_later_step_errors(self):
        # The whole-TC scalar here is ERROR, which used to throw out the
        # entire record — including the first step's genuine PASS evidence.
        tc = self._multi_tc(0, 1, "PASS", "ERROR")
        coverage = compute_coverage(self.index, [tc])
        passing_section = self.testable[0]["section_id"]
        errored_section = self.testable[1]["section_id"]
        entry_pass = next(s for s in coverage["section_coverage"] if s["section_id"] == passing_section)
        entry_error = next(s for s in coverage["section_coverage"] if s["section_id"] == errored_section)
        self.assertEqual(entry_pass["status"], "covered")
        self.assertEqual(entry_pass["outcome"], "passing")
        self.assertEqual(entry_error["status"], "not_covered")

    def test_an_errored_step_section_is_still_offered_as_a_target(self):
        tc = self._multi_tc(0, 1, "PASS", "ERROR")
        targets = pick_next_targets(self.index, [tc], count=10000)
        target_ids = [s["section_id"] for s, _ in targets]
        self.assertIn(self.testable[1]["section_id"], target_ids)
        self.assertIn(self.testable[0]["section_id"], target_ids)

    def test_each_step_gets_its_own_outcome_not_the_siblings(self):
        # Previously the whole TC would read UNSUPPORTED and mislabel the
        # section that actually passed.
        tc = self._multi_tc(0, 1, "PASS", "UNSUPPORTED")
        coverage = compute_coverage(self.index, [tc])
        entry_pass = next(s for s in coverage["section_coverage"]
                           if s["section_id"] == self.testable[0]["section_id"])
        entry_unsupported = next(s for s in coverage["section_coverage"]
                                  if s["section_id"] == self.testable[1]["section_id"])
        self.assertEqual(entry_pass["outcome"], "passing")
        self.assertEqual(entry_unsupported["outcome"], "unsupported")

    def test_legacy_record_without_step_statuses_falls_back_to_the_scalar_for_every_step(self):
        tc = self._multi_tc(0, 1, "PASS", "PASS")
        del tc["step_statuses"]
        tc["status"] = "FAIL"
        coverage = compute_coverage(self.index, [tc])
        for n in (0, 1):
            entry = next(s for s in coverage["section_coverage"]
                         if s["section_id"] == self.testable[n]["section_id"])
            self.assertEqual(entry["outcome"], "failing")


class TestOpcodeAndSectionLookup(unittest.TestCase):
    """`get_opcode_by_name`/`get_section` are what a multi-step generator uses
    to resolve the model's chosen command names back to real opcode/section
    dicts — checked against the real active index, like the rest of this
    file, since the whole point is that these names must actually exist."""

    def setUp(self):
        self.index = SpecCoverageIndexFile(config.active_coverage_index_path())

    def test_get_opcode_by_name_finds_a_real_command(self):
        write = self.index.get_opcode_by_name("Write", "NVM")
        self.assertIsNotNone(write)
        self.assertEqual(write["raw_opcode"], "0x01")

    def test_get_opcode_by_name_is_scoped_by_command_set(self):
        self.assertIsNone(self.index.get_opcode_by_name("Write", "ADMIN"))

    def test_get_opcode_by_name_returns_none_for_an_invented_command(self):
        self.assertIsNone(self.index.get_opcode_by_name("Totally Made Up Command", "NVM"))

    def test_get_section_finds_a_real_section(self):
        write = self.index.get_opcode_by_name("Write", "NVM")
        section = self.index.get_section(write["section_ref"])
        self.assertIsNotNone(section)
        self.assertEqual(section["section_id"], write["section_ref"])

    def test_get_section_returns_none_for_a_nonexistent_id(self):
        self.assertIsNone(self.index.get_section("nvm:999.999.999"))


class TestTargetRotation(unittest.TestCase):
    def setUp(self):
        self.index = SpecCoverageIndexFile(config.active_coverage_index_path())
        # Clauses whose every opcode is executable here (Abort/AER are never offered).
        self.testable = [s for s in self.index.list_sections() if self.index.opcodes_for_section(s)
                         and all(o["name"] not in UNEXECUTABLE_COMMANDS
                                 for o in self.index.opcodes_for_section(s))
                         and not _needs_unverifiable_value(s)]

    def _tc(self, section, status, n=0):
        opcode = self.index.opcodes_for_section(section)[0]
        return {"tc_id": f"tc-{section['section_id']}-{n}", "status": status, "uses_placeholder_args": False,
                "steps": [{"phase": "action"}], "step_section_ids": [section["section_id"]],
                "step_opcodes": [opcode["opcode"]], "source_section_ids": [section["section_id"]],
                "source_opcodes": [opcode["opcode"]]}

    def _order(self, records):
        return [s["section_id"] for s, _ in pick_next_targets(self.index, records, count=10000)]

    def test_unsupported_target_goes_behind_every_unanswered_one(self):
        first = self.testable[0]
        once_errored = self.testable[1]
        order = self._order([self._tc(first, "UNSUPPORTED"), self._tc(once_errored, "ERROR")])
        self.assertIn(first["section_id"], order)  # still offered, never excluded
        self.assertLess(order.index(once_errored["section_id"]), order.index(first["section_id"]))
        never_tried = [s["section_id"] for s in self.testable[2:]]
        self.assertTrue(all(order.index(sid) < order.index(first["section_id"]) for sid in never_tried))

    def test_repeated_errors_stop_outranking_answered_targets_after_the_limit(self):
        stuck, answered = self.testable[0], self.testable[1]
        records = [self._tc(stuck, "ERROR", n) for n in range(UNRESOLVED_ATTEMPT_LIMIT)]
        records.append(self._tc(answered, "UNSUPPORTED"))
        order = self._order(records)
        self.assertLess(order.index(answered["section_id"]), order.index(stuck["section_id"]))

    def test_every_requirement_once_per_full_batch(self):
        picked = pick_next_targets(self.index, [], count=10**9)
        keys = [(s["section_id"], (s.get("target_requirement") or {}).get("requirement_id")) for s, _ in picked]
        self.assertEqual(len(keys), len(set(keys)))
        self.assertGreater(len(picked), 1000)  # requirements, not the 232 clauses

    def test_skipped_targets_count_as_attempts(self):
        first = self._order([])[0]
        opcode = next(o for s, o in pick_next_targets(self.index, [], count=1))
        skips = [{"section_id": first, "opcode": opcode["opcode"]}]
        self.assertNotEqual(pick_next_targets(self.index, [], 1, skip_records=skips)[0][0]["section_id"], first)

    def test_commands_this_executor_cannot_run_are_never_offered(self):
        picked = pick_next_targets(self.index, [], count=10000)
        self.assertFalse([o["name"] for _, o in picked if o["name"] in UNEXECUTABLE_COMMANDS])


    def test_event_type_clauses_are_not_offered(self):
        # Verifying one needs a variable-length event record found in the log;
        # measured: all 22 were skipped or tested something else.
        picked = pick_next_targets(self.index, [], count=10000)
        self.assertFalse([s["section_id"] for s, _ in picked
                          if any(f.get("field_name") == "Event Type" for f in s.get("field_values") or [])])

    def test_a_batch_spreads_over_commands(self):
        names = [o["name"] for _, o in pick_next_targets(self.index, [], count=10)]
        self.assertEqual(len(names), len(set(names)), names)

    def test_fabrics_only_clauses_come_after_the_others(self):
        ids = [s["section_id"] for s, _ in pick_next_targets(self.index, [], count=30)]
        self.assertFalse([sid for sid in ids if sid.startswith("base:5.4.")], ids)


    def test_the_per_command_breakdown_counts_tcs_skips_and_unproven_passes(self):
        from tc_system.coverage.coverage_state import target_breakdown
        section = self.testable[0]
        opcode = self.index.opcodes_for_section(section)[0]
        legacy_pass = self._tc(section, "PASS")  # no contract: proves nothing
        skip = {"section_id": section["section_id"], "opcode": opcode["opcode"], "reason": "bad reply"}
        result = target_breakdown(self.index, [legacy_pass], [skip])
        self.assertEqual(result["testable_targets"], 232)
        self.assertEqual(sum(e["count"] for e in result["excluded"]), 26)
        row = next(r for r in result["commands"] if r["name"] == opcode["name"])
        self.assertEqual(row["statuses"], {"UNVERIFIED": 1})
        self.assertEqual(row["skipped"], 1)
        self.assertEqual(row["tried"], 1)
        entry = next(s for s in row["sections"] if s["section_id"] == section["section_id"])
        self.assertEqual((entry["status"], entry["tcs"], entry["skips"], entry["last_skip"]),
                         ("UNVERIFIED", 1, 1, "bad reply"))
        self.assertEqual(result["targets_tried"], 1)


    def test_per_command_and_total_requirement_counts_use_one_rule(self):
        # Review: a dummy-firmware-activation TC (command FAIL, requirement
        # check satisfied) was 0 in the totals but 1 in the command table.
        from tc_system.coverage.coverage_state import requirement_coverage, target_breakdown
        ops = {o["name"]: o for o in self.index.list_opcodes()}
        commit, download = ops["Firmware Commit"], ops["Firmware Image Download"]
        quote = "The controller shall verify the firmware image before activating it."
        ok = "Admin Command X is Success and result: 0x0"
        steps = [{"name": "Firmware Image Download", "phase": "setup", "opcode": "0x11", "mode": "admin-passthru",
                  "direction": "write", "data_len": 4, "cdw10": "0x0", "expected_status": "SUCCESS"},
                 {"name": "Firmware Commit", "phase": "action", "opcode": "0x10", "mode": "admin-passthru",
                  "direction": "none", "data_len": 0, "cdw10": "0x8", "expected_status": "SUCCESS"}]  # CA=1
        tc = {"tc_id": "fw", "status": "FAIL", "uses_placeholder_args": False, "steps": steps,
              "step_section_ids": [download["section_ref"], commit["section_ref"]],
              "step_opcodes": [download["opcode"], commit["opcode"]], "scenario": {"preconditions": []},
              "verification_contract": {"version": 2, "precondition_checks": [],
                                        "evidence": [{"evidence_id": "e", "text": quote}],
                                        "requirements": [{"requirement_id": "r1", "section_id": commit["section_ref"],
                                                          "evidence_id": "e", "quote": quote, "description": "d",
                                                          "checks": [{"kind": "completion", "step": 1}]}]},
              "execution": {"step_results": [{"step_index": i, "exit_code": 0, "started": True, "stdout": ok}
                                             for i in (0, 1)]}}
        _, summary = requirement_coverage([tc])
        row = next(r for r in target_breakdown(self.index, [tc])["commands"] if r["name"] == "Firmware Commit")
        self.assertEqual(summary["requirements_evaluated"], 0)
        self.assertEqual(row["verified_requirements"], summary["requirements_evaluated"])
        self.assertEqual(row["statuses"], {"FAIL": 1})



class TestRequirementTargets(unittest.TestCase):
    """Targets are the spec's "shall" sentences (and its abort rules), not clauses."""

    @classmethod
    def setUpClass(cls):
        from tc_system.coverage.coverage_state import requirement_targets
        cls.index = SpecCoverageIndexFile(config.active_coverage_index_path())
        cls.targets = requirement_targets(cls.index)

    def test_counts(self):
        reqs = [r for *_, r in self.targets if r]
        self.assertGreater(len(reqs), 1200)
        self.assertGreater(sum(r["kind"] == "abort" for r in reqs), 200)
        clause_only = [s["section_id"] for s, _, r in self.targets if r is None]
        self.assertTrue(clause_only)  # a clause without a "shall" is still a target

    def test_an_abort_rule_carries_its_status_as_nvme_cli_spells_it(self):
        # "shall ... abort ... Invalid Field in Command" (IOS bit cleared, offset given).
        rule = next(r for s, _, r in self.targets if r and s["section_id"] == "base:5.2.12"
                    and "IOS bit is cleared" in r["text"])
        self.assertEqual((rule["kind"], rule["expected_status"]), ("abort", "INVALID_FIELD"))

    def test_a_status_followed_by_more_text_is_still_an_abort_rule(self):
        # "...shall abort the command with a status code of Invalid Log Page with the exception ..."
        rule = next(r for s, _, r in self.targets if r and "Log Page Identifier that is not supported" in r["text"])
        self.assertEqual((rule["kind"], rule["expected_status"]), ("abort", "INVALID_LOG_PAGE"))

    def test_a_judged_requirement_goes_behind_the_unjudged_ones(self):
        first_section, first_opcode = pick_next_targets(self.index, [], 1)[0]
        req = first_section["target_requirement"]
        judged_tc = {"tc_id": "j", "status": "PASS", "uses_placeholder_args": False,
                     "steps": [{"phase": "action"}], "step_section_ids": [first_section["section_id"]],
                     "step_opcodes": [first_opcode["opcode"]], "source_section_ids": [first_section["section_id"]],
                     "verification_contract": {"target_requirement": req}}
        with mock.patch("tc_system.coverage.coverage_state.judged_target_requirements",
                        return_value={req["requirement_id"]}):
            picked = pick_next_targets(self.index, [judged_tc], 1000)
        ids = [(s.get("target_requirement") or {}).get("requirement_id") for s, _ in picked]
        self.assertNotIn(req["requirement_id"], ids)  # behind the ~1300 unanswered ones

    def test_the_breakdown_counts_requirements_per_command(self):
        from tc_system.coverage.coverage_state import target_breakdown
        result = target_breakdown(self.index, [], [])
        self.assertEqual(result["requirement_targets"], sum(1 for *_, r in self.targets if r))
        row = next(r for r in result["commands"] if r["name"] == "Get Log Page")
        self.assertGreater(row["requirements"], 100)
        self.assertEqual((row["requirements_tried"], row["requirements_judged"]), (0, 0))



class TestCodeVariants(unittest.TestCase):
    """Variants: no LLM, a value swept under a rule quoted from the spec."""

    @classmethod
    def setUpClass(cls):
        from tc_system.generation.variants import variant_targets
        cls.index = SpecCoverageIndexFile(config.active_coverage_index_path())
        cls.ops = {o["name"]: o for o in cls.index.list_opcodes()}
        cls.with_device = variant_targets(cls.index, nsze=0x1000, lba_bytes=512)
        cls.without_device = variant_targets(cls.index)

    def _tc(self, variant):
        from tc_system.generation.variants import build_variant_tc
        return build_variant_tc("t", variant, self.ops[variant["command"]], "/dev/nvme0", "/dev/nvme0n1", 1, 512)

    def test_families_and_counts(self):
        import collections
        families = collections.Counter(v["family"] for v in self.with_device)
        self.assertEqual(families["reserved_fid"], 2 * 140)  # Get + Set Features
        self.assertEqual(families["reserved_lid"], 86)
        self.assertEqual(families["lba_boundary"], 23)
        self.assertNotIn("lba_boundary", {v["family"] for v in self.without_device})  # needs NSZE

    def test_every_variant_passes_the_wire_checks(self):
        from tc_system.execution.ssh_runner import passthru_cmd
        for variant in self.with_device:
            with self.subTest(variant=variant["requirement_id"]):
                passthru_cmd(self._tc(variant)["steps"][0])

    def test_a_drive_accepting_a_reserved_lid_fails_the_cited_rule(self):
        variant = next(v for v in self.with_device if v["family"] == "reserved_lid")
        tc = self._tc(variant)
        ok = {"step_results": [{"step_index": 0, "exit_code": 0, "started": True,
                                "stdout": "Admin Command Get Log Page is Success and result: 0x0\n0000: 00 00 00 00"}]}
        rejected = {"step_results": [{"step_index": 0, "exit_code": 22, "started": True,
                                      "stdout": "NVMe status: INVALID_LOG_PAGE: The log page indicated is invalid(0x109)"}]}
        self.assertEqual(verify_tc(tc, ok)["status"], "FAIL")
        self.assertEqual(verify_tc(tc, rejected)["status"], "PASS")

    def test_the_last_lba_is_readable_and_one_past_it_is_out_of_range(self):
        last = next(v for v in self.with_device if v["command"] == "Read" and v["label"] == "last_lba")
        past = next(v for v in self.with_device if v["command"] == "Read" and v["label"] == "one_past_end")
        self.assertEqual((last["fields"]["cdw10"], last["expected_status"]), ("0x00000FFF", "SUCCESS"))
        self.assertEqual((past["fields"]["cdw10"], past["expected_status"]), ("0x00001000", "LBA_RANGE"))
        read_ok = {"step_results": [{"step_index": 0, "exit_code": 0, "started": True,
                                     "stdout": "IO Command Read is Success and result: 0x0"}]}
        self.assertEqual(verify_tc(self._tc(last), read_ok)["status"], "PASS")

    def test_variants_rotate_in_with_the_llm_targets(self):
        picked = pick_next_targets(self.index, [], 120, variants=self.without_device)
        kinds = [(s.get("target_requirement") or {}).get("kind") for s, _ in picked]
        self.assertIn("variant", kinds)
        self.assertIn("shall", kinds)

    def test_the_breakdown_counts_variants(self):
        from tc_system.coverage.coverage_state import target_breakdown
        result = target_breakdown(self.index, [], [], self.with_device)
        self.assertEqual(result["variant_targets"], len(self.with_device))
        row = next(r for r in result["commands"] if r["name"] == "Get Log Page")
        self.assertEqual(row["variants"], 86)



class TestHostEventRequirements(unittest.TestCase):
    """Sentences about state across a reset/power loss need a host step."""

    def test_only_state_across_an_event_needs_a_host_step(self):
        from tc_system.execution.host_actions import required_host_actions
        both = ["controller_reset", "power_cycle"]
        self.assertEqual(required_host_actions(
            "The information in this log page shall be retained across power cycles and resets."), both)
        self.assertEqual(required_host_actions(
            "The firmware image shall be activated at the next Controller Level Reset."), both)
        self.assertEqual(required_host_actions("The value shall be preserved after a power cycle."), ["power_cycle"])
        for text in ("If a Set Features command is submitted for this Feature and the Power Loss Signaling Mode "
                     "field specifies a Power Loss Signaling mode that is not supported, the controller shall abort",
                     "This Feature shall be saveable (refer to section 4.4).",
                     "any successful sanitize operation shall modify this Feature by resetting both the saved value",
                     "This value shall be updated once per power-on hour when the controller is not in a sleep state."):
            with self.subTest(text=text[:50]):
                self.assertEqual(required_host_actions(text), [])

    def test_the_spec_targets_that_need_one(self):
        from tc_system.coverage.coverage_state import requirement_targets
        index = SpecCoverageIndexFile(config.active_coverage_index_path())
        needing = [r for *_, r in requirement_targets(index) if r and r["host_actions"]]
        self.assertEqual(len(needing), 14)
        self.assertTrue(all("controller_reset" in r["host_actions"] for r in needing))  # none is power-only today


if __name__ == "__main__":
    unittest.main()
