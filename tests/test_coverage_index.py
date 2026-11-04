import unittest

import config
from tc_system.coverage.coverage_state import _needs_unverifiable_value
from tc_system.verification import UNEXECUTABLE_COMMANDS
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

    def test_one_opcode_per_clause_per_batch(self):
        order = self._order([])
        self.assertEqual(len(order), len(set(order)))

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


if __name__ == "__main__":
    unittest.main()
