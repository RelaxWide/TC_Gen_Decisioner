import unittest

from build_spec_index import _ancestor_chain, _field_value, link_field_values


def _section(section_id, title, related_opcodes=None):
    return {"section_id": section_id, "title": title,
            "related_opcodes": list(related_opcodes or []), "field_values": []}


class TestFieldValue(unittest.TestCase):
    def test_simple_single_value_title_matches(self):
        self.assertEqual(_field_value("SMART / Health Information (Log Page Identifier 02h)"),
                          ("Log Page Identifier", "02"))

    def test_trailing_text_after_the_paren_still_matches(self):
        # A real title from the index: "(Feature Identifier 0Bh) for Fabrics"
        # — no end anchor, so this must not be rejected just because the
        # parenthetical isn't the last thing in the title.
        self.assertEqual(_field_value("Asynchronous Event Configuration (Feature Identifier 0Bh) for Fabrics"),
                          ("Feature Identifier", "0B"))

    def test_multi_value_title_is_skipped(self):
        # Measured bug: an end-anchored, digit-permitting regex swallowed
        # "10h and" as the field name here instead of skipping the title.
        self.assertIsNone(_field_value("Potentially Unrecoverable LBAs (Action Type 10h and 11h)"))

    def test_multi_paren_parent_heading_is_skipped(self):
        # A real parent heading listing three children's values in its own
        # title — must not be mistaken for a single-value leaf (which would
        # wrongly link the parent itself to the last child's FID).
        self.assertIsNone(_field_value(
            "Host Metadata (Feature Identifier 7Dh), (Feature Identifier 7Eh), (Feature Identifier 7Fh)"))

    def test_no_parenthetical_is_skipped(self):
        self.assertIsNone(_field_value("Get Log Page command"))


class TestAncestorChain(unittest.TestCase):
    def test_yields_ancestors_nearest_first(self):
        self.assertEqual(list(_ancestor_chain("base:5.2.12.1.2")),
                          ["base:5.2.12.1", "base:5.2.12", "base:5.2", "base:5"])

    def test_different_doc_prefix_never_appears(self):
        for ancestor_id in _ancestor_chain("nvm:4.1.5.5"):
            self.assertTrue(ancestor_id.startswith("nvm:"))

    def test_top_level_clause_has_no_ancestors(self):
        self.assertEqual(list(_ancestor_chain("base:5")), [])


class TestLinkFieldValues(unittest.TestCase):
    def test_single_level_inheritance(self):
        sections = {
            "base:5.2.12": _section("base:5.2.12", "Get Log Page command", related_opcodes=["0x02a"]),
            "base:5.2.12.1.2": _section("base:5.2.12.1.2",
                                         "Error Information (Log Page Identifier 01h)"),
        }
        link_field_values(sections)
        leaf = sections["base:5.2.12.1.2"]
        self.assertEqual(leaf["related_opcodes"], ["0x02a"])
        self.assertEqual(leaf["field_values"], [{"field_name": "Log Page Identifier", "hex_value": "0x01"}])

    def test_two_level_inheritance_skips_the_unlinked_intermediate(self):
        # "Common Log Specific Information" (base:5.2.12.1) has no opcodes of
        # its own — the walk must keep going past it to Get Log Page itself.
        sections = {
            "base:5.2.12": _section("base:5.2.12", "Get Log Page command", related_opcodes=["0x02a"]),
            "base:5.2.12.1": _section("base:5.2.12.1", "Common Log Specific Information"),
            "base:5.2.12.1.3": _section("base:5.2.12.1.3",
                                         "SMART / Health Information (Log Page Identifier 02h)"),
        }
        link_field_values(sections)
        leaf = sections["base:5.2.12.1.3"]
        self.assertEqual(leaf["related_opcodes"], ["0x02a"])
        self.assertEqual(leaf["field_values"], [{"field_name": "Log Page Identifier", "hex_value": "0x02"}])
        # The unlinked intermediate itself must stay untouched.
        self.assertEqual(sections["base:5.2.12.1"]["related_opcodes"], [])
        self.assertEqual(sections["base:5.2.12.1"]["field_values"], [])

    def test_three_level_compound_chain(self):
        # Mirrors the real shape: Event Type nested under a specific Log Page
        # Identifier leaf (Persistent Event, LID=0Dh), itself nested under
        # the unlinked "Common Log Specific Information" grouping, itself
        # under Get Log Page. The resolved leaf's field_values must carry
        # BOTH the inherited LID and its own Event Type, in that order.
        sections = {
            "base:5.2.12": _section("base:5.2.12", "Get Log Page command", related_opcodes=["0x02a"]),
            "base:5.2.12.1": _section("base:5.2.12.1", "Common Log Specific Information"),
            "base:5.2.12.1.14": _section("base:5.2.12.1.14",
                                          "Persistent Event (Log Page Identifier 0Dh)"),
            "base:5.2.12.1.14.2.1": _section("base:5.2.12.1.14.2.1",
                                              "Firmware Commit Event (Event Type 02h)"),
        }
        link_field_values(sections)
        event_leaf = sections["base:5.2.12.1.14.2.1"]
        self.assertEqual(event_leaf["related_opcodes"], ["0x02a"])
        self.assertEqual(event_leaf["field_values"], [
            {"field_name": "Log Page Identifier", "hex_value": "0x0D"},
            {"field_name": "Event Type", "hex_value": "0x02"},
        ])

    def test_multi_value_title_never_gets_linked(self):
        sections = {
            "base:4.2.1": _section("base:4.2.1", "Get LBA Status command", related_opcodes=["0x1Ca"]),
            "base:4.2.1.1": _section("base:4.2.1.1",
                                      "Potentially Unrecoverable LBAs (Action Type 10h and 11h)"),
        }
        link_field_values(sections)
        self.assertEqual(sections["base:4.2.1.1"]["related_opcodes"], [])
        self.assertEqual(sections["base:4.2.1.1"]["field_values"], [])

    def test_multi_paren_parent_heading_never_gets_linked(self):
        sections = {
            "base:5.2.26": _section("base:5.2.26", "Set Features command", related_opcodes=["0x09a"]),
            "base:5.2.26.1.50": _section(
                "base:5.2.26.1.50",
                "Host Metadata (Feature Identifier 7Dh), (Feature Identifier 7Eh), (Feature Identifier 7Fh)"),
        }
        link_field_values(sections)
        self.assertEqual(sections["base:5.2.26.1.50"]["related_opcodes"], [])
        self.assertEqual(sections["base:5.2.26.1.50"]["field_values"], [])

    def test_no_qualifying_ancestor_leaves_the_leaf_unlinked(self):
        sections = {
            "base:9.1.2.3": _section("base:9.1.2.3", "Something (Weird Field 05h)"),
        }
        link_field_values(sections)  # must not raise
        self.assertEqual(sections["base:9.1.2.3"]["related_opcodes"], [])
        self.assertEqual(sections["base:9.1.2.3"]["field_values"], [])

    def test_already_resolved_section_is_not_reprocessed(self):
        sections = {
            "base:5.2.12": _section("base:5.2.12", "Get Log Page command", related_opcodes=["0x02a"]),
            "base:5.2.12.1.2": _section("base:5.2.12.1.2",
                                         "Error Information (Log Page Identifier 01h)"),
        }
        sections["base:5.2.12.1.2"]["field_values"] = [{"field_name": "Log Page Identifier", "hex_value": "0x99"}]
        sections["base:5.2.12.1.2"]["related_opcodes"] = ["0xFFa"]  # pre-set, must survive untouched
        link_field_values(sections)
        self.assertEqual(sections["base:5.2.12.1.2"]["related_opcodes"], ["0xFFa"])
        self.assertEqual(sections["base:5.2.12.1.2"]["field_values"],
                          [{"field_name": "Log Page Identifier", "hex_value": "0x99"}])


if __name__ == "__main__":
    unittest.main()
