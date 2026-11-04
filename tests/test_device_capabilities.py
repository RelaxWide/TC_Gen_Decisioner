"""Tests for parsing real nvme-cli diagnostic output into the prompt hint that
lets scenario/arg generation skip commands/values this specific drive is
already known not to support.
"""
import unittest

from tc_system.generation.device_capabilities import summarize_device_capabilities

# A realistic (trimmed) `nvme id-ctrl` text dump. oacs=0x17 = bits 0,1,2,4
# (Security Send/Receive, Format NVM, Firmware Commit/Download, Device
# Self-test). oncs=0x5f = bits 0,1,2,3,4,6 (Compare, Write Uncorrectable,
# Dataset Management, Write Zeroes, Save/Select Feature, Timestamp).
# sanicap=0x3 = bits 0,1 (Crypto Erase, Block Erase).
ID_CTRL = """\
NVME Identify Controller:
vid     : 0x144d
oacs    : 0x17
acl     : 3
frmw    : 0x16
lpa     : 0x1e
oncs    : 0x5f
fuses   : 0
fna     : 0
vwc     : 0x1
sanicap : 0x3
mdts    : 5
npss    : 4
"""

ID_NS = """\
NVME Identify Namespace:
nsze    : 0x3a7e2b0
ncap    : 0x3a7e2b0
nuse    : 0x3a7e2b0
nlbaf   : 0
LBA Format  0 : Metadata Size: 0   bytes - Data Size: 4096 bytes - Relative Performance: 0 Best (in use)
"""

EFFECTS_LOG = """\
Admin Command Set
ACS   0 (Delete I/O Submission Queue)                 CSUPP+ LBCC- NCC- NIC- CCC- CSE 0x0 UUID-
ACS   1 (Create I/O Submission Queue)                 CSUPP+ LBCC- NCC- NIC- CCC- CSE 0x0 UUID-
ACS   9 (Set Features)                                CSUPP+ LBCC- NCC- NIC- CCC- CSE 0x0 UUID-
ACS  13 (Namespace Management)                         CSUPP- LBCC- NCC- NIC- CCC- CSE 0x0 UUID-
IOCS  2 (Read)                                         CSUPP+ LBCC- NCC- NIC- CCC- CSE 0x0 UUID-
"""


class TestSummarizeDeviceCapabilities(unittest.TestCase):
    def test_oacs_bits_are_decoded_to_command_names(self):
        out = summarize_device_capabilities({"id_ctrl": ID_CTRL})
        self.assertIn("Security Send/Receive", out)
        self.assertIn("Format NVM", out)
        self.assertIn("Firmware Commit/Download", out)
        self.assertIn("Device Self-test", out)
        # bit 3 (Namespace Management) is NOT set in 0x17 — must not appear.
        self.assertNotIn("Namespace Management", out)

    def test_oncs_bits_are_decoded_to_command_names(self):
        out = summarize_device_capabilities({"id_ctrl": ID_CTRL})
        self.assertIn("Compare", out)
        self.assertIn("Dataset Management", out)
        self.assertIn("Write Zeroes", out)
        self.assertIn("Timestamp", out)
        # bit 5 (Reservations) is NOT set in 0x5f — must not appear.
        self.assertNotIn("Reservations", out)

    def test_sanicap_bits_are_decoded(self):
        out = summarize_device_capabilities({"id_ctrl": ID_CTRL})
        self.assertIn("Crypto Erase", out)
        self.assertIn("Block Erase", out)
        self.assertNotIn("Overwrite", out)

    def test_npss_and_mdts_raw_fields_are_reported(self):
        out = summarize_device_capabilities({"id_ctrl": ID_CTRL})
        self.assertIn("NPSS=4", out)
        self.assertIn("0~4", out)
        self.assertIn("MDTS", out)

    def test_namespace_size_and_sector_size_are_reported(self):
        out = summarize_device_capabilities({"id_ns": ID_NS})
        self.assertIn("0x3A7E2B0", out)
        self.assertIn("4096 bytes", out)

    def test_effects_log_lists_only_csupp_plus_commands(self):
        out = summarize_device_capabilities({"effects_log": EFFECTS_LOG})
        self.assertIn("Delete I/O Submission Queue", out)
        self.assertIn("Set Features", out)
        self.assertIn("Read", out)
        self.assertNotIn("Namespace Management", out)

    def test_empty_input_returns_empty_string(self):
        self.assertEqual(summarize_device_capabilities({}), "")
        self.assertEqual(summarize_device_capabilities({"id_ctrl": "", "id_ns": "", "effects_log": ""}), "")

    def test_garbage_input_degrades_to_empty_string_instead_of_raising(self):
        # An unreachable target or an nvme-cli version missing a subcommand
        # could plausibly return an error message instead of real field
        # output — this must never raise, only omit what it can't parse.
        garbage = {"id_ctrl": "nvme: command not found\n", "id_ns": "", "effects_log": "garbage\n"}
        self.assertEqual(summarize_device_capabilities(garbage), "")

    def test_all_three_sources_combine_into_one_block(self):
        out = summarize_device_capabilities({"id_ctrl": ID_CTRL, "id_ns": ID_NS, "effects_log": EFFECTS_LOG})
        self.assertIn("Format NVM", out)
        self.assertIn("4096 bytes", out)
        self.assertIn("Set Features", out)


if __name__ == "__main__":
    unittest.main()
