"""A real firmware image from secrets.local.json firmware.image (2026-11-10):
without one, every Firmware Image Download sent zero-filled data and a Commit
that needed an image could only be rejected - judged as the drive's failure."""
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import config
from tc_system.execution import ssh_runner
from tc_system.execution.expectation_checker import _firmware_violation_indices
from tc_system.execution.host_actions import host_action_command, host_action_entries
from tc_system.generation.tc_writer import _command_step
from tc_system.pipeline import _firmware_commit_problem
from tc_system.verification import payload_for_step

IMAGE = bytes(range(256)) * 16  # 4096 bytes, no zero run long enough to look like a dummy


class _ImageDir(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "fw.bin"
        self.path.write_bytes(IMAGE)
        self.image = {"name": "fw.bin", "path": str(self.path), "size": len(IMAGE),
                      "sha256": hashlib.sha256(IMAGE).hexdigest(), "remote": "/tmp/tc_gen_fw/fw.bin",
                      "xfer_bytes": None}


def download(cdw11, data_len, image=None):
    step = {"name": "Firmware Image Download", "mode": "admin-passthru", "opcode": "0x11", "device": "/dev/nvme0",
            "nsid": 0, "cdw10": hex(data_len // 4 - 1), "cdw11": hex(cdw11), "cdw12": "0x0",
            "data_len": data_len, "direction": "write", "payload_hex": None}
    if image:
        step["firmware_image"] = image
    return step


def commit(ca, expected="SUCCESS"):
    return {"name": "Firmware Commit", "mode": "admin-passthru", "opcode": "0x10", "device": "/dev/nvme0",
            "cdw10": hex((ca << 3) | 1), "expected_status": expected}


FULL = {"name": "Firmware Image Download (full image)", "host_action": "firmware_download"}


class TestConfiguredImage(_ImageDir):
    def _status(self, firmware):
        with mock.patch.object(config, "_load_secrets", return_value={"firmware": firmware}):
            return config.firmware_image_status()

    def test_the_file_in_the_project_folder_is_read_and_fingerprinted(self):
        image, why = self._status({"image": str(self.path)})
        self.assertEqual(why, "")
        self.assertEqual((image["size"], image["sha256"]), (4096, hashlib.sha256(IMAGE).hexdigest()))
        self.assertEqual(image["remote"], config.FIRMWARE_REMOTE_DIR + "/fw.bin")
        with mock.patch.object(config, "_load_secrets", return_value={"firmware": {"image": "fw.bin"}}), \
             mock.patch.object(config, "BASE_DIR", Path(self.tmp.name)):
            self.assertEqual(config.firmware_image_status()[0]["path"], str(self.path))  # relative = project folder

    def test_why_there_is_no_image(self):
        self.assertIn("firmware.image 없음", self._status({})[1])
        self.assertIn("없음", self._status({"image": str(self.path) + ".missing"})[1])
        self.path.write_bytes(b"abc")
        self.assertIn("4의 배수", self._status({"image": str(self.path)})[1])


class TestDownloadPayload(_ImageDir):
    def test_a_download_sends_the_image_bytes_at_its_offset(self):
        self.assertEqual(payload_for_step(download(0, 1024, self.image)), IMAGE[:1024])
        self.assertEqual(payload_for_step(download(256, 1024, self.image)), IMAGE[1024:2048])  # OFST in dwords

    def test_past_the_end_of_the_image_is_zero(self):
        self.assertEqual(payload_for_step(download(1000, 1024, self.image)), IMAGE[4000:] + bytes(1024 - 96))

    def test_a_changed_image_is_not_sent_silently(self):
        self.path.write_bytes(bytes(4096))
        with self.assertRaisesRegex(ValueError, "changed"):
            payload_for_step(download(0, 512, dict(self.image, path=str(self.path), sha256="0" * 64)))

    def test_without_an_image_the_buffer_stays_zero_filled(self):
        self.assertEqual(payload_for_step(download(0, 512)), bytes(512))

    def test_a_real_image_download_is_not_the_dummy_rule(self):
        steps = [download(0, 1024, self.image), commit(1)]
        results = {"step_results": [{"step_index": 0, "exit_code": 0, "stdout": "Admin Command x is Success"},
                                    {"step_index": 1, "exit_code": 0, "stdout": "Admin Command x is Success"}]}
        self.assertEqual(_firmware_violation_indices({"steps": steps}, results), set())
        steps[0] = download(0, 1024)  # zero-filled: still the dummy-activation finding
        self.assertEqual(_firmware_violation_indices({"steps": steps}, results), {1})

    def test_an_authored_download_step_carries_the_image(self):
        entry = {"name": "Firmware Image Download", "command_set": "ADMIN", "raw_opcode": "0x11", "opcode": "0x11"}
        authored = {"cdw10": "0xFF", "cdw11": "0x0", "cdw12": "0x0", "nsid": 0, "data_len": 1024,
                    "direction": "write", "shared_facts": {}, "field_breakdown": "x"}
        with mock.patch("tc_system.generation.tc_writer.author_args", return_value=authored) as author:
            step = _command_step({"section_id": "base:5.2.9"}, entry, "/dev/nvme0", "/dev/nvme0n1", 1,
                                 phase="action", test_intent={"firmware_image": self.image, "payload_hex": "AA"})
        self.assertEqual(step["firmware_image"]["sha256"], self.image["sha256"])
        self.assertIsNone(step["payload_hex"])
        self.assertIsNone(author.call_args.kwargs["test_intent"]["payload_hex"])  # the pattern is not checked either
        self.assertEqual(payload_for_step(step), IMAGE[:1024])


class TestFullImageStep(_ImageDir):
    def test_offered_only_with_an_image_on_the_target_and_it_changes_firmware_state(self):
        self.assertNotIn("Firmware Image Download (full image)", [e["name"] for e in host_action_entries(None)])
        entry = host_action_entries(None, self.image)[-1]
        self.assertEqual(entry["host_action"], "firmware_download")
        self.assertTrue(entry["firmware_state"])  # --no-destructive blocks it

    def test_nvme_fw_download_runs_on_the_target_copy(self):
        command, _ = host_action_command("firmware_download", "/dev/nvme0", None, dict(self.image, xfer_bytes=65536))
        self.assertIn("nvme fw-download /dev/nvme0 --fw=/tmp/tc_gen_fw/fw.bin --xfer=65536", command)
        with self.assertRaisesRegex(ValueError, "firmware.image"):
            host_action_command("firmware_download", "/dev/nvme0", None, None)

    def test_the_image_is_copied_and_checked_on_the_target(self):
        sent = []

        class Proc:
            returncode, stderr = 0, b""

        def fake_plink(target, command, stdin=None, timeout=60):
            sent.append((command, stdin))
            proc = Proc()
            proc.stdout = f"{self.image['sha256']}  /tmp/tc_gen_fw/fw.bin\n".encode()
            return proc

        with mock.patch.object(ssh_runner, "_plink", side_effect=fake_plink), \
             mock.patch.object(ssh_runner, "_append_ssh_log"), \
             mock.patch.object(config, "get_ssh_target", return_value={"host": "h", "user": "u", "password": "p"}):
            self.assertEqual(ssh_runner.upload_firmware_image(self.image), "")
            self.assertIn("cat > /tmp/tc_gen_fw/fw.bin", sent[0][0])
            self.assertEqual(sent[0][1], IMAGE)
            self.assertIn("sha256", ssh_runner.upload_firmware_image(dict(self.image, sha256="f" * 64)))


class TestCommitNeedsTheWholeImage(unittest.TestCase):
    def test_a_commit_that_needs_an_image_is_not_sent_without_the_full_download(self):
        self.assertIn("CA=001b", _firmware_commit_problem({"steps": [download(0, 1024), commit(1)]}))
        self.assertIn("CA=011b", _firmware_commit_problem({"steps": [commit(3)]}))
        self.assertIsNone(_firmware_commit_problem({"steps": [FULL, commit(1)]}))

    def test_a_partial_download_after_the_full_one_breaks_it_again(self):
        self.assertIsNotNone(_firmware_commit_problem({"steps": [FULL, download(0, 1024), commit(0)]}))

    def test_rejection_tests_and_existing_slots_are_fine(self):
        self.assertIsNone(_firmware_commit_problem({"steps": [download(0, 1024), commit(1, "FIRMWARE_IMAGE")]}))
        self.assertIsNone(_firmware_commit_problem({"steps": [commit(2)]}))


if __name__ == "__main__":
    unittest.main()
