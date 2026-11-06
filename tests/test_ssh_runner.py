import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import config
from tc_system.execution import ssh_runner
from tc_system.execution.ssh_runner import (DestructiveStepBlocked, passthru_cmd,
                                             _validate_step, execute_tc_steps,
                                             device_responsive, probe_device_capabilities)


class TestSshRunnerValidation(unittest.TestCase):
    def test_valid_step_builds_expected_command(self):
        step = {"mode": "admin-passthru", "device": "/dev/nvme0", "opcode": "0x06",
                 "nsid": 0, "cdw10": "0x00000001", "cdw11": "0x00000000", "cdw12": "0x00000000",
                 "data_len": 0, "direction": "read"}
        cmd = passthru_cmd(step)
        self.assertIn("sudo nvme admin-passthru /dev/nvme0", cmd)
        self.assertNotIn("--read", cmd)  # data_len=0 -> no data flag even though direction=read

    def test_write_direction_with_data_len_appends_write_flag(self):
        step = {"mode": "io-passthru", "device": "/dev/nvme0n1", "opcode": "0x01",
                 "nsid": 1, "cdw10": "0x00000000", "cdw11": "0x00000000", "cdw12": "0x00000000",
                 "data_len": 512, "direction": "write"}
        cmd = passthru_cmd(step)
        self.assertIn("--data-len=512 --write", cmd)

    def test_shell_metacharacters_in_opcode_are_rejected(self):
        step = {"mode": "admin-passthru", "device": "/dev/nvme0", "opcode": "0x06; rm -rf /",
                 "nsid": 0, "cdw10": "0x0", "cdw11": "0x0", "cdw12": "0x0", "data_len": 0}
        with self.assertRaises(ValueError):
            passthru_cmd(step)

    def test_unexpected_device_path_is_rejected(self):
        step = {"mode": "admin-passthru", "device": "/dev/nvme0; echo pwned",
                 "opcode": "0x06", "nsid": 0, "cdw10": "0x0", "cdw11": "0x0", "cdw12": "0x0", "data_len": 0}
        with self.assertRaises(ValueError):
            passthru_cmd(step)

    def test_bool_data_len_is_rejected(self):
        # bool is an int subclass, so a naive isinstance check would let
        # data_len=True through and render "--data-len=True".
        step = {"mode": "admin-passthru", "device": "/dev/nvme0", "opcode": "0x06",
                 "nsid": 0, "cdw10": "0x0", "cdw11": "0x0", "cdw12": "0x0", "data_len": True}
        with self.assertRaises(ValueError):
            _validate_step(step)


class TestDestructiveGate(unittest.TestCase):
    DESTRUCTIVE = [{"mode": "admin-passthru", "device": "/dev/nvme0", "opcode": "0x80",
                     "nsid": 0, "cdw10": "0x0", "cdw11": "0x0", "cdw12": "0x0",
                     "data_len": 0, "destructive": True}]

    def test_destructive_step_is_blocked(self):
        with self.assertRaises(DestructiveStepBlocked) as ctx:
            execute_tc_steps(self.DESTRUCTIVE)
        self.assertIn("0x80", str(ctx.exception))

    def test_block_happens_before_any_ssh_call(self):
        # If the gate ran after connecting, this stub would raise AssertionError
        # instead — assert the destructive check wins.
        import config
        original = config.get_ssh_target
        config.get_ssh_target = lambda: (_ for _ in ()).throw(AssertionError("SSH was contacted"))
        try:
            with self.assertRaises(DestructiveStepBlocked):
                execute_tc_steps(self.DESTRUCTIVE)
        finally:
            config.get_ssh_target = original


class _FakeProc:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class TestCommandLogging(unittest.TestCase):
    """Before this, the exact nvme-cli command text sent over SSH, and how
    long each of the three plink round-trips (dmesg clear / batch / dmesg
    dump) took, were discarded the moment execute_tc_steps returned — a
    multi-minute timeout had no record of which stage it actually hung in.
    """
    STEP = {"mode": "admin-passthru", "device": "/dev/nvme0", "opcode": "0x06",
            "nsid": 0, "cdw10": "0x00000001", "cdw11": "0x00000000", "cdw12": "0x00000000",
            "data_len": 0, "direction": "read"}

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self._real_log_path = config.SSH_COMMAND_LOG_PATH
        config.SSH_COMMAND_LOG_PATH = Path(self.tmp.name) / "ssh_commands.jsonl"
        self._real_get_target = config.get_ssh_target
        config.get_ssh_target = lambda: {"host": "h", "user": "u", "password": "supersecretpw123",
                                          "nvme_ctrl": "/dev/nvme0", "nvme_ns": "/dev/nvme0n1"}

    def tearDown(self):
        config.SSH_COMMAND_LOG_PATH = self._real_log_path
        config.get_ssh_target = self._real_get_target
        self.tmp.cleanup()

    def _lines(self):
        return [json.loads(l) for l in config.SSH_COMMAND_LOG_PATH.read_text(encoding="utf-8").splitlines()]

    def test_each_stage_and_the_exact_command_text_are_logged(self):
        fakes = [_FakeProc(returncode=0),
                 _FakeProc(returncode=0, stdout=f"0\nEXIT_CODE:0\n{ssh_runner.STEP_DELIM}"),
                 _FakeProc(returncode=0, stdout="dmesg output")]
        with mock.patch.object(ssh_runner, "_plink", side_effect=fakes):
            execute_tc_steps([self.STEP])
        line = self._lines()[0]
        self.assertEqual([s["stage"] for s in line["stages"]], ["dmesg_clear", "batch", "dmesg_dump"])
        self.assertIn("--opcode=0x06", line["step_commands"][0])
        for stage in line["stages"]:
            self.assertIn("elapsed_sec", stage)
            self.assertFalse(stage["timed_out"])

    def test_a_batch_timeout_is_still_logged_with_the_command_that_hung(self):
        timeout_proc = _FakeProc(returncode=None, stdout="partial", stderr="[harness] plink timed out and was killed")
        fakes = [_FakeProc(returncode=0), timeout_proc, _FakeProc(returncode=0)]
        with mock.patch.object(ssh_runner, "_plink", side_effect=fakes):
            result = execute_tc_steps([self.STEP])
        self.assertTrue(result["timed_out"])
        batch_stage = self._lines()[0]["stages"][1]
        self.assertEqual(batch_stage["stage"], "batch")
        self.assertTrue(batch_stage["timed_out"])
        self.assertIn("--opcode=0x06", batch_stage["command"])

    def test_batch_timeout_scales_with_step_count(self):
        # Measured on real hardware: every normal completion finished in
        # 3-12s and every real hang landed at 125-143s — nothing in between —
        # so a flat per-batch timeout just wastes wall-clock proportional to
        # however many steps happen to be in the batch. Budgeting per step
        # means a short TC doesn't wait as long to detect a hang, and a
        # longer chain gets a proportionally bigger budget instead of sharing
        # the same fixed number regardless of length.
        calls = []

        def _capture(target, command, **kwargs):
            calls.append(kwargs)
            return _FakeProc(returncode=0)

        with mock.patch.object(ssh_runner, "_plink", side_effect=_capture):
            execute_tc_steps([self.STEP, self.STEP, self.STEP])
        batch_call = next(kw for kw in calls if "timeout" in kw)
        self.assertEqual(batch_call["timeout"], ssh_runner.SECONDS_PER_STEP * 3)

    def test_password_is_never_written_to_the_log(self):
        fakes = [_FakeProc(returncode=0), _FakeProc(returncode=0), _FakeProc(returncode=0)]
        with mock.patch.object(ssh_runner, "_plink", side_effect=fakes):
            execute_tc_steps([self.STEP])
        raw = config.SSH_COMMAND_LOG_PATH.read_text(encoding="utf-8")
        self.assertNotIn("supersecretpw123", raw)

    WRITE_STEP = {"mode": "io-passthru", "device": "/dev/nvme0n1", "opcode": "0x01",
                  "nsid": 1, "cdw10": "0x00000064", "cdw11": "0x00000000", "cdw12": "0x00000000",
                  "data_len": 512, "direction": "write"}

    def test_a_write_step_gets_an_explicit_stdin_buffer_not_the_inherited_terminal(self):
        # Without this, a --write step with no --input-file reads its buffer
        # from stdin (nvme-cli's own documented default) — the local
        # process's own stdin (an attached terminal, forwarded by plink)
        # never sends anything or EOFs, so the step just blocks until the
        # batch timeout kills it. Measured: a 4-step chain with one Write
        # step took the full SECONDS_PER_STEP*4 budget, twice (one retry),
        # instead of the few seconds every other step took.
        calls = []

        def _capture(target, command, **kwargs):
            calls.append(kwargs)
            return _FakeProc(returncode=0)

        with mock.patch.object(ssh_runner, "_plink", side_effect=_capture):
            execute_tc_steps([self.STEP, self.WRITE_STEP])
        batch_call = next(kw for kw in calls if "timeout" in kw)
        self.assertEqual(batch_call.get("stdin"), b"\x00" * 512)

    def test_a_batch_with_no_write_steps_still_gets_an_explicit_empty_stdin(self):
        # An explicit "" (not the default None) still closes stdin
        # immediately instead of leaving it inherited from this process —
        # no step in this batch should ever be able to block on it.
        calls = []

        def _capture(target, command, **kwargs):
            calls.append(kwargs)
            return _FakeProc(returncode=0)

        with mock.patch.object(ssh_runner, "_plink", side_effect=_capture):
            execute_tc_steps([self.STEP])
        batch_call = next(kw for kw in calls if "timeout" in kw)
        self.assertEqual(batch_call.get("stdin"), b"")

    def test_multiple_write_steps_each_get_their_own_slice_of_the_shared_stdin(self):
        second_write = dict(self.WRITE_STEP, data_len=4)
        calls = []

        def _capture(target, command, **kwargs):
            calls.append(kwargs)
            return _FakeProc(returncode=0)

        with mock.patch.object(ssh_runner, "_plink", side_effect=_capture):
            execute_tc_steps([self.WRITE_STEP, self.STEP, second_write])
        batch_call = next(kw for kw in calls if "timeout" in kw)
        self.assertEqual(batch_call.get("stdin"), b"\x00" * 512 + b"\x00" * 4)


class TestProbeDeviceCapabilities(unittest.TestCase):
    """This probe runs once per pipeline run (not once per TC) so
    scenario/arg generation can be steered away from commands/values this
    specific drive is already known not to support — see
    tc_system.generation.device_capabilities.summarize_device_capabilities.
    """
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self._real_log_path = config.SSH_COMMAND_LOG_PATH
        config.SSH_COMMAND_LOG_PATH = Path(self.tmp.name) / "ssh_commands.jsonl"
        self._real_get_target = config.get_ssh_target
        config.get_ssh_target = lambda: {"host": "h", "user": "u", "password": "p",
                                          "nvme_ctrl": "/dev/nvme0", "nvme_ns": "/dev/nvme0n1"}

    def tearDown(self):
        config.SSH_COMMAND_LOG_PATH = self._real_log_path
        config.get_ssh_target = self._real_get_target
        self.tmp.cleanup()

    def test_runs_the_read_only_probes_and_returns_their_raw_stdout(self):
        names = ["id-ctrl output", "id-ns output", "effects-log output", "logs", "fids", "fw", "versions"]
        fakes = [_FakeProc(returncode=0, stdout=n) for n in names]
        with mock.patch.object(ssh_runner, "_plink", side_effect=fakes) as plink:
            out = probe_device_capabilities("/dev/nvme0", "/dev/nvme0n1")
        self.assertEqual(out, {"id_ctrl": "id-ctrl output", "id_ns": "id-ns output",
                                "effects_log": "effects-log output", "supported_logs": "logs",
                                "fid_support": "fids", "fw_log": "fw", "host_versions": "versions"})
        commands = [call.args[1] for call in plink.call_args_list]
        self.assertIn("sudo nvme id-ctrl /dev/nvme0", commands)
        self.assertIn("sudo nvme id-ns /dev/nvme0n1", commands)
        self.assertIn("sudo nvme effects-log /dev/nvme0", commands)
        self.assertTrue(any("--log-id=0" in c for c in commands))
        # Support probe: Get Features SEL=011b (capabilities) only - read-only.
        loop = next(c for c in commands if "get-feature" in c)
        self.assertIn("-s 3", loop)
        self.assertNotIn("set-feature", " ".join(commands))

    def test_commands_and_timing_are_logged(self):
        fakes = [_FakeProc(returncode=0) for _ in range(7)]
        with mock.patch.object(ssh_runner, "_plink", side_effect=fakes):
            probe_device_capabilities("/dev/nvme0", "/dev/nvme0n1")
        lines = [json.loads(l) for l in config.SSH_COMMAND_LOG_PATH.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(len(lines), 1)
        self.assertTrue(lines[0]["probe"])
        self.assertEqual(len(lines[0]["stages"]), 7)
        for stage in lines[0]["stages"]:
            self.assertIn("elapsed_sec", stage)


class TestDeviceResponsive(unittest.TestCase):
    """Run after any TC carrying a destructive/firmware_state/lockout_risk
    step, before the pipeline moves on to the next target — Sanitize/
    Namespace Management can make /dev/nvme0n1 disappear for a while, and
    Lockdown can make the controller reject commands outright without
    removing the device node; a single id-ctrl round trip catches both.
    """
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self._real_log_path = config.SSH_COMMAND_LOG_PATH
        config.SSH_COMMAND_LOG_PATH = Path(self.tmp.name) / "ssh_commands.jsonl"
        self._real_get_target = config.get_ssh_target
        config.get_ssh_target = lambda: {"host": "h", "user": "u", "password": "p",
                                          "nvme_ctrl": "/dev/nvme0", "nvme_ns": "/dev/nvme0n1"}

    def tearDown(self):
        config.SSH_COMMAND_LOG_PATH = self._real_log_path
        config.get_ssh_target = self._real_get_target
        self.tmp.cleanup()

    def test_a_normal_response_is_alive(self):
        with mock.patch.object(ssh_runner, "_plink", return_value=_FakeProc(returncode=0, stdout="...")):
            alive, reason = device_responsive("/dev/nvme0")
        self.assertTrue(alive)
        self.assertEqual(reason, "")

    def test_a_missing_device_node_is_not_alive(self):
        proc = _FakeProc(returncode=22, stdout="/dev/nvme0n1: No such file or directory\n...")
        with mock.patch.object(ssh_runner, "_plink", return_value=proc):
            alive, reason = device_responsive("/dev/nvme0")
        self.assertFalse(alive)
        self.assertIn("No such file or directory", reason)

    def test_a_hung_device_is_not_alive(self):
        with mock.patch.object(ssh_runner, "_plink", return_value=ssh_runner._Timeout()):
            alive, reason = device_responsive("/dev/nvme0", timeout=5)
        self.assertFalse(alive)
        self.assertIn("5s", reason)

    def test_the_check_itself_is_logged(self):
        with mock.patch.object(ssh_runner, "_plink", return_value=_FakeProc(returncode=0)):
            device_responsive("/dev/nvme0")
        lines = [json.loads(l) for l in config.SSH_COMMAND_LOG_PATH.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(len(lines), 1)
        self.assertTrue(lines[0]["health_check"])



class TestTestsCannotReachTheRealTarget(unittest.TestCase):
    """Measured: a test that mocked execute_tc_steps but not capture_dmesg
    launched plink and appended a record to the real logs/ssh_commands.jsonl."""

    def test_an_unmocked_plink_call_fails_the_test(self):
        with self.assertRaisesRegex(RuntimeError, "real plink/SSH call from a test"):
            ssh_runner._plink({"host": "h", "user": "u", "password": "p"}, "true")

    def test_writing_the_real_ssh_log_fails_the_test(self):
        self.assertEqual(config.SSH_COMMAND_LOG_PATH, ssh_runner._REAL_SSH_LOG_PATH)
        with self.assertRaisesRegex(RuntimeError, "real logs/ssh_commands.jsonl"):
            ssh_runner._append_ssh_log({"tc_id": "should-not-be-written"})



class TestHostActions(unittest.TestCase):
    """Controller reset / PMU power cycle, sequence as in pc_sampling_fuzzer_v11.5 POR."""
    PMU = {"enabled": True, "script": "/opt/pmu/pmu_4_1.py", "dev_idx": 1, "voltage_mv": 3300,
           "poweroff_wait_sec": 3, "rescan_delay_sec": 10, "boot_wait_sec": 30, "remove": "root"}

    def test_power_cycle_follows_the_fuzzer_por_order(self):
        from tc_system.execution.host_actions import host_action_command
        command, timeout = host_action_command("power_cycle", "/dev/nvme0", self.PMU)
        self.assertTrue(command.startswith("sudo -S bash -c '"))
        # rindex for ON: it also appears in the failed-OFF branch, before the remove.
        order = [command.index("pmu_4_1.py 7 1"), command.index("/remove"), command.index("sleep 3.0"),
                 command.rindex("pmu_4_1.py 4 1 3300 0 12000 0 0"), command.index("sleep 10.0"),
                 command.index("/sys/bus/pci/rescan"), command.index("nvme id-ctrl /dev/nvme0")]
        self.assertEqual(order, sorted(order))
        self.assertIn("devices/$ROOT/remove", command)  # remove="root": the topmost bridge
        self.assertEqual(timeout, 3 + 10 + 30 + 30)

    def test_a_failed_power_off_is_not_a_power_cycle(self):
        # Review: a fake PMU returning OFF=9, ON=0 ended as a successful power
        # cycle (exit 0), so "retained across power loss" could PASS with no loss.
        from tc_system.execution.host_actions import host_action_command
        command, _ = host_action_command("power_cycle", "/dev/nvme0", self.PMU)
        off_branch = command[command.index("off=$?"):command.index("/remove")]
        self.assertIn("if [ $off -ne 0 ]", off_branch)
        self.assertIn("pmu_4_1.py 4 1 3300 0 12000 0 0", off_branch)  # powered back on, just in case
        self.assertIn("exit 96", off_branch)  # a PMU error (ERROR), not 98 (drive never came back)

    def test_power_cycle_without_a_pmu_is_refused(self):
        from tc_system.execution.host_actions import host_action_command
        with self.assertRaisesRegex(ValueError, "PMU"):
            host_action_command("power_cycle", "/dev/nvme0", None)

    def test_controller_reset_waits_for_the_controller_to_answer(self):
        from tc_system.execution.host_actions import host_action_command
        command, _ = host_action_command("controller_reset", "/dev/nvme0", None)
        self.assertIn("nvme reset /dev/nvme0", command)
        self.assertIn("exit 98", command)  # never answered again -> distinct exit code

    def test_power_cycle_is_offered_only_with_a_pmu(self):
        from tc_system.execution.host_actions import host_action_entries
        self.assertEqual([e["name"] for e in host_action_entries(None)], ["Controller Reset"])
        entries = host_action_entries(self.PMU)
        self.assertEqual([e["name"] for e in entries], ["Controller Reset", "Power Cycle (PMU)"])
        self.assertTrue(entries[1]["destructive"])  # a sudden power loss: blocked by --no-destructive


class TestRunHostActionOverSsh(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        for name, value in (("SSH_COMMAND_LOG_PATH", Path(self.tmp.name) / "ssh.jsonl"),
                            ("get_ssh_target", lambda: {"host": "h", "user": "u", "password": "pw-not-logged",
                                                        "nvme_ctrl": "/dev/nvme0", "nvme_ns": "/dev/nvme0n1"}),
                            ("get_pmu", lambda: None)):
            patcher = mock.patch.object(config, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_the_reset_runs_as_one_root_shell_and_is_logged_without_the_password(self):
        calls = []

        def fake_plink(target, command, stdin=None, timeout=60):
            calls.append((command, stdin, timeout))
            return _FakeProc(returncode=0, stdout="RESET_RC=0\nREADY_AFTER_SEC=2\n")

        with mock.patch.object(ssh_runner, "_plink", side_effect=fake_plink):
            result = ssh_runner.run_host_action("controller_reset", "/dev/nvme0", tc_id="t", step_index=1)
        self.assertEqual(result["exit_code"], 0)
        self.assertIn("READY_AFTER_SEC=2", result["stdout"])
        self.assertEqual(calls[0][1], "pw-not-logged\n")  # password only on stdin
        log = config.SSH_COMMAND_LOG_PATH.read_text(encoding="utf-8")
        self.assertIn('"host_action": "controller_reset"', log)
        self.assertNotIn("pw-not-logged", log)


if __name__ == "__main__":
    unittest.main()
