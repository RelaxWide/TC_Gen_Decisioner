"""Batches TC command steps into a single plink round-trip against the real
target (192.168.137.9, verified reachable — see plan doc). `sudo nvme ...` is
passwordless (sudoers NOPASSWD rule scoped to /usr/sbin/nvme), so the batch
script itself needs no embedded credential; only dmesg clear/dump need a
sudo password, fed via the local plink subprocess's stdin (`sudo -S`).

Step fields are validated before being interpolated into the remote shell
command — today they only ever come from the fixed seed JSON, but the next
planned step is LLM-authored per-opcode values, which must not be trusted
with raw shell interpolation.
"""
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

import config

STEP_DELIM = "---TC_STEP_END---"
# Measured on real hardware: every normal completion finished in 3-12s;
# every real hang landed at 125-143s (the old flat 120s timeout plus plink's
# own kill/teardown overhead) — nothing in between. So the exact threshold
# barely affects correctness, only how much wall-clock one hang wastes.
# Budgeting per-step instead of one flat number means a longer chain gets a
# proportionally longer budget, but a short chain stops wasting time waiting
# for a hang that would've shown up in seconds.
SECONDS_PER_STEP = 30
# Anchored to a whole line: the harness echoes `EXIT_CODE:<n>` on its own line
# as the last thing in a step's block, but a `--read` dump of device data can
# contain the same text inside a hexdump's ASCII column. An unanchored search
# took that first occurrence, so a real exit 22 parsed as 0 — a false PASS.
_EXIT_CODE_RE = re.compile(r"^EXIT_CODE:(-?\d+)$", re.M)
_HEX_RE = re.compile(r"^0x[0-9A-Fa-f]{1,8}$")
_DEVICE_RE = re.compile(r"^/dev/nvme\d+(n\d+)?$")


def _validate_step(step: dict) -> None:
    if step.get("mode") not in ("admin-passthru", "io-passthru"):
        raise ValueError(f"invalid step mode: {step.get('mode')!r}")
    if not _DEVICE_RE.match(step.get("device", "")):
        raise ValueError(f"invalid step device: {step.get('device')!r}")
    for field in ("opcode", "cdw10", "cdw11", "cdw12"):
        if not _HEX_RE.match(step.get(field, "")):
            raise ValueError(f"invalid step {field}: {step.get(field)!r}")
    for field in ("cdw13", "cdw14", "cdw15"):
        if not _HEX_RE.fullmatch(step.get(field, "0x0")):
            raise ValueError(f"invalid step {field}")
    # nsid is required, not defaulted: `passthru_cmd` interpolates step["nsid"]
    # directly, so a `.get(..., 0)` here let a step with no nsid pass validation
    # and then die with KeyError while building the command.
    if "nsid" not in step:
        raise ValueError("step is missing nsid")
    # bool is an int subclass, so reject it explicitly or data_len=True would
    # pass validation and render as `--data-len=True`.
    for field in ("nsid", "data_len"):
        value = step.get(field, 0)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"invalid step {field}: {value!r}")
    if step.get("direction", "none") not in ("none", "read", "write"):
        raise ValueError(f"invalid step direction: {step.get('direction')!r}")
    from tc_system.verification import integer, payload_for_step, validate_fixed_fields
    from tc_system import spec_fields
    # The kernel refuses an I/O command whose nsid differs from the namespace
    # node it is sent to ("nsid (0) in cmd does not match nsid (1) of
    # namespace", measured): it never reaches the controller.
    node = re.search(r"n(\d+)$", step["device"])
    if step["mode"] == "io-passthru" and node and step["nsid"] != int(node.group(1)):
        raise ValueError(f"I/O command nsid={step['nsid']} sent to {step['device']} (nsid {node.group(1)}): the "
                         "kernel rejects it before it reaches the controller")
    if step["mode"] == "admin-passthru":
        raw = int(step["opcode"], 16)
        hazard = spec_fields.queue_command_hazard("ADMIN", raw, step["cdw10"], step.get("expected_status"))
        if hazard:
            raise ValueError(hazard)
        if raw == 0x09:
            irreversible = spec_fields.irreversible_feature_value(integer(step["cdw10"]) & 0xFF, integer(step["cdw11"]))
            if irreversible:
                raise ValueError(irreversible)
        if raw == 0x09 and integer(step["cdw10"]) & 0xFF in spec_fields.HOST_OWNED_SET_FEATURES:
            raise ValueError(f"Set Features FID {integer(step['cdw10']) & 0xFF:02X}h: "
                             f"{spec_fields.HOST_OWNED_SET_FEATURES[integer(step['cdw10']) & 0xFF]}")
    payload_for_step(step)
    validate_fixed_fields(step, step.get("field_constraints", []))
    if step.get("args_source") == "authored":
        from tc_system.command_fields import validate_transfer
        validate_transfer(step, {"command_set": "ADMIN" if step["mode"] == "admin-passthru" else "NVM",
                                 "raw_opcode": step["opcode"], "name": step.get("name", step["opcode"])},
                          lba_bytes=step.get("lba_bytes"))


def passthru_cmd(step: dict) -> str:
    _validate_step(step)
    cmd = (f"sudo nvme {step['mode']} {step['device']} --opcode={step['opcode']} "
           f"--namespace-id={step['nsid']} --cdw10={step['cdw10']} --cdw11={step['cdw11']} "
           f"--cdw12={step['cdw12']}")
    for i in range(13, 16):
        if f"cdw{i}" in step:
            cmd += f" --cdw{i}={step[f'cdw{i}']}"
    direction = step.get("direction", "none")
    if direction != "none" and step.get("data_len"):
        cmd += f" --data-len={step['data_len']} --{direction}"
    return cmd


class _Timeout:
    """Stands in for a CompletedProcess when plink had to be killed.

    Carries whatever was captured before the kill. Discarding it (as a bare
    stdout="" did) threw away the evidence of a device hang: the steps that
    completed before the wedge, and which one never returned.
    """
    returncode = None

    def __init__(self, stdout: str = "", stderr: str = ""):
        self.stdout = stdout or ""
        self.stderr = (stderr or "") + "\n[harness] plink timed out and was killed"


def _plink(target: dict, command: str, stdin: str | None = None, timeout: int = 60):
    _refuse_under_tests("real plink/SSH call")
    fd, pwfile_path = tempfile.mkstemp(prefix="plinkpw-")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(target["password"])
        try:
            proc = subprocess.run(
                ["plink", "-ssh", "-batch", "-pwfile", pwfile_path, f"{target['user']}@{target['host']}", command],
                input=stdin, capture_output=True, text=not isinstance(stdin, bytes), timeout=timeout,
            )
            if isinstance(proc.stdout, bytes):
                proc.stdout = proc.stdout.decode("utf-8", "replace")
                proc.stderr = proc.stderr.decode("utf-8", "replace")
            return proc
        except subprocess.TimeoutExpired as exc:
            # A wedged device is the main thing this tool hunts for, so a timeout
            # must become a recorded finding, not a traceback that aborts the run.
            def _text(value):
                if value is None:
                    return ""
                return value if isinstance(value, str) else value.decode("utf-8", "replace")
            return _Timeout(_text(exc.stdout), _text(exc.stderr))
    finally:
        os.remove(pwfile_path)


def _parse_batch_output(stdout: str, n_steps: int) -> list[dict]:
    blocks = stdout.split(STEP_DELIM)
    results = []
    for i in range(n_steps):
        marker = str(i) + "\n"
        block = next((b[len(marker):] for b in blocks if b.startswith(marker)), None)
        # `started` separates "its delimiter was echoed, then it never
        # returned" (the step that hung) from "the batch was killed before it
        # ever got here" (never ran). Both have no EXIT_CODE, but only the
        # first says anything about the device — treating the second the
        # same way credited coverage to clauses that were never sent.
        started = block is not None
        block = block or ""
        # Last match, not first: the harness's marker always trails the command's
        # own output, which may itself contain the same text.
        codes = _EXIT_CODE_RE.findall(block)
        exit_code = int(codes[-1]) if codes else None
        # Drop only the harness's own marker lines so `stdout` is the command's
        # output — it ends up in the judge's evidence excerpt.
        body = "\n".join(l for l in block.splitlines() if not _EXIT_CODE_RE.fullmatch(l.strip()))
        results.append({"step_index": i, "exit_code": exit_code, "stdout": body.strip(), "started": started})
    return results


class DestructiveStepBlocked(RuntimeError):
    pass


# The real log file, captured at import (tests redirect config's path later).
_REAL_SSH_LOG_PATH = config.SSH_COMMAND_LOG_PATH


def _refuse_under_tests(what: str) -> None:
    """A test that reaches the real wire or the real log forgot a mock. Fail it
    loudly instead (measured: one such test launched plink and appended a
    record to logs/ssh_commands.jsonl). The production entry points never
    import unittest; TC_ALLOW_REAL_SSH=1 overrides for manual experiments."""
    if "unittest" in sys.modules and not os.environ.get("TC_ALLOW_REAL_SSH"):
        raise RuntimeError(f"{what} from a test - mock ssh_runner (execute_tc_steps, capture_dmesg, "
                           "_plink, ...) or redirect config.SSH_COMMAND_LOG_PATH")


def _append_ssh_log(record: dict) -> None:
    if config.SSH_COMMAND_LOG_PATH == _REAL_SSH_LOG_PATH:
        _refuse_under_tests("write to the real logs/ssh_commands.jsonl")
    config.LOGS_DIR.mkdir(parents=True, exist_ok=True)
    with config.SSH_COMMAND_LOG_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def _timed_plink(target: dict, command: str, stage: str, **kwargs):
    """Runs `_plink` and returns (proc, stage_record) — the stage_record is
    what makes it possible to tell, after the fact, which of the three SSH
    round-trips a hang happened in and how long each one actually ran, instead
    of only the TC-level total that `run_tc_pipeline.py` prints."""
    started = time.monotonic()
    proc = _plink(target, command, **kwargs)
    return proc, {
        "stage": stage,
        "command": command,
        "elapsed_sec": round(time.monotonic() - started, 2),
        "exit_code": proc.returncode,
        "timed_out": proc.returncode is None,
    }


def probe_device_capabilities(nvme_ctrl: str, nvme_ns: str) -> dict[str, str]:
    """Runs a handful of read-only diagnostic nvme-cli commands against the
    real target once per pipeline run (not once per TC) and returns their raw
    stdout, keyed by a fixed label — Identify Controller/Namespace plus (best
    effort) the Commands Supported and Effects log. `device_capabilities.
    summarize_device_capabilities` turns this into the prompt hint that lets
    scenario/arg generation skip proposing commands or values this drive is
    already known not to support, instead of spending an LLM call plus an SSH
    round trip to discover the same answer per TC (measured: UNSUPPORTED was
    ~52% of all TC outcomes before this).

    Every nvme-cli subcommand here is a fixed literal, never an LLM-authored
    value, so none of this goes through `passthru_cmd`/`_validate_step` — and
    these are read-only reports, not opcode execution, so there is no
    destructive gate either."""
    target = config.get_ssh_target()
    log_record = {"timestamp": datetime.now(timezone.utc).isoformat(), "probe": True, "stages": []}
    outputs = {}
    from tc_system.generation.device_capabilities import PROBED_FIDS
    # A namespace-specific feature can reject NSID 0 with INVALID_FIELD:
    # retried with the namespace, unsupported only if both are rejected.
    nsid = re.search(r"n(\d+)$", nvme_ns)
    retry = (f"if [ $rc -ne 0 ]; then echo NSID_RETRY; sudo nvme get-feature {nvme_ctrl} -f 0x$f -s 3 "
             f"-n {nsid.group(1)} 2>&1; rc=$?; fi; ") if nsid else ""
    fid_loop = ("for f in " + " ".join(f"{f:02X}" for f in PROBED_FIDS) + "; do echo \"FID=$f\"; "
                f"sudo nvme get-feature {nvme_ctrl} -f 0x$f -s 3 2>&1; rc=$?; " + retry
                + "echo \"RC=$rc\"; done")
    for key, cmd in (
        ("id_ctrl", f"sudo nvme id-ctrl {nvme_ctrl}"),
        ("id_ns", f"sudo nvme id-ns {nvme_ns}"),
        ("effects_log", f"sudo nvme effects-log {nvme_ctrl}"),
        # Which LIDs/FIDs this drive implements: an unsupported one is then a
        # fact about the drive, not "our argument error" (2026-11-05 run: ~30
        # ERRORs were Get Features/Get Log Page of features the drive lacks).
        ("supported_logs", f"sudo nvme get-log {nvme_ctrl} --log-id=0 --log-len=1024 2>&1"),
        ("fid_support", fid_loop),
        # Firmware Slot Information: a committed image waiting for a reset
        # makes Sanitize and others abort with "Firmware Activation Requires
        # ... Reset" (2026-11-06: AFI 11h left by an earlier Firmware Commit).
        ("fw_log", f"sudo nvme fw-log {nvme_ctrl} 2>&1"),
        # Recorded in the run manifest: results depend on the host tool too.
        ("host_versions", "nvme version 2>&1; uname -r"),
    ):
        proc, stage = _timed_plink(target, cmd, f"probe_{key}", timeout=30)
        log_record["stages"].append(stage)
        outputs[key] = proc.stdout
    _append_ssh_log(log_record)
    return outputs


def device_responsive(nvme_ctrl: str, timeout: int = 15) -> tuple[bool, str]:
    """Cheap post-hoc health check — a single `id-ctrl` round trip, not the
    full `probe_device_capabilities` battery — meant to run right after any
    TC that carried a `destructive`/`firmware_state`/`lockout_risk` step
    (Sanitize, Namespace Management, Lockdown, Firmware Commit, ...), before
    the pipeline moves on to the next target.

    Those commands can leave the device in a state later targets silently
    assume didn't change: Sanitize/Format/Namespace Management can make
    `/dev/nvme0n1` disappear for a while (measured: a later TC's Write/Read
    failed with "No such file or directory", not a controller status, because
    an earlier TC in the same batch had reformatted/detached the namespace);
    Lockdown can make the controller reject subsequent admin commands outright
    without removing the device node at all. A bare file-existence check only
    catches the first kind — this sends an actual command and checks it gets
    a real response, catching both.

    Returns (True, "") if the controller answered within `timeout` seconds,
    else (False, reason) — the caller decides whether to stop the batch
    rather than grind through N more targets that would almost certainly all
    fail the same way against a device that's gone or locked out."""
    target = config.get_ssh_target()
    proc, stage = _timed_plink(target, f"sudo nvme id-ctrl {nvme_ctrl}", "health_check", timeout=timeout)
    _append_ssh_log({"timestamp": datetime.now(timezone.utc).isoformat(), "health_check": True,
                      "stages": [stage]})
    if stage["timed_out"]:
        return False, f"device did not respond within {timeout}s"
    if proc.returncode != 0:
        lines = (proc.stdout or proc.stderr or "").strip().splitlines()
        detail = lines[0] if lines else "(no output)"
        return False, f"id-ctrl exit code {proc.returncode}: {detail}"
    return True, ""


def run_host_action(action: str, nvme_ctrl: str, tc_id=None, attempt_id=None, step_index=None) -> dict:
    """Controller reset / PMU power cycle (host_actions.py): on the target host,
    except the PMU board commands of a power cycle with pmu.run_on=local."""
    from tc_system.execution.host_actions import host_action_command, pmu_runs_locally
    pmu = config.get_pmu()
    target = config.get_ssh_target()
    log_record = {"timestamp": datetime.now(timezone.utc).isoformat(), "n_steps": 1, "stages": [],
                  "tc_id": tc_id, "attempt_id": attempt_id, "step_index": step_index, "host_action": action}
    if action == "power_cycle" and pmu_runs_locally(pmu):
        try:
            return _local_power_cycle(nvme_ctrl, pmu, target, log_record)
        finally:
            _append_ssh_log(log_record)
    command, timeout = host_action_command(action, nvme_ctrl, pmu)
    log_record["step_commands"] = [command]
    try:
        proc, stage = _timed_plink(target, command, f"host_{action}", stdin=target["password"] + "\n",
                                   timeout=timeout)
        log_record["stages"].append(stage)
        return {"exit_code": proc.returncode, "stdout": (proc.stdout or "").strip(),
                "batch_stderr": proc.stderr or "", "timed_out": proc.returncode is None}
    finally:
        _append_ssh_log(log_record)


def _run_local_pmu(pmu: dict, what: str, timeout: int = 30) -> tuple[int | None, str, dict]:
    """One PMU board command from this PC (pmu.run_on=local), with the
    script's folder as the working directory so it finds pmu_ip.json."""
    _refuse_under_tests("real PMU board call")
    from tc_system.execution.host_actions import local_pmu_argv
    argv = local_pmu_argv(pmu, what)
    started = time.monotonic()
    try:
        proc = subprocess.run(argv, cwd=str(Path(pmu["script"]).parent), capture_output=True,
                              encoding="utf-8", errors="replace", timeout=timeout)
        rc, out = proc.returncode, ((proc.stdout or "") + (proc.stderr or "")).strip()
    except subprocess.TimeoutExpired:
        rc, out = None, f"PMU 명령이 {timeout}초 안에 끝나지 않음"
    except OSError as exc:
        rc, out = None, f"PMU 스크립트 실행 실패: {exc}"
    stage = {"stage": f"pmu_{what}", "command": " ".join(argv), "elapsed_sec": round(time.monotonic() - started, 2),
             "exit_code": rc, "timed_out": rc is None}
    return rc, out, stage


def local_pmu_problem(pmu: dict) -> str:
    """Start-of-run check for pmu.run_on=local: the files are there and the
    board answers a read-only current measurement (`pmu_4_1.py 3 <dev>`, what
    the fuzzer reads between commands). "" when usable, else why not."""
    from tc_system.execution.host_actions import local_pmu_files_problem
    problem = local_pmu_files_problem(pmu)
    if problem:
        return problem
    rc, out, stage = _run_local_pmu(pmu, "current", timeout=20)
    _append_ssh_log({"timestamp": datetime.now(timezone.utc).isoformat(), "pmu_check": True, "stages": [stage],
                     "output": out[-500:]})
    if rc != 0:
        last = out.strip().splitlines()[-1] if out.strip() else "(출력 없음)"
        return f"PMU 응답 확인(pmu_4_1.py {' '.join(stage['command'].split()[-2:])}) 실패: rc={rc}, {last}"
    return ""


def target_pmu_problem(pmu: dict) -> str:
    """Start-of-run check for pmu.run_on=target, the fuzzer's setup: this PC
    -> SSH -> test PC -> PMU board (pmu_ip.json holds an address on the test
    PC's network, which this PC may not reach - measured: run from Windows,
    the board command timed out). Copies pmu_4_1.py and pmu_ip.json from the
    project folder to the target when `upload_from` is set, then runs the
    read-only current measurement there as root, as the power cycle will.
    "" when usable, else why not (a missing paramiko on the test PC shows here)."""
    from tc_system.execution.host_actions import PMU_CALL_TIMEOUT_SEC, pmu_files_problem, target_pmu_call
    target = config.get_ssh_target()
    record = {"timestamp": datetime.now(timezone.utc).isoformat(), "pmu_check": True, "stages": []}
    ip_name = pmu.get("ip_file", "pmu_ip.json")
    try:
        if pmu.get("upload_from"):
            local = Path(pmu["upload_from"])
            problem = pmu_files_problem(local, ip_name)
            if problem:
                return problem
            folder, _, name = pmu["script"].rpartition("/")
            for src, dest in ((local, name), (local.with_name(ip_name), ip_name)):
                command = (f"mkdir -p {shlex.quote(folder)} && cat > {shlex.quote(folder + '/' + dest)} "
                           "&& echo PMU_UPLOADED")
                proc, stage = _timed_plink(target, command, f"pmu_upload_{dest}", stdin=src.read_bytes(),
                                           timeout=30)
                record["stages"].append(stage)
                if proc.returncode != 0:
                    return f"대상 호스트로 {dest} 복사 실패(rc={proc.returncode})"
        call = target_pmu_call(pmu, "current")
        if "'" in call:
            return f"PMU 스크립트 경로에 작은따옴표를 쓸 수 없음: {pmu['script']}"
        proc, stage = _timed_plink(target, f"sudo -S bash -c '{call}' 2>&1", "pmu_check",
                                   stdin=target["password"] + "\n", timeout=PMU_CALL_TIMEOUT_SEC + 15)
        record["stages"].append(stage)
        out = (proc.stdout or "").strip()
        record["output"] = out[-500:]
        if proc.returncode != 0:
            last = out.splitlines()[-1] if out else "(출력 없음)"
            why = f" - {PMU_CALL_TIMEOUT_SEC}초 안에 끝나지 않음" if proc.returncode in (124, None) else ""
            return (f"대상 호스트에서 PMU 응답 확인({pmu['script']} 3 {pmu.get('dev_idx', 1)}) 실패: "
                    f"rc={proc.returncode}{why}, {last}")
        return ""
    finally:
        _append_ssh_log(record)


def _local_power_cycle(nvme_ctrl: str, pmu: dict, target: dict, log_record: dict) -> dict:
    """The fuzzer's POR with the PMU board driven from this PC: locate the PCIe
    address (target) -> power OFF (PMU) -> PCIe remove (target) -> discharge
    wait -> power ON (PMU) -> rescan + id-ctrl until it answers (target).
    Exit codes as on the target-host path: 96 OFF failed (powered back on),
    97 ON failed, 98 the drive never came back."""
    from tc_system.execution import host_actions as ha
    _, _, off_wait, rescan_delay, boot_wait = ha.pmu_timing(pmu)
    password = target["password"] + "\n"
    out, commands = [], []
    log_record["step_commands"] = commands

    def remote(body, stage_name, timeout):
        command = f"sudo -S bash -c '{body}' 2>&1"
        if "'" in body:
            raise ValueError("host action script must not contain a single quote")
        commands.append(command)
        proc, stage = _timed_plink(target, command, stage_name, stdin=password, timeout=timeout)
        log_record["stages"].append(stage)
        out.append((proc.stdout or "").strip())
        return proc

    def pmu_cmd(what):
        rc, text, stage = _run_local_pmu(pmu, what)
        commands.append(stage["command"])
        log_record["stages"].append(stage)
        out.append(text)
        return rc

    def result(code, timed_out=False):
        return {"exit_code": code, "stdout": "\n".join(o for o in out if o), "batch_stderr": "",
                "timed_out": timed_out}

    located = remote(ha.pcie_locate_script(nvme_ctrl), "host_power_cycle_locate", 30)
    bdf = ha.pcie_remove_target(pmu.get("remove", "endpoint"), located.stdout or "")
    off = pmu_cmd("off")
    out.append(f"POWER_OFF_RC={off}")
    if off != 0:
        # No power loss happened: power back on in case it half worked, and
        # stop with a PMU error so nothing after it is judged.
        pmu_cmd("on")
        return result(96)
    try:
        if bdf:
            remote(ha.pcie_remove_command(bdf), "host_power_cycle_remove", 30)
        time.sleep(off_wait)
        on = pmu_cmd("on")
    except BaseException:
        # Ctrl+C in the discharge wait, an SSH error on the remove: the drive
        # must not be left without power (review: interrupted after OFF, no ON).
        out.append("POWER_ON_AFTER_INTERRUPT")
        try:
            pmu_cmd("on")
        except BaseException:  # noqa: BLE001 - the original interruption is what the caller sees
            pass
        raise
    out.append(f"POWER_ON_RC={on}")
    if on != 0:
        return result(97)
    time.sleep(rescan_delay)
    ready = remote(ha.wait_ready_script(nvme_ctrl, boot_wait), "host_power_cycle_ready", boot_wait + 30)
    return result(ready.returncode, timed_out=ready.returncode is None)


def capture_dmesg(tc_id=None, attempt_id=None) -> str:
    """One `dmesg -T` dump, logged like a batch stage. The step-by-step
    contract executor calls this once after its last step instead of once per
    step (each SSH round trip is a separate plink connection)."""
    target = config.get_ssh_target()
    log_record = {"timestamp": datetime.now(timezone.utc).isoformat(), "n_steps": 0, "stages": [],
                  "tc_id": tc_id, "attempt_id": attempt_id}
    try:
        dump_proc, stage = _timed_plink(target, "sudo -S dmesg -T", "dmesg_dump",
                                         stdin=target["password"] + "\n")
        log_record["stages"].append(stage)
        return dump_proc.stdout
    finally:
        _append_ssh_log(log_record)


def clear_dmesg(tc_id=None, attempt_id=None) -> bool:
    """`dmesg -c` before a TC's first action of any kind (host or NVMe), so
    the dump afterwards is scoped to this TC. Returns whether it worked."""
    target = config.get_ssh_target()
    log_record = {"timestamp": datetime.now(timezone.utc).isoformat(), "n_steps": 0, "stages": [],
                  "tc_id": tc_id, "attempt_id": attempt_id}
    try:
        proc, stage = _timed_plink(target, "sudo -S dmesg -c > /dev/null", "dmesg_clear",
                                   stdin=target["password"] + "\n")
        log_record["stages"].append(stage)
        return proc.returncode == 0
    finally:
        _append_ssh_log(log_record)


def execute_tc_steps(steps: list[dict], allow_destructive: bool = False,
                     tc_id=None, attempt_id=None, step_index: int | None = None,
                     clear_dmesg: bool = True, dump_dmesg: bool = True) -> dict:
    """`step_index` is logged for a single step sent on its own (contract
    executor). With `clear_dmesg=False` the dmesg scope is the caller's
    (`clear_ok`/`dmesg_captured_scoped` are None); with `dump_dmesg=False`
    `dmesg_text` is empty and the caller dumps once itself."""
    # Last gate before the wire. Both flags must be checked: the two commands
    # that can leave the drive unbootable — Firmware Commit 0x10 and Firmware
    # Image Download 0x11 — carry firmware_state=True but destructive=False,
    # so a gate reading only `destructive` let exactly them through while
    # blocking the merely data-destructive ones.
    if not allow_destructive:
        blocked = [s for s in steps if s.get("destructive") or s.get("firmware_state")]
        if blocked:
            def _describe(step):
                kind = "firmware-state" if step.get("firmware_state") else "data-destructive"
                return f"opcode {step.get('opcode', '?')} ({kind}) on {step.get('device', '?')}"
            raise DestructiveStepBlocked(
                "refusing " + ", ".join(_describe(s) for s in blocked)
                + " — omit --no-destructive to permit these"
            )

    step_commands = [passthru_cmd(step) for step in steps]  # Validate before any remote call.
    target = config.get_ssh_target()
    log_record = {"timestamp": datetime.now(timezone.utc).isoformat(), "n_steps": len(steps), "stages": [],
                  "tc_id": tc_id, "attempt_id": attempt_id, "step_index": step_index}

    try:
        clear_ok = None
        if clear_dmesg:
            clear_proc, stage = _timed_plink(target, "sudo -S dmesg -c > /dev/null", "dmesg_clear",
                                              stdin=target["password"] + "\n")
            log_record["stages"].append(stage)
            clear_ok = clear_proc.returncode == 0

        log_record["step_commands"] = step_commands

        lines = []
        for i, cmd in enumerate(step_commands):
            lines.append(f"echo {STEP_DELIM}{i}")
            # nvme-cli writes everything diagnostic ("NVMe status: INVALID_FIELD...",
            # "Admin Command ... is Success") to stderr and leaves stdout empty, so
            # each command's stderr is folded into its own delimited stdout block.
            # Without this the harness captures only the exit code and the judge gets
            # no diagnostic text at all. `$?` still reports the command's status.
            lines.append(f"{cmd} 2>&1")
            lines.append("echo EXIT_CODE:$?")
        # nvme-cli's `--write` with no `--input-file` reads the buffer to send
        # from stdin ("default stdin" per its own --help) — without this, the
        # remote shell's stdin is whatever plink forwards from this local
        # process (an attached terminal, which never sends anything or EOFs),
        # so a write step just blocks until the timeout below kills the whole
        # batch. Measured: a 4-step chain with one Write step took the full
        # 120s twice in a row (one retry) instead of the few seconds every
        # other step took. One shared stdin stream feeds the whole batch
        # script in order, so each write step consumes exactly its own
        # data_len bytes; non-write steps read nothing.
        from tc_system.verification import payload_for_step
        write_payload = b"".join(
            payload_for_step(step) for step in steps
            if step.get("direction") == "write" and step.get("data_len")
        )
        batch_proc, stage = _timed_plink(target, "\n".join(lines), "batch", stdin=write_payload,
                                          timeout=SECONDS_PER_STEP * len(steps))
        log_record["stages"].append(stage)

        dmesg_text = ""
        if dump_dmesg:
            dump_proc, stage = _timed_plink(target, "sudo -S dmesg -T", "dmesg_dump",
                                             stdin=target["password"] + "\n")
            log_record["stages"].append(stage)
            dmesg_text = dump_proc.stdout

        return {
            "step_results": _parse_batch_output(batch_proc.stdout, len(steps)),
            "dmesg_text": dmesg_text,
            "batch_stderr": batch_proc.stderr,
            "clear_ok": clear_ok,
            # When the pre-batch `dmesg -c` fails (it needs the sudo password, which
            # is NOT covered by the NOPASSWD rule), the dump below is the whole boot
            # history instead of just this batch — callers must not read its signal
            # counts as "caused by this TC".
            "dmesg_captured_scoped": clear_ok,
            "timed_out": batch_proc.returncode is None,
        }
    finally:
        # Always written, even on an exception mid-batch — a hang that never
        # reaches the `return` is exactly the case where knowing which stage
        # it hung in (and the exact command sent) matters most.
        _append_ssh_log(log_record)
