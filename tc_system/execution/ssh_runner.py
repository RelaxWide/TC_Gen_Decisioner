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
import subprocess
import tempfile
import time
from datetime import datetime, timezone

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
    from tc_system.verification import payload_for_step, validate_fixed_fields
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


def _append_ssh_log(record: dict) -> None:
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
    for key, cmd in (
        ("id_ctrl", f"sudo nvme id-ctrl {nvme_ctrl}"),
        ("id_ns", f"sudo nvme id-ns {nvme_ns}"),
        ("effects_log", f"sudo nvme effects-log {nvme_ctrl}"),
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
