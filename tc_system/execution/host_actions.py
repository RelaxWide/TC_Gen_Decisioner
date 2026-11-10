"""Host-side steps a test chain can use besides NVMe commands: a controller
reset and, with a PMU board, a full power cycle.

They let requirements about state across a reset or a power loss be tested
(a saved feature after power-on, written data after a power cycle, a feature
returning to its default after a reset). They are setup/verify steps only:
never a target, never authored by the LLM (fixed shell, no LLM-written
values), and run on the target host over the same SSH connection as nvme-cli.

The power-cycle sequence follows the PC-sampling fuzzer's POR
(pc_sampling_fuzzer_v11.5.py `_power_cycle_ssd` / `_por_pcie_rescan`):
power OFF first, then remove the PCIe device (a live link removed first
broke re-enumeration behind some bridges), discharge wait, power ON, then
rescan + `nvme id-ctrl` until the controller answers or the boot wait ends.
PMU commands: `<script> 7 <dev>` power off, `<script> 4 <dev> <mV> 0 12000 0 0`
power on, `<script> 3 <dev>` read the current (read-only, used as the
start-of-run check).

Where the PMU script runs (`pmu.run_on`):
- "target" (default): on the target host (the test PC) as root, like the
  fuzzer - the board is on the test PC's network (its IP is in pmu_ip.json),
  not necessarily reachable from the PC running this pipeline. The files are
  kept in this project folder and copied to the target at the start of each
  run (`ssh_runner.target_pmu_problem`). Each PMU call runs in the script's
  folder (so it finds pmu_ip.json) under `timeout`, like the fuzzer's 5 s/10 s.
- "local": on the PC that runs this pipeline, when the board is reachable from
  it; only the PCIe remove/rescan and the readiness wait go to the target
  (`ssh_runner._local_power_cycle`).
"""
import re
import shlex
import sys
from pathlib import Path

# name shown to the scenario author -> action key
HOST_ACTIONS = {
    "Controller Reset": "controller_reset",
    "Power Cycle (PMU)": "power_cycle",
    "Firmware Image Download (full image)": "firmware_download",
}

# A requirement about state across a reset or a power loss is only tested by a
# chain that performs one. Matched narrowly, on "<across|after|on|...> <event>"
# and "<event> occurs": the words alone are not enough (measured on the spec:
# "Power Loss Signaling mode not supported -> abort", "This Feature shall be
# saveable", "Write Protect Until Power Cycle state" need no host step).
_EVENT = (r"(?:power[- ]cycles?|power[- ]on|(?:sudden |unexpected )?power loss"
          r"|(?:Controller Level |Controller |Conventional )?Resets?|CLRs?)\b")
_ACROSS_EVENT = re.compile(
    r"\b(?:across|through|after|following|upon|on|at the next|since the last|by)\s+"
    r"(?:(?:all|any|a|an|the|each|every)\s+)?(?:(?:other\s+)?types? of\s+)?(?:power states and\s+)?"
    r"(?:(?:that|this)\s+)?" + _EVENT + r"(?:\s+(?:and|or)\s+" + _EVENT + r")?", re.I)
_EVENT_OCCURS = re.compile(r"\b" + _EVENT + r"\)?\s+occurs", re.I)


def required_host_actions(text: str) -> list[str]:
    """Host actions that can perform the event a requirement sentence is
    about: a power cycle for a power loss, either one for a reset (a power
    cycle is a reset too). Empty when the sentence is not about such an event."""
    hits = " ".join(m.group(0) for m in [*_ACROSS_EVENT.finditer(text), *_EVENT_OCCURS.finditer(text)]).lower()
    if not hits:
        return []
    actions = set()
    if re.search(r"power[- ](?:cycle|on)|power loss", hits):
        actions.add("power_cycle")
    if re.search(r"reset|\bclr", hits):
        actions |= {"controller_reset", "power_cycle"}
    return sorted(actions)


def usable_host_steps(target: dict, available_opcodes: list[dict], allow_destructive: bool) -> list[str] | None:
    """Names of the host steps this run can use for a target that needs one
    (None when it needs none). Empty: the target cannot be tested in this run
    (no PMU configured, or the power cycle is blocked by --no-destructive)."""
    needed = set(target.get("host_actions") or [])
    if not needed:
        return None
    return [o["name"] for o in available_opcodes
            if o.get("host_action") in needed and (allow_destructive or not o.get("destructive"))]


def host_action_entries(pmu: dict | None, firmware: dict | None = None) -> list[dict]:
    """Pseudo opcode entries for `available_opcodes`. Power Cycle only when a
    PMU board is configured. A power cycle without shutdown notification is
    a sudden power loss, so it counts as destructive (--no-destructive). The
    full-image download only when a real image is configured and on the
    target; it changes firmware state (--no-destructive blocks it)."""
    entries = [_entry("Controller Reset", "controller_reset", destructive=False)]
    if pmu:
        entries.append(_entry("Power Cycle (PMU)", "power_cycle", destructive=True))
    if firmware:
        entries.append(_entry("Firmware Image Download (full image)", "firmware_download", destructive=False,
                              firmware_state=True))
    return entries


def _entry(name, action, destructive, firmware_state=False):
    return {"name": name, "host_action": action, "command_set": "HOST", "opcode": f"host:{action}",
            "raw_opcode": None, "section_ref": None, "destructive": destructive,
            "firmware_state": firmware_state, "lockout_risk": False,
            "risk_class": 2 if destructive or firmware_state else 1, "direction": "none"}


def pmu_runs_locally(pmu: dict | None) -> bool:
    return bool(pmu) and pmu.get("run_on", "target") == "local"


PMU_CALL_TIMEOUT_SEC = 20  # one board command; the fuzzer allows 5 s (OFF) / 10 s (ON)


def target_pmu_call(pmu: dict, what: str) -> str:
    """Shell for one PMU board command on the target host: in the script's
    folder (pmu_ip.json beside it) and bounded, so an unreachable board is a
    PMU error, not a hang until the whole host step times out."""
    folder, _, name = str(pmu["script"]).rpartition("/")
    return (f"(cd {shlex.quote(folder or '.')} && timeout {PMU_CALL_TIMEOUT_SEC} python3 {shlex.quote(name)} "
            + " ".join(pmu_args(pmu, what)) + ")")


def pmu_timing(pmu: dict) -> tuple[int, int, float, float, int]:
    """(dev_idx, mV, power-off wait, rescan delay, boot wait); defaults are
    the fuzzer's (fuzzer_config.json power.por_*)."""
    return (int(pmu.get("dev_idx", 1)), int(pmu.get("voltage_mv", 3300)),
            float(pmu.get("poweroff_wait_sec", 3)), float(pmu.get("rescan_delay_sec", 10)),
            int(pmu.get("boot_wait_sec", 30)))


def pmu_args(pmu: dict, what: str) -> list[str]:
    dev, mv = pmu_timing(pmu)[:2]
    return {"off": ["7", str(dev)], "on": ["4", str(dev), str(mv), "0", "12000", "0", "0"],
            "current": ["3", str(dev)]}[what]


def local_pmu_argv(pmu: dict, what: str) -> list[str]:
    """argv for the PMU script on this PC: the interpreter running the
    pipeline unless `pmu.python` names another one."""
    return [pmu.get("python") or sys.executable, str(pmu["script"]), *pmu_args(pmu, what)]


def pmu_files_problem(script: str | Path, ip_name: str = "pmu_ip.json") -> str:
    """Why the PMU files on this PC are not usable, or "". pmu_ip.json sits
    next to the script (the script runs with that folder as its working
    directory)."""
    script = Path(script)
    if not script.is_file():
        return f"{script} 없음"
    if not script.with_name(ip_name).is_file():
        return f"{script.with_name(ip_name)} 없음(PMU IP 파일, pmu_4_1.py와 같은 폴더)"
    return ""


def local_pmu_files_problem(pmu: dict) -> str:
    return pmu_files_problem(pmu["script"], pmu.get("ip_file", "pmu_ip.json"))


_BDF_RE = re.compile(r"^[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]$")


def pcie_locate_script(nvme_ctrl: str) -> str:
    """Sets EP (the SSD) and ROOT (the topmost bridge above it) and prints
    them. Run while the drive is still powered: after power off it can be gone
    from sysfs."""
    name = nvme_ctrl.rsplit("/", 1)[-1]
    return (f"P=$(readlink -f /sys/class/nvme/{shlex.quote(name)}/device); "
            "EP=$(basename \"$P\"); ROOT=$(echo \"$P\" | cut -d/ -f5); echo PCIE_EP=$EP PCIE_ROOT=$ROOT; ")


def pcie_remove_target(remove: str, located: str) -> str | None:
    """The BDF to remove from `pcie_locate_script` output: the SSD (endpoint),
    the topmost bridge (root, the fuzzer's auto-root for P9/P7 PMU boards), or
    None (remove="none", or nothing usable was found)."""
    key = {"endpoint": "PCIE_EP", "root": "PCIE_ROOT"}.get(remove)
    m = key and re.search(key + r"=(\S+)", located or "")
    return m.group(1) if m and _BDF_RE.match(m.group(1)) else None


def pcie_remove_command(bdf: str) -> str:
    if not _BDF_RE.match(bdf):
        raise ValueError(f"not a PCIe address: {bdf!r}")
    return f"echo 1 > /sys/bus/pci/devices/{bdf}/remove 2>/dev/null; echo REMOVED={bdf}"


def wait_ready_script(nvme_ctrl: str, seconds: int) -> str:
    """Rescan + `nvme id-ctrl` until the controller answers (exit 98 if not)."""
    return _wait_ready(nvme_ctrl, seconds, rescan=True)


def _wait_ready(nvme_ctrl: str, seconds: int, rescan: bool) -> str:
    ctrl = shlex.quote(nvme_ctrl)
    rescan_cmd = "echo 1 > /sys/bus/pci/rescan 2>/dev/null; " if rescan else ""
    return (f"for i in $(seq 1 {int(seconds)}); do {rescan_cmd}"
            f"if nvme id-ctrl {ctrl} >/dev/null 2>&1; then echo READY_AFTER_SEC=$i; exit 0; fi; sleep 1; done; "
            f"echo NOT_READY_AFTER_SEC={int(seconds)}; exit 98")


def host_action_script(action: str, nvme_ctrl: str, pmu: dict | None,
                       firmware: dict | None = None) -> tuple[str, int]:
    """(shell script run as root on the target, timeout seconds)."""
    ctrl = shlex.quote(nvme_ctrl)
    if action == "firmware_download":
        # The whole configured image, in chunks nvme-cli sizes (or xfer_bytes),
        # from the copy made at the start of the run. Firmware Commit can then
        # act on a complete, real image instead of a dummy.
        if not firmware:
            raise ValueError("Firmware Image Download (full image) needs secrets.local.json firmware.image")
        xfer = f" --xfer={int(firmware['xfer_bytes'])}" if firmware.get("xfer_bytes") else ""
        return (f"nvme fw-download {ctrl} --fw={shlex.quote(firmware['remote'])}{xfer}; rc=$?; "
                "echo FW_DOWNLOAD_RC=$rc; exit $rc"), 120 + int(firmware.get("size", 0)) // (1 << 20) * 10
    if action == "controller_reset":
        return (f"nvme reset {ctrl}; rc=$?; echo RESET_RC=$rc; "
                f"[ $rc -eq 0 ] || exit $rc; " + _wait_ready(nvme_ctrl, 30, rescan=False)), 60
    if action == "power_cycle":
        if not pmu:
            raise ValueError("Power Cycle needs a PMU board configured (secrets.local.json \"pmu\")")
        if pmu_runs_locally(pmu):
            raise ValueError("pmu.run_on=local: the power cycle runs from this PC (ssh_runner.run_host_action)")
        _, _, off_wait, rescan_delay, boot_wait = pmu_timing(pmu)
        off, on = target_pmu_call(pmu, "off"), target_pmu_call(pmu, "on")
        # endpoint: the SSD itself; root: the topmost bridge above it (some
        # PMU boards only cycle cleanly that way); none: no remove at all.
        target = {"endpoint": "$EP", "root": "$ROOT"}.get(pmu.get("remove", "endpoint"))
        remove_cmd = (f"echo 1 > /sys/bus/pci/devices/{target}/remove 2>/dev/null; echo REMOVED={target}; "
                      if target else "")
        body = (pcie_locate_script(nvme_ctrl)
                # Interrupted between OFF and ON (Ctrl+C kills plink, the
                # session closes, bash gets HUP): power back on before exiting.
                + f"trap \"{on}; exit 95\" HUP INT TERM; "
                # A failed OFF is no power loss: power back on in case it half
                # worked, and stop with a PMU error (not 98, which means the
                # drive never came back) so nothing after it is judged.
                + f"{off}; off=$?; echo POWER_OFF_RC=$off; "
                + f"if [ $off -ne 0 ]; then {on}; exit 96; fi; "
                + remove_cmd
                + f"sleep {off_wait}; "
                + f"{on}; rc=$?; echo POWER_ON_RC=$rc; trap - HUP INT TERM; "
                + "[ $rc -eq 0 ] || exit $rc; "
                + f"sleep {rescan_delay}; "
                + _wait_ready(nvme_ctrl, boot_wait, rescan=True))
        return body, int(off_wait + rescan_delay + boot_wait + 30)
    raise ValueError(f"unknown host action {action!r}")


def host_action_command(action: str, nvme_ctrl: str, pmu: dict | None,
                        firmware: dict | None = None) -> tuple[str, int]:
    """One root shell for the whole sequence: the sudo password is read once
    from stdin. The script contains no single quote, so it nests safely."""
    body, timeout = host_action_script(action, nvme_ctrl, pmu, firmware)
    if "'" in body:
        raise ValueError("host action script must not contain a single quote")
    return f"sudo -S bash -c '{body}' 2>&1", timeout
