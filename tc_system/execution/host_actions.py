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
power on.
"""
import re
import shlex

# name shown to the scenario author -> action key
HOST_ACTIONS = {
    "Controller Reset": "controller_reset",
    "Power Cycle (PMU)": "power_cycle",
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


def host_action_entries(pmu: dict | None) -> list[dict]:
    """Pseudo opcode entries for `available_opcodes`. Power Cycle only when a
    PMU board is configured. A power cycle without shutdown notification is
    a sudden power loss, so it counts as destructive (--no-destructive)."""
    entries = [_entry("Controller Reset", "controller_reset", destructive=False)]
    if pmu:
        entries.append(_entry("Power Cycle (PMU)", "power_cycle", destructive=True))
    return entries


def _entry(name, action, destructive):
    return {"name": name, "host_action": action, "command_set": "HOST", "opcode": f"host:{action}",
            "raw_opcode": None, "section_ref": None, "destructive": destructive,
            "firmware_state": False, "lockout_risk": False, "risk_class": 2 if destructive else 1,
            "direction": "none"}


def _wait_ready(nvme_ctrl: str, seconds: int, rescan: bool) -> str:
    ctrl = shlex.quote(nvme_ctrl)
    rescan_cmd = "echo 1 > /sys/bus/pci/rescan 2>/dev/null; " if rescan else ""
    return (f"for i in $(seq 1 {int(seconds)}); do {rescan_cmd}"
            f"if nvme id-ctrl {ctrl} >/dev/null 2>&1; then echo READY_AFTER_SEC=$i; exit 0; fi; sleep 1; done; "
            f"echo NOT_READY_AFTER_SEC={int(seconds)}; exit 98")


def host_action_script(action: str, nvme_ctrl: str, pmu: dict | None) -> tuple[str, int]:
    """(shell script run as root on the target, timeout seconds)."""
    ctrl = shlex.quote(nvme_ctrl)
    if action == "controller_reset":
        return (f"nvme reset {ctrl}; rc=$?; echo RESET_RC=$rc; "
                f"[ $rc -eq 0 ] || exit $rc; " + _wait_ready(nvme_ctrl, 30, rescan=False)), 60
    if action == "power_cycle":
        if not pmu:
            raise ValueError("Power Cycle needs a PMU board configured (secrets.local.json \"pmu\")")
        script = shlex.quote(pmu["script"])
        dev, mv = int(pmu.get("dev_idx", 1)), int(pmu.get("voltage_mv", 3300))
        off_wait = float(pmu.get("poweroff_wait_sec", 3))
        rescan_delay = float(pmu.get("rescan_delay_sec", 10))
        boot_wait = int(pmu.get("boot_wait_sec", 30))
        # endpoint: the SSD itself; root: the topmost bridge above it (some
        # PMU boards only cycle cleanly that way); none: no remove at all.
        remove = pmu.get("remove", "endpoint")
        name = nvme_ctrl.rsplit("/", 1)[-1]
        locate = (f"P=$(readlink -f /sys/class/nvme/{shlex.quote(name)}/device); "
                  "EP=$(basename \"$P\"); ROOT=$(echo \"$P\" | cut -d/ -f5); ")
        target = {"endpoint": "$EP", "root": "$ROOT"}.get(remove)
        remove_cmd = (f"echo 1 > /sys/bus/pci/devices/{target}/remove 2>/dev/null; echo REMOVED={target}; "
                      if target else "")
        body = (locate
                # A failed OFF is no power loss: power back on in case it half
                # worked, and stop with a PMU error (not 98, which means the
                # drive never came back) so nothing after it is judged.
                + f"python3 {script} 7 {dev}; off=$?; echo POWER_OFF_RC=$off; "
                + f"if [ $off -ne 0 ]; then python3 {script} 4 {dev} {mv} 0 12000 0 0; exit 96; fi; "
                + remove_cmd
                + f"sleep {off_wait}; "
                + f"python3 {script} 4 {dev} {mv} 0 12000 0 0; rc=$?; echo POWER_ON_RC=$rc; "
                + "[ $rc -eq 0 ] || exit $rc; "
                + f"sleep {rescan_delay}; "
                + _wait_ready(nvme_ctrl, boot_wait, rescan=True))
        return body, int(off_wait + rescan_delay + boot_wait + 30)
    raise ValueError(f"unknown host action {action!r}")


def host_action_command(action: str, nvme_ctrl: str, pmu: dict | None) -> tuple[str, int]:
    """One root shell for the whole sequence: the sudo password is read once
    from stdin. The script contains no single quote, so it nests safely."""
    body, timeout = host_action_script(action, nvme_ctrl, pmu)
    if "'" in body:
        raise ValueError("host action script must not contain a single quote")
    return f"sudo -S bash -c '{body}' 2>&1", timeout
