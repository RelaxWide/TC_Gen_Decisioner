"""Builds the executable TCRecord from a resolved step plan.

Command dword values come from `args_author.author_args`, which derives them
from the specification text. When authoring fails the step falls back to the
old placeholder shape and is marked `args_source="placeholder"`, which keeps
`tc_system.pipeline`'s guard engaged and excludes the record from coverage —
an un-authored probe (`cdw10=0`) is a reserved field value for most commands
and its failure says nothing about the drive.

A TC can now be a chain of steps, not just one. `resolved_steps` is a list of
`{"section": <section dict>, "opcode_entry": <opcode dict>, "phase":
"setup"|"action"|"verify", "role": <str>}`, in execution order, with exactly
one `phase=="action"` entry — the target `pick_next_targets` actually picked,
and the only step the TC's name/Expectation text is built from, regardless of
how many setup/verify steps surround it.
"""
import re

from tc_system.generation.args_author import ArgsAuthoringError, author_args

PLACEHOLDER_ARGS = "placeholder"
AUTHORED_ARGS = "authored"

_NSID_FROM_PATH_RE = re.compile(r"n(\d+)$")


def namespace_id_from_device_path(nvme_ns: str) -> int:
    """`nvme_ns` (e.g. "/dev/nvme0n1") names the one namespace this harness
    is configured to test — the authoritative source for the single active
    namespace id, not an assumption. Hardcoding 1 here (as this once did)
    broke targets with any other namespace id."""
    match = _NSID_FROM_PATH_RE.search(nvme_ns)
    if not match:
        raise ValueError(f"cannot derive a namespace id from device path {nvme_ns!r}")
    return int(match.group(1))


def _command_step(section: dict, opcode_entry: dict, nvme_ctrl: str, nvme_ns: str, active_nsid: int,
                   phase: str | None = None, role: str | None = None,
                   prior_steps: list[dict] | None = None, rejected: dict | None = None,
                   device_facts: str | None = None) -> dict:
    is_admin = opcode_entry["command_set"] == "ADMIN"
    step = {
        # Carried purely for display (run_tc_pipeline.py names each step by
        # its real command instead of a bare opcode, and shows which role it
        # plays in the chain) — nothing downstream of here reads these back.
        "name": opcode_entry["name"],
        "phase": phase,
        "role": role,
        "mode": "admin-passthru" if is_admin else "io-passthru",
        "device": nvme_ctrl if is_admin else nvme_ns,
        "opcode": opcode_entry["raw_opcode"],
        # Only the placeholder default — author_args decides the real value
        # per command below. I/O commands are namespace-scoped by
        # definition, so active_nsid (not a hardcoded 1) is the only sound
        # default even before authoring succeeds.
        "nsid": 0 if is_admin else active_nsid,
        "cdw10": "0x00000000",
        "cdw11": "0x00000000",
        "cdw12": "0x00000000",
        "data_len": 0,
        "direction": "none",
        "destructive": opcode_entry.get("destructive", False),
        "firmware_state": opcode_entry.get("firmware_state", False),
        # Not read by the destructive gate (that's destructive/firmware_state
        # only) — this is what pipeline.py checks after a TC finishes to
        # decide whether to run a post-hoc device health check before moving
        # on to the next target (Lockdown/Security Send can make the
        # controller reject subsequent commands without removing the device
        # node the way Sanitize/Namespace Management can).
        "lockout_risk": opcode_entry.get("lockout_risk", False),
        "args_source": PLACEHOLDER_ARGS,
        "shared_facts": {},
        "field_value_verified": False,
    }
    try:
        authored = author_args(section, opcode_entry, active_nsid, prior_steps=prior_steps,
                                rejected=rejected, device_facts=device_facts,
                                required_field_values=section.get("field_values"))
    except ArgsAuthoringError as exc:
        step["args_error"] = str(exc)
        return step
    step.update({
        "cdw10": authored["cdw10"],
        "cdw11": authored["cdw11"],
        "cdw12": authored["cdw12"],
        "nsid": authored["nsid"],
        "data_len": authored["data_len"],
        "direction": authored["direction"],
        "args_source": AUTHORED_ARGS,
        # Explanatory only — the model has mislabelled a field name while still
        # emitting a valid value, so this is not a source of truth.
        "args_rationale": authored["field_breakdown"],
        "shared_facts": authored["shared_facts"],
        # Deterministically confirmed (not self-reported) that `section`'s
        # own required field value (e.g. a specific Log Page/Feature
        # Identifier) actually landed in CDW10 — expectation_checker uses
        # this to tell "this drive doesn't implement this specific value"
        # (a real finding) apart from "we authored a malformed argument".
        "field_value_verified": authored.get("field_value_verified", False),
    })
    return step


def _prior_steps_up_to(resolved_steps: list[dict], steps: list[dict], upto: int) -> list[dict]:
    return [
        {"step": j, "phase": resolved_steps[j]["phase"], "opcode_name": resolved_steps[j]["opcode_entry"]["name"],
         "facts": steps[j].get("shared_facts", {})}
        for j in range(upto)
    ]


def reauthor_steps(tc: dict, resolved_steps: list[dict], rejected: dict, active_nsid: int,
                    device_facts: str | None = None) -> list[dict]:
    """Rebuild the rejected step (`rejected["step_index"]`) *and every step
    after it*, keeping everything before it untouched. Rebuilding only the
    rejected step and leaving the rest alone would let them go stale: a later
    step may already have been authored assuming this step's shared_facts
    (e.g. the same LBA), and this step is about to pick different values. For
    a rejection on the chain's last step this degenerates to rebuilding just
    that one step — identical to the original single-step behavior."""
    i = rejected["step_index"]
    steps = list(tc["steps"])
    prior_steps = _prior_steps_up_to(resolved_steps, steps, i)
    for j in range(i, len(resolved_steps)):
        rs = resolved_steps[j]
        first = steps[j]
        rejection = {"step": first, "reason": rejected["reason"]} if j == i else None
        rebuilt = _command_step(rs["section"], rs["opcode_entry"], first["device"], first["device"], active_nsid,
                                 phase=rs["phase"], role=rs.get("role"),
                                 prior_steps=prior_steps, rejected=rejection, device_facts=device_facts)
        steps[j] = rebuilt
        prior_steps.append({"step": j, "phase": rs["phase"], "opcode_name": rs["opcode_entry"]["name"],
                             "facts": rebuilt.get("shared_facts", {})})
    return steps


def build_tc(tc_id: str, resolved_steps: list[dict], scenario: dict,
             nvme_ctrl: str, nvme_ns: str, active_nsid: int, device_facts: str | None = None) -> dict:
    from tc_system.models import make_tc_record

    action = next(rs for rs in resolved_steps if rs["phase"] == "action")
    name_suffix = action["section"]["section_id"].replace(":", "_").replace(".", "_")
    name = f"TC_{action['opcode_entry']['name'].replace(' ', '')}_{name_suffix}"

    steps: list[dict] = []
    for rs in resolved_steps:
        prior_steps = _prior_steps_up_to(resolved_steps, steps, len(steps))
        steps.append(_command_step(rs["section"], rs["opcode_entry"], nvme_ctrl, nvme_ns, active_nsid,
                                    phase=rs["phase"], role=rs.get("role"), prior_steps=prior_steps,
                                    device_facts=device_facts))

    if len(resolved_steps) == 1:
        expectation_description = (
            f"Opcode {action['opcode_entry']['raw_opcode']} ({action['opcode_entry']['name']}) "
            "completes without controller-reported error and within its timeout."
        )
        chain_summary = ""
    else:
        chain = " → ".join(f"{rs['opcode_entry']['raw_opcode']} ({rs['opcode_entry']['name']})"
                                 for rs in resolved_steps)
        expectation_description = (
            f"Command sequence {chain} completes without controller-reported error "
            "and within its timeout at each step."
        )
        chain_summary = scenario.get("chain_summary") or ""

    tc = make_tc_record(
        tc_id=tc_id,
        name=name,
        source_section_ids=list(dict.fromkeys(rs["section"]["section_id"] for rs in resolved_steps)),
        source_opcodes=list(dict.fromkeys(rs["opcode_entry"]["opcode"] for rs in resolved_steps)),
        generated_from={"rag_response_id": scenario["rag_response_id"],
                         "llm_response_id": scenario["llm_response_id"]},
        scenario={"description": scenario["description"], "preconditions": scenario["preconditions"]},
        expectation={
            "description": expectation_description,
            "fail_criteria": scenario["fail_criteria"] + ["nvme-cli exit code != 0", "command timeout exceeded"],
        },
        steps=steps,
        destructive=any(rs["opcode_entry"].get("destructive", False) for rs in resolved_steps),
        uses_placeholder_args=any(s.get("args_source") == PLACEHOLDER_ARGS for s in steps),
    )
    # Not deduped, unlike source_section_ids/source_opcodes above: coverage
    # pairs these index-for-index with per-step statuses, so a step that
    # repeats an earlier step's section/opcode still gets its own entry.
    tc["step_section_ids"] = [rs["section"]["section_id"] for rs in resolved_steps]
    tc["step_opcodes"] = [rs["opcode_entry"]["opcode"] for rs in resolved_steps]
    tc["chain_summary"] = chain_summary
    return tc
