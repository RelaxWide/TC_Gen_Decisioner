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
from copy import deepcopy

from tc_system import spec_fields
from tc_system.verification import (VERSION, integer, payload_for_step, pinned_value, required_selector_masks,
                                    validate_fixed_fields)

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


def _selector_support(opcode_entry: dict, step: dict, device_support: dict | None):
    """True/False when the start-of-run probe knows whether this FID/LID is
    supported, else None. Lets a rejection of an unsupported FID be read as
    "this drive lacks the feature" instead of "our arguments were wrong"."""
    if not device_support or opcode_entry.get("command_set") != "ADMIN" or opcode_entry.get("host_action"):
        return None
    raw, selector = int(opcode_entry["raw_opcode"], 16), integer(step["cdw10"]) & 0xFF
    if raw in (0x09, 0x0A):
        return (device_support.get("fids") or {}).get(selector)
    if raw == 0x02:
        return (device_support.get("lids") or {}).get(selector)
    return None


def _standard_identify(opcode_entry: dict, phase, test_intent: dict | None, active_nsid: int):
    """Identify Controller / Namespace as a setup or verify step, built by
    code: always the same fields (measured: Identify CNS 01h was authored 93
    times and CNS 00h 15 times in one --all run, one LLM call each)."""
    if phase == "action" or opcode_entry.get("command_set") != "ADMIN" or int(opcode_entry["raw_opcode"], 16) != 0x06:
        return None
    constraints = (test_intent or {}).get("field_constraints") or []
    cns = pinned_value(constraints, "cdw10", 0xFF)
    others = [c for c in constraints if not (c["field"] == "cdw10" and integer(c["mask"]) & ~0xFF == 0)]
    if cns not in (0x00, 0x01) or others or (test_intent or {}).get("expected_status", "SUCCESS") != "SUCCESS":
        return None
    return {"cdw10": f"0x{cns:08X}", "nsid": active_nsid if cns == 0x00 else 0, "data_len": 4096, "direction": "read",
            "args_rationale": "하네스가 직접 만든 표준 Identify " + ("Namespace(CNS 00h)" if cns == 0 else "Controller(CNS 01h)")
                              + " — LLM 호출 없음"}


def _command_step(section: dict, opcode_entry: dict, nvme_ctrl: str, nvme_ns: str, active_nsid: int,
                   phase: str | None = None, role: str | None = None,
                   prior_steps: list[dict] | None = None, rejected: dict | None = None,
                   device_facts: str | None = None, test_intent: dict | None = None,
                   device_support: dict | None = None) -> dict:
    if opcode_entry.get("host_action"):
        return _host_step(opcode_entry, nvme_ctrl, phase, role, test_intent)
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
        "cdw13": "0x00000000", "cdw14": "0x00000000", "cdw15": "0x00000000",
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
        "test_intent": test_intent or {},
        "field_constraints": (test_intent or {}).get("field_constraints", []),
        "expected_status": (test_intent or {}).get("expected_status", "SUCCESS"),
        "payload_hex": (test_intent or {}).get("payload_hex"),
        "lba_bytes": (test_intent or {}).get("lba_bytes"),
    }
    if is_admin and str(opcode_entry.get("raw_opcode", "")).lower() == "0x11" and (test_intent or {}).get("firmware_image"):
        # A real image is configured: the step sends its bytes at OFST, not a
        # pattern (2026-11-10: zero-filled downloads made every Commit that
        # needed an image a rejection, judged as the drive's failure).
        step["firmware_image"] = test_intent["firmware_image"]
        step["payload_hex"] = None
        # The scenario's pattern is not sent, so it is not checked either.
        test_intent = step["test_intent"] = dict(test_intent, payload_hex=None)
    standard = None if rejected else _standard_identify(opcode_entry, phase, test_intent, active_nsid)
    if standard:
        step.update(standard, args_source=AUTHORED_ARGS, harness_built=True, shared_facts={},
                    field_value_verified=False)
        if phase != "action":
            freeze_selectors(step, opcode_entry)
        return step
    try:
        authored = author_args(section, opcode_entry, active_nsid, prior_steps=prior_steps,
                                rejected=rejected, device_facts=device_facts,
                                required_field_values=section.get("field_values"), test_intent=test_intent)
    except ArgsAuthoringError as exc:
        step["args_error"] = str(exc)
        return step
    step.update({
        "cdw10": authored["cdw10"],
        "cdw11": authored["cdw11"],
        "cdw12": authored["cdw12"],
        **{f"cdw{i}": authored.get(f"cdw{i}", "0x00000000") for i in range(13, 16)},
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
        "args_llm_response_id": authored.get("llm_response_id"),
        # Bits the harness wrote over the author's reply (scenario field_constraints).
        "constraint_overrides": authored.get("constraint_overrides", []),
        # Length/direction fields the harness computed from the spec (derive_transfer).
        "derived_fields": authored.get("derived_fields", []),
    })
    try:
        validate_fixed_fields(step, step["field_constraints"])
        payload_for_step(step)  # Reject a promised payload that does not fit the buffer.
    except ValueError as exc:
        # Same outcome as an authoring failure (author_args checks both first),
        # so the retry log names the real reason instead of an "LLM failure".
        step["args_source"] = PLACEHOLDER_ARGS
        step["args_error"] = str(exc)
        return step
    if phase != "action":
        freeze_selectors(step, opcode_entry)
    _freeze_feature_instance(step, opcode_entry)
    step["selector_support"] = _selector_support(opcode_entry, step, device_support)
    return step


def _freeze_feature_instance(step: dict, opcode_entry: dict) -> None:
    """Get/Set Features: the restore identity - instance bits in CDW11
    (temperature sensor/threshold, interrupt vector, EXHID), and for Set the
    SV bit and, per namespace, the NSID - is pinned from the first authoring,
    for every phase. A retry that changed any of them made the saved original
    value and its restore point at something else (review: NSID 1 -> FFFFFFFFh
    changed two namespaces and restored one; SV 0 -> 1 changed the saved value
    and restored only the current one)."""
    if opcode_entry.get("command_set") != "ADMIN" or int(opcode_entry["raw_opcode"], 16) not in (0x09, 0x0A):
        return
    raw, fid = int(opcode_entry["raw_opcode"], 16), integer(step["cdw10"]) & 0xFF
    codec = spec_fields.FEATURE_CODECS.get(fid) or {}
    wanted = {"cdw11": codec.get("instance", 0)}
    if raw == 0x09:
        wanted["cdw10"] = 0x80000000  # SV
        if codec.get("ns"):
            wanted["nsid"] = 0xFFFFFFFF
    constraints = list(step.get("field_constraints") or [])
    fixed = {}
    for c in constraints:
        fixed[c["field"]] = fixed.get(c["field"], 0) | integer(c["mask"])
    added = []
    for field, mask in wanted.items():
        open_bits = mask & ~fixed.get(field, 0)
        if open_bits:
            added.append({"field": field, "mask": hex(open_bits), "value": hex(integer(step[field]) & open_bits),
                          "frozen_from_first_authoring": True})
    if added:
        step["field_constraints"] = constraints + added
        step["test_intent"] = dict(step.get("test_intent") or {}, field_constraints=step["field_constraints"])


def freeze_selectors(step: dict, opcode_entry: dict) -> None:
    """Pin a setup/verify step's selector/address fields to the values it was
    first authored with, when the scenario did not fix them. Stored in both the
    step and its test_intent, which a reauthor reuses, so a retry keeps e.g. the
    same Identify CNS a precondition check reads from."""
    constraints = list(step.get("field_constraints") or [])
    fixed = {}
    for c in constraints:
        fixed[c["field"]] = fixed.get(c["field"], 0) | integer(c["mask"])
    added = []
    for field, mask in required_selector_masks(opcode_entry).items():
        open_bits = mask & ~fixed.get(field, 0)
        if open_bits:
            added.append({"field": field, "mask": hex(open_bits), "value": hex(integer(step[field]) & open_bits),
                          "frozen_from_first_authoring": True})
    if added:
        step["field_constraints"] = constraints + added
        step["test_intent"] = dict(step.get("test_intent") or {}, field_constraints=step["field_constraints"])


def _host_step(opcode_entry: dict, nvme_ctrl: str, phase, role, test_intent) -> dict:
    """Controller reset / power cycle: a fixed host script, nothing to author."""
    zero = "0x00000000"
    return {"name": opcode_entry["name"], "phase": phase, "role": role, "mode": "host",
            "host_action": opcode_entry["host_action"], "device": nvme_ctrl, "opcode": opcode_entry["opcode"],
            "nsid": 0, **{f"cdw{i}": zero for i in range(10, 16)}, "data_len": 0, "direction": "none",
            "destructive": opcode_entry.get("destructive", False),
            "firmware_state": opcode_entry.get("firmware_state", False),
            "lockout_risk": False, "args_source": AUTHORED_ARGS, "shared_facts": {},
            "field_value_verified": False, "test_intent": test_intent or {}, "field_constraints": [],
            "expected_status": (test_intent or {}).get("expected_status", "SUCCESS"), "payload_hex": None,
            "firmware_image": ((test_intent or {}).get("firmware_image")
                               if opcode_entry["host_action"] == "firmware_download" else None)}


def _harness_step(name, raw, command_set, device, nsid, phase, role, harness, cdw10=0, cdw11=0, cdw12=0,
                  data_len=0, direction="none", destructive=False, lba_bytes=None, **extra):
    zero = "0x00000000"
    step = {"name": name, "phase": phase, "role": role,
            "mode": "admin-passthru" if command_set == "ADMIN" else "io-passthru",
            "device": device, "opcode": f"0x{raw:02X}", "nsid": nsid, "cdw10": f"0x{cdw10:08X}",
            "cdw11": f"0x{cdw11:08X}", "cdw12": f"0x{cdw12:08X}", "cdw13": zero, "cdw14": zero, "cdw15": zero,
            "data_len": data_len, "direction": direction, "destructive": destructive, "firmware_state": False,
            "lockout_risk": False, "args_source": AUTHORED_ARGS, "shared_facts": {}, "field_value_verified": False,
            "test_intent": {}, "field_constraints": [], "expected_status": "SUCCESS", "payload_hex": None,
            "lba_bytes": lba_bytes, "harness": harness}
    step.update(extra)
    return step


def restore_identity(step: dict) -> dict:
    """What a Set Features step changes: (FID, SV, namespace, instance)."""
    c10, c11 = integer(step["cdw10"]), integer(step["cdw11"])
    fid = c10 & 0xFF
    codec = spec_fields.FEATURE_CODECS.get(fid) or {}
    return {"fid": fid, "sv": bool(c10 >> 31 & 1), "nsid": integer(step["nsid"]) if codec.get("ns") else 0,
            "instance": c11 & codec.get("instance", 0)}


def _not_restorable(fid: int, step: dict):
    codec = spec_fields.FEATURE_CODECS.get(fid)
    if codec is None:
        return (f"FID {fid:02X}h는 원래 값을 되돌리는 방법(값이 든 레지스터·버퍼 형식)을 하네스가 모름 — "
                "성공을 기대하는 Set Features는 보내지 않음")
    if codec["ns"] and integer(step["nsid"]) in (0, 0xFFFFFFFF):
        return (f"FID {fid:02X}h({codec['name']})는 네임스페이스별 값인데 NSID={integer(step['nsid']):#x}로 바꾸면 "
                "각 네임스페이스의 원래 값을 하나로 백업할 수 없음")
    irreversible = spec_fields.irreversible_feature_value(fid, integer(step["cdw11"]))
    return irreversible


def plan_state_restore(steps: list[dict], nvme_ctrl: str, nvme_ns: str, lba_bytes: int | None = None):
    """(snapshot steps to run first, cleanup steps to run last) that put back
    what this chain changes on the drive (spec_fields.FEATURE_CODECS says how,
    per FID). Cleanup steps run even when the chain stops early. Measured: a
    Write Uncorrectable chain stopped before its repair Write and left LBAs
    0x1001..0x1007 unreadable; temperature threshold 300 K, Timestamp, AEC,
    Interrupt Coalescing, Write Atomicity and Arbitration were all left as the
    tests set them.

    Every restore lists the steps it guards: the executor does not send a
    guarded change expected to succeed unless its original value was captured
    whole, and skips the restore when no guarded step ran. SV=1 changes the
    saved AND the current value, so both are read before and written back
    after (saved first, with SV=1, then current). A FID without a codec gets a
    restore entry marked not restorable, with its reason."""
    snapshots, groups, done = [], [], {}
    for index, step in enumerate(steps):
        if step.get("host_action") or step.get("harness"):
            continue
        raw = integer(step["opcode"])
        if step["mode"] == "admin-passthru" and raw == 0x09:
            fid = integer(step["cdw10"]) & 0xFF
            if fid in spec_fields.HOST_OWNED_SET_FEATURES:
                continue
            identity = restore_identity(step)
            key = ("fid",) + tuple(identity.values())
            if key in done:
                for restore in done[key]:
                    restore["restore"]["guards"].append(index)
                continue
            reason = _not_restorable(fid, step)
            codec = spec_fields.FEATURE_CODECS.get(fid) or {}
            c11, nsid = integer(step["cdw11"]), identity["nsid"]
            group = []
            if reason or not codec:
                group.append(_harness_step("Set Features", 0x09, "ADMIN", nvme_ctrl, nsid, "cleanup",
                                           f"하네스: FID {fid:02X}h 원복 불가", "restore",
                                           restore={"from_snapshot": None, "guards": [index], "identity": identity},
                                           restorable=False, unrestorable_reason=reason))
            else:
                get_len = spec_fields.feature_buffer(fid, False, 0, c11) if codec["buffer"] else 0
                set_len = spec_fields.feature_buffer(fid, True, 0, c11) if codec["buffer"] else 0
                for sel in ([0b010, 0b000] if identity["sv"] else [0b000]):
                    label = f"FID {fid:02X}h({codec['name']}) " + ("저장값" if sel == 0b010 else "현재값")
                    if identity["instance"]:
                        label += f" (CDW11 선택자 0x{identity['instance']:08X})"
                    if codec["ns"]:
                        label += f" (NSID {nsid})"
                    snapshots.append(_harness_step(
                        "Get Features", 0x0A, "ADMIN", nvme_ctrl, nsid, "setup",
                        f"하네스: {label}을 바꾸기 전에 읽어 둠(원복용)", "snapshot",
                        cdw10=fid | sel << 8, cdw11=identity["instance"], data_len=get_len,
                        direction="read" if get_len else "none", codec_fid=fid))
                    group.append(_harness_step(
                        "Set Features", 0x09, "ADMIN", nvme_ctrl, nsid, "cleanup", f"하네스: {label} 원복", "restore",
                        cdw10=fid | ((sel == 0b010) << 31), cdw11=identity["instance"], data_len=set_len,
                        direction="write" if set_len else "none", codec_fid=fid,
                        restore={"from_snapshot": len(snapshots) - 1, "guards": [index], "identity": identity},
                        restorable=True))
            done[key] = group
            groups.insert(0, group)
        elif step["mode"] == "io-passthru" and raw == 0x04:
            key = ("wu", integer(step["nsid"]), (integer(step["cdw11"]) << 32) | integer(step["cdw10"]),
                   integer(step["cdw12"]) & 0xFFFF)
            if key in done:
                done[key][0]["restore"]["guards"].append(index)
                continue
            # Write Zeroes rewrites the range, which clears the uncorrectable
            # mark - only if the Write Uncorrectable was actually sent.
            done[key] = [_harness_step(
                "Write Zeroes", 0x08, "NVM", nvme_ns, step["nsid"], "cleanup",
                "하네스: Write Uncorrectable로 표시한 LBA를 다시 써서 복구", "restore",
                cdw10=integer(step["cdw10"]), cdw11=integer(step["cdw11"]), cdw12=integer(step["cdw12"]) & 0xFFFF,
                destructive=True, lba_bytes=lba_bytes, restore={"from_snapshot": None, "guards": [index]})]
            groups.insert(0, done[key])
    cleanups = [c for group in groups for c in group]
    # Guarded step indexes as they will be in snapshots + steps + cleanups.
    for cleanup in cleanups:
        cleanup["restore"]["guards"] = [i + len(snapshots) for i in cleanup["restore"]["guards"]]
    return snapshots, cleanups


def _shift_repairs(repairs, n):
    return [dict(r, step=r["step"] + n) if isinstance(r.get("step"), int) else r for r in repairs or []]


def _shift_checks(groups, n):
    shifted = deepcopy(groups or [])
    for group in shifted:
        for check in group.get("checks") or []:
            for key in ("step", "other_step"):
                if isinstance(check, dict) and check.get(key) is not None:
                    check[key] = integer(check[key]) + n
    return shifted


def _prior_steps_up_to(resolved_steps: list[dict], steps: list[dict], upto: int) -> list[dict]:
    return [
        {"step": j, "phase": resolved_steps[j]["phase"], "opcode_name": resolved_steps[j]["opcode_entry"]["name"],
         "facts": steps[j].get("shared_facts", {}),
         "encoded_fields": {k: steps[j].get(k) for k in ("nsid", "cdw10", "cdw11", "cdw12",
                                                         "cdw13", "cdw14", "cdw15", "data_len", "direction")}}
        for j in range(upto)
    ]


def reauthor_steps(tc: dict, resolved_steps: list[dict], rejected: dict, active_nsid: int,
                    device_facts: str | None = None, device_support: dict | None = None) -> list[dict]:
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
        if rs.get("harness") or first.get("harness"):
            continue  # snapshot/restore steps are fixed by code, not re-authored
        rejection = {"step": first, "reason": rejected["reason"]} if j == i else None
        rebuilt = _command_step(rs["section"], rs["opcode_entry"], first["device"], first["device"], active_nsid,
                                 phase=rs["phase"], role=rs.get("role"),
                                 prior_steps=prior_steps, rejected=rejection, device_facts=device_facts,
                                 test_intent=first.get("test_intent"), device_support=device_support)
        steps[j] = rebuilt
        prior_steps = _prior_steps_up_to(resolved_steps, steps, j + 1)
    return steps


def build_tc(tc_id: str, resolved_steps: list[dict], scenario: dict,
             nvme_ctrl: str, nvme_ns: str, active_nsid: int, device_facts: str | None = None,
             lba_bytes: int | None = None, device_support: dict | None = None,
             firmware_image: dict | None = None) -> dict:
    from tc_system.models import make_tc_record

    action = next(rs for rs in resolved_steps if rs["phase"] == "action")
    name_suffix = action["section"]["section_id"].replace(":", "_").replace(".", "_")
    name = f"TC_{action['opcode_entry']['name'].replace(' ', '')}_{name_suffix}"

    steps: list[dict] = []
    for rs in resolved_steps:
        prior_steps = _prior_steps_up_to(resolved_steps, steps, len(steps))
        intent = {"scenario": scenario["description"], "preconditions": scenario["preconditions"],
                  "requirements": scenario.get("requirements", []),
                  "phase": rs["phase"], "role": rs.get("role"),
                  "field_constraints": rs.get("field_constraints", []),
                  "expected_status": rs.get("expected_status", "SUCCESS"),
                  "payload_hex": rs.get("payload_hex"),
                  # Rides in test_intent so a reauthor (which reuses the stored
                  # intent) checks the same buffer size as the first attempt.
                  "lba_bytes": lba_bytes, "firmware_image": firmware_image}
        steps.append(_command_step(rs["section"], rs["opcode_entry"], nvme_ctrl, nvme_ns, active_nsid,
                                    phase=rs["phase"], role=rs.get("role"), prior_steps=prior_steps,
                                    device_facts=device_facts, test_intent=intent, device_support=device_support))

    # Put back what the chain changes. Snapshots go first, so every check's
    # step index moves by their count; resolved_steps is updated in place to
    # stay index-aligned with tc["steps"] for retries.
    snapshots, cleanups = plan_state_restore(steps, nvme_ctrl, nvme_ns, lba_bytes)
    requirements = scenario.get("requirements", [])
    precondition_checks = scenario.get("precondition_checks", [])
    if snapshots or cleanups:
        def harness_entry(step):
            # Everything build_tc and the pipeline read from a resolved step;
            # "opcode" (the coverage id) is None so no clause is credited.
            return {"section": action["section"], "phase": step["phase"], "role": step["role"], "harness": True,
                    "opcode_entry": {"name": step["name"], "opcode": None, "raw_opcode": step["opcode"],
                                     "command_set": "ADMIN" if step["mode"] == "admin-passthru" else "NVM",
                                     "harness": True}}
        steps = snapshots + steps + cleanups
        resolved_steps[:0] = [harness_entry(s) for s in snapshots]
        resolved_steps.extend(harness_entry(s) for s in cleanups)
        requirements = _shift_checks(requirements, len(snapshots))
        precondition_checks = _shift_checks(precondition_checks, len(snapshots))

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
        source_section_ids=list(dict.fromkeys(rs["section"]["section_id"] for rs in resolved_steps
                                               if not rs["opcode_entry"].get("host_action") and not rs.get("harness"))),
        source_opcodes=list(dict.fromkeys(rs["opcode_entry"]["opcode"] for rs in resolved_steps
                                          if not rs.get("harness"))),
        generated_from={"rag_response_id": scenario["rag_response_id"],
                         "llm_response_id": scenario["llm_response_id"]},
        scenario={"description": scenario["description"], "preconditions": scenario["preconditions"],
                  "out_of_scope": scenario.get("out_of_scope", [])},
        expectation={
            "description": expectation_description,
            "fail_criteria": scenario["fail_criteria"] + ["nvme-cli exit code != 0", "command timeout exceeded"],
        },
        steps=steps,
        destructive=any(s.get("destructive", False) for s in steps),
        uses_placeholder_args=any(s.get("args_source") == PLACEHOLDER_ARGS for s in steps),
    )
    # Not deduped, unlike source_section_ids/source_opcodes above: coverage
    # pairs these index-for-index with per-step statuses, so a step that
    # repeats an earlier step's section/opcode still gets its own entry.
    # A host step (reset/power cycle) tests no clause: None keeps the per-step
    # arrays aligned while coverage skips it.
    tc["step_section_ids"] = [None if rs["opcode_entry"].get("host_action") or rs.get("harness")
                              else rs["section"]["section_id"] for rs in resolved_steps]
    tc["step_opcodes"] = [rs["opcode_entry"]["opcode"] for rs in resolved_steps]
    tc["chain_summary"] = chain_summary
    tc["verification_contract"] = {
        "version": VERSION, "target_section_id": action["section"]["section_id"],
        "requirements": requirements,
        "precondition_checks": precondition_checks,
        "out_of_scope": scenario.get("out_of_scope", []),
        "target_requirement": scenario.get("target_requirement"),
        "unmeasured_preconditions": scenario.get("unmeasured_preconditions", []),
        # Checks the harness rewrote to the field their description names.
        "check_repairs": _shift_repairs(scenario.get("check_repairs", []), len(snapshots)),
        "evidence": scenario.get("spec_evidence", []),
    }
    if requirements:
        tc["expectation"]["description"] = " / ".join(r["description"] for r in requirements)
        tc["expectation"]["fail_criteria"] = []  # The contract is the single source of checks.
    return tc
