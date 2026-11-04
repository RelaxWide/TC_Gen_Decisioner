import json

from shared.spec_evidence import format_evidence
from tc_system.verification import validate_plan_contract, CAPABILITIES
from shared.llm_client import generate_llm_response
from shared.rag_client import generate_rag_response

SCENARIO_SCHEMA = {
    "description": "string — what this test case exercises and why it is worth testing",
    "preconditions": "array of strings — device/namespace state required before the command runs",
    "steps_plan": (
        'array of objects {"opcode_name": <a real command name from available_commands>, '
        '"role": <what this step checks>, "phase": "setup" | "action" | "verify", '
        '"expected_status": "SUCCESS" or the exact expected NVMe error token, '
        '"field_constraints": [{"field": "cdw10", "mask": "0x000007FF", "value": "0x0000037D"}], '
        '"payload_hex": null or a short hex byte pattern (e.g. "A55A") repeated to fill a write buffer}. '
        'Exactly one step must have phase="action" and its opcode_name must equal the target '
        'command given above (opcode=... command_set=...). setup steps must come before the '
        'action step, verify steps must come after it. If the clause needs several preconditions '
        'or a multi-step state transition, use as many setup steps as genuinely needed — do not '
        'force the count down. A single-entry plan (just the action step) is correct and common; '
        'only add setup/verify steps when the clause text actually calls for them.'
    ),
    "chain_summary": ("string — 1-2 sentence summary of what the whole step sequence verifies. "
                       "If steps_plan has only the action step, this can repeat description."),
    "requirements": (
        'array of {"description": Korean string, "evidence_id": supplied evidence ID, '
        '"quote": one contiguous English sentence or table row copied exactly from that evidence block '
        '(never translated or paraphrased; at least 20 characters), "checks": [check objects]}. '
        'Each requirement needs executable checks. A check has "kind" and zero-based "step". '
        'Allowed kinds: completion (compare with step.expected_status); '
        'result_bits (CQE DW0: mask, value, operator eq/ne/le/ge); '
        'data_length (bytes); data_field (little-endian offset, width 1..8, mask, value, operator); '
        'data_equal (other_step); data_matches_write (other_step, compare with that write payload). '
        'Masks and values are integers or 0x hex strings. No Python, expressions or regex checks.'
    ),
    "precondition_checks": 'array of {"description": exact preconditions entry, "checks": [check objects]}; '
                           'every precondition needs checks on steps BEFORE action',
    "required_capabilities": 'array of required executor capability names from the supplied list',
    "out_of_scope": 'array of Korean strings; related behaviors this TC deliberately does NOT verify '
                    '(other LIDs/values, deeper data comparison, ...). Informational only: recorded in the '
                    'report, never blocks the test. Not for the requirement\'s own preconditions.',

}

SCENARIO_SYSTEM_PROMPT = (
    "You are an NVMe test scenario author. Given a specification section and the command it "
    "covers, write a concrete test scenario grounded in the supplied specification text. "
    "Only state requirements the specification actually supports.\n\n"
    "STEPS_PLAN: decide whether this clause needs supporting commands around the target command. "
    "Use setup steps for state the target command needs established first (e.g. write data before "
    "reading it back, or set a feature before checking it was applied) and verify steps for "
    "commands that confirm the target command's effect afterward. Only ever choose commands that "
    "appear in available_commands, by their exact name — never invent one.\n\n"
    "Write description, requirement descriptions, chain_summary, every out_of_scope entry and every steps_plan[].role in "
    "Korean (한국어). steps_plan[].opcode_name and steps_plan[].phase must stay exactly as given "
    "(a real English command name, and one of setup/action/verify) — do not translate those.\n\n"
    "DEVICE_FACTS: if the prompt includes a device_facts block, it lists commands/ranges measured "
    "directly from this real target. Prefer setup/verify commands it confirms this drive "
    "supports; avoid proposing one its OACS/ONCS/SANICAP bits report as absent unless it is the "
    "action step itself (the action step is fixed by the clause under test even if this drive "
    "turns out not to implement it)."
    "\n\nEXECUTABLE CONTRACT: test one concrete cited requirement at a time. Do not list multiple "
    "variants in prose while issuing only one command. Every claimed observation must have a check. "
    "Fix the request selectors/addresses that define the test in field_constraints; these survive retries. "
    "For Get Features constrain CDW10[10:0] (FID and SEL); Identify CNS and Get Log Page LID "
    "use CDW10[7:0]; Directive DTYPE/DOPER use CDW11[15:0]. NVM Read/Write/Compare must "
    "fix SLBA (CDW10,11) and NLB (CDW12[15:0]). Firmware Commit fixes CA/FS in CDW10[5:0]. "
    "Declare expected_status for EVERY step, including intentionally expected errors in negative tests. "
    "preconditions are claims to MEASURE before action, not assumptions inferred from device_facts. "
    "DEVICE LIMITS: sequential nvme-cli passthru only; no concurrent outstanding command/CID control, "
    "event injection, resets, timing measurements or dynamic runtime parameters. Abort/AER tests are "
    "not executable here. Write payloads are zero bytes unless payload_hex is explicitly provided; "
    "never claim a structured management payload was sent unless you encode it. Data comparisons "
    "use captured hex bytes, not the model's explanation. data_equal/data_matches_write compare the "
    "same data only: for NVM Read/Write/Compare the compared step's SLBA/NLB (field_constraints) must "
    "lie inside the other step's range, and data_matches_write needs a non-zero payload_hex (zeros "
    "look the same as unwritten LBAs). If the cited requirement itself cannot be "
    "stimulated or observed with this executor, pick another requirement from the evidence that can be. "
    "List related behaviors this TC leaves untested in out_of_scope (a note, never a reason to skip). "
    "A condition the requirement depends on belongs in preconditions with a check before the action, "
    "not in out_of_scope. Never simplify away the original requirement "
    "just to make a command return success. Previously verified requirement quotes are provided to "
    "help select a different requirement; testing one does not cover an entire clause."

)


def _as_list(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value.strip() else []
    return [str(v) for v in value]


def _scope_notes(structured):
    """out_of_scope, also accepting the older unverified_conditions key."""
    return [str(n) for n in (structured.get("out_of_scope") or structured.get("unverified_conditions") or [])]


def _validate_steps_plan(plan, opcode_entry: dict, available_opcodes: list[dict]) -> list[dict]:
    if not isinstance(plan, list) or not plan:
        raise ValueError("steps_plan must be a non-empty array")
    # Checked up front: a bare string entry (e.g. ["Identify", {...}]) used to
    # reach `step.get` below as AttributeError, which nothing upstream caught —
    # one malformed reply must not take the whole --count batch down.
    if not all(isinstance(s, dict) for s in plan):
        raise ValueError("every steps_plan entry must be an object")
    by_name = {o["name"]: o for o in available_opcodes}

    action_indices = [i for i, s in enumerate(plan) if isinstance(s, dict) and s.get("phase") == "action"]
    if len(action_indices) != 1:
        raise ValueError(f"steps_plan must have exactly one phase=='action' step, got {len(action_indices)}")
    action_index = action_indices[0]
    if plan[action_index].get("opcode_name") != opcode_entry["name"]:
        raise ValueError("the action step's opcode_name must be the target command")

    for i, step in enumerate(plan):
        name = step.get("opcode_name")
        if name not in by_name:
            raise ValueError(f"step {i} names {name!r}, which is not in available_commands")
        phase = step.get("phase")
        if phase not in ("setup", "action", "verify"):
            raise ValueError(f"step {i} has invalid phase {phase!r}")
        if phase == "setup" and i > action_index:
            raise ValueError(f"setup step {i} comes after the action step")
        if phase == "verify" and i < action_index:
            raise ValueError(f"verify step {i} comes before the action step")

    # Deliberately NOT gated on risk_class relative to the action step: the
    # canonical motivating case (Write setup before a Read action) has a
    # destructive setup (risk_class 2) ahead of a safe action (risk_class 0),
    # which an "no step riskier than the action" rule would reject outright.
    # The real safety boundary for destructive/firmware_state steps is
    # execute_tc_steps's DestructiveStepBlocked gate (allow_destructive),
    # which already scans every step regardless of phase or position —
    # risk_class here is only ever a batch-ordering preference, not a hard
    # safety limit, so it has no business blocking a legitimate plan.
    return plan


def generate_scenario(section: dict, opcode_entry: dict, available_opcodes: list[dict],
                       feedback: str | None = None, device_facts: str | None = None) -> dict:
    """`available_opcodes` is the full opcode table (every command_set — ADMIN/NVM combos are
    allowed), used both to list real command names in the prompt and to validate the model's
    `steps_plan` choices against. `feedback`, when given, describes why a previous attempt's plan
    didn't work out (a step it depended on was rejected or unsupported) and asks for a plan that
    doesn't repeat that dependency — this is a full replan, not the single-field retry `author_args`
    does, because the problem is structural (which commands to chain), not one bad field value.

    `device_facts`, when given, is `device_capabilities.summarize_device_capabilities`'s formatted
    text — read directly off the real target once per run, not per TC — so setup/verify picks can
    be steered toward commands this drive is already known to support instead of discovering
    UNSUPPORTED the expensive way (an LLM call plus an SSH round trip) for every target."""
    rag = generate_rag_response(
        f"{section['title']} ({opcode_entry['name']}) expected behavior and error handling",
        top_k=3, doc_filter=[section["spec_doc"]], section=section, command_name=opcode_entry["name"],
        layout_ref=opcode_entry.get("section_ref"), purpose="scenario",
    )
    if not rag["chunks"]:
        raise ValueError(f"exact spec evidence unavailable for {section['section_id']}")
    available_names = sorted({o["name"] for o in available_opcodes})
    prompt = (
        f"spec_doc={section['spec_doc']} section={section['section_id']} title={section['title']} "
        f"opcode={opcode_entry['raw_opcode']} command_set={opcode_entry['command_set']}\n"
        f"available_commands={', '.join(available_names)}\n"
        f"executor_capabilities={sorted(CAPABILITIES)}\n"
        f"previously_verified_requirements={json.dumps(section.get('previous_requirements', []), ensure_ascii=False)}\n"
        f"spec_context=\n" + format_evidence(rag["chunks"])
    )
    if device_facts:
        prompt += f"\n\ndevice_facts=\n{device_facts}"
    if feedback:
        prompt += (
            f"\n\nA previous attempt's plan did not work out: {feedback}\n"
            "Propose a plan that does not depend on that outcome."
        )
    for attempt in range(2):
        llm = generate_llm_response(prompt, system=SCENARIO_SYSTEM_PROMPT,
                                   response_schema=SCENARIO_SCHEMA, caller="scenario_generator")
        structured = llm["structured"]
        try:
            steps_plan = _validate_steps_plan(structured.get("steps_plan"), opcode_entry, available_opcodes)
            validate_plan_contract(structured, rag["chunks"], section["section_id"], available_opcodes)
            break
        except (ValueError, TypeError, KeyError) as exc:
            if attempt:
                raise ValueError(f"scenario contract invalid: {exc}") from exc
            prompt += f"\n\nYour plan is not executable: {exc}. Correct the contract without changing its target."

    return {
        "description": str(structured["description"]),
        "preconditions": structured["preconditions"],
        "fail_criteria": [r["description"] for r in structured["requirements"]],
        "steps_plan": steps_plan,
        "chain_summary": str(structured.get("chain_summary") or structured["description"]),
        "requirements": structured["requirements"],
        "precondition_checks": structured.get("precondition_checks", []),
        "out_of_scope": _scope_notes(structured),
        "spec_evidence": rag["chunks"],
        "rag_response_id": rag["response_id"],
        "llm_response_id": llm["response_id"],
    }
