"""Authors real NVMe command dword values from the specification text.

This replaces the placeholder `cdw10=0` steps that kept the TC pipeline gated.
`cdw10=0` is a reserved CNS/LID/FID for most commands, so those probes were
rejected outright (INVALID_FIELD) — or worse, silently succeeded without
transferring anything (NVM Read), which would have been recorded as a PASS.

Measured against the real device, LLM-authored values grounded in the spec were
accepted 3/3 (Identify CNS=1 + 4096B, Get Log Page LID=02h with NUMD computed
to 512B, Get Features with a valid FID). Values are validated for shape here
and again in `ssh_runner._validate_step` before anything is sent.

Note the `field_breakdown` text is explanatory only and is NOT authoritative:
in that same measurement the model labelled FID 02h "Number of Queues" (it is
Power Management) while still emitting a valid value. Keep it for the report,
do not rely on it.
"""
import re
import json

from shared.spec_evidence import format_evidence
from tc_system.command_fields import verify_selectors, validate_transfer
from tc_system.verification import apply_fixed_fields, validate_fixed_fields, integer, payload_for_step

from shared.llm_client import LLMCallError, generate_llm_response
from shared.rag_client import generate_rag_response

HEX32_RE = re.compile(r"^0x[0-9A-Fa-f]{1,8}$")
MAX_DATA_LEN = 1 << 20  # a test probe has no reason to move more than 1 MiB

# Bits 1:0 of the opcode byte are the Data Transfer field (NVMe Base spec):
# 00=no data, 01=host-to-controller, 10=controller-to-host. 11=bidirectional
# is deliberately absent — either direction is legitimate there, so it is
# left unchecked rather than guessed at.
_OPCODE_DIRECTION_BITS = {0b00: "none", 0b01: "write", 0b10: "read"}


def _opcode_data_transfer(raw_opcode: str) -> str | None:
    return _OPCODE_DIRECTION_BITS.get(int(raw_opcode, 16) & 0b11)


# Compatibility helper for callers with the original CDW10-only API. Runtime
# authoring uses verify_selectors with the actual command set/opcode/registers.
def _verify_field_values(cdw10, required_field_values):
    names = {e["field_name"] for e in required_field_values or []}
    opcode = "0x06" if "CNS" in names else "0x0A" if "Feature Identifier" in names else "0x02"
    try:
        return verify_selectors({"cdw10": cdw10}, {"command_set": "ADMIN", "raw_opcode": opcode},
                                required_field_values)
    except ValueError as exc:
        raise ArgsAuthoringError(str(exc)) from exc


ARGS_SCHEMA = {
    "cdw10": 'hex string, e.g. "0x00000001" — the CDW10 value for this command',
    "cdw11": 'hex string, e.g. "0x00000000"',
    "cdw12": 'hex string, e.g. "0x00000000"',
    "cdw13": 'hex string, zero if reserved',
    "cdw14": 'hex string, zero if reserved',
    "cdw15": 'hex string, zero if reserved',
    "data_len": "integer — bytes this command transfers, 0 if it transfers none",
    "direction": '"read" (device-to-host), "write" (host-to-device), or "none"',
    "nsid": "integer — the command's Namespace Identifier field; see system prompt for the allowed values",
    "shared_facts": ('object — named fields this step establishes that LATER steps in the same '
                      'multi-command test must reuse verbatim, e.g. {"lba": "0x5", "nlb": "0"} for '
                      'an LBA-addressed command, {"feature_id": "0x0A"} for Set/Get Features. '
                      'Empty object {} if this step establishes nothing another step would need.'),
    "field_breakdown": "string — which spec field each value encodes",
}

SYSTEM_PROMPT = (
    "You are an NVMe firmware test engineer. Given specification text for one command, "
    "produce the concrete command dword values required by TEST_INTENT. "
    "Choose the specified variant, even when it deliberately expects rejection. Avoid reserved or "
    "vendor-specific field values. If the command requires a data buffer, give its correct "
    "length in bytes; if it transfers no data, use data_len 0 and direction \"none\".\n\n"
    "CRITICAL: when a CDW field encodes a transfer length as a NUMBER OF DWORDS "
    "(Get Log Page NUMDL/NUMDU, and similar), data_len must equal that dword count times 4, "
    "using the field's own zero-based convention. A mismatch makes the controller return more "
    "data than the buffer holds, which corrupts the host tool's heap instead of producing a "
    "test result. Keep the requested length small (a single 512-byte or 4096-byte transfer).\n\n"
    "NSID: decide the command's Namespace Identifier field from the spec text's own description "
    "of this exact command, not from habit. There are exactly three legal choices, and the "
    "prompt tells you which real namespace is attached as active_nsid: use 0h if the command is "
    "not namespace-specific (e.g. Identify Controller, most controller-wide admin commands); use "
    "active_nsid if the command identifies, reads, or operates on a specific namespace (e.g. "
    "Identify Namespace, Read, Write, Compare); use FFFFFFFFh (all namespaces) only if the spec "
    "text explicitly permits that broadcast value for this exact command (a minority of commands "
    "do). Never invent a different namespace id — only active_nsid exists on this target.\n\n"
    "SHARED_FACTS: if this command is one step in a multi-command test, earlier steps' already-"
    "committed values are listed below as prior_steps. If an earlier step targeted a specific "
    "LBA range, Feature Identifier, or similar, and this command addresses the same resource, "
    "REUSE that exact value — a Read after a Write must read the same LBA/NLB it wrote, a Get "
    "Features after a Set Features must query the same Feature Identifier it set — unless the "
    "spec text for THIS command requires something different. Report your own command's "
    "reusable facts in shared_facts so later steps can do the same.\n\n"
    "Write field_breakdown in Korean (한국어). shared_facts keys should stay short English "
    "identifiers (e.g. \"lba\", \"nlb\", \"feature_id\") for consistency across steps; its "
    "values are hex/numeric, not natural language. direction must stay exactly \"read\"/"
    "\"write\"/\"none\" — do not translate it.\n\n"
    "DEVICE_FACTS: if the prompt includes a device_facts block, it was measured directly from "
    "this real target (not spec generalities) — ground field values in it: keep LBA addresses "
    "inside the reported namespace size, pick only a Sanitize action its SANICAP bits actually "
    "report, and keep a Power State value within its reported range.\n\n"
    "FIRMWARE: Firmware Commit CDW10 CA is bits 5:3; FS is bits 2:0. CA=0 replaces "
    "without activation, 1 replaces/activates on reset, 2 activates an EXISTING slot, "
    "3 replaces/activates immediately, 6 replaces a boot partition, 7 marks it active. "
    "Do not infer invalid image acceptance without evidence of the actual preceding download.\n\n"
    "TEST_INTENT: the scenario, this step's role, checks and field_constraints define the test. "
    "The harness writes the field_constraints bits itself after your reply; choose every other field, "
    "above all the transfer length (NUMD/NLB) and data_len, to be consistent with those fixed bits. "
    "Preserve them exactly, INCLUDING during retries. Never switch FID/LID/CNS, address or expected "
    "outcome to make a different command succeed. Negative tests deliberately expect an error; "
    "do not turn them into positive tests. If the fixed constraints cannot be encoded, report the "
    "conflict rather than substituting another test. prior_steps are planned values, NOT measured "
    "facts or proof that a prior command succeeded.\n\n"
    "REQUIRED_FIELD_VALUE: encode the clause's selector in its actual spec-defined register. "
    "LID/FID/CNS are CDW10[7:0]; Directive DOPER=CDW11[7:0], DTYPE=CDW11[15:8]; "
    "Get LBA Status ATYPE=CDW13[31:24]. Event Type is an observed log value, not a CDW selector."

)


class ArgsAuthoringError(RuntimeError):
    pass


def _normalize_hex(value, field: str) -> str:
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ArgsAuthoringError(f"{field} is not a 32-bit hex value: {value!r}")
    text = hex(value) if isinstance(value, int) else value.strip()
    # Case-insensitive on the prefix: a reply of "0XABCD" would otherwise get a
    # second prefix glued on ("0x0XABCD") and be rejected as malformed.
    if not text.lower().startswith("0x"):
        text = f"0x{text}"
    if not HEX32_RE.match(text.lower()):
        raise ArgsAuthoringError(f"{field} is not a 32-bit hex value: {value!r}")
    return f"0x{int(text, 16):08X}"


def _author_once(prompt: str, opcode_entry: dict, active_nsid: int,
                  required_field_values: list[dict] | None = None, test_intent: dict | None = None) -> dict:
    try:
        llm = generate_llm_response(prompt, system=SYSTEM_PROMPT,
                                            response_schema=ARGS_SCHEMA, caller="args_author")
        structured = llm["structured"]
    except LLMCallError as exc:
        raise ArgsAuthoringError(f"LLM could not author args: {exc}") from exc

    direction = str(structured["direction"]).strip().lower()
    if direction not in ("read", "write", "none"):
        raise ArgsAuthoringError(f"invalid direction: {structured['direction']!r}")
    # Measured on real hardware: a TC authored direction="write" for opcode
    # 0x2A, whose own bits 1:0 encode controller-to-host ("read"). nvme-cli
    # warned ("write flag set but write direction bit is not set in the
    # opcode") and sent it anyway — the command never completed, burning the
    # full SSH batch timeout (~125s) for a request that was malformed before
    # it left this host. Rejecting the mismatch here fails in milliseconds
    # instead, before anything reaches the device.
    # direction="none" is exempt: many read-capable commands (e.g. Get
    # Features returning its value in CDW0) legitimately transfer no buffer
    # at all despite the opcode's bits nominally allowing one, and that
    # zero-length choice was measured accepted (PASS) on real hardware.
    expected = _opcode_data_transfer(opcode_entry["raw_opcode"])
    if direction != "none" and expected is not None and direction != expected:
        raise ArgsAuthoringError(
            f"direction={direction!r} conflicts with opcode {opcode_entry['raw_opcode']}'s own "
            f"encoded transfer direction (bits 1:0 require {expected!r})")
    try:
        nsid = integer(structured["nsid"])
    except (TypeError, ValueError) as exc:
        raise ArgsAuthoringError(f"invalid nsid: {structured['nsid']!r}") from exc
    # Hardcoding nsid=0 for every admin command (as this once did) broke any
    # namespace-scoped CNS/LID — measured on real hardware, Identify with
    # CNS=0 ("Identify Namespace") returns INVALID_NS against nsid=0 no matter
    # how many times cdw10 is retried, because nsid isn't a field author_args
    # used to control at all. But accepting whatever nsid the model invents
    # is just as wrong: this harness has exactly one real target, so only its
    # own namespace, the controller-wide 0h, or the explicit FFFFFFFFh
    # broadcast are legitimate — anything else would hit a *different*
    # drive-reported error (likely INVALID_NS again) for an unrelated reason.
    allowed_nsids = {0, active_nsid, 0xFFFFFFFF}
    if nsid not in allowed_nsids:
        raise ArgsAuthoringError(
            f"nsid={nsid} is not one of the values this target supports: "
            f"0 (not namespace-specific), {active_nsid} (this target's active namespace), "
            "or 4294967295/0xFFFFFFFF (all namespaces)")
    try:
        data_len = integer(structured["data_len"])
    except (TypeError, ValueError) as exc:
        raise ArgsAuthoringError(f"invalid data_len: {structured['data_len']!r}") from exc
    if not 0 <= data_len <= MAX_DATA_LEN:
        raise ArgsAuthoringError(f"data_len out of range: {data_len}")
    # A declared direction with no buffer is the vacuous-success shape — a
    # command that exits 0 having moved nothing. Coercing direction to "none"
    # here (as this once did) *hides* it: `_vacuous_success` only fires when
    # direction != "none", so an Identify with data_len=0 would sail through as
    # a PASS and be counted as real coverage. Reject it instead.
    if direction != "none" and data_len == 0:
        raise ArgsAuthoringError(
            f"direction={direction} with data_len=0 transfers nothing; "
            "a command that moves no data cannot confirm the clause")
    if direction == "none" and data_len:
        raise ArgsAuthoringError(f"data_len={data_len} but direction is none")

    shared_facts = structured.get("shared_facts") or {}
    if not isinstance(shared_facts, dict):
        raise ArgsAuthoringError(f"shared_facts must be an object: {shared_facts!r}")

    fields = {f"cdw{i}": _normalize_hex(structured.get(f"cdw{i}", "0x0"), f"cdw{i}")
              for i in range(10, 16)}
    fields.update(nsid=nsid, data_len=data_len, direction=direction)
    try:
        overrides = apply_fixed_fields(fields, (test_intent or {}).get("field_constraints", []))
        if fields["nsid"] not in allowed_nsids:
            raise ValueError(f"fixed nsid={fields['nsid']} is not one of {sorted(allowed_nsids)}")
        if not 0 <= fields["data_len"] <= MAX_DATA_LEN:
            raise ValueError(f"fixed data_len out of range: {fields['data_len']}")
        field_value_verified = verify_selectors(fields, opcode_entry, required_field_values)
        validate_fixed_fields(fields, (test_intent or {}).get("field_constraints", []))
        validate_transfer(fields, opcode_entry, lba_bytes=(test_intent or {}).get("lba_bytes"))
        payload_hex = (test_intent or {}).get("payload_hex")
        if payload_hex is not None and direction == "write":
            # Caught here, inside the one-retry loop, instead of later in
            # tc_writer where it skipped the whole target with no second try.
            payload_for_step({"direction": direction, "data_len": fields["data_len"], "payload_hex": payload_hex})
    except ValueError as exc:
        raise ArgsAuthoringError(str(exc)) from exc
    return dict(fields, shared_facts=dict(shared_facts),
                field_breakdown=str(structured["field_breakdown"]),
                field_value_verified=field_value_verified, llm_response_id=llm["response_id"],
                constraint_overrides=overrides)


def author_args(section: dict, opcode_entry: dict, active_nsid: int,
                 prior_steps: list[dict] | None = None, rejected: dict | None = None,
                 device_facts: str | None = None, required_field_values: list[dict] | None = None,
                 test_intent: dict | None = None) -> dict:
    """`active_nsid` is the one real namespace this harness is wired to test
    (derived from the target's configured device path) — the model is told
    this and must pick 0, this value, or the explicit broadcast FFFFFFFFh,
    never an invented namespace id. `rejected` carries a previous attempt the
    controller refused, as {"step": <the step dict>, "reason": <controller
    text>}; including it lets the model correct a reserved/unsupported field
    instead of repeating it.

    `prior_steps`, for a multi-command TC, is every earlier step's own record
    verbatim — [{"step": i, "phase": ..., "opcode_name": ..., "facts": {...}},
    ...] — kept as a list rather than merged into one flat dict, so a later
    step can still see e.g. a power-state value a middle step changed, not
    just whatever the most recent step happened to set under the same key.

    `device_facts`, when given, is `device_capabilities.
    summarize_device_capabilities`'s formatted text — facts read directly off
    the real target once per run (namespace size, Power State range, SANICAP,
    ...) so a value gets grounded in what this exact drive reports instead of
    guessed at, cutting down on INVALID_FIELD rejections the controller would
    otherwise have to spend a round trip reporting.

    `required_field_values`, when given, is the target section's own
    `field_values` list (see `build_spec_index.py`'s `link_field_values`) —
    this clause is about one specific value of an enumerated field (a Log
    Page Identifier, Feature Identifier, CNS, ...), not the command in
    general. Deterministically checked against CDW10 bits 7:0 (see
    `_verify_field_values`) rather than trusted from the model's own
    self-report, the same way direction/nsid are checked rather than trusted."""
    rag = generate_rag_response(
        f"{opcode_entry['name']} command CDW fields and data buffer requirements",
        top_k=4, doc_filter=[section["spec_doc"]], section=section, command_name=opcode_entry["name"],
        # The command's own Command Dword figures first: a leaf clause such as
        # "Return Allocated LBAs (Action Type 02h)" carries the value, not the
        # register layout it has to be encoded into.
        layout_ref=opcode_entry.get("section_ref"), purpose="args")
    if not rag["chunks"]:
        raise ArgsAuthoringError(f"no spec context found for {opcode_entry['name']}")

    prompt = (
        f"command={opcode_entry['name']} opcode={opcode_entry['raw_opcode']} "
        f"command_set={opcode_entry['command_set']} clause={section['section_id']} "
        f"active_nsid={active_nsid}\n\n"
        "spec_context=\n" + format_evidence(rag["chunks"])
    )
    if test_intent:
        prompt += "\n\nTEST_INTENT=" + json.dumps(test_intent, ensure_ascii=False)
    if device_facts:
        prompt += f"\n\ndevice_facts=\n{device_facts}"
    if required_field_values:
        values_str = ", ".join(f"{e['field_name']}={e['hex_value']}" for e in required_field_values)
        prompt += f"\n\nrequired_field_value={values_str}"
    if prior_steps:
        lines = "\n".join(
            f"  step{p['step']}({p['phase']}, {p['opcode_name']}): facts={p['facts']} encoded_fields={p.get('encoded_fields', {})}"
            for p in prior_steps if p.get("facts") or p.get("encoded_fields")
        )
        if lines:
            prompt += (
                "\n\nprior_steps (earlier commands already committed to in this same test — "
                "reuse these values unless this command's own spec text requires otherwise):\n"
                + lines
            )
    if rejected:
        step = rejected["step"]
        prompt += (
            "\n\nA previous attempt was REJECTED by the real controller. Do not repeat it.\n"
            f"  rejected: cdw10={step['cdw10']} cdw11={step['cdw11']} cdw12={step['cdw12']} "
            f"nsid={step['nsid']} data_len={step['data_len']} direction={step['direction']}\n"
            f"  controller said: {rejected['reason']}\n"
            "Keep TEST_INTENT and every field constraint unchanged. Correct only other fields — a reserved or unsupported "
            "identifier in any field causes exactly this rejection."
        )
    try:
        return _author_once(prompt, opcode_entry, active_nsid, required_field_values=required_field_values, test_intent=test_intent)
    except ArgsAuthoringError as exc:
        # The mistake here (bad direction, bad nsid, out-of-range length, ...)
        # is the LLM's own and was never sent anywhere — nothing about the
        # device is at stake. Give it one chance to see what it got wrong and
        # fix it itself, the same way a controller rejection already gets fed
        # back above, instead of immediately falling back to a placeholder
        # probe and halting the whole batch over what is usually a one-off
        # slip (measured: opcode 0x1D authored direction="read" against bits
        # that require "write" — an unrelated command from the one 0x2A was
        # first caught on, so this is a recurring LLM mistake, not a one-off).
        retry_prompt = prompt + (
            f"\n\nYour previous reply was INVALID: {exc}\n"
            "Fix exactly that problem and reply again with the full set of values."
        )
        return _author_once(retry_prompt, opcode_entry, active_nsid, required_field_values=required_field_values, test_intent=test_intent)
