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


# Fields the HOST chooses and writes into CDW10 bits 7:0 before sending the
# command — a genuine, stable NVMe convention for all of these (Get Log
# Page's LID, Get/Set Features' FID, Identify's CNS, and CDW10[7:0] as a
# generic sub-operation selector on the single-purpose admin commands that
# define "Management Operation"/"Directive Operation"/etc.), so a mismatch
# here is an unambiguous authoring mistake, not a question of interpretation.
# Validate this empirically against real hardware before trusting it for a
# newly-added field name — same caveat as this project's other hard-coded
# per-command conventions (direction bits, nsid allow-list).
#
# "Event Type" is deliberately NOT in this set: it classifies events the
# controller already logged, discovered only by parsing the *returned* log
# payload — there is no CDW10/11/12 bit pattern that says "only give me
# Event Type 02h entries." A clause requiring a specific Event Type can still
# be linked to its opcode (see build_spec_index.py's `link_field_values`) so
# it shows up in coverage, but it can never be marked `field_value_verified`
# the way a request-side field can.
#
# "Action Type" is deliberately NOT in this set either, for a different
# reason: it IS host-selected, but not in CDW10. Get LBA Status — the only
# command whose clauses carry it in the index — defines ATYPE as Command
# Dword 13 bits 31:24 (checked against the spec chunks), while CDW10 is the
# low half of the Starting LBA. Checking it against CDW10 bits 7:0 forced the
# model to overwrite SLBA with the ATYPE value, so every such TC went out
# malformed. This harness only sends CDW10-12 (`ssh_runner.passthru_cmd`), so
# there is no CDW13 to verify it in at all.
REQUEST_SELECTABLE_FIELDS = {
    "Log Page Identifier", "Feature Identifier", "CNS", "Management Operation",
    "Directive Operation", "Directive Type", "Configuration Identifier",
}


def _verify_field_values(cdw10: str, required_field_values: list[dict] | None) -> bool:
    """Returns True only if every entry in `required_field_values` is both
    request-selectable (see `REQUEST_SELECTABLE_FIELDS`) and matches the
    value actually placed in CDW10 bits 7:0 — the deterministic signal
    `expectation_checker` uses to tell "this drive doesn't implement this
    specific value" (a real finding) apart from "we authored a malformed
    argument" (our bug). Still deterministically checks — and rejects on
    mismatch — every selectable entry even when an unselectable one (like
    Event Type) means the overall clause can't be fully verified; getting a
    checkable field wrong is a real, catchable mistake either way."""
    if not required_field_values:
        return False
    cdw10_byte = int(cdw10, 16) & 0xFF
    all_selectable = True
    for entry in required_field_values:
        if entry["field_name"] not in REQUEST_SELECTABLE_FIELDS:
            all_selectable = False
            continue
        if cdw10_byte != int(entry["hex_value"], 16):
            raise ArgsAuthoringError(
                f"clause requires {entry['field_name']}={entry['hex_value']} in CDW10 bits 7:0, "
                f"but cdw10={cdw10} encodes 0x{cdw10_byte:02X}")
    return all_selectable


ARGS_SCHEMA = {
    "cdw10": 'hex string, e.g. "0x00000001" — the CDW10 value for this command',
    "cdw11": 'hex string, e.g. "0x00000000"',
    "cdw12": 'hex string, e.g. "0x00000000"',
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
    "produce a concrete set of command dword values that a real NVMe controller will accept. "
    "Choose the simplest well-defined variant of the command. Never use reserved or "
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
    "FIRMWARE: Firmware Image Download sends a zero-filled dummy buffer — there is no real signed "
    "firmware image to transmit, so do not describe the downloaded content as valid firmware in "
    "field_breakdown. For Firmware Commit, choose the Commit Action (CDW10 bits 2:0) deliberately: "
    "0 only stages the dummy image into the slot without activating it; 1/2/3/6/7 activate it "
    "(immediately or at the next reset). This harness treats an activating commit that the "
    "controller accepts (rather than rejecting the invalid image) as the serious finding it is, "
    "so pick whichever Commit Action the clause under test actually calls for — do not default to "
    "0 just to avoid activation.\n\n"
    "REQUIRED_FIELD_VALUE: if the prompt includes a required_field_value line, this exact clause "
    "is about one specific value of an enumerated field (e.g. Log Page Identifier, Feature "
    "Identifier, CNS, Management Operation) — put that exact value in CDW10 bits 7:0, not a "
    "different well-defined value for the same command. This is what makes this TC about THIS "
    "clause specifically rather than some other value of the same command."
)


class ArgsAuthoringError(RuntimeError):
    pass


def _normalize_hex(value, field: str) -> str:
    text = str(value).strip()
    # Case-insensitive on the prefix: a reply of "0XABCD" would otherwise get a
    # second prefix glued on ("0x0XABCD") and be rejected as malformed.
    if not text.lower().startswith("0x"):
        text = f"0x{text}"
    if not HEX32_RE.match(text.lower()):
        raise ArgsAuthoringError(f"{field} is not a 32-bit hex value: {value!r}")
    return f"0x{int(text, 16):08X}"


def _author_once(prompt: str, opcode_entry: dict, active_nsid: int,
                  required_field_values: list[dict] | None = None) -> dict:
    try:
        structured = generate_llm_response(prompt, system=SYSTEM_PROMPT,
                                            response_schema=ARGS_SCHEMA, caller="args_author")["structured"]
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
        nsid = int(structured["nsid"])
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
        data_len = int(structured["data_len"])
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

    cdw10 = _normalize_hex(structured["cdw10"], "cdw10")
    # Raises ArgsAuthoringError (caught by the same retry-with-feedback loop
    # as every other check here) if a request-selectable entry's value isn't
    # actually in CDW10 bits 7:0 — see _verify_field_values's own docstring
    # for why an unselectable entry (Event Type) doesn't block this check for
    # the entries that ARE selectable.
    field_value_verified = _verify_field_values(cdw10, required_field_values)

    return {
        "cdw10": cdw10,
        "cdw11": _normalize_hex(structured["cdw11"], "cdw11"),
        "cdw12": _normalize_hex(structured["cdw12"], "cdw12"),
        "data_len": data_len,
        "direction": direction,
        "nsid": nsid,
        "shared_facts": dict(shared_facts),
        "field_breakdown": str(structured["field_breakdown"]),
        "field_value_verified": field_value_verified,
    }


def author_args(section: dict, opcode_entry: dict, active_nsid: int,
                 prior_steps: list[dict] | None = None, rejected: dict | None = None,
                 device_facts: str | None = None, required_field_values: list[dict] | None = None) -> dict:
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
        top_k=4, doc_filter=[section["spec_doc"]])
    if not rag["chunks"]:
        raise ArgsAuthoringError(f"no spec context found for {opcode_entry['name']}")

    prompt = (
        f"command={opcode_entry['name']} opcode={opcode_entry['raw_opcode']} "
        f"command_set={opcode_entry['command_set']} clause={section['section_id']} "
        f"active_nsid={active_nsid}\n\n"
        "spec_context=\n" + "\n\n".join(c["text"] for c in rag["chunks"])
    )
    if device_facts:
        prompt += f"\n\ndevice_facts=\n{device_facts}"
    if required_field_values:
        values_str = ", ".join(f"{e['field_name']}={e['hex_value']}" for e in required_field_values)
        prompt += f"\n\nrequired_field_value={values_str}"
    if prior_steps:
        lines = "\n".join(
            f"  step{p['step']}({p['phase']}, {p['opcode_name']}): {p['facts']}"
            for p in prior_steps if p.get("facts")
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
            "Pick different, explicitly-defined field values — a reserved or unsupported "
            "identifier in any field causes exactly this rejection."
        )
    try:
        return _author_once(prompt, opcode_entry, active_nsid, required_field_values=required_field_values)
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
        return _author_once(retry_prompt, opcode_entry, active_nsid, required_field_values=required_field_values)
