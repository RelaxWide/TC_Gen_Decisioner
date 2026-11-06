"""Deterministic encodings checked against the local NVMe specification tables."""
import re
from tc_system.spec_fields import feature_buffer
from tc_system.verification import integer

# (command set, opcode, field name) -> (register, shift, mask).
# Do not infer a register from a field name alone.
SELECTORS = {
    ("ADMIN", 0x02, "Log Page Identifier"): ("cdw10", 0, 0xFF),
    ("ADMIN", 0x02, "Log Identifier"): ("cdw10", 0, 0xFF),
    ("ADMIN", 0x09, "Feature Identifier"): ("cdw10", 0, 0xFF),
    ("ADMIN", 0x0A, "Feature Identifier"): ("cdw10", 0, 0xFF),
    ("ADMIN", 0x06, "CNS"): ("cdw10", 0, 0xFF),
    ("ADMIN", 0x19, "Directive Operation"): ("cdw11", 0, 0xFF),
    ("ADMIN", 0x1A, "Directive Operation"): ("cdw11", 0, 0xFF),
    ("ADMIN", 0x19, "Directive Type"): ("cdw11", 8, 0xFF),
    ("ADMIN", 0x1A, "Directive Type"): ("cdw11", 8, 0xFF),
    ("ADMIN", 0x86, "Action Type"): ("cdw13", 24, 0xFF),
}
# Individual tables in Base: Figures 165, 356, 365, 486, 492, 551, 555,
# 562, 595 and 599. These are opcode-specific, not a global field-name rule.
for command_set, opcodes in (("ADMIN", (0x45, 0x42, 0x41, 0x3E, 0x3D, 0x31, 0x2D, 0x35)),
                             ("NVM", (0x12, 0x1D))):
    for opcode in opcodes:
        SELECTORS[command_set, opcode, "Management Operation"] = ("cdw10", 0, 0xFF)


# Register layouts, from the local spec's command figures ( Get Log
# Page/Identify/Set Features/Create and Delete queue CDW10, Read/Write/
# Verify/Compare/Write Zeroes CDW12, Firmware Commit, Format NVM, Device
# Self-test, Sanitize). Used to show the auditor what was sent and to check a
# step's role text against its encoding.
_NVM_CDW12 = [("cdw12", "NLB(0-based)", 15, 0), ("cdw12", "STC", 24, 24), ("cdw12", "PRINFO", 29, 26),
              ("cdw12", "PRACT", 29, 29), ("cdw12", "FUA", 30, 30), ("cdw12", "LR", 31, 31)]
REGISTER_LAYOUTS = {
    ("ADMIN", 0x02): [("cdw10", "LID", 7, 0), ("cdw10", "LSP", 14, 8), ("cdw10", "RAE", 15, 15),
                               ("cdw10", "NUMDL", 31, 16), ("cdw11", "NUMDU", 15, 0)],
    ("ADMIN", 0x06): [("cdw10", "CNS", 7, 0), ("cdw10", "CNTID", 31, 16)],
    ("ADMIN", 0x09): [("cdw10", "FID", 7, 0), ("cdw10", "SV", 31, 31)],
    ("ADMIN", 0x0A): [("cdw10", "FID", 7, 0), ("cdw10", "SEL", 10, 8)],
    ("ADMIN", 0x10): [("cdw10", "FS", 2, 0), ("cdw10", "CA", 5, 3), ("cdw10", "BPID", 31, 31)],
    ("ADMIN", 0x05): [("cdw10", "QID", 15, 0), ("cdw10", "QSIZE(0-based)", 31, 16),
                               ("cdw11", "PC", 0, 0), ("cdw11", "IEN", 1, 1), ("cdw11", "IV", 31, 16)],
    ("ADMIN", 0x01): [("cdw10", "QID", 15, 0), ("cdw10", "QSIZE(0-based)", 31, 16),
                               ("cdw11", "PC", 0, 0), ("cdw11", "QPRIO", 2, 1), ("cdw11", "CQID", 31, 16)],
    ("ADMIN", 0x00): [("cdw10", "QID", 15, 0)],
    ("ADMIN", 0x04): [("cdw10", "QID", 15, 0)],
    ("ADMIN", 0x14): [("cdw10", "STC", 3, 0)],
    ("ADMIN", 0x80): [("cdw10", "LBAFL", 3, 0), ("cdw10", "MSET", 4, 4), ("cdw10", "PI", 7, 5),
                               ("cdw10", "PIL", 8, 8), ("cdw10", "SES", 11, 9), ("cdw10", "LBAFU", 13, 12)],
    ("ADMIN", 0x84): [("cdw10", "SANACT", 2, 0), ("cdw10", "AUSE", 3, 3), ("cdw10", "OWPASS", 7, 4),
                               ("cdw10", "OIPBP", 8, 8), ("cdw10", "NDAS", 9, 9), ("cdw10", "EMVS", 10, 10)],
    ("NVM", 0x01): _NVM_CDW12 + [("cdw12", "DTYPE", 23, 20)],
    ("NVM", 0x02): _NVM_CDW12, ("NVM", 0x05): _NVM_CDW12, ("NVM", 0x0C): _NVM_CDW12,
    ("NVM", 0x08): [("cdw12", "NLB(0-based)", 15, 0), ("cdw12", "DTYPE", 22, 20), ("cdw12", "NSZ", 23, 23),
                            ("cdw12", "STC", 24, 24), ("cdw12", "DEAC", 25, 25), ("cdw12", "PRINFO", 29, 26),
                            ("cdw12", "PRACT", 29, 29), ("cdw12", "FUA", 30, 30), ("cdw12", "LR", 31, 31)],
    ("NVM", 0x04): [("cdw12", "NLB(0-based)", 15, 0)],
}




def decode_fields(command_set, raw, values):
    """{field: hex value} by REGISTER_LAYOUTS, or None for an unlisted command."""
    layout = REGISTER_LAYOUTS.get((command_set, raw))
    if not layout:
        return None
    out = {}
    try:
        for register, name, hi, lo in layout:
            out[name] = hex((integer(values.get(register, "0x0")) >> lo) & ((1 << (hi - lo + 1)) - 1))
        if command_set == "NVM" and raw in (0x01, 0x02, 0x04, 0x05, 0x08, 0x0C):
            out["SLBA"] = hex(integer(values.get("cdw11", "0x0")) << 32 | integer(values.get("cdw10", "0x0")))
    except (TypeError, ValueError):
        return None
    return out


# Selectors have their own check (verification.selector_in_text).
_ROLE_SKIP = {"LID", "FID", "CNS", "NLB(0-based)", "QSIZE(0-based)", "NUMDL", "NUMDU", "SLBA"}


def _role_value(text):
    text = text.strip().lower()
    if text.endswith("b") and set(text[:-1]) <= {"0", "1"}:
        return int(text[:-1], 2)
    if text.endswith("h"):
        return int(text[:-1], 16)
    return int(text, 0)


def role_field_mismatch(command_set, raw, fields, role):
    """A step's role says NAME=value for a field it encodes otherwise. 2026-11-06:
    a Write Zeroes role said "NSZ=1, DEAC=1" while CDW12=0x01800001 set NSZ and
    STC with DEAC=0; the FAIL that followed was about a command never sent."""
    decoded = decode_fields(command_set, raw, fields)
    if not decoded or not role:
        return None
    wrong = []
    for name, actual in decoded.items():
        if name in _ROLE_SKIP:
            continue
        said = {m for m in re.findall(rf"(?<![A-Za-z]){re.escape(name)}\s*=\s*(0x[0-9a-fA-F]+|[01]+b|[0-9a-fA-F]+h|\d+)"
                                      rf"(?![0-9A-Za-z])", str(role))}
        try:
            values = {_role_value(v) for v in said}
        except ValueError:
            continue
        if len(values) == 1 and values != {int(actual, 16)}:
            wrong.append(f"{name}={next(iter(values))} (encoded {name}={int(actual, 16)})")
    if wrong:
        return ("the step's role says " + ", ".join(wrong) + " - encode the fields the role describes "
                f"(layout: {', '.join(f'{n} {r}[{h}:{l}]' for r, n, h, l in REGISTER_LAYOUTS[command_set, raw])})")
    return None


def verify_selectors(fields, opcode_entry, required):
    if not required:
        return False
    all_checked = True
    for entry in required:
        layout = SELECTORS.get((opcode_entry["command_set"], int(opcode_entry["raw_opcode"], 16),
                                entry["field_name"]))
        if layout is None:
            all_checked = False
            continue
        register, shift, mask = layout
        actual = (integer(fields.get(register, "0x0")) >> shift) & mask
        expected = int(entry["hex_value"], 16)
        if actual != expected:
            raise ValueError(f"clause requires {entry['field_name']}={entry['hex_value']} in "
                             f"{register}[shift={shift}, mask=0x{mask:X}], got 0x{actual:X}")
    return all_checked


# NVM command set, Figure "Opcodes for NVM Commands": the LBA data commands
# and the direction their buffer must move in.
NVM_DATA_COMMANDS = {0x01: "write", 0x02: "read", 0x05: "write"}  # Write, Read, Compare
# NVM commands that address LBAs but move no host buffer.
NVM_NO_DATA_COMMANDS = {0x04, 0x08, 0x0C}  # Write Uncorrectable, Write Zeroes, Verify
LBA_DATA_SIZES = {512 << i for i in range(8)}  # 512 B .. 64 KiB, LBADS 9..16


def _validate_nvm_transfer(fields, opcode_entry, lba_bytes):
    opcode = int(opcode_entry["raw_opcode"], 16)
    length, direction = fields["data_len"], fields["direction"]
    if opcode in NVM_NO_DATA_COMMANDS:
        if length or direction != "none":
            raise ValueError(f"{opcode_entry['name']} transfers no data, got data_len={length} "
                             f"direction={direction}")
        return
    if opcode not in NVM_DATA_COMMANDS:
        return
    blocks = (integer(fields["cdw12"]) & 0xFFFF) + 1  # NLB, 0-based
    if direction != NVM_DATA_COMMANDS[opcode]:
        raise ValueError(f"{opcode_entry['name']} needs direction={NVM_DATA_COMMANDS[opcode]}, "
                         f"got {direction}")
    if lba_bytes:
        if length != blocks * lba_bytes:
            raise ValueError(f"{opcode_entry['name']} NLB={blocks} blocks x {lba_bytes} B LBA = "
                             f"{blocks * lba_bytes} bytes but buffer is {length}")
    # LBA size unknown (device probe failed): the buffer must still be a whole
    # number of plausible LBAs, which rejects e.g. 65,536 blocks into 1 byte.
    elif length % blocks or length // blocks not in LBA_DATA_SIZES:
        raise ValueError(f"{opcode_entry['name']} NLB={blocks} blocks cannot fit a {length}-byte buffer "
                         f"(needs blocks x one of {sorted(LBA_DATA_SIZES)})")


_DIRECTION_BITS = {0b01: "write", 0b10: "read"}  # opcode bits 1:0 (11b bidirectional: left alone)
_NUMD_IN_CDW10 = {0x11, 0x19, 0x1A}  # Firmware Image Download, Directive Send/Receive: CDW10 = NUMD, 0-based


def _fixed_mask(constraints, field):
    mask = 0
    for c in constraints or []:
        if c.get("field") == field:
            mask |= integer(c["mask"])
    return mask


def derive_transfer(fields, opcode_entry, lba_bytes=None, constraints=None):
    """Write the transfer fields the spec determines, instead of rejecting the
    author's arithmetic. Returns what changed, for the terminal and report.

    Replayed against the logged replies (logs/llm_calls.jsonl, 235 replies):
    22 of the 24 that today's checks reject are a length field that disagrees
    with data_len (Get Log Page NUMDL/NUMDU, Directive NUMD) and the other two
    a direction against the opcode's own bits. Both sides are fixed by the
    spec, so the harness computes one from the other, keeping whichever side
    the scenario pinned (field_constraints) or else the one that carries the
    test: the buffer size for dword counts, NLB (the LBA range later steps
    reuse) for Read/Write/Compare. Two pinned sides that disagree are left
    alone for validate_transfer to reject (the scenario contradicts itself)."""
    changes = []

    def put(field, value, why):
        old = fields[field]
        same = old == value if field == "direction" else integer(old) == integer(value)
        if not same:
            new = f"0x{value:08X}" if field.startswith("cdw") else value
            changes.append(f"{field} {old} -> {new} ({why})")
            fields[field] = new

    if opcode_entry.get("host_action") or opcode_entry.get("raw_opcode") is None:
        return changes
    opcode = int(opcode_entry["raw_opcode"], 16)
    cset = opcode_entry["command_set"]
    length = integer(fields["data_len"])
    len_fixed = bool(_fixed_mask(constraints, "data_len"))
    if cset == "ADMIN" and opcode == 0x06:
        put("data_len", 4096, "Identify는 항상 4096B 구조 하나")
        put("direction", "read", "opcode 비트 1:0")
    elif cset == "ADMIN" and opcode == 0x02:
        numd_fixed = bool(_fixed_mask(constraints, "cdw10") & 0xFFFF0000 or _fixed_mask(constraints, "cdw11") & 0xFFFF)
        numd = ((integer(fields["cdw11"]) & 0xFFFF) << 16) | (integer(fields["cdw10"]) >> 16)
        if numd_fixed and len_fixed:
            pass
        elif not numd_fixed and length > 0 and length % 4 == 0:
            want = length // 4 - 1
            put("cdw10", (integer(fields["cdw10"]) & 0xFFFF) | ((want & 0xFFFF) << 16),
                f"NUMDL = data_len {length}B/4 - 1")
            put("cdw11", (integer(fields["cdw11"]) & 0xFFFF0000) | (want >> 16), "NUMDU")
        else:
            put("data_len", (numd + 1) * 4, f"NUMD 0x{numd:X} dwords, 0-based")
        put("direction", "read", "opcode 비트 1:0")
    elif cset == "ADMIN" and opcode in _NUMD_IN_CDW10 and length > 0:
        cdw10_fixed = bool(_fixed_mask(constraints, "cdw10"))
        if cdw10_fixed and not len_fixed:
            put("data_len", (integer(fields["cdw10"]) + 1) * 4, "NUMD = CDW10, 0-based")
        elif not cdw10_fixed and length % 4 == 0:
            put("cdw10", length // 4 - 1, f"NUMD = data_len {length}B/4 - 1")
        put("direction", _DIRECTION_BITS[opcode & 0b11], "opcode 비트 1:0")
    elif cset == "ADMIN" and opcode in (0x09, 0x0A):
        # The buffer is the feature's own structure (measured: a 4-byte
        # buffer for the 4096-byte HMB Attributes crashed nvme-cli).
        c10 = integer(fields["cdw10"])
        fid, sel, is_set = c10 & 0xFF, (c10 >> 8) & 0x7, opcode == 0x09
        size = feature_buffer(fid, is_set, sel, integer(fields["cdw11"]))
        if size is not None and not len_fixed:
            what = f"FID {fid:02X}h {'Set' if is_set else 'Get'} Features"
            put("data_len", size, f"{what} 버퍼 {size}B(스펙 구조 크기)" if size else f"{what}는 버퍼 없음")
            put("direction", ("write" if is_set else "read") if size else "none",
                "opcode 비트 1:0" if size else "버퍼 없음")
        elif integer(fields["data_len"]) > 0:
            put("direction", "write" if is_set else "read", "opcode 비트 1:0")
    elif cset == "NVM" and opcode in NVM_NO_DATA_COMMANDS:
        put("data_len", 0, "이 커맨드는 버퍼가 없음")
        put("direction", "none", "이 커맨드는 버퍼가 없음")
    elif cset == "NVM" and opcode in NVM_DATA_COMMANDS:
        put("direction", NVM_DATA_COMMANDS[opcode], "opcode 비트 1:0")
        nlb_fixed = bool(_fixed_mask(constraints, "cdw12") & 0xFFFF)
        if lba_bytes and not (nlb_fixed and len_fixed):
            if len_fixed and length > 0 and length % lba_bytes == 0:
                put("cdw12", (integer(fields["cdw12"]) & 0xFFFF0000) | (length // lba_bytes - 1),
                    f"NLB = data_len {length}B / LBA {lba_bytes}B - 1")
            elif not len_fixed:
                blocks = (integer(fields["cdw12"]) & 0xFFFF) + 1
                put("data_len", blocks * lba_bytes, f"NLB {blocks}블록 x LBA {lba_bytes}B")
    elif _DIRECTION_BITS.get(opcode & 0b11) and length > 0:
        put("direction", _DIRECTION_BITS[opcode & 0b11], "opcode 비트 1:0")
    return changes


def validate_transfer(fields, opcode_entry, lba_bytes=None):
    """Buffer length/direction implied by the encoded command dwords.

    `lba_bytes` is the in-use LBA data size measured on the target (Identify
    Namespace "in use" format); NVM Read/Write/Compare are checked against it.
    """
    if opcode_entry["command_set"] == "NVM":
        _validate_nvm_transfer(fields, opcode_entry, lba_bytes)
        return
    if opcode_entry["command_set"] != "ADMIN":
        return
    opcode = int(opcode_entry["raw_opcode"], 16)
    length, direction = fields["data_len"], fields["direction"]
    # The message is fed back to the argument author for its one retry, so it
    # says where each field lives and what would agree (measured: NUMDL 0x7F
    # written into CDW11, i.e. NUMDU, asked for 32 MB into a 512-byte buffer,
    # and the retry repeated it because the error only said "33292292 bytes").
    fix = None
    if opcode == 0x02:  # Get Log Page NUMDL/NUMDU, both 0-based together.
        numdu, numdl = integer(fields["cdw11"]) & 0xFFFF, integer(fields["cdw10"]) >> 16
        numd = (numdu << 16) | numdl
        required = (numd + 1) * 4
        encoded = (f"NUMD = NUMDU(CDW11[15:0]=0x{numdu:04X})<<16 | NUMDL(CDW10[31:16]=0x{numdl:04X}) "
                   f"= 0x{numd:X} dwords, 0-based")
        if length > 0 and length % 4 == 0:
            want = length // 4 - 1
            fix = f"CDW10[31:16]=0x{want & 0xFFFF:04X} and CDW11[15:0]=0x{want >> 16:04X}"
    elif opcode in {0x11, 0x19, 0x1A} and direction != "none":
        numd = integer(fields["cdw10"])
        required = (numd + 1) * 4
        encoded = f"NUMD = CDW10 = 0x{numd:X} dwords, 0-based"
        if length > 0 and length % 4 == 0:
            fix = f"CDW10=0x{length // 4 - 1:08X}"
    elif opcode == 0x06:
        required, encoded = 4096, "Identify always returns one 4096-byte data structure"
    elif opcode in (0x09, 0x0A):
        c10 = integer(fields["cdw10"])
        size = feature_buffer(c10 & 0xFF, opcode == 0x09, (c10 >> 8) & 0x7, integer(fields["cdw11"]))
        if size is None or (length == size and (direction == "none") == (size == 0)):
            return
        raise ValueError(f"{opcode_entry['name']} FID {c10 & 0xFF:02X}h moves a {size}-byte buffer"
                         f"{'' if size else ' (none)'}, but data_len={length} direction={direction}")
    else:
        return
    if length != required or direction == "none":
        message = (f"{opcode_entry['name']}: {encoded} -> {required} bytes, but data_len={length} "
                   f"direction={direction}. Make them agree: data_len={required} with direction=read/write "
                   "as the opcode requires")
        if fix and length != required:
            message += f", or for data_len={length} set {fix} (keep the other bits)"
        raise ValueError(message)
