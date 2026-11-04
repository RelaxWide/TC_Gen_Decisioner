"""Deterministic encodings checked against the local NVMe specification tables."""
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
    else:
        return
    if length != required or direction == "none":
        message = (f"{opcode_entry['name']}: {encoded} -> {required} bytes, but data_len={length} "
                   f"direction={direction}. Make them agree: data_len={required} with direction=read/write "
                   "as the opcode requires")
        if fix and length != required:
            message += f", or for data_len={length} set {fix} (keep the other bits)"
        raise ValueError(message)
