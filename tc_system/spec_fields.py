"""Spec facts the harness applies itself instead of trusting the model with them.

Every table here is checked against the local spec text by
tests/test_spec_fields.py (byte ranges, bit numbers, status codes), so a
wrong entry fails a test instead of silently mis-reading a drive.

Why (2026-11-05 --all run, 191 TCs): the model wrote Identify checks from the
prompt's "OACS 257:256" notation as offset=257, read Security Send support
from OACS bit 3 (it is bit 0), looked for Format NVM in ONCS, wrote KAS at
328 and VWC at 527 - at least 17 TCs were stopped by a precondition the drive
actually met (Security Send, Firmware Commit, Format NVM, Sanitize, Verify,
Compare never ran) and others passed one they did not. Expected statuses
spelled the spec's way (COMPARE_FAILURE, UNRECOVERED_READ_ERROR, INVALID_QUEUE_
IDENTIFIER) never matched nvme-cli's tokens, turning four correct rejections
into FAILs. A 4-byte buffer for the 4096-byte HMB Attributes structure crashed
nvme-cli on the host.
"""
import re

# ---------------------------------------------------------------------------
# Data structures returned by commands: name -> (byte offset, width, bits)
# bits: abbreviation -> bit number or (low, high) bit range, with the names a
# description may use for it. Byte ranges are the spec's "hi:lo" rows.

def _f(offset, width, bits=None, names=()):
    return {"offset": offset, "width": width, "bits": bits or {}, "names": tuple(names)}


def _b(bit, *names):
    return {"bits": bit, "names": names}


ID_CTRL = {
    "MDTS": _f(77, 1, names=("Maximum Data Transfer Size",)),
    "CNTLID": _f(78, 2, names=("Controller ID",)),
    "VER": _f(80, 4),  # "version" appears in many descriptions (log page version, ...)
    "OAES": _f(92, 4, {
        "NSAN": _b(8, "Namespace Attribute Notices"), "FAN": _b(9, "Firmware Activation Notices"),
        "ANACN": _b(11, "Asymmetric Namespace Access Change", "ANA Change"),
        "PLEALCN": _b(12, "Predictable Latency Event Aggregate"), "LSIAN": _b(13, "LBA Status Information Alert"),
        "EGEALCN": _b(14, "Endurance Group Event Aggregate"), "NNSSHDN": _b(15, "Normal NVM Subsystem Shutdown"),
    }, ("Optional Asynchronous Events Supported",)),
    "CTRATT": _f(96, 4, {
        "HIDS": _b(0, "128-bit Host Identifier", "Host Identifier Support"),
        "NOPSPM": _b(1, "Non-Operational Power State Permissive"), "NSETS": _b(2, "NVM Sets"),
        "RRLVLS": _b(3, "Read Recovery Level"), "EGS": _b(4, "Endurance Groups"),
        "PLM": _b(5, "Predictable Latency Mode"), "TBKAS": _b(6, "Traffic Based Keep Alive"),
        "NG": _b(7, "Namespace Granularity"), "SQA": _b(8, "SQ Associations"), "ULIST": _b(9, "UUID List"),
        "MDS": _b(10, "Multi-Domain Subsystem"), "FCM": _b(11, "Fixed Capacity Management"),
        "VCM": _b(12, "Variable Capacity Management"), "DEG": _b(13, "Delete Endurance Group"),
        "DNVMS": _b(14, "Delete NVM Set"), "ELBAS": _b(15, "Extended LBA Format"),
        "FDPS": _b(19, "Flexible Data Placement", "FDP"),
    }, ("Controller Attributes",)),
    "CNTRLTYPE": _f(111, 1, names=("Controller Type",)),
    "OACS": _f(256, 2, {
        "SSRS": _b(0, "Security Send", "Security Receive"), "FNVMS": _b(1, "Format NVM"),
        "FWDS": _b(2, "Firmware Download", "Firmware Commit", "Firmware Image Download"),
        "NMS": _b(3, "Namespace Management"), "DSTS": _b(4, "Device Self-test", "Self-test"),
        "DIRS": _b(5, "Directives", "Directive"), "NSRS": _b(6, "NVMe-MI"),
        "VMS": _b(7, "Virtualization Management"), "DBCS": _b(8, "Doorbell Buffer Config"),
        "GLSS": _b(9, "Get LBA Status"), "CFLS": _b(10, "Lockdown"),
        "HMLMS": _b(11, "Host Managed Live Migration", "Live Migration"),
    }, ("Optional Admin Command Support",)),
    "ACL": _f(258, 1, names=("Abort Command Limit",)),
    "AERL": _f(259, 1, names=("Asynchronous Event Request Limit",)),
    "FRMW": _f(260, 1, {
        "SLOT1RO": _b(0, "Slot 1 is read only", "read only"), "NOFS": _b((1, 3), "Number Of Firmware Slots"),
        "FAWR": _b(4, "Firmware Activation Without Reset"), "SMUD": _b(5, "Support Multiple Update Detection"),
    }, ("Firmware Updates",)),
    "LPA": _f(261, 1, {
        "SMARTS": _b(0, "SMART / Health information log page on a per namespace basis"),
        "CSES": _b(1, "Commands Supported and Effects"), "LPEDS": _b(2, "Extended Data"),
        "TS": _b(3, "Telemetry"), "PELS": _b(4, "Persistent Event Log"),
    }, ("Log Page Attributes",)),
    "ELPE": _f(262, 1, names=("Error Log Page Entries",)),
    "NPSS": _f(263, 1, names=("Number of Power States Support",)),
    "AVSCC": _f(264, 1), "APSTA": _f(265, 1, names=("Autonomous Power State Transition Attributes",)),
    "WCTEMP": _f(266, 2, names=("Warning Composite Temperature Threshold",)),
    "CCTEMP": _f(268, 2, names=("Critical Composite Temperature Threshold",)),
    "MTFA": _f(270, 2), "HMPRE": _f(272, 4, names=("Host Memory Buffer Preferred Size",)),
    "HMMIN": _f(276, 4, names=("Host Memory Buffer Minimum Size",)),
    "RPMBS": _f(312, 4), "EDSTT": _f(316, 2, names=("Extended Device Self-test Time",)),
    "DSTO": _f(318, 1), "FWUG": _f(319, 1), "KAS": _f(320, 2, names=("Keep Alive Support",)),
    "HCTMA": _f(322, 2, {"HCTMS": _b(0, "Host Controlled Thermal Management")},
                ("Host Controlled Thermal Management Attributes",)),
    "MNTMT": _f(324, 2), "MXTMT": _f(326, 2),
    "SANICAP": _f(328, 4, {
        "CES": _b(0, "Crypto Erase"), "BES": _b(1, "Block Erase"), "OWS": _b(2, "Overwrite"),
        "NDI": _b(29, "No-Deallocate Inhibited"), "NODMMAS": _b((30, 31), "No-Deallocate Modifies Media"),
    }, ("Sanitize Capabilities",)),
    "HMMINDS": _f(332, 4), "HMMAXD": _f(336, 2), "NSETIDMAX": _f(338, 2), "ENDGIDMAX": _f(340, 2),
    "ANATT": _f(342, 1), "ANACAP": _f(343, 1), "ANAGRPMAX": _f(344, 4), "NANAGRPID": _f(348, 4),
    "SQES": _f(512, 1), "CQES": _f(513, 1), "MAXCMD": _f(514, 2),
    "NN": _f(516, 4, names=("Number of Namespaces",)),
    "ONCS": _f(520, 2, {
        "NVMCMPS": _b(0, "Compare"), "NVMWUSV": _b(1, "Write Uncorrectable"),
        "NVMDSMSV": _b(2, "Dataset Management"), "NVMWZSV": _b(3, "Write Zeroes"),
        "SSFS": _b(4, "Save and Select", "Save/Select"), "RESERVS": _b(5, "Reservation"),
        "TSS": _b(6, "Timestamp"), "NVMVFYS": _b(7, "Verify"), "NVMCPYS": _b(8, "Copy"),
    }, ("Optional NVM Command Support",)),
    "FUSES": _f(522, 2), "FNA": _f(524, 1, names=("Format NVM Attributes",)),
    "VWC": _f(525, 1, {"VWCP": _b(0, "Volatile Write Cache Present")}, ("Volatile Write Cache",)),
    "AWUN": _f(526, 2, names=("Atomic Write Unit Normal",)),
    "AWUPF": _f(528, 2, names=("Atomic Write Unit Power Fail",)),
    "ICSVSCC": _f(530, 1), "NWPC": _f(531, 1, names=("Namespace Write Protection Capabilities",)),
    "ACWU": _f(532, 2), "SGLS": _f(536, 4), "MNAN": _f(540, 4),
}

# Identify Namespace, NVM Command Set (CNS 00h).
ID_NS = {
    "NSZE": _f(0, 8, names=("Namespace Size",)), "NCAP": _f(8, 8, names=("Namespace Capacity",)),
    "NUSE": _f(16, 8, names=("Namespace Utilization",)),
    "NSFEAT": _f(24, 1, {"THINP": _b(0, "thin provisioning"), "DAE": _b(2, "Deallocated or Unwritten Logical Block Error"),
                         "UIDREUSE": _b(3, "NGUID and EUI64 fields if non-zero are never reused")},
                 ("Namespace Features",)),
    "NLBAF": _f(25, 1, names=("Number of LBA Formats",)),
    "FLBAS": _f(26, 1, names=("Formatted LBA Size",)), "MC": _f(27, 1, names=("Metadata Capabilities",)),
    "DPC": _f(28, 1, names=("End-to-end Data Protection Capabilities",)),
    "DPS": _f(29, 1, names=("End-to-end Data Protection Type Settings",)),
    "NMIC": _f(30, 1, {"SHRNS": _b(0, "shared namespace"), "DISNS": _b(1, "Dispersed Namespace")},
               ("Namespace Multi-path I/O and Namespace Sharing Capabilities",)),
    "RESCAP": _f(31, 1, names=("Reservation Capabilities",)), "FPI": _f(32, 1, names=("Format Progress Indicator",)),
    "DLFEAT": _f(33, 1, names=("Deallocate Logical Block Features",)),
    "NAWUN": _f(34, 2), "NAWUPF": _f(36, 2), "NACWU": _f(38, 2), "NABSN": _f(40, 2), "NABO": _f(42, 2),
    "NABSPF": _f(44, 2), "NOIOB": _f(46, 2), "NPWG": _f(64, 2), "NPWA": _f(66, 2), "NPDG": _f(68, 2),
    "NPDA": _f(70, 2), "NOWS": _f(72, 2), "ANAGRPID": _f(92, 4), "NSATTR": _f(99, 1),
    "NVMSETID": _f(100, 2), "ENDGID": _f(102, 2), "EUI64": _f(120, 8), "LBAF0": _f(128, 4),
}

STRUCTURES = {"id_ctrl": ("Identify Controller (CNS 01h)", ID_CTRL),
              "id_ns": ("Identify Namespace (CNS 00h)", ID_NS)}
# One 4-byte entry per identifier, support bit 0 (Figures 205, 214, 267).
ENTRY_LOGS = {
    "supported_logs": ("Supported Log Pages (LID 00h)", "LSUPP", 0, ("LID", "Log Page Identifier", "Log Identifier")),
    "cse": ("Commands Supported and Effects (LID 05h)", "CSUPP", 0, ("opcode",)),
    "fid_effects": ("FID Supported and Effects (LID 12h)", "FSUPP", 0, ("FID", "Feature Identifier")),
}


def _int(value):
    from tc_system.verification import integer
    return integer(value)


def structure_of(opcode_entry, fields):
    """Which data structure a step returns, from its opcode and the selector
    bits we know (`fields`: cdw10..cdw13 that are fixed), else None."""
    if opcode_entry.get("command_set") != "ADMIN" or opcode_entry.get("host_action"):
        return None
    raw = int(opcode_entry["raw_opcode"], 16)
    if "cdw10" not in fields:
        return None
    sel = _int(fields["cdw10"]) & 0xFF
    if raw == 0x06:
        return {0x01: "id_ctrl", 0x00: "id_ns"}.get(sel)
    if raw == 0x02:
        # Offset into the log must be zero for an entry offset to mean anything.
        if any(_int(fields.get(f, 0)) for f in ("cdw12", "cdw13")):
            return None
        return {0x00: "supported_logs", 0x05: "cse", 0x12: "fid_effects"}.get(sel)
    return None


def _bit_mask(bits):
    lo, hi = bits if isinstance(bits, tuple) else (bits, bits)
    return ((1 << (hi - lo + 1)) - 1) << lo, lo


def resolve_named_check(check, structure):
    """{"field": "OACS.NMS", "value": 1} -> offset/width/mask/value. Also
    {"field": "OACS", "mask": .., "value": ..} and, for entry logs,
    {"field": "LSUPP", "index": "16h", "value": 1}. Returns a new check;
    raises ValueError with a message the scenario retry can act on."""
    name = str(check["field"]).strip()
    out = {k: v for k, v in check.items() if k != "field"}
    out["field"] = name
    if structure in ENTRY_LOGS:
        title, bit_name, bit, _ = ENTRY_LOGS[structure]
        if name.upper() not in (bit_name, f"{bit_name}[{check.get('index')}]") or check.get("index") is None:
            raise ValueError(f"{title} entries are read with {{\"field\": \"{bit_name}\", \"index\": <id>, "
                             f"\"value\": 1|0}}, got field={name!r}")
        index = _int(check["index"])
        base = 1024 if structure == "cse" and str(check.get("set", "")).lower() in ("io", "nvm") else 0
        out.update(offset=base + index * 4, width=4, mask=hex(1 << bit),
                   value=hex((1 << bit) if _int(check.get("value", 1)) else 0))
        return out
    title, table = STRUCTURES[structure]
    field_name, _, bit_name = name.upper().partition(".")
    field = table.get(field_name)
    if field is None:
        other = next((t for s, (t, tab) in STRUCTURES.items() if s != structure and field_name in tab), None)
        hint = f" ({field_name} is in {other})" if other else ""
        raise ValueError(f"{title} has no field {field_name!r}{hint}; known: {', '.join(sorted(table))}")
    out.update(offset=field["offset"], width=field["width"])
    if bit_name:
        bit = field["bits"].get(bit_name)
        if bit is None:
            raise ValueError(f"{field_name} has no bit {bit_name!r}; known: {', '.join(sorted(field['bits']))}")
        mask, shift = _bit_mask(bit["bits"])
        value = _int(check.get("value", 1))
        if value << shift & ~mask:
            raise ValueError(f"{name}: value {value} does not fit its bits")
        out.update(mask=hex(mask), value=hex(value << shift))
    else:
        out.setdefault("mask", hex((1 << (8 * field["width"])) - 1))
        out.setdefault("value", 0)
    return out


def interpret_check(check, structure):
    """What a data_field check on `structure` actually reads:
    {"label": "OACS bit 3 (NMS)", "field": "OACS", "bits": {"NMS"}, "error": str|None}."""
    try:
        offset, width, mask = _int(check["offset"]), _int(check["width"]), _int(check.get("mask", 0))
    except (KeyError, TypeError, ValueError):
        return None
    if structure in ENTRY_LOGS:
        title, bit_name, bit, _ = ENTRY_LOGS[structure]
        base = 1024 if structure == "cse" and offset >= 1024 else 0
        limit = 2048 if structure == "cse" else 1024
        index, inner = divmod(offset - base, 4)
        if offset >= limit:
            return {"label": f"{title} byte {offset} (예약 영역)", "field": None, "index": None, "bits": set(),
                    "support_bit": False, "error": None}
        support_bit = inner == 0 and mask << (8 * inner) == 1 << bit
        error = None
        if inner + width > 4:
            error = f"검사식이 {title}의 엔트리 경계를 넘어 읽음(offset {offset}, {width}바이트) — 엔트리는 id×4에서 4바이트"
        label = f"{title} 0x{index:02X} " + (bit_name if support_bit else f"byte {inner} mask {hex(mask)}")
        return {"label": label, "field": bit_name, "index": index, "bits": set(), "support_bit": support_bit,
                "error": error}
    title, table = STRUCTURES[structure]
    lo_byte, hi_byte = offset, offset + width
    hits = [(n, f) for n, f in table.items() if f["offset"] < hi_byte and lo_byte < f["offset"] + f["width"]]
    if not hits:
        return {"label": f"{title} byte {offset}..{offset + width - 1} (등록되지 않은 영역)", "field": None,
                "bits": set(), "error": None}
    if len(hits) > 1:
        names = ", ".join(f"{n}(offset {f['offset']}, {f['width']}B)" for n, f in hits)
        return {"label": names, "field": None, "bits": set(),
                "error": f"검사식(offset {offset}, {width}바이트)이 {title}의 여러 필드에 걸침: {names}"}
    name, field = hits[0]
    # A wider read that starts at the field into unregistered bytes is fine
    # (e.g. 8 zero bytes from LBAF0); one starting inside or before it is not.
    if lo_byte != field["offset"] and (lo_byte < field["offset"] or hi_byte > field["offset"] + field["width"]):
        return {"label": name, "field": name, "bits": set(),
                "error": (f"검사식(offset {offset}, {width}바이트)이 {name} 밖까지 읽음 — {name}은 "
                          f"offset {field['offset']}부터 {field['width']}바이트")}
    in_field = mask << (8 * (lo_byte - field["offset"]))
    bits = {b for b, d in field["bits"].items() if _bit_mask(d["bits"])[0] & in_field}
    exact = {b for b, d in field["bits"].items() if _bit_mask(d["bits"])[0] == in_field}
    if field["bits"] and in_field and in_field & (in_field - 1) == 0:
        bit_no = in_field.bit_length() - 1
        label = f"{name} bit {bit_no}" + (f" ({', '.join(sorted(exact))})" if exact else " (정의되지 않은 비트)")
    else:
        label = f"{name} mask {hex(in_field)}"
    return {"label": label, "field": name, "bits": exact or bits, "error": None}


def _mentions(text, words):
    for word in words:
        pattern = (r"(?<![A-Za-z0-9])" + re.escape(word) + r"(?![A-Za-z0-9])") if word.isupper() and len(word) <= 8 \
            else re.escape(word)
        if re.search(pattern, text, re.I if not word.isupper() else 0):
            return True
    return False


def check_matches_description(check, structure, description, sibling_fields=()):
    """None when the check reads what `description` names, else a Korean
    message. Only names are trusted, not "bit N" in the text (the model got
    both wrong together: "NVMe-MI(OACS 비트 4)"). `sibling_fields` are the
    fields the group's other checks read: a description that names several
    things may be covered by several checks."""
    interp = interpret_check(check, structure)
    if interp is None:
        return None
    if interp["error"]:
        return interp["error"]
    text = str(description or "")
    if structure in ENTRY_LOGS:
        _, _, _, id_words = ENTRY_LOGS[structure]
        wanted = wanted_ids(structure, text)
        if wanted and interp["index"] is not None and (interp["index"] not in wanted or not interp["support_bit"]):
            want = ", ".join(f"0x{w:02X}(offset {w * 4} bit {ENTRY_LOGS[structure][2]})" for w in sorted(wanted))
            return f"설명은 {want}의 지원 여부인데 검사식은 {interp['label']}을 읽음(offset {_int(check['offset'])})"
        return None
    title, table = STRUCTURES[structure]
    field = interp["field"]
    named_fields = {n for n in table if _mentions(text, (n,) + table[n]["names"])}
    elsewhere = [(n, t) for s, (t, tab) in STRUCTURES.items() if s != structure
                 for n in tab if n not in table and _mentions(text, (n,))]
    if field is None:
        if elsewhere and not named_fields:
            n, t = elsewhere[0]
            return f"설명의 {n}은 {t}의 필드인데 이 스텝은 {title}을 반환"
        return None
    if named_fields and field not in named_fields and not (named_fields & set(sibling_fields)):
        others = ", ".join(f"{n}(offset {table[n]['offset']}, {table[n]['width']}B)" for n in sorted(named_fields))
        return f"설명은 {others}인데 검사식은 {interp['label']}을 읽음"
    named_bits = {b for b, d in table[field]["bits"].items() if _mentions(text, (b,) + d["names"])}
    if named_bits and interp["bits"] and not (named_bits & interp["bits"]):
        want = ", ".join(f"{field}.{b}(bit {_bit_mask(table[field]['bits'][b]['bits'])[1]})" for b in sorted(named_bits))
        return f"설명은 {want}인데 검사식은 {interp['label']}을 읽음"
    if named_bits and not interp["bits"] and table[field]["bits"]:
        want = ", ".join(f"{field}.{b}" for b in sorted(named_bits))
        return f"설명은 {want}인데 검사식은 {interp['label']}을 읽음(그 비트가 아님)"
    return None


def wanted_ids(structure, text):
    """The LID/opcode/FID values a description names for an entry log."""
    _, _, _, id_words = ENTRY_LOGS[structure]
    wanted = {int(m, 16) for word in id_words
              for m in re.findall(re.escape(word) + r"\s*(?:=\s*)?(?:0x)?([0-9A-Fa-f]{1,2})h?(?![0-9A-Za-z])",
                                  str(text or ""))}
    if structure == "supported_logs" and len(wanted) > 1:
        wanted.discard(0x00)  # "Supported Log Pages (LID 00h)" names the table itself
    return wanted


def described_target(structure, description, sibling_fields=()):
    """(field, bit or None) when the description names exactly one field
    (and at most one of its bits) of this structure, else None."""
    text = str(description or "")
    _, table = STRUCTURES[structure]
    named = {n for n in table if _mentions(text, (n,) + table[n]["names"])} - set(sibling_fields)
    if not named:
        # Only a bit is named ("Security Send/Receive 지원(SSRS)"): use it if
        # exactly one bit of the whole structure matches.
        hits = [(n, b) for n, f in table.items() if n not in sibling_fields
                for b, d in f["bits"].items() if _mentions(text, (b,) + d["names"])]
        return hits[0] if len(hits) == 1 else None
    if len(named) != 1:
        return None
    name = named.pop()
    bits = {b for b, d in table[name]["bits"].items() if _mentions(text, (b,) + d["names"])}
    if len(bits) > 1:
        return None
    return name, (bits.pop() if bits else None)


def field_catalog_text():
    """Compact list for the scenario prompt."""
    parts = []
    for structure, (title, table) in STRUCTURES.items():
        rows = []
        for name, f in table.items():
            bits = ", ".join(b + "=" + ("%d..%d" % d["bits"] if isinstance(d["bits"], tuple) else str(d["bits"]))
                             for b, d in f["bits"].items())
            rows.append(f"{name}@{f['offset']}+{f['width']}" + (f"[{bits}]" if bits else ""))
        parts.append(f"{title}: " + "; ".join(rows))
    for structure, (title, bit_name, bit, _) in ENTRY_LOGS.items():
        parts.append(f"{title}: field \"{bit_name}\" with \"index\" (4-byte entry at index*4, bit {bit})")
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Completion status codes: (Status Code Type, Status Code). SCT 1/2 values are
# the local spec's Command Specific / Media and Data Integrity tables; SCT 0
# are its Generic Command Status values. Keys are normalized names: the
# nvme-cli token and the spec's own name both map to the same code.
STATUS_CODES = {
    "SUCCESS": (0, 0x00), "INVALID_OPCODE": (0, 0x01), "INVALID_FIELD": (0, 0x02),
    "CMDID_CONFLICT": (0, 0x03), "DATA_XFER_ERROR": (0, 0x04), "POWER_LOSS": (0, 0x05),
    "INTERNAL": (0, 0x06), "ABORT_REQ": (0, 0x07), "ABORT_QUEUE": (0, 0x08), "FUSED_FAIL": (0, 0x09),
    "FUSED_MISSING": (0, 0x0A), "INVALID_NS": (0, 0x0B), "CMD_SEQ_ERROR": (0, 0x0C),
    "SANITIZE_FAILED": (0, 0x1C), "SANITIZE_IN_PROGRESS": (0, 0x1D), "NS_WRITE_PROTECTED": (0, 0x20),
    "CMD_INTERRUPTED": (0, 0x21), "LBA_RANGE": (0, 0x80), "CAP_EXCEEDED": (0, 0x81),
    "NS_NOT_READY": (0, 0x82), "RESERVATION_CONFLICT": (0, 0x83), "FORMAT_IN_PROGRESS": (0, 0x84),
    "CQ_INVALID": (1, 0x00), "QID_INVALID": (1, 0x01), "QUEUE_SIZE": (1, 0x02), "ABORT_LIMIT": (1, 0x03),
    "ASYNC_LIMIT": (1, 0x05), "FIRMWARE_SLOT": (1, 0x06), "FIRMWARE_IMAGE": (1, 0x07),
    "INVALID_VECTOR": (1, 0x08), "INVALID_LOG_PAGE": (1, 0x09), "INVALID_FORMAT": (1, 0x0A),
    "FW_NEEDS_CONV_RESET": (1, 0x0B), "INVALID_QUEUE": (1, 0x0C), "FEATURE_NOT_SAVEABLE": (1, 0x0D),
    "FEATURE_NOT_CHANGEABLE": (1, 0x0E), "FEATURE_NOT_PER_NS": (1, 0x0F),
    "FW_NEEDS_SUBSYS_RESET": (1, 0x10), "FW_NEEDS_RESET": (1, 0x11), "OVERLAPPING_RANGE": (1, 0x14),
    "NS_INSUFFICIENT_CAP": (1, 0x15), "NS_ID_UNAVAILABLE": (1, 0x16), "NS_ALREADY_ATTACHED": (1, 0x18),
    "NS_NOT_ATTACHED": (1, 0x1A), "THIN_PROV_NOT_SUPP": (1, 0x1B), "CTRL_LIST_INVALID": (1, 0x1C),
    "SELF_TEST_IN_PROGRESS": (1, 0x1D), "BP_WRITE_PROHIBITED": (1, 0x1E), "INVALID_CTRL_ID": (1, 0x1F),
    "INVALID_SEC_CTRL_STATE": (1, 0x20), "INVALID_CTRL_RESOURCES": (1, 0x21), "INVALID_RESOURCE_ID": (1, 0x22),
    "IOCS_NOT_SUPPORTED": (1, 0x29), "IOCS_NOT_ENABLED": (1, 0x2A), "INVALID_IOCS": (1, 0x2C),
    "ID_UNAVAILABLE": (1, 0x2D), "INVALID_CONTROLLER_DATA_QUEUE": (1, 0x37), "CONTROLLER_SUSPENDED": (1, 0x39),
    "CONTROLLER_NOT_SUSPENDED": (1, 0x3A), "CONFLICTING_ATTRIBUTES": (1, 0x80),
    "INVALID_PI": (1, 0x81), "READ_ONLY_RANGE": (1, 0x82), "CMD_SIZE_LIMIT_EXCEEDED": (1, 0x83),
    "WRITE_FAULT": (2, 0x80), "READ_ERROR": (2, 0x81), "GUARD_CHECK": (2, 0x82), "APPTAG_CHECK": (2, 0x83),
    "REFTAG_CHECK": (2, 0x84), "COMPARE_FAILED": (2, 0x85), "ACCESS_DENIED": (2, 0x86),
    "UNWRITTEN_BLOCK": (2, 0x87),
}
# Rejections of the command's own parameters: the controller aborts the
# command instead of processing it, so the value it would set is untouched.
# Anything else that is not SUCCESS (Internal Error, Data Transfer Error,
# Command Interrupted, media errors, an unknown code) failed while or after
# processing and says nothing about whether the change took effect (review
# N01: value set 360 -> 300, then INTERNAL; the restore was skipped).
REJECTED_BEFORE_EFFECT = {STATUS_CODES[n] for n in (
    "INVALID_OPCODE", "INVALID_FIELD", "INVALID_NS", "CMD_SEQ_ERROR", "LBA_RANGE", "NS_WRITE_PROTECTED",
    "INVALID_LOG_PAGE", "FEATURE_NOT_SAVEABLE", "FEATURE_NOT_CHANGEABLE", "FEATURE_NOT_PER_NS")}

# The spec's (and the model's) names for the same codes.
STATUS_NAMES = {
    "SUCCESSFUL_COMPLETION": "SUCCESS", "INVALID_COMMAND_OPCODE": "INVALID_OPCODE",
    "INVALID_FIELD_IN_COMMAND": "INVALID_FIELD", "COMMAND_ID_CONFLICT": "CMDID_CONFLICT",
    "DATA_TRANSFER_ERROR": "DATA_XFER_ERROR", "COMMANDS_ABORTED_DUE_TO_POWER_LOSS_NOTIFICATION": "POWER_LOSS",
    "INTERNAL_ERROR": "INTERNAL", "COMMAND_ABORT_REQUESTED": "ABORT_REQ",
    "INVALID_NAMESPACE_OR_FORMAT": "INVALID_NS", "INVALID_NAMESPACE": "INVALID_NS",
    "COMMAND_SEQUENCE_ERROR": "CMD_SEQ_ERROR", "SANITIZE_IN_PROGRESS": "SANITIZE_IN_PROGRESS",
    "NAMESPACE_IS_WRITE_PROTECTED": "NS_WRITE_PROTECTED", "COMMAND_INTERRUPTED": "CMD_INTERRUPTED",
    "LBA_OUT_OF_RANGE": "LBA_RANGE", "CAPACITY_EXCEEDED": "CAP_EXCEEDED", "NAMESPACE_NOT_READY": "NS_NOT_READY",
    "COMPLETION_QUEUE_INVALID": "CQ_INVALID", "INVALID_QUEUE_IDENTIFIER": "QID_INVALID",
    "INVALID_QUEUE_SIZE": "QUEUE_SIZE", "ABORT_COMMAND_LIMIT_EXCEEDED": "ABORT_LIMIT",
    "ASYNCHRONOUS_EVENT_REQUEST_LIMIT_EXCEEDED": "ASYNC_LIMIT", "INVALID_FIRMWARE_SLOT": "FIRMWARE_SLOT",
    "INVALID_FIRMWARE_IMAGE": "FIRMWARE_IMAGE", "INVALID_INTERRUPT_VECTOR": "INVALID_VECTOR",
    "INVALID_LOG_PAGE_IDENTIFIER": "INVALID_LOG_PAGE", "INVALID_QUEUE_DELETION": "INVALID_QUEUE",
    "FEATURE_IDENTIFIER_NOT_SAVEABLE": "FEATURE_NOT_SAVEABLE", "FEATURE_ID_NOT_SAVEABLE": "FEATURE_NOT_SAVEABLE",
    "FEATURE_NOT_NAMESPACE_SPECIFIC": "FEATURE_NOT_PER_NS",
    "NAMESPACE_INSUFFICIENT_CAPACITY": "NS_INSUFFICIENT_CAP", "NAMESPACE_IDENTIFIER_UNAVAILABLE": "NS_ID_UNAVAILABLE",
    "NAMESPACE_ALREADY_ATTACHED": "NS_ALREADY_ATTACHED", "NAMESPACE_NOT_ATTACHED": "NS_NOT_ATTACHED",
    "CONTROLLER_LIST_INVALID": "CTRL_LIST_INVALID", "DEVICE_SELF_TEST_IN_PROGRESS": "SELF_TEST_IN_PROGRESS",
    "INVALID_CONTROLLER_IDENTIFIER": "INVALID_CTRL_ID", "I_O_COMMAND_SET_NOT_SUPPORTED": "IOCS_NOT_SUPPORTED",
    "INVALID_I_O_COMMAND_SET": "INVALID_IOCS", "IDENTIFIER_UNAVAILABLE": "ID_UNAVAILABLE",
    "CTRL_NOT_SUSPENDED": "CONTROLLER_NOT_SUSPENDED", "INVALID_PROTECTION_INFORMATION": "INVALID_PI",
    "ATTEMPTED_WRITE_TO_READ_ONLY_RANGE": "READ_ONLY_RANGE", "UNRECOVERED_READ_ERROR": "READ_ERROR",
    "END_TO_END_GUARD_CHECK_ERROR": "GUARD_CHECK", "COMPARE_FAILURE": "COMPARE_FAILED",
    "DEALLOCATED_OR_UNWRITTEN_LOGICAL_BLOCK": "UNWRITTEN_BLOCK", "INVALID_FORMAT": "INVALID_FORMAT",
}
_STATUS_VALUE_RE = re.compile(r"NVMe status:[^\n]*\((0x[0-9a-fA-F]+)\)")


def normalize_status_name(name):
    token = re.sub(r"[^A-Z0-9]+", "_", str(name or "").upper()).strip("_")
    return STATUS_NAMES.get(token, token)


def status_code_of_name(name):
    return STATUS_CODES.get(normalize_status_name(name))


def status_code_in_output(out):
    """(SCT, SC) from nvme-cli's "NVMe status: X: ...(0x2285)", without the
    CRD/More/DNR flag bits (0x2285 = More + SCT 2 / SC 85h Compare Failure)."""
    match = _STATUS_VALUE_RE.search(str(out or ""))
    if not match:
        return None
    value = int(match[1], 16)
    return (value >> 8) & 0x7, value & 0xFF


# ---------------------------------------------------------------------------
# Get/Set Features data buffers: FID -> (Get bytes, Set bytes). Every other
# listed FID moves no buffer (its value is in CDW11..15 / CQE DW0).
FEATURE_BUFFERS = {
    0x03: (4096, 4096),   # LBA Range Type: 64 entries x 64 bytes
    0x0C: (256, 256),     # Autonomous Power State Transition: 32 x 8 bytes
    0x0D: (4096, 0),      # Host Memory Buffer: Get returns the 4096-byte attributes; Set uses CDW11..15
    0x0E: (8, 8),         # Timestamp
    0x13: (512, 512),     # Predictable Latency Mode Config
    0x16: (512, 512),     # Host Behavior Support
}
FEATURES_WITHOUT_BUFFER = {0x01, 0x02, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0F, 0x10, 0x11,
                           0x12, 0x14, 0x15, 0x17, 0x18, 0x19, 0x1A, 0x1D, 0x80, 0x82, 0x83, 0x84}
HOST_IDENTIFIER_FID = 0x81  # 8 bytes, or 16 when CDW11 EXHID (bit 0) is set

# How to put a feature back: which CDW11 bits hold its value (Get Features
# returns them in CQE DW0 in the same layout), which CDW11 bits name the
# instance (temperature sensor/threshold, interrupt vector, EXHID), whether
# it is per namespace, its data buffer, the bytes Set must send as zero, and
# values that cannot be undone. A FID that is not here is NOT restorable: a
# Set Features expected to succeed on it is not sent. Review (2026-11-05):
# copying DW0 into CDW11 restored PLM Config/Window and Read Recovery Level
# into the wrong register (their value is in CDW12), sent Timestamp's Origin
# attributes into its reserved bytes, and "restored" Permanent Write Protect.
def _codec(name, value=0, instance=0, ns=False, buffer=False, set_reserved=(), irreversible=None, approx=False):
    return {"name": name, "value": value, "instance": instance, "ns": ns, "buffer": buffer,
            "set_reserved": tuple(set_reserved), "irreversible": irreversible or {}, "approx": approx}


FEATURE_CODECS = {
    0x01: _codec("Arbitration", value=0xFFFFFF07),
    0x02: _codec("Power Management", value=0xFF),
    0x04: _codec("Temperature Threshold", value=0xFFFF, instance=0x003F0000),
    0x05: _codec("Error Recovery", value=0x1FFFF, ns=True),
    0x06: _codec("Volatile Write Cache", value=0x1),
    0x08: _codec("Interrupt Coalescing", value=0xFFFF),
    0x09: _codec("Interrupt Vector Configuration", value=0x10000, instance=0xFFFF),
    0x0A: _codec("Write Atomicity Normal", value=0x1),
    0x0B: _codec("Asynchronous Event Configuration", value=0xFFFFFFFF),
    0x0C: _codec("Autonomous Power State Transition", value=0x1, buffer=True),
    # Bytes 7:6 of the Get structure carry Synch/Origin attributes; in Set
    # they are reserved. The original time cannot be restored exactly (time
    # has passed and the Origin becomes "set by host"): approximate.
    0x0E: _codec("Timestamp", buffer=True, set_reserved=[(6, 8)], approx=True),
    0x0F: _codec("Keep Alive Timer", value=0xFFFFFFFF),
    0x10: _codec("Host Controlled Thermal Management", value=0xFFFFFFFF),
    0x11: _codec("Non-Operational Power State Config", value=0x1),
    0x16: _codec("Host Behavior Support", buffer=True),
    0x80: _codec("Software Progress Marker", value=0xFF),
    # 0x81 Host Identifier is NOT here: once non-zero, a Set Features is
    # refused with Command Sequence Error (base:5.2.26.1.32), so it cannot be
    # restored by Set Features alone (review F03).
    0x82: _codec("Reservation Notification Mask", value=0xE, ns=True),
    0x83: _codec("Reservation Persistence", value=0x1, ns=True),
    # WPS 2 (Write Protect Until Power Cycle) and 3 (Permanent Write Protect):
    # once set, Set Features is refused with Feature Not Changeable.
    0x84: _codec("Namespace Write Protection Config", value=0x7, ns=True, irreversible={0x7: {2, 3}}),
}


def irreversible_feature_value(fid, cdw11):
    """Korean reason when this Set Features value cannot be undone, else None."""
    codec = FEATURE_CODECS.get(fid)
    for mask, values in (codec or {}).get("irreversible", {}).items():
        if cdw11 & mask in values:
            return (f"FID {fid:02X}h({codec['name']}) 값 {cdw11 & mask}은 Set Features로 되돌릴 수 없는 상태"
                    "(전원 사이클 또는 영구) — 보내지 않음")
    return None
# Features the Linux driver owns on this host: changing them under it is not a
# device test. Measured: the HMB was enabled (Get Features DW0=1) and a chain
# set out to disable it.
HOST_OWNED_SET_FEATURES = {0x0D: "Host Memory Buffer는 리눅스 nvme 드라이버가 할당·관리"}


def feature_buffer(fid, is_set, sel=0, cdw11=0):
    """Bytes the Get/Set Features data buffer must have, or None if unknown."""
    if not is_set and sel == 0b011:
        return 0  # Supported Capabilities come back in CQE DW0
    if fid == HOST_IDENTIFIER_FID:
        return 16 if cdw11 & 1 else 8
    if fid in FEATURE_BUFFERS:
        return FEATURE_BUFFERS[fid][1 if is_set else 0]
    if fid in FEATURES_WITHOUT_BUFFER:
        return 0
    return None


# ---------------------------------------------------------------------------
# Queues the OS driver owns. Create/Delete I/O SQ/CQ through passthru gives
# the controller no queue memory (PRP1=0) and can take a QID the driver uses.
QUEUE_COMMANDS = {0x00: "Delete I/O Submission Queue", 0x01: "Create I/O Submission Queue",
                  0x04: "Delete I/O Completion Queue", 0x05: "Create I/O Completion Queue"}
# QID 0 is the Admin queue (always invalid here) and no driver allocates this many.
SAFE_INVALID_QID = 0x8000


def queue_command_hazard(command_set, raw_opcode, cdw10, expected_status):
    """Korean reason this queue command must not be sent, else None."""
    if command_set != "ADMIN" or raw_opcode not in QUEUE_COMMANDS:
        return None
    qid = _int(cdw10) & 0xFFFF
    name = QUEUE_COMMANDS[raw_opcode]
    if normalize_status_name(expected_status or "SUCCESS") == "SUCCESS":
        return (f"{name}을 성공으로 기대함 — I/O 큐는 리눅스 드라이버가 소유하고 passthru는 큐 메모리(PRP)를 줄 수 없어 "
                "이 실행기로는 시험할 수 없음")
    if qid != 0 and qid < SAFE_INVALID_QID:
        return (f"{name} QID={qid}: 드라이버가 쓰는 큐일 수 있고 받아들여지면 메모리 주소 0을 큐로 씀 — "
                f"부정 테스트는 QID 0 또는 0x{SAFE_INVALID_QID:X} 이상만 허용")
    return None
