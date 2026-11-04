"""Builds `specs/spec_coverage_index.json` from the real RAG spec index.

Replaces the 15-entry hand-written seed with the actual specification contents.

  sections  — every numbered clause heading in Base / NVM Command Set / MI.
              TCG is excluded: its subject matter is not reachable through
              nvme-cli passthru, so including its 1,241 clauses would cap
              coverage near zero regardless of how much testing is done.
  opcodes   — taken from the specs' own opcode tables, not from memory.

## Why the opcode parsing is defensive

Destructive and firmware-state commands run in the automated loop, so a wrong
name->opcode mapping means issuing a *different* command than intended. Two
real traps were hit while writing this:

  * A loose regex paired `Firmware Commit` with `0Dh` (it is `10h`) because it
    read the opcode from one table row and the name from the next.
  * Lookalike tables use the same row shape: the Feature-ID table lists
    `Write Atomicity Normal 0Ah` (a FID, not an opcode), and a command-support
    table lists `Identify 00h 8.1.9.2 No`.

The discriminator is that a genuine opcode table row carries an M/O/P
requirement flag cell. Rows without one are ignored. On top of that, EXPECTED
below spot-checks known values and the build aborts rather than writing an
index that would send the wrong command.

## Manual supplement

Chunking split some table rows, losing four NVM commands (Flush, Write
Uncorrectable, Dataset Management, Copy). All five NVM opcodes that *did*
parse match the published NVM Command Set table exactly, so those four are
supplied from the same table and labelled `source: "manual_standard_table"` —
distinguishable from parsed entries at a glance. Their clause headings were
confirmed present in the spec text (e.g. `3.3.3 Dataset Management command`).

Run:  python build_spec_index.py
"""
import json
import re
from collections import OrderedDict

import config

# `spec_doc` must stay the chunk-title prefix, not a prettified name: it is fed
# to rag_client's `doc_filter`, which substring-matches it against the chunk
# title ("NVM-Express-Base-Specification-Revision-2.3-..."). A display name like
# "NVMe Base Specification 2.3" matches nothing, so every spec lookup silently
# returns zero chunks. `spec_doc_label` carries the readable name instead.
DOC_PREFIXES = {
    "NVM-Express-Base-Specification": ("base", "NVM-Express-Base-Specification",
                                        "NVMe Base Specification 2.3"),
    "NVM-Express-NVM-Command-Set-Specification": ("nvm", "NVM-Express-NVM-Command-Set-Specification",
                                                   "NVMe NVM Command Set Specification 1.2"),
    "NVM-Express-Management-Interface-Specification": ("mi", "NVM-Express-Management-Interface-Specification",
                                                        "NVMe Management Interface Specification 2.1"),
}
EXCLUDED_PREFIX = "TCG_Storage_Architecture_Core_Spec"

HEADING_RE = re.compile(r"^#{1,6}\s*(\d+(?:\.\d+)*)\s+(.{3,100}?)\s*$", re.M)
ROW_RE = re.compile(r"<tr>(.*?)</tr>", re.S)
CELL_RE = re.compile(r"<td>(.*?)</td>", re.S)
TAG_RE = re.compile(r"<[^>]+>")
OPCODE_CELL_RE = re.compile(r"^([0-9A-Fa-f]{2})h$")
SECTION_REF_RE = re.compile(r"^\d+(?:\.\d+)+$")
COMMAND_NAME_RE = re.compile(r"^[A-Z][A-Za-z0-9 /()\-]{2,48}$")
# "M", "O", "P", or the LaTeX-ish footnote forms the export produces.
FLAG_CELL_RE = re.compile(r"^(?:[MOP]|\$ *[MOP]\^\{?\d+\}? *\$|Note \d+)$")

# Matches the trailing "(<field name> <hex>h)" a spec clause uses to name one
# specific value of an enumerated field — e.g. "SMART / Health Information
# (Log Page Identifier 02h)". No digits allowed in the field-name group and no
# end-anchor: `findall` + requiring EXACTLY ONE match (see `_field_value`) is
# what actually distinguishes a genuine single-value title from the two kinds
# of title that must be skipped instead of mis-parsed — measured against the
# real index: "Potentially Unrecoverable LBAs (Action Type 10h and 11h)" (two
# values in one title; an end-anchored, digit-permitting version of this regex
# swallowed "10h and" as the field name) and "Host Metadata (Feature
# Identifier 7Dh), (Feature Identifier 7Eh), (Feature Identifier 7Fh)" (a
# parent heading listing three children's values in its own title — matching
# only the last one would wrongly link the parent itself to that FID).
FIELD_VALUE_RE = re.compile(r"\(([A-Za-z][A-Za-z /]*?)\s+([0-9A-Fa-f]{1,4})h\)")


def _field_value(title: str) -> tuple[str, str] | None:
    matches = FIELD_VALUE_RE.findall(title.strip())
    return (matches[0][0].strip(), matches[0][1].upper()) if len(matches) == 1 else None


def _ancestor_chain(section_id: str):
    """Yields `section_id`'s ancestors from immediate parent up to the top,
    by stripping trailing dotted clause components — e.g. 'base:5.2.12.1.2'
    yields 'base:5.2.12.1', 'base:5.2.12', 'base:5.2', 'base:5'. Mirrors
    `_nests_under`'s doc-prefixed string convention so a section in one spec
    document never resolves to an "ancestor" in another."""
    doc, _, clause = section_id.partition(":")
    parts = clause.split(".")
    for i in range(len(parts) - 1, 0, -1):
        yield f"{doc}:{'.'.join(parts[:i])}"


def _link(section: dict, opcode_key: str) -> None:
    if opcode_key not in section["related_opcodes"]:
        section["related_opcodes"].append(opcode_key)


def link_field_values(sections: dict) -> None:
    """Fourth linking pass, strictly additive after the three `section_ref`/
    `covers_commands`/`"<name> command"` passes in `build()`: a clause titled
    "... (Log Page Identifier 02h)" etc. names one specific value of an
    enumerated field (Log Page Identifier, Feature Identifier, CNS,
    Management Operation, ...) but is its own section, nested — often two
    levels deep, through an unlinked intermediate grouping clause like
    "Common Log Specific Information" — under the command's own clause.
    Measured: 188 such clauses exist (Get Log Page alone has 42, one per
    LID), and before this pass NONE of them had related_opcodes, so testing
    ANY one LID marked the whole command covered and the other 41 values
    were never offered as targets again.

    Mutates `sections` in place. The fixed-point loop (not a single pass) is
    what lets a 2-level-deep case resolve: e.g. Event Type nested under a
    specific Log Page Identifier leaf needs that LID leaf to have already
    gained related_opcodes (an earlier loop iteration) before an Event Type
    leaf nested under IT can find it as its nearest linked ancestor and
    inherit+extend its field_values chain."""
    changed = True
    while changed:
        changed = False
        for section in sections.values():
            if section["field_values"]:
                continue
            fv = _field_value(section["title"])
            if not fv:
                continue
            for ancestor_id in _ancestor_chain(section["section_id"]):
                ancestor = sections.get(ancestor_id)
                if not ancestor or not ancestor["related_opcodes"]:
                    continue
                for key in ancestor["related_opcodes"]:
                    _link(section, key)
                section["field_values"] = ancestor["field_values"] + [
                    {"field_name": fv[0], "hex_value": f"0x{fv[1].zfill(2)}"}
                ]
                changed = True
                break  # nearest qualifying ancestor only

# NVM rows lost to chunk boundaries. Same published table the parsed rows came
# from; clause numbers verified against the extracted section headings.
MANUAL_NVM = [
    {"name": "Flush", "raw_opcode": "0x00", "section_ref": None},
    {"name": "Write Uncorrectable", "raw_opcode": "0x04", "section_ref": "nvm:3.3.7"},
    {"name": "Dataset Management", "raw_opcode": "0x09", "section_ref": "nvm:3.3.3"},
    {"name": "Copy", "raw_opcode": "0x19", "section_ref": "nvm:3.3.2"},
]

FIRMWARE_STATE_COMMANDS = {"Firmware Commit", "Firmware Image Download"}
DATA_DESTRUCTIVE_COMMANDS = {
    "Format NVM", "Sanitize", "Write", "Write Zeroes", "Write Uncorrectable",
    "Dataset Management", "Copy", "Namespace Management", "Namespace Attachment",
    "Capacity Management", "Sanitize Namespace",
}
# Commands that leave data intact but change host or controller state in ways
# that can break the test environment or lock the drive out. They were all
# classed "safe" by data-destructiveness alone and therefore ran in the very
# first batch, which is the wrong end of the run for them:
#   Security Send   — carries TCG payloads (credential change, RevertSP); can
#                     leave the drive locked with a password nobody holds.
#   Lockdown        — can prohibit execution of further commands/features.
#   Device Self-test— the extended variant runs for hours and times out every
#                     later step in the batch.
#   queue create/delete, Doorbell Buffer Config, Virtualization Management —
#                     the kernel nvme driver owns those queues and registers.
#   Set Features    — the `saved` attribute persists across controller reset.
LOCKOUT_COMMANDS = {"Security Send", "Security Receive", "Lockdown"}
STATE_CHANGING_COMMANDS = {
    "Set Features", "Directive Send", "Device Self-test",
    "Create I/O Submission Queue", "Delete I/O Submission Queue",
    "Create I/O Completion Queue", "Delete I/O Completion Queue",
    "Doorbell Buffer Config", "Virtualization Management",
    "Controller Data Queue", "Migration Send", "Track Send",
}

# Execution order within a run, lowest first. Ordering only — none of these are
# excluded; the sweep is meant to reach all of them.
RISK_SAFE, RISK_STATE, RISK_DATA, RISK_LOCKOUT = 0, 1, 2, 3


def _risk_class(name: str) -> int:
    if name in FIRMWARE_STATE_COMMANDS or name in LOCKOUT_COMMANDS:
        return RISK_LOCKOUT
    if name in DATA_DESTRUCTIVE_COMMANDS:
        return RISK_DATA
    if name in STATE_CHANGING_COMMANDS:
        return RISK_STATE
    return RISK_SAFE
HOST_TO_DEVICE = {
    "Set Features", "Firmware Image Download", "Write", "Compare", "Dataset Management",
    "Security Send", "Directive Send", "Namespace Management", "Format NVM",
    "Track Send", "Migration Send", "I/O Management Send", "Copy",
}
DEVICE_TO_HOST = {
    "Identify", "Get Log Page", "Get Features", "Read", "Security Receive",
    "Directive Receive", "Get LBA Status", "Reservation Report", "Track Receive",
    "Migration Receive", "I/O Management Receive",
}

# Which command set a clause's commands belong to, taken from the specs' own
# top-level clause titles (Base: "5 Admin Command Set", "6 Fabrics Command Set",
# "7 I/O Commands"; NVM: "3 I/O Commands for the NVM Command Set", "4 Admin
# Commands for the NVM Command Set"). Deriving this from the document instead
# of the clause is what made Base-spec I/O commands (Flush at base:7.2) collide
# with admin opcodes of the same number.
# Fabrics (base:6) is deliberately absent: it is a separate command set that
# `nvme admin-passthru` cannot submit. MI is absent for the same reason — a
# different transport entirely — though its clauses still count in coverage.
COMMAND_SET_BY_CLAUSE = {
    ("base", "5"): "ADMIN",
    ("base", "7"): "NVM",
    ("nvm", "3"): "NVM",
    ("nvm", "4"): "ADMIN",
}

# Keyed by (command name, command set) — a command's opcode is only unique
# within its set, and which document defines it is incidental (Flush is an I/O
# command defined in the Base spec).
EXPECTED = {
    ("Identify", "ADMIN"): "0x06",
    ("Get Log Page", "ADMIN"): "0x02",
    ("Set Features", "ADMIN"): "0x09",
    ("Get Features", "ADMIN"): "0x0A",
    ("Abort", "ADMIN"): "0x08",
    ("Firmware Commit", "ADMIN"): "0x10",
    ("Firmware Image Download", "ADMIN"): "0x11",
    ("Format NVM", "ADMIN"): "0x80",
    ("Device Self-test", "ADMIN"): "0x14",
    ("Read", "NVM"): "0x02",
    ("Write", "NVM"): "0x01",
    ("Compare", "NVM"): "0x05",
    ("Verify", "NVM"): "0x0C",
    ("Write Zeroes", "NVM"): "0x08",
    ("Flush", "NVM"): "0x00",
    ("Dataset Management", "NVM"): "0x09",
}


def _clean(cell: str) -> str:
    text = TAG_RE.sub("", cell)
    for entity, char in (("&#x27;", "'"), ("&amp;", "&"), ("&lt;", "<"), ("&gt;", ">")):
        text = text.replace(entity, char)
    return re.sub(r"\s+", " ", text).strip()


def _doc_of(title: str):
    for prefix, (short, match_prefix, label) in DOC_PREFIXES.items():
        if title.startswith(prefix):
            return short, match_prefix, label
    return None, None, None


def _doc_fields(short: str):
    return next((m, l) for _, (s, m, l) in DOC_PREFIXES.items() if s == short)


def load_chunks():
    version = config.RAG_INDEX_CURRENT_PATH.read_text(encoding="utf-8").strip()
    path = config.RAG_INDEX_DIR / version / "chunks.jsonl"
    with path.open(encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()], version


def extract_sections(chunks):
    sections = OrderedDict()
    for chunk in chunks:
        if chunk["title"].startswith(EXCLUDED_PREFIX):
            continue
        short, match_prefix, label = _doc_of(chunk["title"])
        if short is None:
            continue
        covers = list(chunk.get("covers_commands") or [])
        for number, name in HEADING_RE.findall(chunk.get("content", "")):
            key = f"{short}:{number}"
            entry = sections.setdefault(key, {
                "section_id": key, "spec_doc": match_prefix, "spec_doc_label": label,
                "doc": short, "clause": number,
                "title": name.strip(), "related_opcodes": [],
                "chunk_ids": [], "covers_commands": [], "field_values": [],
            })
            if chunk["doc_id"] not in entry["chunk_ids"]:
                entry["chunk_ids"].append(chunk["doc_id"])
            for cmd in covers:
                if cmd not in entry["covers_commands"]:
                    entry["covers_commands"].append(cmd)
    return sections


def extract_opcode_tables(chunks, sections):
    """Rows are accepted only when the clause they cite is titled exactly
    "<name> command".

    The M/O/P flag column alone is not enough: the Log-Page-ID, Feature-ID and
    Fabrics tables all carry one too, and they collided onto the same opcode
    keys (0x02a was simultaneously Get Log Page, Power Management and SMART).
    Requiring an exact "<name> command" clause title removes all three at once —
    Log Page / Feature clauses are titled "... (Log Page Identifier 01h)", and
    Fabrics clauses "Property Set Command and Response". Fabrics must be
    excluded regardless: those are a separate command set that admin-passthru
    cannot submit.
    """
    found = {}
    for chunk in chunks:
        if chunk["title"].startswith(EXCLUDED_PREFIX):
            continue
        short = _doc_of(chunk["title"])[0]
        if short is None:
            continue
        for row in ROW_RE.findall(chunk.get("content", "")):
            cells = [_clean(c) for c in CELL_RE.findall(row)]
            if len(cells) < 3:
                continue
            name, opcode_cell, rest = cells[0], cells[1], cells[2:]
            match = OPCODE_CELL_RE.match(opcode_cell)
            if not match or not COMMAND_NAME_RE.match(name):
                continue
            if not any(FLAG_CELL_RE.match(c) for c in rest):
                continue
            ref = next((c for c in rest if SECTION_REF_RE.match(c)), None)
            if ref is None:
                continue
            section_id = f"{short}:{ref}"
            clause = sections.get(section_id)
            if clause is None:
                continue
            if clause["title"].strip().rstrip(".").lower() != f"{name.lower()} command":
                continue
            command_set = COMMAND_SET_BY_CLAUSE.get((short, ref.split(".")[0]))
            if command_set is None:
                continue  # Fabrics, MI, or a non-command clause
            key = (short, name)
            if key not in found:
                found[key] = {"raw_opcode": f"0x{match.group(1).upper()}",
                               "section_ref": section_id,
                               "command_set": command_set,
                               "source": "parsed_from_spec_table"}
    # Supplement only what no document yielded. Flush, for instance, parses
    # fine from base:7.2 even though the NVM doc's row was lost to chunking.
    already = {(name, info["command_set"]) for (_, name), info in found.items()}
    for entry in MANUAL_NVM:
        if (entry["name"], "NVM") in already:
            continue
        found[("nvm", entry["name"])] = {
            "raw_opcode": entry["raw_opcode"],
            "section_ref": entry["section_ref"],
            "command_set": "NVM",
            "source": "manual_standard_table",
        }
    return found


def find_collisions(opcodes):
    """Two commands sharing one opcode key would make target selection ambiguous
    and could send a different command than the TC names."""
    by_key = {}
    for o in opcodes:
        by_key.setdefault(o["opcode"], []).append(o["name"])
    return {k: v for k, v in by_key.items() if len(v) > 1}


def verify(opcode_table):
    by_name_set = {(name, info["command_set"]): info["raw_opcode"]
                   for (_, name), info in opcode_table.items()}
    problems = []
    for key, expected in EXPECTED.items():
        actual = by_name_set.get(key)
        if actual != expected:
            problems.append(f"  {key[1]} {key[0]!r}: expected {expected}, got {actual}")
    return problems


def build():
    chunks, version = load_chunks()
    sections = extract_sections(chunks)
    opcode_table = extract_opcode_tables(chunks, sections)

    problems = verify(opcode_table)
    if problems:
        raise SystemExit("opcode 표 검증 실패 — 인덱스를 생성하지 않습니다:\n" + "\n".join(problems))

    opcodes = []
    for (doc, name), info in sorted(opcode_table.items(), key=lambda kv: (kv[0][0], kv[1]["raw_opcode"])):
        command_set = info["command_set"]
        direction = ("write" if name in HOST_TO_DEVICE else
                      "read" if name in DEVICE_TO_HOST else "none")
        opcodes.append({
            "opcode": f"{info['raw_opcode']}{'a' if command_set == 'ADMIN' else 'n'}",
            "raw_opcode": info["raw_opcode"],
            "name": name,
            "command_set": command_set,
            "spec_doc": _doc_fields(doc)[0],
            "spec_doc_label": _doc_fields(doc)[1],
            "section_ref": info["section_ref"],
            "direction": direction,
            "destructive": name in DATA_DESTRUCTIVE_COMMANDS,
            "firmware_state": name in FIRMWARE_STATE_COMMANDS,
            "lockout_risk": name in LOCKOUT_COMMANDS,
            "risk_class": _risk_class(name),
            "source": info["source"],
        })

    collisions = find_collisions(opcodes)
    if collisions:
        raise SystemExit("opcode 키 충돌 — 인덱스를 생성하지 않습니다:\n"
                          + "\n".join(f"  {k}: {v}" for k, v in collisions.items()))

    name_to_opcodes = {}
    for o in opcodes:
        name_to_opcodes.setdefault(o["name"].lower(), []).append(o["opcode"])
    opcode_by_key = {o["opcode"]: o for o in opcodes}

    def _nests_under(section_id: str, ancestor_section_id: str) -> bool:
        return section_id == ancestor_section_id or section_id.startswith(ancestor_section_id + ".")

    # The opcode table's own section_ref column is the authoritative link.
    for o in opcodes:
        if o["section_ref"] and o["section_ref"] in sections:
            _link(sections[o["section_ref"]], o["opcode"])
    # covers_commands tags and "<name> command" headings broaden recall, but
    # only within that command's own clause subtree. A chunk's covers_commands
    # tag is set at chunk granularity, and one chunk can span a command's
    # trailing subclauses *and* the next command's own top-level heading (e.g.
    # the chunk for Abort's "5.2.1.2 Command Completion" also contains
    # "5.2.2 Asynchronous Event Request command") while carrying only the
    # first command's tag. Applying that tag to every heading pulled from the
    # chunk — instead of just the ones nested under that command's own
    # section_ref — linked base:5.2.2 (AER's own clause) to Abort's opcode too,
    # so a TC named after Abort ended up sending opcode 0x08 while judging
    # AER's fail criteria. Requiring the heading to nest under the command's
    # verified section_ref removes exactly that class of cross-command leak.
    # "Command Completion" is excluded outright even when correctly nested:
    # it is reused verbatim as a subheading under nearly every command (59
    # occurrences) and its boilerplate prose routinely illustrates the rule
    # with a *different* command's example, so even a correctly-scoped link
    # produces a scenario about the wrong command.
    GENERIC_TITLES = {"Command Completion"}
    for section in sections.values():
        if section["title"].strip() in GENERIC_TITLES:
            continue
        for cmd in section["covers_commands"]:
            for key in name_to_opcodes.get(cmd.lower(), []):
                ref = opcode_by_key[key]["section_ref"]
                if ref and _nests_under(section["section_id"], ref):
                    _link(section, key)
        title_lower = section["title"].lower()
        for cmd_lower, keys in name_to_opcodes.items():
            if len(cmd_lower) > 4 and f"{cmd_lower} command" in title_lower:
                for key in keys:
                    _link(section, key)

    # Fourth pass, strictly additive after the three above — see
    # `link_field_values`'s own docstring for why this needs a fixed-point
    # loop rather than a single pass.
    link_field_values(sections)

    section_list = list(sections.values())
    testable = [s for s in section_list if s["related_opcodes"]]
    field_value_linked = [s for s in section_list if s["field_values"]]
    index = {
        "schema_version": 3,
        "source": "built_from_rag_index",
        "rag_index_version": version,
        "excluded_docs": ["TCG Storage Architecture Core Specification 2.01"],
        "sections": section_list,
        "opcodes": opcodes,
    }
    config.SPEC_COVERAGE_INDEX_PATH.write_text(
        json.dumps(index, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    parsed = sum(1 for o in opcodes if o["source"] == "parsed_from_spec_table")
    print(f"RAG index version : {version}")
    print(f"섹션(조항)         : {len(section_list)}   [TCG 제외 — Base+NVM+MI]")
    print(f"  opcode 연결됨    : {len(testable)}")
    print(f"  세부 값 단위 연결: {len(field_value_linked)}   (LID/FID/CNS/Management Operation 등)")
    print(f"opcode             : {len(opcodes)}   (스펙표 파싱 {parsed} / 표준표 보충 {len(opcodes)-parsed})")
    print(f"  데이터 파괴적    : {sum(1 for o in opcodes if o['destructive'])}")
    print(f"  펌웨어 상태 변경 : {sum(1 for o in opcodes if o['firmware_state'])}")
    print(f"검증               : spot-check {len(EXPECTED)}건 통과")
    print(f"출력               : {config.SPEC_COVERAGE_INDEX_PATH}")


if __name__ == "__main__":
    build()
