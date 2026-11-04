"""Address specification clauses directly; retain complete tables and citations.

Search is useful for discovery, but cannot establish which clause was tested.
This module reconstructs document order, then follows numbered headings and
explicit section references. A budget omits whole evidence blocks, never the
tail of a field table. Each block carries source chunk IDs and a content hash.
"""
from collections import defaultdict
from functools import lru_cache
import html
import re

from shared.ids import stable_id
from shared.spec_chunks import load_chunks

DOCS = {
    "base": "NVM-Express-Base-Specification",
    "nvm": "NVM-Express-NVM-Command-Set-Specification",
    "mi": "NVM-Express-Management-Interface-Specification",
}
HEADING = re.compile(r"^#{1,6}\s*(\d+(?:\.\d+)*)\s+([^\n]+)$", re.M)


# Character budgets for the evidence block of each prompt. English spec text
# with compacted tables runs at roughly 3.5-4 chars/token, so these keep the
# whole prompt (system prompt + evidence + intent/device facts) under ~10K
# tokens. tests/test_spec_verification.py measures every real target.
SCENARIO_EVIDENCE_CHARS = 20000
ARGS_EVIDENCE_CHARS = 16000
JUDGE_EVIDENCE_CHARS = 14000


def plain_text(text):
    return " ".join(html.unescape(re.sub(r"<[^>]+>", " ", text)).split())


def compact_text(text):
    """HTML tables -> one "| cell | cell" line per row. Same words, far fewer
    tokens; quotes are compared through plain_text so the formatting is moot."""
    text = re.sub(r"<tr[^>]*>", "\n", text, flags=re.I)
    text = re.sub(r"<t[dh][^>]*>", " | ", text, flags=re.I)
    text = html.unescape(re.sub(r"<[^>]+>", "", text))
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r" *\n *", "\n", text)
    return re.sub(r"\n{3,}", "\n\n", text).strip()


def _fit(text, budget):
    """Whole lines (paragraphs / table rows) up to the budget, never a cut row."""
    if len(text) <= budget:
        return text
    kept, used = [], 0
    for line in text.split("\n"):
        if used + len(line) + 1 > budget:
            break
        kept.append(line)
        used += len(line) + 1
    return "\n".join(kept).rstrip()


def _order(chunk):
    page = re.search(r"_p(\d+)-", chunk.get("title", ""))
    suffix = chunk.get("doc_id", "").rsplit("#", 1)[-1]
    return (int(page[1]) if page else 0, int(suffix) if suffix.isdigit() else 0)


@lru_cache(maxsize=1)
def clause_catalog():
    grouped = defaultdict(list)
    for chunk in load_chunks():
        for doc, prefix in DOCS.items():
            if chunk.get("title", "").startswith(prefix):
                grouped[doc].append(chunk)
                break
    catalog = {}
    for doc, chunks in grouped.items():
        parts, spans, offset = [], [], 0
        for chunk in sorted(chunks, key=_order):
            text = chunk.get("content", "") + "\n"
            parts.append(text)
            spans.append((offset, offset + len(text), chunk["doc_id"]))
            offset += len(text)
        text = "".join(parts)
        headings = list(HEADING.finditer(text))
        for i, match in enumerate(headings):
            end = headings[i + 1].start() if i + 1 < len(headings) else len(text)
            body = compact_text(text[match.start():end])
            sid = f"{doc}:{match[1]}"
            block = {"section_id": sid, "doc": DOCS[doc], "title": match[2].strip(),
                     "text": body, "chunk_ids": [cid for a, b, cid in spans
                                                  if a < end and b > match.start()],
                     "evidence_id": stable_id("spec", sid, body)}
            # Repeated TOC headings must not replace the substantive clause.
            if sid not in catalog or len(body) > len(catalog[sid]["text"]):
                catalog[sid] = block
    return catalog


def _layout_keys(catalog, layout_ref):
    """The command's own clause: its body, plus direct children that define
    Command Dwords when the body is only a heading (Identify's layout lives in
    "Identify command overview")."""
    if not layout_ref or layout_ref not in catalog:
        return []
    keys = [layout_ref]
    if "Command Dword" not in catalog[layout_ref]["text"]:
        depth = layout_ref.count(".") + 1
        keys += [k for k in catalog if k.startswith(layout_ref + ".") and k.count(".") == depth
                 and "Command Dword" in catalog[k]["text"]]
    return keys


def section_evidence(section, command_name=None, max_chars=SCENARIO_EVIDENCE_CHARS,
                     layout_ref=None, purpose="scenario"):
    """`purpose="scenario"`: target clause, the command layout, descendants and
    explicit references. `purpose="args"`: the command layout first (what the
    encoding needs), then the target clause; nothing else.

    A block that does not fit whole is omitted, except the target and layout
    blocks, which keep whole leading lines and are marked truncated, so a 133K
    Identify Controller table still yields a usable, honest excerpt."""
    catalog = clause_catalog()
    sid = section["section_id"]
    if sid not in catalog:
        return {"chunks": [], "complete": False, "missing": [sid], "omitted_sections": [],
                "truncated_sections": [], "response_id": stable_id("rag-section", sid, "missing")}
    selected, seen, omitted, truncated = [], set(), [], []
    used = 0

    def add(key, role, may_truncate=False):
        nonlocal used
        if key in seen or key not in catalog:
            return
        seen.add(key)
        block = catalog[key]
        room = max_chars - used
        if len(block["text"]) > room:
            text = _fit(block["text"], room) if may_truncate else ""
            if not text:
                omitted.append(key)
                return
            truncated.append(key)
            block = dict(block, text=text, truncated=True,
                         evidence_id=stable_id("spec", key, text))
        selected.append(dict(block, role=role, chunk_id=block["chunk_ids"][0]))
        used += len(block["text"])

    layout = [k for k in _layout_keys(catalog, layout_ref) if k != sid]
    if purpose == "args":
        for key in layout:
            add(key, "command_layout", may_truncate=True)
        add(sid, "target", may_truncate=True)
    else:
        add(sid, "target", may_truncate=True)
        for key in layout:
            add(key, "command_layout", may_truncate=True)
        # Immediate body + descendants: command overview and tables often live in
        # the first child, while a leaf's continuation may span several chunks.
        for key in catalog:
            if key.startswith(sid + "."):
                add(key, "target")
        # Cross-spec indirection (e.g. Base NVMe-MI Send refers to the MI spec).
        root_text = catalog[sid]["text"]
        if "Management Interface Specification" in root_text and command_name:
            for key, block in catalog.items():
                if key.startswith("mi:") and block["title"].casefold() == (command_name + " command").casefold():
                    add(key, "reference")
                    for child in catalog:
                        if child.startswith(key + "."):
                            add(child, "reference")
        # Follow explicit numbered references, not arbitrary command-name hits.
        for block in list(selected):
            prefix = block["section_id"].split(":")[0]
            for ref in re.findall(r"(?:section|Section)\s+(\d+(?:\.\d+)+)", block["text"]):
                add(f"{prefix}:{ref}", "reference")
    return {"chunks": selected, "complete": not omitted and not truncated,
            "omitted_sections": omitted, "truncated_sections": truncated,
            "response_id": stable_id("rag-section", sid, purpose, *(b["evidence_id"] for b in selected))}


def limit_evidence(chunks, max_chars, min_excerpt=1000):
    """Blocks in order up to the budget. One that does not fit keeps its whole
    leading lines when at least `min_excerpt` chars of room remain."""
    kept, used = [], 0
    for chunk in chunks or []:
        text = chunk.get("text", "")
        room = max_chars - used
        if len(text) > room:
            text = _fit(text, room) if room >= min_excerpt else ""
            if not text:
                continue
            chunk = dict(chunk, text=text, truncated=True)
        kept.append(chunk)
        used += len(text)
    return kept


def format_evidence(chunks):
    return "\n\n".join(
        f"[evidence_id={c.get('evidence_id', '')} section={c.get('section_id', '')} "
        f"role={c.get('role', 'reference')}]\n{c['text']}" for c in chunks)
