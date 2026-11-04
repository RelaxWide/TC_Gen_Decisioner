"""Loads and searches the real RAG index at rag/index/<version>/chunks.jsonl —
969 chunks across the actual NVMe Base/Command Set/MI and TCG spec documents,
105 of them tagged with real command names (`covers_commands`). No network
call, no credentials: this is a static file already checked into the repo.

Lexical search only (substring/token overlap) — the real embedding search
needs `embed_base_url` from the manifest, which isn't reachable from here.
Good enough for command-name-shaped queries; not a replacement for the real
vector search once that's wired in.
"""
import json
import re
from functools import lru_cache

import config



def _resolve_index_dir():
    if not config.RAG_INDEX_CURRENT_PATH.exists():
        return None
    version = config.RAG_INDEX_CURRENT_PATH.read_text(encoding="utf-8").strip()
    index_dir = config.RAG_INDEX_DIR / version
    return index_dir if index_dir.is_dir() else None


@lru_cache(maxsize=1)
def load_chunks() -> list[dict]:
    index_dir = _resolve_index_dir()
    if index_dir is None:
        return []
    chunks_path = index_dir / "chunks.jsonl"
    if not chunks_path.exists():
        return []
    chunks = []
    with chunks_path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                chunks.append(json.loads(line))
    return chunks


def _doc_title(chunk: dict) -> str:
    # title is "<spec doc name>_p<start>-<end>" — strip the page-range suffix.
    return chunk.get("title", "").rsplit("_p", 1)[0]


def _score(chunk: dict, query_terms: list[str]) -> float:
    covers = [c.lower() for c in (chunk.get("covers_commands") or [])]
    title = chunk.get("title", "").lower()
    content = chunk.get("content", "").lower()
    score = 0.0
    for term in query_terms:
        if not term:
            continue
        if any(term in c or c in term for c in covers):
            score += 10.0
        if term in title:
            score += 2.0
        score += min(content.count(term), 5) * 0.2
    return score


def search_chunks(query_text: str, top_k: int = 5, doc_filter: list[str] | None = None) -> list[dict]:
    chunks = load_chunks()
    if not chunks:
        return []
    query_terms = [t for t in query_text.lower().replace("(", " ").replace(")", " ").split() if len(t) > 2]
    scored = []
    for chunk in chunks:
        if doc_filter and not any(d.lower() in _doc_title(chunk).lower() for d in doc_filter):
            continue
        score = _score(chunk, query_terms)
        if score > 0:
            scored.append((score, chunk))
    scored.sort(key=lambda sc: sc[0], reverse=True)
    results = []
    for score, chunk in scored[:top_k]:
        title = _doc_title(chunk)
        prefix = ("nvm" if "NVM-Command-Set" in title else "mi" if "Management-Interface" in title
                  else "base" if "Base-Specification" in title else "tcg")
        sections = [f"{prefix}:{s}" for s in re.findall(r"^#{1,6}\s*(\d+(?:\.\d+)*)\s+", chunk.get("content", ""), re.M)]
        results.append({
            "chunk_id": chunk.get("doc_id"),
            "doc": _doc_title(chunk),
            "section_id": sections[0] if len(sections) == 1 else None,
            "section_ids": sections,
            "title": chunk.get("title"),
            "covers_commands": chunk.get("covers_commands") or [],
            "text": chunk.get("content", ""),
            "score": round(score, 2),
        })
    return results
