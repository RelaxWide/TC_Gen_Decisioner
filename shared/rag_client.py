"""Real local search over the RAG index checked into `rag/index/` — no
network call, no credentials needed (unlike the LLM completion side, which
still goes through the dummy client until real credentials are filled into
`rag/srag_llm_guide.py`). See `shared/spec_chunks.py` for the search itself.

Falls back to an empty, clearly-labeled result if the index isn't present —
callers already treat zero chunks as a valid (if unhelpful) answer.
"""
from shared.ids import stable_id
from shared.spec_chunks import search_chunks


def generate_rag_response(user_prompt: str, *, top_k: int = 5, doc_filter: list[str] | None = None) -> dict:
    response_id = stable_id("rag", user_prompt, str(top_k), str(doc_filter))
    chunks = search_chunks(user_prompt, top_k=top_k, doc_filter=doc_filter)
    return {
        "response_id": response_id,
        "query": user_prompt,
        "chunks": chunks,
        "is_dummy": False,
    }
