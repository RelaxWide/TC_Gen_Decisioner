import logging
import requests
import json
from openai import OpenAI
import uuid

# 템플릿: 이 파일을 rag/srag_llm_guide.py로 복사해서 아래 값을 채운다.
# srag_llm_guide.py는 .gitignore 대상 — 크레덴셜이 들어가므로 절대 커밋하지 말 것.
#
# 직접 채워서 쓸 값들. .env/set_key 거치지 않음 — import될 때마다 외부 파일을
# 덮어쓰는 문제를 피하려고 여기 그대로 박아넣는다.
OPENAI_API_KEY = ""
credential_key = ""
send_system_name = "QA-PC-LLM"
model = ""
api_base_url = ""  # DS API HUB에서 발급 받은 stg / prod 주소, v1 까지만 적기
user_id = ""
user_pw = ""

rag_api_key = ""
rag_credential_key = ""
index_name = ""
search_url = ""

# =========================================================
# LLM과 통신할 대상 생성
# =========================================================
client = OpenAI(
    api_key = OPENAI_API_KEY,
    base_url = api_base_url,
    default_headers = {"x-dep-ticket": credential_key,
        "Send-System-Name": send_system_name,
        "User-Id": '',
        "User-Type": "", # 유저 AD ID
        "Prompt-Msg-Id": str(uuid.uuid4()),
        "Completion-Msg-Id": str(uuid.uuid4()),
    }
)

_rag_query_log = logging.getLogger(__name__)
_RAG_QUERY_START, _RAG_QUERY_END = '[RAG-QUERY]', '[/RAG-QUERY]'
_RAG_QUERY_MAX_CHARS = 1024
_RAG_QUERY_MAX_BYTES = 2048
_RAG_QUERY_FALLBACK = 'NVMe command requirements, field relationships, state transitions and error completion status.'

class _rag_RagSearchError(RuntimeError):
    """Search failure which must not be represented as an empty successful search."""
    def __init__(self, message, retryable=False, error_code=None):
        super().__init__(message)
        self.retryable = retryable
        self.error_code = error_code

def _rag_extract_query(prompt):
    if prompt.count(_RAG_QUERY_START) == 1 and prompt.count(_RAG_QUERY_END) == 1:
        start = prompt.index(_RAG_QUERY_START) + len(_RAG_QUERY_START)
        end = prompt.index(_RAG_QUERY_END)
        if end > start and prompt[start:end].strip():
            return prompt[start:end].strip(), 'marker'
    _rag_query_log.warning('[RAG query] missing/invalid marker; using short generic NVMe query')
    return _RAG_QUERY_FALLBACK, 'generic'


def _rag_prepare_query(prompt):
    query, mode = _rag_extract_query(prompt)
    before = len(query)
    # These are character/UTF-8 byte limits, not estimated token counts.
    query = query[:_RAG_QUERY_MAX_CHARS].encode('utf-8')[:_RAG_QUERY_MAX_BYTES].decode('utf-8', errors='ignore').strip()
    _rag_query_log.warning('[RAG query] mode=%s chars=%d->%d bytes=%d tokenizer=none',
                           mode, before, len(query), len(query.encode('utf-8')))
    return query


def _rag_extract_search_context(response):
    status = response.status_code
    try:
        result = response.json()
    except (ValueError, TypeError) as exc:
        raise _rag_RagSearchError(f'RAG search HTTP {status}: invalid JSON',
                             retryable=status == 429 or status >= 500) from exc
    if not isinstance(result, dict):
        raise _rag_RagSearchError(f'RAG search HTTP {status}: expected JSON object')
    code = result.get('error_code')
    if not 200 <= status < 300 or code or result.get('error'):
        details = {key: result[key] for key in
                   ('error_code', 'query_tokens', 'max_tokens', 'embedding_model') if key in result}
        if isinstance(result.get('message'), str):
            details['message'] = result['message'][:500]
        raise _rag_RagSearchError(f'RAG search HTTP {status}: {details or "server error"}',
                             retryable=code != 'QUERY_TOKEN_LIMIT_EXCEEDED' and
                             (status == 429 or status >= 500), error_code=code)
    envelope = result.get('hits')
    if not isinstance(envelope, dict) or not isinstance(envelope.get('hits'), list):
        raise _rag_RagSearchError('RAG search malformed response: expected hits.hits array')
    hits = envelope['hits']
    if not hits:
        _rag_query_log.warning('[RAG query] no documents; generating with original prompt only')
        return ''
    contexts = []
    for hit in hits:
        source = hit.get('_source') if isinstance(hit, dict) else None
        text = source.get('merge_title_content') if isinstance(source, dict) else None
        if isinstance(text, str):
            contexts.append(text)
    if not contexts:
        raise _rag_RagSearchError('RAG search malformed hit: missing merge_title_content string')
    return "\n\n---\n\n".join(contexts)


def _rag_generate_with_rag(prompt, retrieve, generate):
    query = _rag_prepare_query(prompt)
    # At most 4 searches: initial query + 3 shorter retries, only for this error.
    for attempt in range(4):
        try:
            context = retrieve(query)
            break
        except _rag_RagSearchError as exc:
            if exc.error_code != 'QUERY_TOKEN_LIMIT_EXCEEDED' or attempt == 3 or len(query) <= 1:
                raise
            shorter = query[:max(1, len(query) // 2)].strip()
            if not shorter:
                raise
            _rag_query_log.warning('[RAG query] server token limit; retry=%d/3 chars=%d->%d',
                                   attempt + 1, len(query), len(shorter))
            query = shorter
    suffix = '\n[참고 문서]\n' + context if context else '\n[RAG 문서 없음]'
    return generate(prompt + suffix)

# =========================================================
# LLM 응답 생성
# =========================================================
def _rag_search(query_text):
    headers = {
        "Content-Type": "application/json",
        "api-key": rag_api_key,
        "x-dep-ticket": rag_credential_key,
    }
    fields = {
        "index_name": index_name,
        "permission_groups": ["rag-public"],
        "query_text": query_text,
        "num_result_doc": 5,
        "fields_exclude": ["v_merge_title_content"],
    }
    response = requests.request("POST", search_url, data=json.dumps(fields), headers=headers)
    return _rag_extract_search_context(response)


def generate_rag_response(user_prompt):
    def _generate(full_prompt):
        completion = client.chat.completions.create(
            model="testmodel",
            messages=[
                {"role": "system", "content": "You are an expert in NVMe SSDs. Please provide answers based on factual technical knowledge."},
                {"role": "user", "content": full_prompt}
            ],
            reasoning_effort="low"
        )
        return completion.choices[0].message.content

    return _rag_generate_with_rag(user_prompt, _rag_search, _generate)