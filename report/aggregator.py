from datetime import datetime, timezone

import config
from shared.file_store import load_json
from tc_system.coverage.coverage_state import compute_coverage
from tc_system.coverage.spec_coverage_index import SpecCoverageIndexFile

LOG_SOURCES = ("qst", "pulsefz")


def _judgments(sources):
    failure_contexts_by_id, verdicts_by_source = {}, {}
    for source in sources:
        for fc_path in sorted((config.FAILURE_CONTEXTS_DIR / source).glob("*.json")):
            fc = load_json(fc_path)
            failure_contexts_by_id[fc["failure_context_id"]] = fc
        verdicts = load_json(config.VERDICTS_DIR / f"{source}.json", default=[])
        verdicts_by_source[source] = sorted(verdicts, key=lambda v: v.get("judged_at", ""), reverse=True)
    return verdicts_by_source, failure_contexts_by_id


def build_log_model() -> dict:
    verdicts_by_source, fc_by_id = _judgments(LOG_SOURCES)
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "counts": {source: len(verdicts_by_source[source]) for source in LOG_SOURCES},
        "verdicts_by_source": verdicts_by_source,
        "failure_contexts_by_id": fc_by_id,
    }


def build_tc_model() -> dict:
    tc_records = load_json(config.TC_STORE_PATH, default=[])
    coverage = load_json(config.COVERAGE_STATE_PATH, default=None)
    if config.active_coverage_index_path().exists():
        index = SpecCoverageIndexFile(config.active_coverage_index_path())
        coverage = compute_coverage(index, tc_records, load_json(config.TARGET_SKIPS_PATH, default=[]))
    verdicts_by_source, fc_by_id = _judgments(("tc_exec",))
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "coverage": coverage,
        "tc_records": tc_records,
        "verdicts": verdicts_by_source["tc_exec"],
        "failure_contexts_by_id": fc_by_id,
    }
