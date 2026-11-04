from datetime import datetime, timezone

import config
from shared.file_store import load_json
from tc_system.coverage.coverage_state import compute_coverage
from tc_system.coverage.spec_coverage_index import SpecCoverageIndexFile

SOURCES = ("qst", "pulsefz", "tc_exec")


def build_report_model() -> dict:
    tc_records = load_json(config.TC_STORE_PATH, default=[])

    coverage = load_json(config.COVERAGE_STATE_PATH, default=None)
    if coverage is None and config.active_coverage_index_path().exists():
        index = SpecCoverageIndexFile(config.active_coverage_index_path())
        coverage = compute_coverage(index, tc_records)

    failure_contexts_by_id = {}
    for source in SOURCES:
        for fc_path in sorted((config.FAILURE_CONTEXTS_DIR / source).glob("*.json")):
            fc = load_json(fc_path)
            failure_contexts_by_id[fc["failure_context_id"]] = fc

    verdicts_by_source = {}
    for source in SOURCES:
        verdicts = load_json(config.VERDICTS_DIR / f"{source}.json", default=[])
        verdicts_by_source[source] = sorted(verdicts, key=lambda v: v.get("judged_at", ""), reverse=True)

    counts = {source: len(verdicts_by_source[source]) for source in SOURCES}

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "counts": counts,
        "coverage": coverage,
        "tc_records": tc_records,
        "verdicts_by_source": verdicts_by_source,
        "failure_contexts_by_id": failure_contexts_by_id,
    }
