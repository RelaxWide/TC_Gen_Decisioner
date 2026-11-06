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
        from tc_system.generation.variants import variant_targets
        device = load_json(config.DEVICE_INFO_PATH, default={}) or {}
        variants = variant_targets(index, nsze=device.get("nsze"), lba_bytes=device.get("lba_bytes"))
        coverage = compute_coverage(index, tc_records, load_json(config.TARGET_SKIPS_PATH, default=[]), variants)
    verdicts_by_source, fc_by_id = _judgments(("tc_exec",))
    skips = load_json(config.TARGET_SKIPS_PATH, default=[])
    # Every run writes a manifest, also one that produced no TC (all skipped):
    # the latest run is the latest manifest/record, not the latest TC (review F05).
    candidates = [p.stem for p in config.RUN_MANIFESTS_DIR.glob("*.json")] if config.RUN_MANIFESTS_DIR.exists() else []
    candidates += [t.get("run_id") for t in tc_records] + [s.get("run_id") for s in skips]
    run_id = max((c for c in candidates if c), default=None)
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "coverage": coverage,
        "run_id": run_id,
        "skips": skips,
        "tc_records": tc_records,
        "verdicts": verdicts_by_source["tc_exec"],
        "failure_contexts_by_id": fc_by_id,
    }
