from datetime import datetime, timezone


def make_tc_record(*, tc_id, name, source_section_ids, source_opcodes, generated_from,
                    scenario, expectation, steps, status="generated", destructive=False,
                    uses_placeholder_args=True):
    now = datetime.now(timezone.utc).isoformat()
    return {
        "tc_id": tc_id,
        "name": name,
        "destructive": destructive,
        "uses_placeholder_args": uses_placeholder_args,
        "source_section_ids": source_section_ids,
        "source_opcodes": source_opcodes,
        "generated_from": generated_from,
        "scenario": scenario,
        "expectation": expectation,
        "steps": steps,
        "status": status,
        "execution": None,
        "verdict_id": None,
        "created_at": now,
        "updated_at": now,
    }
