import config
from shared.file_store import load_json, save_json_atomic


def load_all() -> list[dict]:
    return load_json(config.TC_STORE_PATH, default=[])


def save_all(records: list[dict]) -> None:
    save_json_atomic(config.TC_STORE_PATH, records)


def upsert(record: dict) -> None:
    records = load_all()
    records = [r for r in records if r["tc_id"] != record["tc_id"]]
    records.append(record)
    save_all(records)
