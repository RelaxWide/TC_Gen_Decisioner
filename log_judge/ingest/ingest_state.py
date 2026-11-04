from pathlib import Path

from shared.file_store import load_json, save_json_atomic


def load_manifest(state_path) -> dict:
    return load_json(state_path, default={})


def is_processed(manifest: dict, path: Path) -> bool:
    entry = manifest.get(str(path))
    if entry is None:
        return False
    stat = path.stat()
    return entry.get("mtime") == stat.st_mtime and entry.get("size") == stat.st_size


def mark_processed(manifest: dict, path: Path, extra: dict | None = None) -> None:
    stat = path.stat()
    manifest[str(path)] = {"mtime": stat.st_mtime, "size": stat.st_size, **(extra or {})}


def save_manifest(state_path, manifest: dict) -> None:
    save_json_atomic(state_path, manifest)
