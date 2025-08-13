import os
import json
from typing import Dict, Optional


SNAPSHOT_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "snapshots")


def _ensure_dir() -> None:
    os.makedirs(SNAPSHOT_DIR, exist_ok=True)


def get_snapshot_path(scan_id: str) -> str:
    safe_id = "".join(c for c in scan_id if c.isalnum() or c in ("_", "-"))
    return os.path.join(SNAPSHOT_DIR, f"{safe_id}.json")


def save_snapshot(scan_id: str, data: Dict) -> None:
    _ensure_dir()
    path = get_snapshot_path(scan_id)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def load_snapshot(scan_id: str) -> Optional[Dict]:
    path = get_snapshot_path(scan_id)
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

