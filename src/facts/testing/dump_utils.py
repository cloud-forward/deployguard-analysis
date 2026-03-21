from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from src.facts.canonical_fact import Fact


def ensure_dir(path: str | Path) -> Path:
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p


def write_json(path: str | Path, payload: Any) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2, sort_keys=True)


def facts_to_stable_list(facts: list[Fact]) -> list[dict[str, Any]]:
    rows = [f.to_stable_dict() for f in facts]
    return sorted(
        rows,
        key=lambda x: (
            x["fact_type"],
            x["subject_id"],
            x["object_id"],
            json.dumps(x["metadata"], sort_keys=True, ensure_ascii=False),
        ),
    )