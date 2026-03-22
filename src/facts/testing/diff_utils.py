from __future__ import annotations

import json
from pathlib import Path
from typing import Any


COMPARE_FILES = [
    "k8s_raw_facts.json",
    "lateral_raw_facts.json",
    "aws_raw_facts.json",
    "all_raw_facts.json",
    "valid_facts.json",
    "validation_errors.json",
    "summary.json",
    "builder_input.json",
    "cross_domain_bridge_output.json",
]


def compare_run_dirs(run_a: str | Path, run_b: str | Path) -> dict[str, Any]:
    run_a = Path(run_a)
    run_b = Path(run_b)

    result = {
        "run_a": str(run_a),
        "run_b": str(run_b),
        "is_identical": True,
        "files": {},
    }

    for file_name in COMPARE_FILES:
        a_path = run_a / file_name
        b_path = run_b / file_name

        if not a_path.exists() or not b_path.exists():
            result["is_identical"] = False
            result["files"][file_name] = {
                "status": "missing",
                "run_a_exists": a_path.exists(),
                "run_b_exists": b_path.exists(),
            }
            continue

        a_json = _read_json(a_path)
        b_json = _read_json(b_path)

        identical = a_json == b_json
        if not identical:
            result["is_identical"] = False

        result["files"][file_name] = {
            "status": "identical" if identical else "different",
        }

    return result


def _read_json(path: Path) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)