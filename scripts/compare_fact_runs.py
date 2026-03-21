from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import argparse
import json

from src.facts.testing.diff_utils import compare_run_dirs


def main():
    parser = argparse.ArgumentParser(description="Compare two fact harness outputs")
    parser.add_argument("--run-a", required=True)
    parser.add_argument("--run-b", required=True)
    parser.add_argument("--output", required=False)
    args = parser.parse_args()

    diff = compare_run_dirs(args.run_a, args.run_b)

    output_path = Path(args.output) if args.output else Path(args.run_a) / "diff_report.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(diff, f, ensure_ascii=False, indent=2, sort_keys=True)

    print(f"[OK] diff written to {output_path}")
    print(f"is_identical = {diff['is_identical']}")


if __name__ == "__main__":
    main()