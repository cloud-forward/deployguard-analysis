from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import argparse
import asyncio
import json

from src.facts.testing.harness import FactPipelineHarness


def load_json(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


async def _main():
    parser = argparse.ArgumentParser(description="Run Fact pipeline harness from raw fixtures")
    parser.add_argument("--k8s", required=True, help="Path to K8s raw fixture JSON")
    parser.add_argument("--aws", required=True, help="Path to AWS raw fixture JSON")
    parser.add_argument("--image", required=False, help="Path to image raw fixture JSON")
    parser.add_argument("--output", required=True, help="Output directory")
    args = parser.parse_args()

    k8s_scan = load_json(args.k8s)
    aws_scan = load_json(args.aws)
    image_scan = load_json(args.image) if args.image else None

    harness = FactPipelineHarness()
    result = await harness.run(
        k8s_scan=k8s_scan,
        aws_scan=aws_scan,
        image_scan=image_scan,
        output_dir=Path(args.output),
    )

    print("[OK] Fact harness completed")
    print(f"scan_id          = {result.scan_id}")
    print(f"raw_fact_count   = {result.summary['raw_fact_count']}")
    print(f"valid_fact_count = {result.summary['valid_fact_count']}")
    print(f"skipped_count    = {result.summary['skipped_count']}")
    print(f"error_count      = {result.summary['error_count']}")
    print(f"warning_count    = {result.summary['warning_count']}")


if __name__ == "__main__":
    asyncio.run(_main())