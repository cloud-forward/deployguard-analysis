from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.facts.testing.harness import FactPipelineHarness
from src.facts.testing.diff_utils import compare_run_dirs


def _load(path: Path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


@pytest.mark.asyncio
async def test_fact_harness_deterministic(tmp_path: Path):
    fixture_dir = Path("tests/fixtures/fact_pipeline/sample_case")

    k8s_scan = _load(fixture_dir / "k8s.json")
    aws_scan = _load(fixture_dir / "aws.json")

    image_file = fixture_dir / "image.json"
    image_scan = _load(image_file) if image_file.exists() else None

    harness = FactPipelineHarness()

    run1 = tmp_path / "run1"
    run2 = tmp_path / "run2"

    await harness.run(
        k8s_scan=k8s_scan,
        aws_scan=aws_scan,
        image_scan=image_scan,
        output_dir=run1,
    )
    await harness.run(
        k8s_scan=k8s_scan,
        aws_scan=aws_scan,
        image_scan=image_scan,
        output_dir=run2,
    )

    diff = compare_run_dirs(run1, run2)
    assert diff["is_identical"] is True, diff