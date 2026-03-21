from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional

from src.facts.orchestrator import FactOrchestrator
from src.facts.testing.dump_utils import ensure_dir, write_json, facts_to_stable_list


class FactPipelineHarness:
    """
    Final-direction harness:
    - does NOT reimplement the pipeline
    - uses FactOrchestrator.extract_all_debug()
    - only dumps / verifies / compares
    """

    def __init__(self):
        self.orchestrator = FactOrchestrator()

    async def run(
        self,
        *,
        k8s_scan: Dict[str, Any],
        aws_scan: Dict[str, Any],
        image_scan: Optional[Dict[str, Any]] = None,
        output_dir: str | Path,
        db_session=None,
        analysis_job_id: Optional[str] = None,
    ):
        debug_result = await self.orchestrator.extract_all_debug(
            k8s_scan=k8s_scan,
            aws_scan=aws_scan,
            image_scan=image_scan,
        )

        output_path = ensure_dir(output_dir)

        write_json(output_path / "k8s_raw_facts.json", facts_to_stable_list(debug_result.k8s_raw_facts))
        write_json(output_path / "lateral_raw_facts.json", facts_to_stable_list(debug_result.lateral_raw_facts))
        write_json(output_path / "aws_raw_facts.json", facts_to_stable_list(debug_result.aws_raw_facts))
        write_json(output_path / "all_raw_facts.json", facts_to_stable_list(debug_result.all_raw_facts))
        write_json(output_path / "valid_facts.json", facts_to_stable_list(debug_result.valid_facts))
        write_json(output_path / "validation_errors.json", debug_result.validation_errors)
        write_json(output_path / "summary.json", debug_result.summary)
        write_json(
            output_path / "builder_input.json",
            {
                "facts": facts_to_stable_list(debug_result.valid_facts),
                "fact_count": len(debug_result.valid_facts),
            },
        )
        write_json(output_path / "cross_domain_bridge_output.json", debug_result.bridge_output)

        if db_session is not None:
            from src.facts.testing.db_verify import verify_db_state

            db_result = await verify_db_state(
                db_session=db_session,
                valid_fact_count=len(debug_result.valid_facts),
                validation_error_count=len(debug_result.validation_errors),
                analysis_job_id=analysis_job_id,
            )
            write_json(output_path / "db_verification.json", db_result)

        return debug_result