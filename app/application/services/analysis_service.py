"""
Application service orchestrating analysis use-cases.
Coordinates domain/core algorithms and repositories.
"""
from __future__ import annotations
import logging
from typing import Dict, Any
from uuid import UUID

from app.core.constants import SCANNER_TYPE_K8S, SCANNER_TYPE_AWS, SCANNER_TYPE_IMAGE
from app.domain.entities.analysis import AnalysisRequest, AnalysisResponse
from app.domain.repositories.analysis_jobs import AnalysisJobRepository
from app.domain.repositories.scan_repository import ScanRepository

logger = logging.getLogger(__name__)

REQUIRED_SCAN_TYPES = {SCANNER_TYPE_K8S, SCANNER_TYPE_AWS, SCANNER_TYPE_IMAGE}


def _context(**kwargs):
    return {key: value for key, value in kwargs.items() if value is not None}


class AnalysisService:
    def __init__(
        self,
        jobs_repo: AnalysisJobRepository,
        scan_repo: ScanRepository,
    ) -> None:
        self._jobs = jobs_repo
        self._scans = scan_repo

    async def analyze(self, request: AnalysisRequest) -> AnalysisResponse:
        job_id = await self._jobs.create_job(request.target_id, _params_dict(request))
        return AnalysisResponse(
            job_id=job_id,
            status="accepted",
            message=f"Analysis started for target {request.target_id}",
        )

    async def maybe_trigger_analysis(self, cluster_id: str | UUID, request_id: str | None = None) -> None:
        cluster_id_str = str(cluster_id)
        logger.info(
            "scan.analysis.trigger_check_invoked",
            extra=_context(request_id=request_id, cluster_id=cluster_id_str),
        )
        latest = await self._scans.get_latest_completed_scans(cluster_id_str)
        if not REQUIRED_SCAN_TYPES.issubset(latest.keys()):
            return
        normalized_cluster_id = str(UUID(cluster_id_str))
        job_id = await self._jobs.create_analysis_job(
            cluster_id=normalized_cluster_id,
            k8s_scan_id=latest[SCANNER_TYPE_K8S].scan_id,
            aws_scan_id=latest[SCANNER_TYPE_AWS].scan_id,
            image_scan_id=latest[SCANNER_TYPE_IMAGE].scan_id,
        )
        logger.info("Analysis job created: job_id=%s cluster_id=%s", job_id, normalized_cluster_id)


def _params_dict(request: AnalysisRequest) -> Dict[str, Any]:
    return {"depth": request.depth, **(request.parameters or {})}
