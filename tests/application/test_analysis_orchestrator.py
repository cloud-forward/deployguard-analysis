from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from app.application.services.analysis_service import AnalysisService


@pytest.fixture
def jobs_repo():
    repo = AsyncMock()
    repo.get_analysis_job = AsyncMock()
    repo.create_analysis_job = AsyncMock(return_value="job-123")
    return repo


@pytest.fixture
def scan_repo():
    repo = AsyncMock()
    repo.set_analysis_run_id = AsyncMock()
    return repo


@pytest.fixture
def service(jobs_repo, scan_repo):
    return AnalysisService(jobs_repo=jobs_repo, scan_repo=scan_repo)


@pytest.mark.asyncio
async def test_execute_analysis_job_uses_explicit_scan_ids_from_job(service, jobs_repo):
    jobs_repo.get_analysis_job.return_value = MagicMock(
        id="job-123",
        cluster_id="a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        k8s_scan_id="k8s-selected",
        aws_scan_id="aws-selected",
        image_scan_id="img-selected",
    )
    service.execute_analysis = AsyncMock(return_value={"job_id": "job-123"})

    result = await service.execute_analysis_job("job-123")

    service.execute_analysis.assert_awaited_once_with(
        cluster_id="a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        k8s_scan_id="k8s-selected",
        aws_scan_id="aws-selected",
        image_scan_id="img-selected",
        analysis_job_id="job-123",
    )
    assert result == {"job_id": "job-123"}


@pytest.mark.asyncio
async def test_no_auto_trigger_from_scan_completion_path_anymore(service, jobs_repo):
    assert not hasattr(service, "maybe_trigger_analysis")
    jobs_repo.create_analysis_job.assert_not_called()
