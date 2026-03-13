from unittest.mock import AsyncMock, MagicMock
import pytest
from app.application.services.analysis_service import AnalysisService
from app.core.constants import SCANNER_TYPE_K8S, SCANNER_TYPE_AWS, SCANNER_TYPE_IMAGE


def _make_scan(scan_id: str, scanner_type: str):
    record = MagicMock()
    record.scan_id = scan_id
    record.scanner_type = scanner_type
    return record


@pytest.fixture
def jobs_repo():
    repo = AsyncMock()
    repo.create_analysis_job = AsyncMock(return_value="job-123")
    return repo


@pytest.fixture
def scan_repo():
    return AsyncMock()


@pytest.fixture
def service(jobs_repo, scan_repo):
    return AnalysisService(jobs_repo=jobs_repo, scan_repo=scan_repo)


@pytest.mark.asyncio
async def test_maybe_trigger_analysis_creates_job_when_all_scans_present(service, jobs_repo, scan_repo):
    scan_repo.get_latest_completed_scans.return_value = {
        SCANNER_TYPE_K8S: _make_scan("k8s-1", SCANNER_TYPE_K8S),
        SCANNER_TYPE_AWS: _make_scan("aws-1", SCANNER_TYPE_AWS),
        SCANNER_TYPE_IMAGE: _make_scan("img-1", SCANNER_TYPE_IMAGE),
    }

    await service.maybe_trigger_analysis("cluster-abc")

    jobs_repo.create_analysis_job.assert_awaited_once_with(
        cluster_id="cluster-abc",
        k8s_scan_id="k8s-1",
        aws_scan_id="aws-1",
        image_scan_id="img-1",
    )


@pytest.mark.asyncio
async def test_maybe_trigger_analysis_skips_when_scan_missing(service, jobs_repo, scan_repo):
    scan_repo.get_latest_completed_scans.return_value = {
        SCANNER_TYPE_K8S: _make_scan("k8s-1", SCANNER_TYPE_K8S),
        SCANNER_TYPE_AWS: _make_scan("aws-1", SCANNER_TYPE_AWS),
    }

    await service.maybe_trigger_analysis("cluster-abc")

    jobs_repo.create_analysis_job.assert_not_awaited()


@pytest.mark.asyncio
async def test_maybe_trigger_analysis_skips_when_no_scans(service, jobs_repo, scan_repo):
    scan_repo.get_latest_completed_scans.return_value = {}

    await service.maybe_trigger_analysis("cluster-abc")

    jobs_repo.create_analysis_job.assert_not_awaited()
