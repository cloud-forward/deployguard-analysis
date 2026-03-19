from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, call

import pytest

from app.application.services.analysis_service import AnalysisService
from app.core.constants import SCANNER_TYPE_AWS, SCANNER_TYPE_IMAGE, SCANNER_TYPE_K8S


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
async def test_triggers_when_all_three_scans_completed(service, jobs_repo, scan_repo):
    cluster_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    scan_repo.get_latest_completed_scans.return_value = {
        SCANNER_TYPE_K8S: _make_scan("k8s-1", SCANNER_TYPE_K8S),
        SCANNER_TYPE_AWS: _make_scan("aws-1", SCANNER_TYPE_AWS),
        SCANNER_TYPE_IMAGE: _make_scan("img-1", SCANNER_TYPE_IMAGE),
    }
    await service.maybe_trigger_analysis(cluster_id)
    jobs_repo.create_analysis_job.assert_awaited_once()


@pytest.mark.asyncio
async def test_uses_correct_scan_ids(service, jobs_repo, scan_repo):
    cluster_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    scan_repo.get_latest_completed_scans.return_value = {
        SCANNER_TYPE_K8S: _make_scan("k8s-42", SCANNER_TYPE_K8S),
        SCANNER_TYPE_AWS: _make_scan("aws-99", SCANNER_TYPE_AWS),
        SCANNER_TYPE_IMAGE: _make_scan("img-7", SCANNER_TYPE_IMAGE),
    }
    await service.maybe_trigger_analysis(cluster_id)
    jobs_repo.create_analysis_job.assert_awaited_once_with(
        cluster_id=cluster_id,
        k8s_scan_id="k8s-42",
        aws_scan_id="aws-99",
        image_scan_id="img-7",
    )


@pytest.mark.asyncio
async def test_does_not_trigger_when_k8s_missing(service, jobs_repo, scan_repo):
    scan_repo.get_latest_completed_scans.return_value = {
        SCANNER_TYPE_AWS: _make_scan("aws-1", SCANNER_TYPE_AWS),
        SCANNER_TYPE_IMAGE: _make_scan("img-1", SCANNER_TYPE_IMAGE),
    }
    await service.maybe_trigger_analysis("a1b2c3d4-e5f6-7890-abcd-ef1234567890")
    jobs_repo.create_analysis_job.assert_not_awaited()


@pytest.mark.asyncio
async def test_does_not_trigger_when_aws_missing(service, jobs_repo, scan_repo):
    scan_repo.get_latest_completed_scans.return_value = {
        SCANNER_TYPE_K8S: _make_scan("k8s-1", SCANNER_TYPE_K8S),
        SCANNER_TYPE_IMAGE: _make_scan("img-1", SCANNER_TYPE_IMAGE),
    }
    await service.maybe_trigger_analysis("a1b2c3d4-e5f6-7890-abcd-ef1234567890")
    jobs_repo.create_analysis_job.assert_not_awaited()


@pytest.mark.asyncio
async def test_does_not_trigger_when_image_missing(service, jobs_repo, scan_repo):
    scan_repo.get_latest_completed_scans.return_value = {
        SCANNER_TYPE_K8S: _make_scan("k8s-1", SCANNER_TYPE_K8S),
        SCANNER_TYPE_AWS: _make_scan("aws-1", SCANNER_TYPE_AWS),
    }
    await service.maybe_trigger_analysis("a1b2c3d4-e5f6-7890-abcd-ef1234567890")
    jobs_repo.create_analysis_job.assert_not_awaited()


@pytest.mark.asyncio
async def test_does_not_trigger_when_no_scans(service, jobs_repo, scan_repo):
    scan_repo.get_latest_completed_scans.return_value = {}
    await service.maybe_trigger_analysis("a1b2c3d4-e5f6-7890-abcd-ef1234567890")
    jobs_repo.create_analysis_job.assert_not_awaited()


@pytest.mark.asyncio
async def test_only_one_job_created_per_trigger(service, jobs_repo, scan_repo):
    cluster_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    scan_repo.get_latest_completed_scans.return_value = {
        SCANNER_TYPE_K8S: _make_scan("k8s-1", SCANNER_TYPE_K8S),
        SCANNER_TYPE_AWS: _make_scan("aws-1", SCANNER_TYPE_AWS),
        SCANNER_TYPE_IMAGE: _make_scan("img-1", SCANNER_TYPE_IMAGE),
    }
    await service.maybe_trigger_analysis(cluster_id)
    assert jobs_repo.create_analysis_job.await_count == 1


@pytest.mark.asyncio
async def test_passes_correct_cluster_id(service, jobs_repo, scan_repo):
    cluster_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    scan_repo.get_latest_completed_scans.return_value = {
        SCANNER_TYPE_K8S: _make_scan("k8s-1", SCANNER_TYPE_K8S),
        SCANNER_TYPE_AWS: _make_scan("aws-1", SCANNER_TYPE_AWS),
        SCANNER_TYPE_IMAGE: _make_scan("img-1", SCANNER_TYPE_IMAGE),
    }
    await service.maybe_trigger_analysis(cluster_id)
    _, kwargs = jobs_repo.create_analysis_job.call_args
    assert kwargs["cluster_id"] == cluster_id


@pytest.mark.asyncio
async def test_queries_scans_for_correct_cluster(service, jobs_repo, scan_repo):
    scan_repo.get_latest_completed_scans.return_value = {}
    cluster_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    await service.maybe_trigger_analysis(cluster_id)
    scan_repo.get_latest_completed_scans.assert_awaited_once_with(cluster_id)


@pytest.mark.asyncio
async def test_does_not_trigger_on_empty_string_cluster(service, jobs_repo, scan_repo):
    scan_repo.get_latest_completed_scans.return_value = {}
    await service.maybe_trigger_analysis("")
    jobs_repo.create_analysis_job.assert_not_awaited()
