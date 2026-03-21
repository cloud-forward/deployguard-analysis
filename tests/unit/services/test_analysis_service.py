from unittest.mock import AsyncMock, MagicMock
import pytest
import networkx as nx
from app.application.services.analysis_service import AnalysisService
from app.core.constants import SCANNER_TYPE_K8S, SCANNER_TYPE_AWS, SCANNER_TYPE_IMAGE
from src.facts.canonical_fact import FactCollection


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
    cluster_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    scan_repo.get_latest_completed_scans.return_value = {
        SCANNER_TYPE_K8S: _make_scan("k8s-1", SCANNER_TYPE_K8S),
        SCANNER_TYPE_AWS: _make_scan("aws-1", SCANNER_TYPE_AWS),
        SCANNER_TYPE_IMAGE: _make_scan("img-1", SCANNER_TYPE_IMAGE),
    }

    await service.maybe_trigger_analysis(cluster_id)

    jobs_repo.create_analysis_job.assert_awaited_once_with(
        cluster_id=cluster_id,
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

    await service.maybe_trigger_analysis("a1b2c3d4-e5f6-7890-abcd-ef1234567890")

    jobs_repo.create_analysis_job.assert_not_awaited()


@pytest.mark.asyncio
async def test_maybe_trigger_analysis_skips_when_no_scans(service, jobs_repo, scan_repo):
    scan_repo.get_latest_completed_scans.return_value = {}

    await service.maybe_trigger_analysis("a1b2c3d4-e5f6-7890-abcd-ef1234567890")

    jobs_repo.create_analysis_job.assert_not_awaited()


@pytest.mark.asyncio
async def test_execute_analysis_passes_k8s_scan_into_graph_builder(service):
    k8s_scan = {
        "scan_id": "k8s-1",
        "pods": [{"namespace": "production", "name": "api-pod"}],
        "services": [],
        "ingresses": [],
        "secrets": [],
        "service_accounts": [],
        "roles": [],
        "cluster_roles": [],
        "role_bindings": [],
        "cluster_role_bindings": [],
        "network_policies": [],
    }
    aws_scan = {"scan_id": "aws-1"}
    image_scan = {"scan_id": "img-1"}

    async def fake_load_scan_data(cluster_id: str, scan_id: str, scanner_type: str):
        if scanner_type == SCANNER_TYPE_K8S:
            return k8s_scan
        if scanner_type == SCANNER_TYPE_AWS:
            return aws_scan
        return image_scan

    service._load_scan_data = fake_load_scan_data
    service._fact_orchestrator.extract_all = AsyncMock(return_value=FactCollection(scan_id="k8s-1", facts=[]))
    service._graph_builder.build_from_facts = AsyncMock(return_value=nx.DiGraph())
    service._graph_builder.get_entry_points = MagicMock(return_value=[])
    service._graph_builder.get_crown_jewels = MagicMock(return_value=[])
    service._path_finder.find_all_paths = MagicMock(return_value=[])

    await service.execute_analysis(
        cluster_id="cluster-1",
        k8s_scan_id="k8s-1",
        aws_scan_id="aws-1",
        image_scan_id="img-1",
    )

    service._graph_builder.build_from_facts.assert_awaited_once_with(
        [],
        k8s_scan=k8s_scan,
        scan_id="k8s-1",
        aws_scan=aws_scan,
        policy_results=None,
        user_policy_results=None,
    )
