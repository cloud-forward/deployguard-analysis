from unittest.mock import AsyncMock, MagicMock

import networkx as nx
import pytest
from fastapi import HTTPException
from datetime import datetime, UTC

from app.application.services.analysis_service import AnalysisService
from app.core.constants import SCANNER_TYPE_AWS, SCANNER_TYPE_IMAGE, SCANNER_TYPE_K8S
from app.main import app
from src.graph.builders.aws_graph_builder import GraphEdge as AWSGraphEdge
from src.graph.builders.aws_graph_builder import GraphNode as AWSGraphNode
from src.graph.builders.build_result_types import AWSBuildResult, K8sBuildResult, UnifiedGraphResult
from src.graph.graph_models import GraphNode as K8sGraphNode


def _make_scan(
    scan_id: str,
    scanner_type: str,
    *,
    status: str = "completed",
    cluster_id: str = "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    s3_keys: list[str] | None = None,
):
    record = MagicMock()
    record.scan_id = scan_id
    record.scanner_type = scanner_type
    record.status = status
    record.cluster_id = cluster_id
    record.s3_keys = s3_keys or [f"scans/{cluster_id}/{scan_id}/{scanner_type}/{scanner_type}-snapshot.json"]
    return record


def _make_job(
    job_id: str = "job-123",
    *,
    cluster_id: str = "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    status: str = "pending",
    current_step: str | None = None,
    k8s_scan_id: str | None = "k8s-1",
    aws_scan_id: str | None = None,
    image_scan_id: str | None = "img-1",
    expected_scans: list[str] | None = None,
    error_message: str | None = None,
    created_at: datetime | None = None,
    started_at: datetime | None = None,
    completed_at: datetime | None = None,
    graph_id: str | None = None,
):
    job = MagicMock()
    job.id = job_id
    job.cluster_id = cluster_id
    job.status = status
    job.current_step = current_step
    job.k8s_scan_id = k8s_scan_id
    job.aws_scan_id = aws_scan_id
    job.image_scan_id = image_scan_id
    job.expected_scans = expected_scans if expected_scans is not None else ["k8s", "image"]
    job.error_message = error_message
    job.created_at = created_at or datetime(2026, 3, 23, 0, 0, tzinfo=UTC)
    job.started_at = started_at
    job.completed_at = completed_at
    job.graph_id = graph_id
    return job


@pytest.fixture
def jobs_repo():
    repo = AsyncMock()
    repo.create_analysis_job = AsyncMock(return_value="job-123")
    repo.get_analysis_job = AsyncMock()
    return repo


@pytest.fixture
def scan_repo():
    repo = AsyncMock()
    repo.set_analysis_run_id = AsyncMock()
    return repo


@pytest.fixture
def s3_service():
    service = MagicMock()
    service.load_json = MagicMock()
    return service


@pytest.fixture
def service(jobs_repo, scan_repo, s3_service):
    return AnalysisService(jobs_repo=jobs_repo, scan_repo=scan_repo, s3_service=s3_service)


def test_analysis_service_uses_direct_fact_extractors_instead_of_orchestrator(service):
    assert hasattr(service, "_k8s_extractor")
    assert hasattr(service, "_lateral_extractor")
    assert not hasattr(service, "_fact_orchestrator")


@pytest.mark.asyncio
async def test_manual_analysis_job_creation_with_k8s_image_aws(service, jobs_repo, scan_repo):
    cluster_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    scan_repo.get_by_scan_id.side_effect = [
        _make_scan("k8s-1", SCANNER_TYPE_K8S, cluster_id=cluster_id),
        _make_scan("aws-1", SCANNER_TYPE_AWS, cluster_id=cluster_id),
        _make_scan("img-1", SCANNER_TYPE_IMAGE, cluster_id=cluster_id),
    ]

    result = await service.create_analysis_job(
        cluster_id=cluster_id,
        k8s_scan_id="k8s-1",
        aws_scan_id="aws-1",
        image_scan_id="img-1",
    )

    jobs_repo.create_analysis_job.assert_awaited_once_with(
        cluster_id=cluster_id,
        k8s_scan_id="k8s-1",
        aws_scan_id="aws-1",
        image_scan_id="img-1",
        expected_scans=["k8s", "aws", "image"],
    )
    assert scan_repo.set_analysis_run_id.await_args_list[0].args == ("k8s-1", "job-123")
    assert scan_repo.set_analysis_run_id.await_args_list[1].args == ("aws-1", "job-123")
    assert scan_repo.set_analysis_run_id.await_args_list[2].args == ("img-1", "job-123")
    assert result.job_id == "job-123"


@pytest.mark.asyncio
async def test_manual_analysis_job_creation_with_k8s_image_only(service, jobs_repo, scan_repo):
    cluster_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    scan_repo.get_by_scan_id.side_effect = [
        _make_scan("k8s-1", SCANNER_TYPE_K8S, cluster_id=cluster_id),
        _make_scan("img-1", SCANNER_TYPE_IMAGE, cluster_id=cluster_id),
    ]

    await service.create_analysis_job(
        cluster_id=cluster_id,
        k8s_scan_id="k8s-1",
        image_scan_id="img-1",
    )

    jobs_repo.create_analysis_job.assert_awaited_once_with(
        cluster_id=cluster_id,
        k8s_scan_id="k8s-1",
        aws_scan_id=None,
        image_scan_id="img-1",
        expected_scans=["k8s", "image"],
    )
    assert scan_repo.set_analysis_run_id.await_count == 2


@pytest.mark.asyncio
async def test_list_analysis_jobs_returns_cluster_jobs(service, jobs_repo):
    jobs_repo.list_analysis_jobs.return_value = [
        _make_job("job-2", status="running", current_step="graph_building"),
        _make_job("job-1", status="completed", current_step=None, graph_id="graph-1"),
    ]

    result = await service.list_analysis_jobs("a1b2c3d4-e5f6-7890-abcd-ef1234567890")

    jobs_repo.list_analysis_jobs.assert_awaited_once_with(
        cluster_id="a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        status=None,
    )
    assert result.total == 2
    assert [item.job_id for item in result.items] == ["job-2", "job-1"]
    assert result.items[0].current_step == "graph_building"
    assert result.items[1].graph_id == "graph-1"


@pytest.mark.asyncio
async def test_get_analysis_job_returns_detail(service, jobs_repo):
    jobs_repo.get_analysis_job.return_value = _make_job(
        "job-123",
        status="failed",
        error_message="raw load failed",
        aws_scan_id="aws-1",
    )

    result = await service.get_analysis_job("job-123")

    jobs_repo.get_analysis_job.assert_awaited_once_with("job-123")
    assert result.job_id == "job-123"
    assert result.cluster_id == "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    assert result.status == "failed"
    assert result.aws_scan_id == "aws-1"
    assert result.error_message == "raw load failed"


@pytest.mark.asyncio
async def test_get_analysis_job_missing_raises_404(service, jobs_repo):
    jobs_repo.get_analysis_job.return_value = None

    with pytest.raises(HTTPException) as exc_info:
        await service.get_analysis_job("missing-job")

    assert exc_info.value.status_code == 404


@pytest.mark.asyncio
async def test_rejects_non_completed_scans(service, jobs_repo, scan_repo):
    cluster_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    scan_repo.get_by_scan_id.return_value = _make_scan(
        "k8s-1",
        SCANNER_TYPE_K8S,
        status="processing",
        cluster_id=cluster_id,
    )

    with pytest.raises(HTTPException) as exc_info:
        await service.create_analysis_job(cluster_id=cluster_id, k8s_scan_id="k8s-1")

    assert exc_info.value.status_code == 400
    jobs_repo.create_analysis_job.assert_not_awaited()


@pytest.mark.asyncio
async def test_rejects_mismatched_scanner_type(service, jobs_repo, scan_repo):
    cluster_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    scan_repo.get_by_scan_id.return_value = _make_scan(
        "aws-1",
        SCANNER_TYPE_AWS,
        cluster_id=cluster_id,
    )

    with pytest.raises(HTTPException) as exc_info:
        await service.create_analysis_job(cluster_id=cluster_id, k8s_scan_id="aws-1")

    assert exc_info.value.status_code == 400
    jobs_repo.create_analysis_job.assert_not_awaited()


@pytest.mark.asyncio
async def test_analysis_execution_uses_explicit_scan_ids_from_analysis_job(service, jobs_repo):
    jobs_repo.get_analysis_job.return_value = MagicMock(
        id="job-123",
        cluster_id="cluster-1",
        k8s_scan_id="k8s-explicit",
        aws_scan_id="aws-explicit",
        image_scan_id="img-explicit",
    )
    service.execute_analysis = AsyncMock(return_value={"ok": True})

    result = await service.execute_analysis_job("job-123")

    jobs_repo.mark_running.assert_awaited_once_with("job-123", current_step="fact_extraction")
    service.execute_analysis.assert_awaited_once_with(
        cluster_id="cluster-1",
        k8s_scan_id="k8s-explicit",
        aws_scan_id="aws-explicit",
        image_scan_id="img-explicit",
        analysis_job_id="job-123",
    )
    jobs_repo.mark_completed.assert_awaited_once_with("job-123", {})
    assert result == {"ok": True}


@pytest.mark.asyncio
async def test_execute_analysis_job_marks_failed_on_execution_error(service, jobs_repo):
    jobs_repo.get_analysis_job.return_value = MagicMock(
        id="job-123",
        cluster_id="cluster-1",
        k8s_scan_id="k8s-explicit",
        aws_scan_id=None,
        image_scan_id=None,
    )
    service.execute_analysis = AsyncMock(side_effect=RuntimeError("raw load failed"))

    with pytest.raises(RuntimeError, match="raw load failed"):
        await service.execute_analysis_job("job-123")

    jobs_repo.mark_running.assert_awaited_once_with("job-123", current_step="fact_extraction")
    jobs_repo.mark_failed.assert_awaited_once_with("job-123", "raw load failed")
    jobs_repo.mark_completed.assert_not_awaited()


@pytest.mark.asyncio
async def test_load_scan_data_uses_explicit_scan_id_and_s3_payload(service, scan_repo, s3_service):
    cluster_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    scan_repo.get_by_scan_id.return_value = _make_scan(
        "k8s-1",
        SCANNER_TYPE_K8S,
        cluster_id=cluster_id,
        s3_keys=["scans/test/k8s-1/k8s/k8s-snapshot.json"],
    )
    s3_service.load_json.return_value = {"resources": []}

    payload = await service._load_scan_data(cluster_id, "k8s-1", SCANNER_TYPE_K8S)

    scan_repo.get_by_scan_id.assert_awaited_once_with("k8s-1")
    s3_service.load_json.assert_called_once_with("scans/test/k8s-1/k8s/k8s-snapshot.json")
    assert payload["scan_id"] == "k8s-1"
    assert payload["cluster_id"] == cluster_id
    assert payload["scanner_type"] == SCANNER_TYPE_K8S


@pytest.mark.asyncio
async def test_execute_analysis_does_not_infer_latest_scans_from_cluster(service, scan_repo):
    scan_repo.get_latest_completed_scans.side_effect = AssertionError("latest scan lookup should not be used")
    service._load_scan_data = AsyncMock(side_effect=[
        {"scan_id": "k8s-1", "cluster_id": "cluster-1", "pods": []},
        {"scan_id": "aws-1", "aws_account_id": "123456789012"},
        {"scan_id": "img-1"},
    ])
    k8s_result = K8sBuildResult(
        nodes=[K8sGraphNode(id="pod:prod:api", type="pod")],
        edges=[],
        metadata={"scan_id": "k8s-1", "cluster_id": "cluster-1", "graph_id": "k8s-1-graph"},
    )
    aws_result = AWSBuildResult(
        nodes=[AWSGraphNode(id="iam:123456789012:AppRole", type="iam_role", namespace="123456789012")],
        edges=[],
        metadata={"scan_id": "aws-1", "account_id": "123456789012", "graph_id": "aws-1-graph"},
    )
    unified_result = UnifiedGraphResult(nodes=[*k8s_result.nodes, *aws_result.nodes], edges=[], metadata={}, warnings=[])
    graph = nx.DiGraph()
    graph.add_node("pod:prod:api", id="pod:prod:api", type="pod", is_entry_point=True, is_crown_jewel=False, base_risk=0.3, metadata={})
    graph.add_node("iam:123456789012:AppRole", id="iam:123456789012:AppRole", type="iam_role", is_entry_point=False, is_crown_jewel=True, base_risk=0.9, metadata={})

    service._build_k8s_result = MagicMock(return_value=k8s_result)
    service._coerce_aws_scan_result = MagicMock(return_value=MagicMock())
    service._bridge_builder.build = MagicMock(return_value=MagicMock(irsa_mappings=[], credential_facts=[], warnings=[]))
    service._build_aws_result = MagicMock(return_value=aws_result)
    service._unified_graph_builder.build = MagicMock(return_value=unified_result)
    service._graph_builder.build_from_unified_result = AsyncMock(return_value=graph)
    service._graph_builder.get_entry_points = MagicMock(return_value=["pod:prod:api"])
    service._graph_builder.get_crown_jewels = MagicMock(return_value=["iam:123456789012:AppRole"])
    service._path_finder.find_all_paths = MagicMock(return_value=[])
    service._remediation_optimizer.optimize = MagicMock(return_value={"summary": {}, "recommendations": []})

    await service.execute_analysis("cluster-1", "k8s-1", "aws-1", "img-1")

    scan_repo.get_latest_completed_scans.assert_not_called()


@pytest.mark.asyncio
async def test_execute_analysis_uses_domain_results_and_unified_merge(service, jobs_repo):
    service._load_scan_data = AsyncMock(side_effect=[
        {"scan_id": "k8s-1", "cluster_id": "cluster-1", "pods": []},
        {"scan_id": "aws-1", "aws_account_id": "123456789012"},
        {"scan_id": "img-1"},
    ])
    k8s_result = K8sBuildResult(
        nodes=[K8sGraphNode(id="pod:prod:api", type="pod")],
        edges=[],
        metadata={"scan_id": "k8s-1", "cluster_id": "cluster-1", "graph_id": "k8s-1-graph"},
    )
    aws_result = AWSBuildResult(
        nodes=[AWSGraphNode(id="iam:123456789012:AppRole", type="iam_role", namespace="123456789012")],
        edges=[AWSGraphEdge(
            source="pod:prod:api",
            target="iam:123456789012:AppRole",
            type="service_account_assumes_iam_role",
        )],
        metadata={"scan_id": "aws-1", "account_id": "123456789012", "graph_id": "aws-1-graph"},
    )
    unified_result = UnifiedGraphResult(
        nodes=[*k8s_result.nodes, *aws_result.nodes],
        edges=aws_result.edges,
        metadata={"sources": ["k8s", "aws"]},
        warnings=[],
    )
    bridge_result = MagicMock(irsa_mappings=[], credential_facts=[], warnings=[])
    graph = nx.DiGraph()
    graph.add_node("pod:prod:api", id="pod:prod:api", type="pod", is_entry_point=True, is_crown_jewel=False, base_risk=0.3, metadata={})
    graph.add_node("iam:123456789012:AppRole", id="iam:123456789012:AppRole", type="iam_role", is_entry_point=False, is_crown_jewel=True, base_risk=0.9, metadata={})
    graph.add_edge("pod:prod:api", "iam:123456789012:AppRole", type="service_account_assumes_iam_role", metadata={})

    service._build_k8s_result = MagicMock(return_value=k8s_result)
    service._coerce_aws_scan_result = MagicMock(return_value=MagicMock())
    service._bridge_builder.build = MagicMock(return_value=bridge_result)
    service._build_aws_result = MagicMock(return_value=aws_result)
    service._unified_graph_builder.build = MagicMock(return_value=unified_result)
    service._graph_builder.build_from_unified_result = AsyncMock(return_value=graph)
    service._graph_builder.get_entry_points = MagicMock(return_value=["pod:prod:api"])
    service._graph_builder.get_crown_jewels = MagicMock(return_value=["iam:123456789012:AppRole"])
    service._path_finder.find_all_paths = MagicMock(return_value=[["pod:prod:api", "iam:123456789012:AppRole"]])
    service._path_finder.get_path_edges = MagicMock(return_value=[("pod:prod:api", "iam:123456789012:AppRole", "service_account_assumes_iam_role")])
    service._risk_engine.calculate_path_risk_details = MagicMock(return_value={"risk_score": 0.9, "raw_final_risk": 0.9})
    service._remediation_optimizer.optimize = MagicMock(return_value={"summary": {"selected_count": 1}, "recommendations": []})

    result = await service.execute_analysis("cluster-1", "k8s-1", "aws-1", "img-1")

    service._build_k8s_result.assert_called_once()
    service._build_aws_result.assert_called_once()
    service._unified_graph_builder.build.assert_called_once_with(k8s_result, aws_result)
    service._graph_builder.build_from_unified_result.assert_awaited_once_with(unified_result)
    jobs_repo.persist_attack_paths.assert_awaited_once_with(
        cluster_id="cluster-1",
        graph_id="k8s-1-graph",
        k8s_scan_id="k8s-1",
        aws_scan_id="aws-1",
        image_scan_id="img-1",
        attack_paths=[{
            "path_id": "path:0:pod:prod:api->iam:123456789012:AppRole",
            "path": ["pod:prod:api", "iam:123456789012:AppRole"],
            "risk_score": 0.9,
            "raw_final_risk": 0.9,
            "length": 2,
            "edges": [{"source": "pod:prod:api", "target": "iam:123456789012:AppRole", "type": "service_account_assumes_iam_role"}],
        }],
    )
    jobs_repo.persist_remediation_recommendations.assert_awaited_once_with(
        cluster_id="cluster-1",
        graph_id="k8s-1-graph",
        k8s_scan_id="k8s-1",
        aws_scan_id="aws-1",
        image_scan_id="img-1",
        remediation_optimization={"summary": {"selected_count": 1}, "recommendations": []},
    )
    assert result["stats"]["graph"]["nodes"] == 2
    assert result["stats"]["paths"]["total"] == 1


@pytest.mark.asyncio
async def test_execute_analysis_updates_job_steps_when_analysis_job_id_present(service, jobs_repo):
    service._load_scan_data = AsyncMock(side_effect=[
        {"scan_id": "k8s-1", "cluster_id": "cluster-1", "pods": []},
        {"scan_id": "aws-1", "aws_account_id": "123456789012"},
        {"scan_id": "img-1"},
    ])
    k8s_result = K8sBuildResult(
        nodes=[K8sGraphNode(id="pod:prod:api", type="pod")],
        edges=[],
        metadata={"scan_id": "k8s-1", "cluster_id": "cluster-1", "graph_id": "k8s-1-graph"},
    )
    aws_result = AWSBuildResult(
        nodes=[AWSGraphNode(id="iam:123456789012:AppRole", type="iam_role", namespace="123456789012")],
        edges=[],
        metadata={"scan_id": "aws-1", "account_id": "123456789012", "graph_id": "aws-1-graph"},
    )
    unified_result = UnifiedGraphResult(nodes=[*k8s_result.nodes, *aws_result.nodes], edges=[], metadata={}, warnings=[])
    graph = nx.DiGraph()
    graph.add_node("pod:prod:api", id="pod:prod:api", type="pod", is_entry_point=True, is_crown_jewel=False, base_risk=0.3, metadata={})
    graph.add_node("iam:123456789012:AppRole", id="iam:123456789012:AppRole", type="iam_role", is_entry_point=False, is_crown_jewel=True, base_risk=0.9, metadata={})

    service._build_k8s_result = MagicMock(return_value=k8s_result)
    service._coerce_aws_scan_result = MagicMock(return_value=MagicMock())
    service._bridge_builder.build = MagicMock(return_value=MagicMock(irsa_mappings=[], credential_facts=[], warnings=[]))
    service._build_aws_result = MagicMock(return_value=aws_result)
    service._unified_graph_builder.build = MagicMock(return_value=unified_result)
    service._graph_builder.build_from_unified_result = AsyncMock(return_value=graph)
    service._graph_builder.get_entry_points = MagicMock(return_value=["pod:prod:api"])
    service._graph_builder.get_crown_jewels = MagicMock(return_value=["iam:123456789012:AppRole"])
    service._path_finder.find_all_paths = MagicMock(return_value=[])
    service._remediation_optimizer.optimize = MagicMock(return_value={"summary": {}, "recommendations": []})

    await service.execute_analysis("cluster-1", "k8s-1", "aws-1", "img-1", analysis_job_id="job-123")

    assert [call.args for call in jobs_repo.update_current_step.await_args_list] == [
        ("job-123", "fact_extraction"),
        ("job-123", "graph_building"),
        ("job-123", "path_discovery"),
        ("job-123", "risk_calculation"),
        ("job-123", "optimization"),
    ]


def test_openapi_docs_distinguish_standard_and_debug_analysis_flows():
    openapi = app.openapi()
    create_job = openapi["paths"]["/api/v1/analysis/jobs"]["post"]
    execute_job = openapi["paths"]["/api/v1/analysis/jobs/{job_id}/execute"]["post"]
    execute_debug = openapi["paths"]["/api/v1/analysis/execute"]["post"]
    get_job = openapi["paths"]["/api/v1/analysis/jobs/{job_id}"]["get"]
    list_jobs = openapi["paths"]["/api/v1/clusters/{cluster_id}/analysis/jobs"]["get"]

    assert "표준 persisted-job 워크플로우" in create_job["description"]
    assert "표준 persisted-job 워크플로우" in execute_job["description"]
    assert "내부 디버그/검증 전용" in execute_debug["summary"]
    assert "표준 프론트엔드/제품 흐름이 아닙니다" in execute_debug["description"]
    assert "선택된 scan_id와 실행 상태" in get_job["description"]
    assert "persisted analysis job 목록" in list_jobs["description"]
