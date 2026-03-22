from unittest.mock import AsyncMock, MagicMock
import networkx as nx
import pytest
from app.application.services.analysis_service import AnalysisService
from app.core.constants import SCANNER_TYPE_K8S, SCANNER_TYPE_AWS, SCANNER_TYPE_IMAGE
from src.graph.builders.aws_graph_builder import GraphEdge as AWSGraphEdge
from src.graph.builders.aws_graph_builder import GraphNode as AWSGraphNode
from src.graph.builders.build_result_types import AWSBuildResult, K8sBuildResult, UnifiedGraphResult
from src.graph.graph_models import GraphEdge as K8sGraphEdge
from src.graph.graph_models import GraphNode as K8sGraphNode


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


def test_analysis_service_uses_direct_fact_extractors_instead_of_orchestrator(service):
    assert hasattr(service, "_k8s_extractor")
    assert hasattr(service, "_lateral_extractor")
    assert not hasattr(service, "_fact_orchestrator")


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
async def test_execute_analysis_uses_domain_results_and_unified_merge(service):
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
    service._graph_builder.build_from_facts = AsyncMock(side_effect=AssertionError("legacy fact graph path should not be primary"))
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
    service._graph_builder.build_from_facts.assert_not_called()
    service._path_finder.find_all_paths.assert_called_once_with(
        graph,
        ["pod:prod:api"],
        ["iam:123456789012:AppRole"],
        max_path_length=7,
    )
    service._remediation_optimizer.optimize.assert_called_once_with(
        [{
            "path_id": "path:0:pod:prod:api->iam:123456789012:AppRole",
            "path": ["pod:prod:api", "iam:123456789012:AppRole"],
            "risk_score": 0.9,
            "raw_final_risk": 0.9,
            "length": 2,
            "edges": [{"source": "pod:prod:api", "target": "iam:123456789012:AppRole", "type": "service_account_assumes_iam_role"}],
        }],
        graph,
    )
    assert result["stats"]["graph"]["nodes"] == 2
    assert result["stats"]["paths"]["total"] == 1
    assert result["remediation_optimization"] == {"summary": {"selected_count": 1}, "recommendations": []}


@pytest.mark.asyncio
async def test_execute_analysis_preserves_downstream_networkx_compatibility(service):
    service._load_scan_data = AsyncMock(side_effect=[
        {"scan_id": "k8s-1", "cluster_id": "cluster-1", "pods": []},
        {"scan_id": "aws-1", "aws_account_id": "123456789012"},
        {"scan_id": "img-1"},
    ])
    service._build_k8s_result = MagicMock(return_value=K8sBuildResult(nodes=[], edges=[], metadata={}))
    service._coerce_aws_scan_result = MagicMock(return_value=MagicMock())
    service._bridge_builder.build = MagicMock(return_value=MagicMock(warnings=[]))
    service._build_aws_result = MagicMock(return_value=AWSBuildResult(nodes=[], edges=[], metadata={}))
    service._unified_graph_builder.build = MagicMock(return_value=UnifiedGraphResult(nodes=[], edges=[], metadata={}, warnings=[]))

    graph = nx.DiGraph()
    graph.add_node("ingress:prod:web", id="ingress:prod:web", type="ingress", is_entry_point=True, is_crown_jewel=False, base_risk=0.4, metadata={})
    graph.add_node("s3:123:data", id="s3:123:data", type="s3_bucket", is_entry_point=False, is_crown_jewel=True, base_risk=0.5, metadata={})
    graph.add_edge("ingress:prod:web", "s3:123:data", type="path", metadata={})
    service._graph_builder.build_from_unified_result = AsyncMock(return_value=graph)
    service._graph_builder.get_entry_points = MagicMock(return_value=["ingress:prod:web"])
    service._graph_builder.get_crown_jewels = MagicMock(return_value=["s3:123:data"])
    service._path_finder.find_all_paths = MagicMock(return_value=[["ingress:prod:web", "s3:123:data"]])
    service._path_finder.get_path_edges = MagicMock(return_value=[("ingress:prod:web", "s3:123:data", "path")])
    service._risk_engine.calculate_path_risk_details = MagicMock(return_value={"risk_score": 0.5, "raw_final_risk": 0.5})
    service._remediation_optimizer.optimize = MagicMock(return_value={"summary": {"selected_count": 1}, "recommendations": []})

    result = await service.execute_analysis("cluster-1", "k8s-1", "aws-1", "img-1")

    assert result["attack_paths"] == [{
        "path_id": "path:0:ingress:prod:web->s3:123:data",
        "path": ["ingress:prod:web", "s3:123:data"],
        "risk_score": 0.5,
        "raw_final_risk": 0.5,
        "length": 2,
        "edges": [{"source": "ingress:prod:web", "target": "s3:123:data", "type": "path"}],
    }]
    assert result["remediation_optimization"] == {"summary": {"selected_count": 1}, "recommendations": []}
