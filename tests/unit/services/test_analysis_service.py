from unittest.mock import AsyncMock, MagicMock

import networkx as nx
import pytest
from fastapi import HTTPException
from datetime import datetime, UTC

from app.application.services.analysis_service import AnalysisService
from app.application.services.analysis_service import MAX_HOPS
from app.core.constants import SCANNER_TYPE_AWS, SCANNER_TYPE_IMAGE, SCANNER_TYPE_K8S
from app.main import app
from src.facts.canonical_fact import Fact
from src.graph.builders.aws_graph_builder import GraphEdge as AWSGraphEdge
from src.graph.builders.aws_graph_builder import GraphNode as AWSGraphNode
from src.graph.builders.aws_scanner_types import IAMRoleScan
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
    repo.rollback = AsyncMock()
    repo.persist_attack_paths = AsyncMock(return_value="11111111-1111-1111-1111-111111111111")
    repo.persist_facts = AsyncMock()
    repo.persist_graph = AsyncMock()
    repo.finalize_graph_snapshot = AsyncMock()
    repo.persist_remediation_recommendations = AsyncMock()
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
    assert hasattr(service, "_aws_extractor")
    assert hasattr(service, "_lateral_extractor")
    assert not hasattr(service, "_fact_orchestrator")


def _enriched_path(
    path_id: str,
    path: list[str],
    raw_final_risk: float,
    edge_types: list[str] | None = None,
) -> dict:
    edge_types = edge_types or []
    edges = []
    for index, edge_type in enumerate(edge_types):
        edges.append(
            {
                "source": path[index],
                "target": path[index + 1],
                "type": edge_type,
            }
        )
    return {
        "path_id": path_id,
        "path": path,
        "risk_score": raw_final_risk,
        "raw_final_risk": raw_final_risk,
        "length": len(path),
        "edges": edges,
    }


def test_refine_attack_paths_prunes_same_endpoint_superset_when_shorter_path_has_no_lower_risk(service):
    shorter = _enriched_path(
        "path-short",
        ["ingress:prod:web", "service:prod:web", "s3:123:data"],
        0.8,
        ["ingress_exposes_service", "iam_role_access_resource"],
    )
    longer = _enriched_path(
        "path-long",
        ["ingress:prod:web", "service:prod:web", "pod:prod:api", "s3:123:data"],
        0.8,
        ["ingress_exposes_service", "service_targets_pod", "iam_role_access_resource"],
    )

    refined = service._refine_attack_paths([longer, shorter])

    assert [item["path_id"] for item in refined] == ["path-short"]


def test_refine_attack_paths_keeps_higher_risk_longer_path_when_shorter_same_endpoint_path_is_lower_risk(service):
    shorter_lower_risk = _enriched_path(
        "path-short-low",
        ["ingress:prod:web", "service:prod:web", "s3:123:data"],
        0.6,
        ["ingress_exposes_service", "iam_role_access_resource"],
    )
    longer_higher_risk = _enriched_path(
        "path-long-high",
        ["ingress:prod:web", "service:prod:web", "pod:prod:api", "s3:123:data"],
        0.9,
        ["ingress_exposes_service", "service_targets_pod", "iam_role_access_resource"],
    )

    refined = service._refine_attack_paths([shorter_lower_risk, longer_higher_risk])

    assert [item["path_id"] for item in refined] == ["path-long-high", "path-short-low"]


def test_refine_attack_paths_orders_by_risk_then_hops_then_generic_allows_then_path_id(service):
    highest_risk = _enriched_path(
        "path-a-highest-risk",
        ["entry", "mid", "target-a"],
        0.95,
        ["ingress_exposes_service", "iam_role_access_resource"],
    )
    fewer_hops = _enriched_path(
        "path-b-fewer-hops",
        ["entry", "target-b"],
        0.8,
        ["iam_role_access_resource"],
    )
    fewer_allows = _enriched_path(
        "path-c-fewer-allows",
        ["entry", "mid", "target-c"],
        0.8,
        ["allows", "iam_role_access_resource"],
    )
    more_allows = _enriched_path(
        "path-d-more-allows",
        ["entry", "mid", "target-d"],
        0.8,
        ["allows", "allows"],
    )
    same_sort_fields_later_id = _enriched_path(
        "path-f-later-id",
        ["entry", "mid", "target-f"],
        0.8,
        ["allows", "iam_role_access_resource"],
    )
    same_sort_fields_earlier_id = _enriched_path(
        "path-e-earlier-id",
        ["entry", "mid", "target-e"],
        0.8,
        ["allows", "iam_role_access_resource"],
    )

    refined = service._refine_attack_paths(
        [
            more_allows,
            same_sort_fields_later_id,
            highest_risk,
            fewer_hops,
            same_sort_fields_earlier_id,
            fewer_allows,
        ]
    )

    assert [item["path_id"] for item in refined] == [
        "path-a-highest-risk",
        "path-b-fewer-hops",
        "path-c-fewer-allows",
        "path-e-earlier-id",
        "path-f-later-id",
        "path-d-more-allows",
    ]


def test_refine_attack_paths_prunes_within_same_entry_target_group_only(service):
    prune_group_short = _enriched_path(
        "path-prune-short",
        ["ingress:prod:web", "service:prod:web", "s3:123:data"],
        0.8,
        ["ingress_exposes_service", "iam_role_access_resource"],
    )
    prune_group_long = _enriched_path(
        "path-prune-long",
        ["ingress:prod:web", "service:prod:web", "pod:prod:api", "s3:123:data"],
        0.8,
        ["ingress_exposes_service", "service_targets_pod", "iam_role_access_resource"],
    )
    different_target = _enriched_path(
        "path-other-target",
        ["ingress:prod:web", "service:prod:web", "rds:123:db"],
        0.7,
        ["ingress_exposes_service", "iam_role_access_resource"],
    )
    different_entry = _enriched_path(
        "path-other-entry",
        ["s3:123:public", "iam_user:123:deployer", "s3:123:data"],
        0.85,
        ["secret_contains_aws_credentials", "iam_user_access_resource"],
    )

    refined = service._refine_attack_paths(
        [prune_group_long, different_target, prune_group_short, different_entry]
    )

    assert [item["path_id"] for item in refined] == [
        "path-other-entry",
        "path-prune-short",
        "path-other-target",
    ]


@pytest.mark.asyncio
async def test_manual_analysis_job_creation_with_k8s_image_aws(service, jobs_repo, scan_repo):
    k8s_cluster_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    aws_cluster_id = "b2c3d4e5-f6a7-8901-bcde-f12345678901"
    scan_repo.get_by_scan_id.side_effect = [
        _make_scan("k8s-1", SCANNER_TYPE_K8S, cluster_id=k8s_cluster_id),
        _make_scan("aws-1", SCANNER_TYPE_AWS, cluster_id=aws_cluster_id),
        _make_scan("img-1", SCANNER_TYPE_IMAGE, cluster_id=k8s_cluster_id),
    ]

    result = await service.create_analysis_job(
        k8s_scan_id="k8s-1",
        aws_scan_id="aws-1",
        image_scan_id="img-1",
    )

    jobs_repo.create_analysis_job.assert_awaited_once_with(
        cluster_id=k8s_cluster_id,
        k8s_scan_id="k8s-1",
        aws_scan_id="aws-1",
        image_scan_id="img-1",
        expected_scans=["k8s", "aws", "image"],
        user_id=None,
    )
    assert scan_repo.set_analysis_run_id.await_args_list[0].args == ("k8s-1", "job-123")
    assert scan_repo.set_analysis_run_id.await_args_list[1].args == ("aws-1", "job-123")
    assert scan_repo.set_analysis_run_id.await_args_list[2].args == ("img-1", "job-123")
    assert result.job_id == "job-123"


@pytest.mark.asyncio
async def test_manual_analysis_job_creation_passes_user_id_through(service, jobs_repo, scan_repo):
    cluster_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    scan_repo.get_by_scan_id.side_effect = [
        _make_scan("k8s-1", SCANNER_TYPE_K8S, cluster_id=cluster_id),
        _make_scan("img-1", SCANNER_TYPE_IMAGE, cluster_id=cluster_id),
    ]

    await service.create_analysis_job(
        k8s_scan_id="k8s-1",
        image_scan_id="img-1",
        user_id="user-1",
    )

    jobs_repo.create_analysis_job.assert_awaited_once_with(
        cluster_id=cluster_id,
        k8s_scan_id="k8s-1",
        aws_scan_id=None,
        image_scan_id="img-1",
        expected_scans=["k8s", "image"],
        user_id="user-1",
    )


@pytest.mark.asyncio
async def test_manual_analysis_job_creation_with_k8s_image_only(service, jobs_repo, scan_repo):
    cluster_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    scan_repo.get_by_scan_id.side_effect = [
        _make_scan("k8s-1", SCANNER_TYPE_K8S, cluster_id=cluster_id),
        _make_scan("img-1", SCANNER_TYPE_IMAGE, cluster_id=cluster_id),
    ]

    await service.create_analysis_job(
        k8s_scan_id="k8s-1",
        image_scan_id="img-1",
    )

    jobs_repo.create_analysis_job.assert_awaited_once_with(
        cluster_id=cluster_id,
        k8s_scan_id="k8s-1",
        aws_scan_id=None,
        image_scan_id="img-1",
        expected_scans=["k8s", "image"],
        user_id=None,
    )
    assert scan_repo.set_analysis_run_id.await_count == 2


@pytest.mark.asyncio
async def test_create_analysis_job_derives_representative_cluster_from_image_when_k8s_absent(service, jobs_repo, scan_repo):
    image_cluster_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    aws_cluster_id = "b2c3d4e5-f6a7-8901-bcde-f12345678901"
    scan_repo.get_by_scan_id.side_effect = [
        _make_scan("aws-1", SCANNER_TYPE_AWS, cluster_id=aws_cluster_id),
        _make_scan("img-1", SCANNER_TYPE_IMAGE, cluster_id=image_cluster_id),
    ]

    await service.create_analysis_job(
        aws_scan_id="aws-1",
        image_scan_id="img-1",
    )

    jobs_repo.create_analysis_job.assert_awaited_once_with(
        cluster_id=image_cluster_id,
        k8s_scan_id=None,
        aws_scan_id="aws-1",
        image_scan_id="img-1",
        expected_scans=["aws", "image"],
        user_id=None,
    )


@pytest.mark.asyncio
async def test_create_analysis_job_derives_representative_cluster_from_aws_when_only_aws(service, jobs_repo, scan_repo):
    aws_cluster_id = "b2c3d4e5-f6a7-8901-bcde-f12345678901"
    scan_repo.get_by_scan_id.return_value = _make_scan("aws-1", SCANNER_TYPE_AWS, cluster_id=aws_cluster_id)

    await service.create_analysis_job(aws_scan_id="aws-1")

    jobs_repo.create_analysis_job.assert_awaited_once_with(
        cluster_id=aws_cluster_id,
        k8s_scan_id=None,
        aws_scan_id="aws-1",
        image_scan_id=None,
        expected_scans=["aws"],
        user_id=None,
    )


@pytest.mark.asyncio
async def test_create_analysis_job_prefers_k8s_cluster_over_aws_when_both_present(service, jobs_repo, scan_repo):
    k8s_cluster_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    aws_cluster_id = "b2c3d4e5-f6a7-8901-bcde-f12345678901"
    scan_repo.get_by_scan_id.side_effect = [
        _make_scan("k8s-1", SCANNER_TYPE_K8S, cluster_id=k8s_cluster_id),
        _make_scan("aws-1", SCANNER_TYPE_AWS, cluster_id=aws_cluster_id),
    ]

    await service.create_analysis_job(
        k8s_scan_id="k8s-1",
        aws_scan_id="aws-1",
    )

    jobs_repo.create_analysis_job.assert_awaited_once_with(
        cluster_id=k8s_cluster_id,
        k8s_scan_id="k8s-1",
        aws_scan_id="aws-1",
        image_scan_id=None,
        expected_scans=["k8s", "aws"],
        user_id=None,
    )


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
async def test_mixed_k8s_secret_to_aws_user_s3_chain_is_traversable_through_real_build_flow(service):
    k8s_scan = {
        "scan_id": "k8s-1",
        "cluster_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        "pods": [
            {
                "namespace": "production",
                "name": "api",
                "containers": [
                    {
                        "name": "api",
                        "image": "api:latest",
                        "volume_mounts": [
                            {
                                "source_type": "secret",
                                "source_name": "aws-credentials",
                                "mount_path": "/var/run/secrets/aws",
                                "read_only": True,
                            }
                        ],
                    }
                ],
            }
        ],
        "service_accounts": [],
        "roles": [],
        "cluster_roles": [],
        "role_bindings": [],
        "cluster_role_bindings": [],
        "services": [],
        "ingresses": [],
        "network_policies": [],
        "secrets": [
            {
                "metadata": {
                    "namespace": "production",
                    "name": "aws-credentials",
                },
                "stringData": {
                    "AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE",
                    "AWS_SECRET_ACCESS_KEY": "super-secret",
                },
            }
        ],
    }
    aws_scan = {
        "scan_id": "aws-1",
        "aws_account_id": "123456789012",
        "scanned_at": "2026-03-25T00:00:00Z",
        "iam_roles": [],
        "iam_users": [
            {
                "username": "web-app-deployer",
                "arn": "arn:aws:iam::123456789012:user/web-app-deployer",
                "access_keys": [
                    {
                        "access_key_id": "AKIAIOSFODNN7EXAMPLE",
                        "status": "Active",
                        "create_date": "2026-01-01T00:00:00Z",
                    }
                ],
                "attached_policies": [
                    {
                        "PolicyName": "DeployerPolicy",
                        "PolicyDocument": {
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": ["s3:GetObject"],
                                    "Resource": [
                                        "arn:aws:s3:::sensitive-data-bucket",
                                        "arn:aws:s3:::sensitive-data-bucket/*",
                                    ],
                                }
                            ]
                        },
                    }
                ],
                "inline_policies": [],
                "has_mfa": False,
                "last_used": None,
            }
        ],
        "s3_buckets": [
            {
                "name": "sensitive-data-bucket",
                "arn": "arn:aws:s3:::sensitive-data-bucket",
                "public_access_block": None,
                "encryption": None,
                "versioning": "Disabled",
                "logging_enabled": False,
            }
        ],
        "rds_instances": [],
        "ec2_instances": [],
        "security_groups": [],
    }

    k8s_result = service._build_k8s_result(k8s_scan, "k8s-1")
    aws_scan_result = service._coerce_aws_scan_result(aws_scan, "aws-1")
    bridge_result = service._bridge_builder.build(k8s_scan, aws_scan_result)
    aws_result = service._build_aws_result(aws_scan_result, bridge_result)
    unified_result = service._unified_graph_builder.build(k8s_result, aws_result)
    graph = await service._graph_builder.build_from_unified_result(unified_result)

    pod_id = "pod:production:api"
    secret_id = "secret:production:aws-credentials"
    user_id = "iam_user:123456789012:web-app-deployer"
    bucket_id = "s3:123456789012:sensitive-data-bucket"

    paths = service._path_finder.find_all_paths(
        graph,
        [pod_id],
        [bucket_id],
        max_path_length=3,
        max_paths=10,
    )

    assert paths == [[pod_id, secret_id, user_id, bucket_id]]
    assert service._path_finder.get_path_edges(graph, paths[0]) == [
        (pod_id, secret_id, "pod_mounts_secret"),
        (secret_id, user_id, "secret_contains_aws_credentials"),
        (user_id, bucket_id, "iam_user_access_resource"),
    ]


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
async def test_execute_analysis_debug_uses_explicit_scan_ids_only(service, scan_repo):
    scan_repo.get_by_scan_id.return_value = _make_scan(
        "k8s-1",
        SCANNER_TYPE_K8S,
        cluster_id="cluster-from-scan",
    )
    service.execute_analysis = AsyncMock(return_value={"ok": True})

    result = await service.execute_analysis_debug(k8s_scan_id="k8s-1")

    service.execute_analysis.assert_awaited_once_with(
        cluster_id="cluster-from-scan",
        k8s_scan_id="k8s-1",
        aws_scan_id=None,
        image_scan_id=None,
        require_cluster_match=False,
    )
    assert result == {"ok": True}


@pytest.mark.asyncio
async def test_execute_analysis_debug_rejects_wrong_scanner_type(service, scan_repo):
    scan_repo.get_by_scan_id.return_value = _make_scan("aws-1", SCANNER_TYPE_AWS)

    with pytest.raises(HTTPException) as exc_info:
        await service.execute_analysis_debug(k8s_scan_id="aws-1")

    assert exc_info.value.status_code == 400
    assert "expected k8s" in exc_info.value.detail


@pytest.mark.asyncio
async def test_execute_analysis_debug_rejects_non_completed_scan(service, scan_repo):
    scan_repo.get_by_scan_id.return_value = _make_scan(
        "k8s-1",
        SCANNER_TYPE_K8S,
        status="processing",
    )

    with pytest.raises(HTTPException) as exc_info:
        await service.execute_analysis_debug(k8s_scan_id="k8s-1")

    assert exc_info.value.status_code == 400
    assert "is not completed" in exc_info.value.detail


@pytest.mark.asyncio
async def test_execute_analysis_debug_rejects_k8s_image_cluster_mismatch(service, scan_repo):
    scan_repo.get_by_scan_id.side_effect = [
        _make_scan("k8s-1", SCANNER_TYPE_K8S, cluster_id="cluster-a"),
        _make_scan("img-1", SCANNER_TYPE_IMAGE, cluster_id="cluster-b"),
    ]

    with pytest.raises(HTTPException) as exc_info:
        await service.execute_analysis_debug(k8s_scan_id="k8s-1", image_scan_id="img-1")

    assert exc_info.value.status_code == 400
    assert "must belong to the same cluster" in exc_info.value.detail


@pytest.mark.asyncio
async def test_execute_analysis_debug_requires_at_least_one_scan_id(service):
    with pytest.raises(HTTPException) as exc_info:
        await service.execute_analysis_debug()

    assert exc_info.value.status_code == 422


@pytest.mark.asyncio
async def test_rejects_non_completed_scans(service, jobs_repo, scan_repo):
    scan_repo.get_by_scan_id.return_value = _make_scan(
        "k8s-1",
        SCANNER_TYPE_K8S,
        status="processing",
    )

    with pytest.raises(HTTPException) as exc_info:
        await service.create_analysis_job(k8s_scan_id="k8s-1")

    assert exc_info.value.status_code == 400
    jobs_repo.create_analysis_job.assert_not_awaited()


@pytest.mark.asyncio
async def test_rejects_mismatched_scanner_type(service, jobs_repo, scan_repo):
    scan_repo.get_by_scan_id.return_value = _make_scan(
        "aws-1",
        SCANNER_TYPE_AWS,
    )

    with pytest.raises(HTTPException) as exc_info:
        await service.create_analysis_job(k8s_scan_id="aws-1")

    assert exc_info.value.status_code == 400
    jobs_repo.create_analysis_job.assert_not_awaited()


@pytest.mark.asyncio
async def test_rejects_k8s_image_cluster_mismatch(service, jobs_repo, scan_repo):
    scan_repo.get_by_scan_id.side_effect = [
        _make_scan("k8s-1", SCANNER_TYPE_K8S, cluster_id="a1b2c3d4-e5f6-7890-abcd-ef1234567890"),
        _make_scan("img-1", SCANNER_TYPE_IMAGE, cluster_id="b2c3d4e5-f6a7-8901-bcde-f12345678901"),
    ]

    with pytest.raises(HTTPException) as exc_info:
        await service.create_analysis_job(k8s_scan_id="k8s-1", image_scan_id="img-1")

    assert exc_info.value.status_code == 400
    assert "must belong to the same cluster" in exc_info.value.detail
    jobs_repo.create_analysis_job.assert_not_awaited()


@pytest.mark.asyncio
async def test_allows_aws_scan_from_different_cluster_than_k8s_image(service, jobs_repo, scan_repo):
    scan_repo.get_by_scan_id.side_effect = [
        _make_scan("k8s-1", SCANNER_TYPE_K8S, cluster_id="a1b2c3d4-e5f6-7890-abcd-ef1234567890"),
        _make_scan("aws-1", SCANNER_TYPE_AWS, cluster_id="b2c3d4e5-f6a7-8901-bcde-f12345678901"),
        _make_scan("img-1", SCANNER_TYPE_IMAGE, cluster_id="a1b2c3d4-e5f6-7890-abcd-ef1234567890"),
    ]

    await service.create_analysis_job(
        k8s_scan_id="k8s-1",
        aws_scan_id="aws-1",
        image_scan_id="img-1",
    )

    jobs_repo.create_analysis_job.assert_awaited_once_with(
        cluster_id="a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        k8s_scan_id="k8s-1",
        aws_scan_id="aws-1",
        image_scan_id="img-1",
        expected_scans=["k8s", "aws", "image"],
        user_id=None,
    )


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
    jobs_repo.rollback.assert_awaited_once_with()
    jobs_repo.mark_failed.assert_awaited_once_with("job-123", "raw load failed")
    jobs_repo.mark_completed.assert_not_awaited()


@pytest.mark.asyncio
async def test_execute_analysis_job_uses_snapshotted_scalars_after_repo_state_changes(service, jobs_repo):
    class ExpiringJob:
        def __init__(self) -> None:
            self._expired = False

        @property
        def id(self):
            if self._expired:
                raise RuntimeError("expired job.id access")
            return "job-123"

        @property
        def cluster_id(self):
            if self._expired:
                raise RuntimeError("expired job.cluster_id access")
            return "cluster-1"

        @property
        def k8s_scan_id(self):
            if self._expired:
                raise RuntimeError("expired job.k8s_scan_id access")
            return "k8s-explicit"

        @property
        def aws_scan_id(self):
            if self._expired:
                raise RuntimeError("expired job.aws_scan_id access")
            return "aws-explicit"

        @property
        def image_scan_id(self):
            if self._expired:
                raise RuntimeError("expired job.image_scan_id access")
            return "img-explicit"

    job = ExpiringJob()
    jobs_repo.get_analysis_job.return_value = job

    async def expire_after_mark_running(*args, **kwargs):
        job._expired = True

    jobs_repo.mark_running.side_effect = expire_after_mark_running
    service.execute_analysis = AsyncMock(return_value={"stats": {"graph": {"nodes": 1}}})

    result = await service.execute_analysis_job("job-123")

    service.execute_analysis.assert_awaited_once_with(
        cluster_id="cluster-1",
        k8s_scan_id="k8s-explicit",
        aws_scan_id="aws-explicit",
        image_scan_id="img-explicit",
        analysis_job_id="job-123",
    )
    jobs_repo.mark_completed.assert_awaited_once_with("job-123", {"graph": {"nodes": 1}})
    assert result == {"stats": {"graph": {"nodes": 1}}}


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
async def test_load_scan_data_allows_aws_scan_from_different_cluster_when_cluster_match_disabled(service, scan_repo, s3_service):
    scan_repo.get_by_scan_id.return_value = _make_scan(
        "aws-1",
        SCANNER_TYPE_AWS,
        cluster_id="other-cluster",
        s3_keys=["scans/other-cluster/aws-1/aws/aws-snapshot.json"],
    )
    s3_service.load_json.return_value = {"resources": []}

    payload = await service._load_scan_data(
        "job-cluster",
        "aws-1",
        SCANNER_TYPE_AWS,
        require_cluster_match=False,
    )

    assert payload["scan_id"] == "aws-1"
    assert payload["cluster_id"] == "job-cluster"
    s3_service.load_json.assert_called_once_with("scans/other-cluster/aws-1/aws/aws-snapshot.json")


@pytest.mark.asyncio
async def test_load_scan_data_rejects_k8s_cluster_mismatch_when_cluster_match_required(service, scan_repo):
    scan_repo.get_by_scan_id.return_value = _make_scan(
        "k8s-1",
        SCANNER_TYPE_K8S,
        cluster_id="other-cluster",
    )

    with pytest.raises(ValueError, match="does not belong to cluster"):
        await service._load_scan_data("job-cluster", "k8s-1", SCANNER_TYPE_K8S, require_cluster_match=True)


@pytest.mark.asyncio
async def test_load_scan_data_rejects_scanner_type_mismatch(service, scan_repo):
    scan_repo.get_by_scan_id.return_value = _make_scan(
        "aws-1",
        SCANNER_TYPE_AWS,
        cluster_id="job-cluster",
    )

    with pytest.raises(ValueError, match="expected k8s"):
        await service._load_scan_data("job-cluster", "aws-1", SCANNER_TYPE_K8S)


@pytest.mark.asyncio
async def test_load_scan_data_rejects_non_completed_scan(service, scan_repo):
    scan_repo.get_by_scan_id.return_value = _make_scan(
        "img-1",
        SCANNER_TYPE_IMAGE,
        status="processing",
        cluster_id="job-cluster",
    )

    with pytest.raises(ValueError, match="is not completed"):
        await service._load_scan_data("job-cluster", "img-1", SCANNER_TYPE_IMAGE)


def test_coerce_aws_scan_result_maps_role_name_payload_to_iam_role_scan(service):
    result = service._coerce_aws_scan_result(
        {
            "scan_id": "aws-1",
            "aws_account_id": "123456789012",
            "scanned_at": "2026-03-23T00:00:00Z",
            "iam_roles": [
                {
                    "role_name": "AppRole",
                    "arn": "arn:aws:iam::123456789012:role/AppRole",
                    "is_irsa": True,
                    "irsa_oidc_issuer": "oidc.eks.ap-northeast-2.amazonaws.com/id/example",
                    "attached_policies": [],
                    "inline_policies": [],
                    "trust_policy": {"Version": "2012-10-17"},
                }
            ],
            "s3_buckets": [],
            "rds_instances": [],
            "ec2_instances": [],
            "security_groups": [],
        },
        "aws-1",
    )

    assert len(result.iam_roles) == 1
    assert isinstance(result.iam_roles[0], IAMRoleScan)
    assert result.iam_roles[0].name == "AppRole"
    assert result.iam_roles[0].arn == "arn:aws:iam::123456789012:role/AppRole"
    assert result.iam_roles[0].is_irsa is True


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
    assert service._load_scan_data.await_args_list[0].kwargs["require_cluster_match"] is True
    assert service._load_scan_data.await_args_list[1].kwargs["require_cluster_match"] is False
    assert service._load_scan_data.await_args_list[2].kwargs["require_cluster_match"] is True


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

    k8s_fact = Fact(
            fact_type="pod_uses_service_account",
            subject_id="pod:prod:api",
            subject_type="pod",
            object_id="sa:prod:api",
            object_type="service_account",
        )
    setattr(k8s_fact, "_persisted_scan_id", "k8s-1")
    aws_fact = Fact(
            fact_type="service_account_assumes_iam_role",
            subject_id="sa:prod:api",
            subject_type="service_account",
            object_id="iam:123456789012:AppRole",
            object_type="iam_role",
        )
    setattr(aws_fact, "_persisted_scan_id", "aws-1")

    service._build_k8s_result = MagicMock(return_value=k8s_result)
    service._extract_k8s_facts = MagicMock(return_value=[k8s_fact])
    service._coerce_aws_scan_result = MagicMock(return_value=MagicMock())
    service._bridge_builder.build = MagicMock(return_value=bridge_result)
    service._extract_aws_facts = MagicMock(return_value=[aws_fact])
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
    jobs_repo.persist_facts.assert_awaited_once()
    assert jobs_repo.persist_facts.await_args.kwargs["cluster_id"] == "cluster-1"
    assert jobs_repo.persist_facts.await_args.kwargs["graph_id"] == "11111111-1111-1111-1111-111111111111"
    persisted_facts = jobs_repo.persist_facts.await_args.kwargs["facts"]
    assert len(persisted_facts) == result["stats"]["facts"]["total"]
    assert [fact.fact_type for fact in persisted_facts] == [
        "pod_uses_service_account",
        "service_account_assumes_iam_role",
    ]
    facts_by_type = {fact.fact_type: getattr(fact, "_persisted_scan_id", None) for fact in persisted_facts}
    assert facts_by_type["pod_uses_service_account"] == "k8s-1"
    assert facts_by_type["service_account_assumes_iam_role"] == "aws-1"
    jobs_repo.persist_remediation_recommendations.assert_awaited_once_with(
        cluster_id="cluster-1",
        graph_id="11111111-1111-1111-1111-111111111111",
        k8s_scan_id="k8s-1",
        aws_scan_id="aws-1",
        image_scan_id="img-1",
        remediation_optimization={"summary": {"selected_count": 1}, "recommendations": []},
    )
    jobs_repo.persist_graph.assert_awaited_once()
    assert jobs_repo.persist_graph.await_args.kwargs["graph_id"] == "11111111-1111-1111-1111-111111111111"
    assert jobs_repo.persist_graph.await_args.kwargs["graph"] is graph
    jobs_repo.finalize_graph_snapshot.assert_awaited_once_with(
        graph_id="11111111-1111-1111-1111-111111111111",
        node_count=2,
        edge_count=1,
        entry_point_count=1,
        crown_jewel_count=1,
    )
    assert result["stats"]["graph"]["nodes"] == 2
    assert result["stats"]["paths"]["total"] == 1


@pytest.mark.asyncio
async def test_execute_analysis_returns_zero_paths_when_entry_and_crown_have_no_path(service, jobs_repo):
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
        nodes=[AWSGraphNode(id="iam_user:123456789012:target", type="iam_user", namespace="123456789012")],
        edges=[],
        metadata={"scan_id": "aws-1", "account_id": "123456789012", "graph_id": "aws-1-graph"},
    )
    unified_result = UnifiedGraphResult(
        nodes=[*k8s_result.nodes, *aws_result.nodes],
        edges=[],
        metadata={"sources": ["k8s", "aws"]},
        warnings=[],
    )
    bridge_result = MagicMock(irsa_mappings=[], credential_facts=[], warnings=[])
    graph = nx.DiGraph()
    graph.add_node("pod:prod:api", id="pod:prod:api", type="pod", is_entry_point=True, is_crown_jewel=False, base_risk=0.3, metadata={})
    graph.add_node("iam_user:123456789012:target", id="iam_user:123456789012:target", type="iam_user", is_entry_point=False, is_crown_jewel=True, base_risk=0.9, metadata={})

    service._build_k8s_result = MagicMock(return_value=k8s_result)
    service._extract_k8s_facts = MagicMock(return_value=[])
    service._coerce_aws_scan_result = MagicMock(return_value=MagicMock())
    service._bridge_builder.build = MagicMock(return_value=bridge_result)
    service._extract_aws_facts = MagicMock(return_value=[])
    service._build_aws_result = MagicMock(return_value=aws_result)
    service._unified_graph_builder.build = MagicMock(return_value=unified_result)
    service._graph_builder.build_from_unified_result = AsyncMock(return_value=graph)
    service._graph_builder.get_entry_points = MagicMock(return_value=["pod:prod:api"])
    service._graph_builder.get_crown_jewels = MagicMock(return_value=["iam_user:123456789012:target"])
    service._remediation_optimizer.optimize = MagicMock(return_value={"summary": {"selected_count": 0}, "recommendations": []})

    result = await service.execute_analysis("cluster-1", "k8s-1", "aws-1", "img-1")

    jobs_repo.persist_attack_paths.assert_awaited_once_with(
        cluster_id="cluster-1",
        graph_id="k8s-1-graph",
        k8s_scan_id="k8s-1",
        aws_scan_id="aws-1",
        image_scan_id="img-1",
        attack_paths=[],
    )
    jobs_repo.persist_remediation_recommendations.assert_awaited_once_with(
        cluster_id="cluster-1",
        graph_id="11111111-1111-1111-1111-111111111111",
        k8s_scan_id="k8s-1",
        aws_scan_id="aws-1",
        image_scan_id="img-1",
        remediation_optimization={"summary": {"selected_count": 0}, "recommendations": []},
    )
    jobs_repo.finalize_graph_snapshot.assert_awaited_once_with(
        graph_id="11111111-1111-1111-1111-111111111111",
        node_count=2,
        edge_count=0,
        entry_point_count=1,
        crown_jewel_count=1,
    )
    assert result["stats"]["graph"] == {
        "nodes": 2,
        "edges": 0,
        "entry_points": 1,
        "crown_jewels": 1,
    }
    assert result["stats"]["paths"] == {
        "total": 0,
        "returned": 0,
    }
    assert result["attack_paths"] == []
    assert result["remediation_optimization"] == {"summary": {"selected_count": 0}, "recommendations": []}


@pytest.mark.asyncio
async def test_execute_analysis_skips_self_entry_target_pairs(service, jobs_repo):
    service._load_scan_data = AsyncMock(side_effect=[
        {"scan_id": "k8s-1", "cluster_id": "cluster-1", "pods": []},
        {"scan_id": "aws-1", "aws_account_id": "123456789012"},
        {"scan_id": "img-1"},
    ])
    k8s_result = K8sBuildResult(
        nodes=[K8sGraphNode(id="s3:244105859679:testbed-bucket-02", type="s3_bucket")],
        edges=[],
        metadata={"scan_id": "k8s-1", "cluster_id": "cluster-1", "graph_id": "k8s-1-graph"},
    )
    aws_result = AWSBuildResult(
        nodes=[],
        edges=[],
        metadata={"scan_id": "aws-1", "account_id": "123456789012", "graph_id": "aws-1-graph"},
    )
    unified_result = UnifiedGraphResult(
        nodes=list(k8s_result.nodes),
        edges=[],
        metadata={"sources": ["k8s", "aws"]},
        warnings=[],
    )
    bridge_result = MagicMock(irsa_mappings=[], credential_facts=[], warnings=[])
    graph = nx.DiGraph()
    graph.add_node(
        "s3:244105859679:testbed-bucket-02",
        id="s3:244105859679:testbed-bucket-02",
        type="s3_bucket",
        is_entry_point=True,
        is_crown_jewel=True,
        base_risk=0.9,
        metadata={},
    )

    service._build_k8s_result = MagicMock(return_value=k8s_result)
    service._extract_k8s_facts = MagicMock(return_value=[])
    service._coerce_aws_scan_result = MagicMock(return_value=MagicMock())
    service._bridge_builder.build = MagicMock(return_value=bridge_result)
    service._extract_aws_facts = MagicMock(return_value=[])
    service._build_aws_result = MagicMock(return_value=aws_result)
    service._unified_graph_builder.build = MagicMock(return_value=unified_result)
    service._graph_builder.build_from_unified_result = AsyncMock(return_value=graph)
    service._graph_builder.get_entry_points = MagicMock(return_value=["s3:244105859679:testbed-bucket-02"])
    service._graph_builder.get_crown_jewels = MagicMock(return_value=["s3:244105859679:testbed-bucket-02"])
    service._remediation_optimizer.optimize = MagicMock(return_value={"summary": {"selected_count": 0}, "recommendations": []})

    result = await service.execute_analysis("cluster-1", "k8s-1", "aws-1", "img-1")

    jobs_repo.persist_attack_paths.assert_awaited_once_with(
        cluster_id="cluster-1",
        graph_id="k8s-1-graph",
        k8s_scan_id="k8s-1",
        aws_scan_id="aws-1",
        image_scan_id="img-1",
        attack_paths=[],
    )
    assert result["stats"]["paths"] == {
        "total": 0,
        "returned": 0,
    }
    assert result["attack_paths"] == []


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


@pytest.mark.asyncio
async def test_execute_analysis_uses_hop_limit_10_for_path_discovery(service):
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
    service._extract_k8s_facts = MagicMock(return_value=[])
    service._coerce_aws_scan_result = MagicMock(return_value=MagicMock())
    service._bridge_builder.build = MagicMock(return_value=MagicMock(irsa_mappings=[], credential_facts=[], warnings=[]))
    service._extract_aws_facts = MagicMock(return_value=[])
    service._build_aws_result = MagicMock(return_value=aws_result)
    service._unified_graph_builder.build = MagicMock(return_value=unified_result)
    service._graph_builder.build_from_unified_result = AsyncMock(return_value=graph)
    service._graph_builder.get_entry_points = MagicMock(return_value=["pod:prod:api"])
    service._graph_builder.get_crown_jewels = MagicMock(return_value=["iam:123456789012:AppRole"])
    service._path_finder.find_all_paths = MagicMock(return_value=[])
    service._remediation_optimizer.optimize = MagicMock(return_value={"summary": {"selected_count": 0}, "recommendations": []})

    await service.execute_analysis("cluster-1", "k8s-1", "aws-1", "img-1")

    assert MAX_HOPS == 10
    service._path_finder.find_all_paths.assert_called_once_with(
        graph,
        ["pod:prod:api"],
        ["iam:123456789012:AppRole"],
        max_path_length=10,
        max_paths=100,
    )


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
    assert "cluster_id" not in openapi["components"]["schemas"]["AnalysisJobRequest"]["properties"]
    debug_schema = openapi["components"]["schemas"]["DebugAnalysisExecuteRequest"]
    assert "cluster_id" not in debug_schema["properties"]
    assert "aws_scan_id" in debug_schema["properties"]
    assert len(debug_schema.get("examples", [])) == 3
    assert debug_schema["examples"][0]["aws_scan_id"] == "20260309T113020-aws"
    assert debug_schema["examples"][1] == {
        "k8s_scan_id": "20260309T113020-k8s",
        "image_scan_id": "20260309T113020-image",
    }
    assert debug_schema["examples"][2] == {"aws_scan_id": "20260309T113020-aws"}
