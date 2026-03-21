import pytest

from app.core.graph_builder import GraphBuilder
from src.facts.canonical_fact import Fact
from src.facts.types import FactType, NodeType
from src.graph.builders.iam_policy_types import (
    IAMPolicyAnalysisResult,
    IAMUserPolicyAnalysisResult,
    ResourceAccess,
    TrustPolicyAnalysis,
)


@pytest.mark.asyncio
async def test_build_from_facts_seeds_k8s_nodes_from_k8s_builder_output():
    builder = GraphBuilder()
    facts = [
        Fact(
            fact_type=FactType.POD_USES_SERVICE_ACCOUNT.value,
            subject_id="pod:production:api-pod",
            subject_type=NodeType.POD.value,
            object_id="sa:production:api-sa",
            object_type=NodeType.SERVICE_ACCOUNT.value,
            metadata={},
        )
    ]
    k8s_scan = {
        "scan_id": "k8s-1",
        "pods": [
            {
                "namespace": "production",
                "name": "api-pod",
                "service_account": "api-sa",
                "node_name": "worker-1",
                "labels": {"app": "api"},
                "containers": [{"image": "nginx:1.25"}],
            }
        ],
        "service_accounts": [
            {"metadata": {"namespace": "production", "name": "api-sa", "annotations": {}}}
        ],
        "roles": [],
        "cluster_roles": [],
        "secrets": [],
        "services": [],
        "ingresses": [],
    }

    graph = await builder.build_from_facts(facts, k8s_scan=k8s_scan, scan_id="k8s-1")

    assert "pod:production:api-pod" in graph.nodes
    assert graph.nodes["pod:production:api-pod"]["metadata"]["node_name"] == "worker-1"
    assert graph.nodes["pod:production:api-pod"]["metadata"]["container_images"] == ["nginx:1.25"]


@pytest.mark.asyncio
async def test_build_from_facts_without_k8s_scan_remains_compatible():
    builder = GraphBuilder()
    facts = [
        Fact(
            fact_type=FactType.POD_USES_SERVICE_ACCOUNT.value,
            subject_id="pod:production:api-pod",
            subject_type=NodeType.POD.value,
            object_id="sa:production:api-sa",
            object_type=NodeType.SERVICE_ACCOUNT.value,
            metadata={},
        )
    ]

    graph = await builder.build_from_facts(facts)

    assert "pod:production:api-pod" in graph.nodes
    assert "sa:production:api-sa" in graph.nodes
    assert graph.edges["pod:production:api-pod", "sa:production:api-sa"]["type"] == FactType.POD_USES_SERVICE_ACCOUNT.value


@pytest.mark.asyncio
async def test_build_from_facts_without_aws_scan_remains_compatible():
    builder = GraphBuilder()
    facts = [
        Fact(
            fact_type=FactType.SECURITY_GROUP_ALLOWS.value,
            subject_id="sg:123456789012:sg-db",
            subject_type=NodeType.SECURITY_GROUP.value,
            object_id="rds:123456789012:production-db",
            object_type=NodeType.RDS.value,
            metadata={"source": "fact-only"},
        )
    ]

    graph = await builder.build_from_facts(facts)

    assert "sg:123456789012:sg-db" in graph.nodes
    assert "rds:123456789012:production-db" in graph.nodes
    assert graph.edges["sg:123456789012:sg-db", "rds:123456789012:production-db"]["metadata"] == {"source": "fact-only"}


@pytest.mark.asyncio
async def test_seeded_k8s_edge_metadata_is_not_overwritten_by_generic_fact_loop():
    builder = GraphBuilder()
    facts = [
        Fact(
            fact_type=FactType.POD_USES_SERVICE_ACCOUNT.value,
            subject_id="pod:production:api-pod",
            subject_type=NodeType.POD.value,
            object_id="sa:production:api-sa",
            object_type=NodeType.SERVICE_ACCOUNT.value,
            metadata={},
        )
    ]
    k8s_scan = {
        "scan_id": "k8s-1",
        "pods": [
            {
                "namespace": "production",
                "name": "api-pod",
                "service_account": "api-sa",
                "node_name": "worker-1",
                "labels": {"app": "api"},
                "containers": [{"image": "nginx:1.25"}],
            }
        ],
        "service_accounts": [
            {"metadata": {"namespace": "production", "name": "api-sa", "annotations": {}}}
        ],
        "roles": [],
        "cluster_roles": [],
        "secrets": [],
        "services": [],
        "ingresses": [],
    }

    graph = await builder.build_from_facts(facts, k8s_scan=k8s_scan, scan_id="k8s-1")

    assert graph.edges["pod:production:api-pod", "sa:production:api-sa"]["metadata"] == {}


@pytest.mark.asyncio
async def test_build_from_facts_seeds_aws_nodes_and_internal_edges_from_aws_builder():
    builder = GraphBuilder()
    facts = []
    aws_scan = {
        "scan_id": "aws-1",
        "aws_account_id": "123456789012",
        "scanned_at": "2026-03-21T00:00:00Z",
        "iam_roles": [],
        "iam_users": [],
        "s3_buckets": [],
        "rds_instances": [
            {
                "identifier": "production-db",
                "arn": "arn:aws:rds:us-east-1:123456789012:db:production-db",
                "engine": "postgres",
                "storage_encrypted": False,
                "publicly_accessible": False,
                "vpc_security_groups": ["sg-db"],
            }
        ],
        "ec2_instances": [],
        "security_groups": [
            {
                "group_id": "sg-db",
                "group_name": "db-sg",
                "vpc_id": "vpc-1",
                "inbound_rules": [
                    {"IpRanges": [{"CidrIp": "0.0.0.0/0"}], "FromPort": 5432, "ToPort": 5432, "IpProtocol": "tcp"}
                ],
                "outbound_rules": [],
            }
        ],
    }

    graph = await builder.build_from_facts(facts, aws_scan=aws_scan)

    assert "rds:123456789012:production-db" in graph.nodes
    assert "sg:123456789012:sg-db" in graph.nodes
    assert graph.nodes["rds:123456789012:production-db"]["metadata"]["engine"] == "postgres"
    assert graph.edges["sg:123456789012:sg-db", "rds:123456789012:production-db"]["type"] == "security_group_allows"
    assert graph.edges["sg:123456789012:sg-db", "rds:123456789012:production-db"]["metadata"]["source_type"] == "aws_scanner"


@pytest.mark.asyncio
async def test_cross_domain_edges_remain_on_generic_fact_loop_not_aws_typed_seed():
    builder = GraphBuilder()
    facts = [
        Fact(
            fact_type=FactType.SERVICE_ACCOUNT_ASSUMES_IAM_ROLE.value,
            subject_id="sa:production:api-sa",
            subject_type=NodeType.SERVICE_ACCOUNT.value,
            object_id="iam:123456789012:WebAppRole",
            object_type=NodeType.IAM_ROLE.value,
            metadata={"via": "fact-loop"},
        )
    ]
    aws_scan = {
        "scan_id": "aws-1",
        "aws_account_id": "123456789012",
        "scanned_at": "2026-03-21T00:00:00Z",
        "iam_roles": [
            {
                "name": "WebAppRole",
                "arn": "arn:aws:iam::123456789012:role/WebAppRole",
                "is_irsa": True,
                "irsa_oidc_issuer": "https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE",
                "attached_policies": [],
                "inline_policies": [],
                "trust_policy": {},
            }
        ],
        "iam_users": [],
        "s3_buckets": [],
        "rds_instances": [],
        "ec2_instances": [],
        "security_groups": [],
    }

    graph = await builder.build_from_facts(facts, aws_scan=aws_scan)

    assert graph.edges["sa:production:api-sa", "iam:123456789012:WebAppRole"]["metadata"] == {"via": "fact-loop"}


@pytest.mark.asyncio
async def test_seeded_aws_edge_metadata_is_not_overwritten_by_generic_fact_loop():
    builder = GraphBuilder()
    facts = [
        Fact(
            fact_type=FactType.SECURITY_GROUP_ALLOWS.value,
            subject_id="sg:123456789012:sg-db",
            subject_type=NodeType.SECURITY_GROUP.value,
            object_id="rds:123456789012:production-db",
            object_type=NodeType.RDS.value,
            metadata={"via": "fact-loop"},
        )
    ]
    aws_scan = {
        "scan_id": "aws-1",
        "aws_account_id": "123456789012",
        "scanned_at": "2026-03-21T00:00:00Z",
        "iam_roles": [],
        "iam_users": [],
        "s3_buckets": [],
        "rds_instances": [
            {
                "identifier": "production-db",
                "arn": "arn:aws:rds:us-east-1:123456789012:db:production-db",
                "engine": "postgres",
                "storage_encrypted": False,
                "publicly_accessible": False,
                "vpc_security_groups": ["sg-db"],
            }
        ],
        "ec2_instances": [],
        "security_groups": [
            {
                "group_id": "sg-db",
                "group_name": "db-sg",
                "vpc_id": "vpc-1",
                "inbound_rules": [],
                "outbound_rules": [],
            }
        ],
    }

    graph = await builder.build_from_facts(facts, aws_scan=aws_scan)

    assert graph.edges["sg:123456789012:sg-db", "rds:123456789012:production-db"]["metadata"]["source_type"] == "aws_scanner"
    assert graph.edges["sg:123456789012:sg-db", "rds:123456789012:production-db"]["metadata"].get("via") != "fact-loop"


@pytest.mark.asyncio
async def test_aws_policy_analysis_edges_are_seeded_when_policy_inputs_are_provided():
    builder = GraphBuilder()
    aws_scan = {
        "scan_id": "aws-1",
        "aws_account_id": "123456789012",
        "scanned_at": "2026-03-21T00:00:00Z",
        "iam_roles": [
            {
                "name": "DataRole",
                "arn": "arn:aws:iam::123456789012:role/DataRole",
                "is_irsa": False,
                "irsa_oidc_issuer": None,
                "attached_policies": [],
                "inline_policies": [],
                "trust_policy": {},
            }
        ],
        "iam_users": [
            {
                "username": "analyst",
                "arn": "arn:aws:iam::123456789012:user/analyst",
                "access_keys": [],
                "attached_policies": [],
                "inline_policies": [],
                "has_mfa": True,
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
    policy_results = [
        IAMPolicyAnalysisResult(
            role_name="DataRole",
            role_arn="arn:aws:iam::123456789012:role/DataRole",
            account_id="123456789012",
            tier=3,
            tier_reason="data_access",
            trust_analysis=TrustPolicyAnalysis(
                is_irsa_enabled=False,
                oidc_issuer=None,
                allows_all_sa=False,
                allowed_sa_patterns=[],
                allowed_sa_explicit=[],
                allows_ec2=False,
                allows_lambda=False,
                cross_account_principals=[],
            ),
            resource_access=[
                ResourceAccess(
                    service="s3",
                    actions=["s3:GetObject"],
                    resource_arns=["*"],
                    effect="Allow",
                    is_wildcard_action=False,
                    is_wildcard_resource=True,
                    policy_name="DataReadPolicy",
                    policy_arn=None,
                    conditions=None,
                )
            ],
            has_privilege_escalation=False,
            has_data_exfiltration_risk=True,
            has_credential_access=False,
        )
    ]
    user_policy_results = [
        IAMUserPolicyAnalysisResult(
            username="analyst",
            user_arn="arn:aws:iam::123456789012:user/analyst",
            account_id="123456789012",
            tier=3,
            tier_reason="data_access",
            resource_access=[
                ResourceAccess(
                    service="s3",
                    actions=["s3:GetObject"],
                    resource_arns=["*"],
                    effect="Allow",
                    is_wildcard_action=False,
                    is_wildcard_resource=True,
                    policy_name="DataReadPolicy",
                    policy_arn=None,
                    conditions=None,
                )
            ],
            has_privilege_escalation=False,
            has_data_exfiltration_risk=True,
            has_credential_access=False,
        )
    ]

    graph = await builder.build_from_facts(
        [],
        aws_scan=aws_scan,
        policy_results=policy_results,
        user_policy_results=user_policy_results,
    )

    assert graph.edges["iam:123456789012:DataRole", "s3:123456789012:sensitive-data-bucket"]["type"] == FactType.IAM_ROLE_ACCESS_RESOURCE.value
    assert graph.edges["iam:123456789012:DataRole", "s3:123456789012:sensitive-data-bucket"]["metadata"]["source_type"] == "iam_policy_parser"
    assert graph.edges["iam_user:123456789012:analyst", "s3:123456789012:sensitive-data-bucket"]["type"] == FactType.IAM_USER_ACCESS_RESOURCE.value
    assert graph.edges["iam_user:123456789012:analyst", "s3:123456789012:sensitive-data-bucket"]["metadata"]["source_type"] == "iam_policy_parser"


@pytest.mark.asyncio
async def test_seeded_aws_policy_edge_metadata_is_not_overwritten_by_generic_fact_loop():
    builder = GraphBuilder()
    facts = [
        Fact(
            fact_type=FactType.IAM_ROLE_ACCESS_RESOURCE.value,
            subject_id="iam:123456789012:DataRole",
            subject_type=NodeType.IAM_ROLE.value,
            object_id="s3:123456789012:sensitive-data-bucket",
            object_type=NodeType.S3_BUCKET.value,
            metadata={"via": "fact-loop"},
        )
    ]
    aws_scan = {
        "scan_id": "aws-1",
        "aws_account_id": "123456789012",
        "scanned_at": "2026-03-21T00:00:00Z",
        "iam_roles": [
            {
                "name": "DataRole",
                "arn": "arn:aws:iam::123456789012:role/DataRole",
                "is_irsa": False,
                "irsa_oidc_issuer": None,
                "attached_policies": [],
                "inline_policies": [],
                "trust_policy": {},
            }
        ],
        "iam_users": [],
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
    policy_results = [
        IAMPolicyAnalysisResult(
            role_name="DataRole",
            role_arn="arn:aws:iam::123456789012:role/DataRole",
            account_id="123456789012",
            tier=3,
            tier_reason="data_access",
            trust_analysis=TrustPolicyAnalysis(
                is_irsa_enabled=False,
                oidc_issuer=None,
                allows_all_sa=False,
                allowed_sa_patterns=[],
                allowed_sa_explicit=[],
                allows_ec2=False,
                allows_lambda=False,
                cross_account_principals=[],
            ),
            resource_access=[
                ResourceAccess(
                    service="s3",
                    actions=["s3:GetObject"],
                    resource_arns=["*"],
                    effect="Allow",
                    is_wildcard_action=False,
                    is_wildcard_resource=True,
                    policy_name="DataReadPolicy",
                    policy_arn=None,
                    conditions=None,
                )
            ],
            has_privilege_escalation=False,
            has_data_exfiltration_risk=True,
            has_credential_access=False,
        )
    ]

    graph = await builder.build_from_facts(
        facts,
        aws_scan=aws_scan,
        policy_results=policy_results,
    )

    assert graph.edges["iam:123456789012:DataRole", "s3:123456789012:sensitive-data-bucket"]["metadata"]["source_type"] == "iam_policy_parser"
    assert graph.edges["iam:123456789012:DataRole", "s3:123456789012:sensitive-data-bucket"]["metadata"].get("via") != "fact-loop"
