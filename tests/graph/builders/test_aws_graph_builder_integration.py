"""Integration tests for AWS Graph Builder — complete flow validation."""
import pytest
from src.graph.builders.aws_graph_builder import AWSGraphBuilder
from src.graph.builders.build_result_types import AWSBuildResult
from src.graph.builders.aws_scanner_types import (
    AccessKeyScan,
    AWSScanResult,
    EC2InstanceScan,
    IAMRoleScan,
    IAMUserScan,
    RDSInstanceScan,
    S3BucketScan,
    SecurityGroupScan,
)
from src.graph.builders.cross_domain_types import IRSAMapping, SecretContainsCredentialsFact
from src.graph.builders.irsa_mapping_extractor import IRSAMappingExtractor
from src.graph.builders.iam_policy_parser import IAMPolicyParser
from src.graph.builders.iam_policy_types import (
    IAMPolicyAnalysisResult,
    IAMUserPolicyAnalysisResult,
    ResourceAccess,
    TrustPolicyAnalysis,
)
from src.graph.builders.secret_credentials_extractor import SecretCredentialsExtractor


def test_golden_path_002_partial():
    """Test GP-002 scenario (RBAC → Secret → RDS) for AWS components only.

    Validates that:
    - RDS and SG nodes are created with correct IDs and properties
    - Compliance violations are detected on both nodes
    - SG → RDS and Secret → RDS edges are created
    - scan_id is propagated to all node and edge metadata
    """
    account_id = "123456789012"
    scan_id = "20260309T113025-aws"

    # --- Setup scan data ---
    rds = RDSInstanceScan(
        identifier="production-db",
        arn=f"arn:aws:rds:us-east-1:{account_id}:db:production-db",
        engine="postgres",
        storage_encrypted=False,
        publicly_accessible=False,
        vpc_security_groups=["sg-id"],
    )

    sg = SecurityGroupScan(
        group_id="sg-id",
        group_name="production-db-sg",
        vpc_id="vpc-12345",
        inbound_rules=[
            {"IpRanges": [{"CidrIp": "0.0.0.0/0"}], "FromPort": 5432, "ToPort": 5432, "IpProtocol": "tcp"}
        ],
        outbound_rules=[],
    )

    scan = AWSScanResult(
        scan_id=scan_id,
        aws_account_id=account_id,
        scanned_at="2026-03-09T11:30:25Z",
        iam_roles=[],
        s3_buckets=[],
        rds_instances=[rds],
        ec2_instances=[],
        security_groups=[sg],
    )

    credential_fact = SecretContainsCredentialsFact(
        secret_namespace="production",
        secret_name="rds-master-creds",
        target_type="rds",
        target_id="production-db",
        matched_keys=["host", "port", "username", "password"],
        confidence="high",
    )

    # --- Execute ---
    builder = AWSGraphBuilder(account_id, scan_id)
    result = builder.build(scan, [], [credential_fact])
    assert isinstance(result, AWSBuildResult)
    nodes, edges = result.nodes, result.edges

    # --- Helper lookups ---
    nodes_by_id = {n.id: n for n in nodes}
    edges_as_pairs = [(e.source, e.target) for e in edges]
    edge_types_by_pair = {(e.source, e.target): e.type for e in edges}

    # --- RDS node assertions ---
    rds_id = f"rds:{account_id}:production-db"
    assert rds_id in nodes_by_id, "RDS node should exist"
    rds_node = nodes_by_id[rds_id]
    assert rds_node.is_crown_jewel is True
    assert "PISM-034" in rds_node.metadata["compliance_violations"]

    # --- SG node assertions ---
    sg_id = f"sg:{account_id}:sg-id"
    assert sg_id in nodes_by_id, "SG node should exist"
    sg_node = nodes_by_id[sg_id]
    assert sg_node.metadata["is_publicly_accessible"] is True
    assert "PISM-007" in sg_node.metadata["compliance_violations"]

    # --- Edge assertions ---
    assert (sg_id, rds_id) in edges_as_pairs, "SG → RDS edge should exist"

    secret_id = "secret:production:rds-master-creds"
    assert (secret_id, rds_id) in edges_as_pairs, "Secret → RDS edge should exist"

    # --- scan_id propagation ---
    for node in nodes:
        assert node.metadata.get("scan_id") == scan_id, (
            f"Node {node.id} missing scan_id in metadata"
        )
    for edge in edges:
        assert edge.metadata.get("scan_id") == scan_id, (
            f"Edge {edge.source}→{edge.target} missing scan_id in metadata"
        )


def test_golden_path_001_full():
    """GP-001: SSRF → IMDS → IRSA → S3 full attack path."""
    account_id = "123456789012"
    scan_id = "20260309T113025-aws"

    ec2 = EC2InstanceScan(
        instance_id="i-worker-node-1",
        instance_type="t3.medium",
        metadata_options={"HttpTokens": "optional"},
        iam_instance_profile=None,
        security_groups=[],
        tags={},
    )
    iam_role = IAMRoleScan(
        name="WebAppRole",
        arn=f"arn:aws:iam::{account_id}:role/WebAppRole",
        is_irsa=True,
        irsa_oidc_issuer="https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE",
        attached_policies=[],
        inline_policies=[],
        trust_policy={},
    )
    s3 = S3BucketScan(
        name="sensitive-data-bucket",
        arn=f"arn:aws:s3:::sensitive-data-bucket",
        public_access_block={"BlockPublicAcls": False},
        encryption=None,
        versioning="Disabled",
        logging_enabled=False,
    )
    scan = AWSScanResult(
        scan_id=scan_id,
        aws_account_id=account_id,
        scanned_at="2026-03-09T11:30:25Z",
        iam_roles=[iam_role],
        s3_buckets=[s3],
        rds_instances=[],
        ec2_instances=[ec2],
        security_groups=[],
    )
    irsa_mappings = [
        IRSAMapping(
            sa_namespace="production",
            sa_name="api-sa",
            iam_role_arn=f"arn:aws:iam::{account_id}:role/WebAppRole",
            iam_role_name="WebAppRole",
            account_id=account_id,
        )
    ]
    policy_results = [
        IAMPolicyAnalysisResult(
            role_name="WebAppRole",
            role_arn=f"arn:aws:iam::{account_id}:role/WebAppRole",
            account_id=account_id,
            tier=3,
            tier_reason="data_access",
            trust_analysis=TrustPolicyAnalysis(
                is_irsa_enabled=True,
                oidc_issuer="https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE",
                allows_all_sa=True,
                allowed_sa_patterns=[],
                allowed_sa_explicit=[],
                allows_ec2=False,
                allows_lambda=False,
                cross_account_principals=[],
            ),
            resource_access=[
                ResourceAccess(
                    service="s3",
                    actions=["s3:*"],
                    resource_arns=["*"],
                    effect="Allow",
                    is_wildcard_action=True,
                    is_wildcard_resource=True,
                    policy_name=None,
                    policy_arn=None,
                    conditions=None,
                )
            ],
            has_privilege_escalation=False,
            has_data_exfiltration_risk=True,
            has_credential_access=False,
        )
    ]

    builder = AWSGraphBuilder(account_id, scan_id)
    result = builder.build(scan, irsa_mappings, [], policy_results)
    nodes, edges = result.nodes, result.edges

    nodes_by_id = {n.id: n for n in nodes}
    edges_as_pairs = [(e.source, e.target, e.type) for e in edges]

    # EC2 node: IMDSv1 enabled, PISM-064 violation
    ec2_id = f"ec2:{account_id}:i-worker-node-1"
    assert ec2_id in nodes_by_id
    ec2_node = nodes_by_id[ec2_id]
    assert ec2_node.metadata["imds_v1_enabled"] is True
    assert "PISM-064" in ec2_node.metadata["compliance_violations"]

    # IAM node: tier=3 → not crown jewel, trust allows_all_sa=True
    iam_id = f"iam:{account_id}:WebAppRole"
    assert iam_id in nodes_by_id
    iam_node = nodes_by_id[iam_id]
    assert iam_node.is_crown_jewel is False
    assert iam_node.metadata["trust"]["allows_all_sa"] is True

    # S3 node: crown jewel, public
    s3_id = f"s3:{account_id}:sensitive-data-bucket"
    assert s3_id in nodes_by_id
    s3_node = nodes_by_id[s3_id]
    assert s3_node.is_crown_jewel is True
    assert s3_node.metadata["is_public"] is True

    # SA → IAM edge
    sa_id = "sa:production:api-sa"
    assert (sa_id, iam_id, "service_account_assumes_iam_role") in edges_as_pairs

    # IAM → S3 edge
    assert (iam_id, s3_id, "iam_role_access_resource") in edges_as_pairs


def test_golden_path_004_full():
    """GP-004: Supply Chain → Data Exfiltration via IRSA with explicit SA binding."""
    account_id = "123456789012"
    scan_id = "20260309T113025-aws"

    iam_role = IAMRoleScan(
        name="ApiServerRole",
        arn=f"arn:aws:iam::{account_id}:role/ApiServerRole",
        is_irsa=True,
        irsa_oidc_issuer="https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE",
        attached_policies=[],
        inline_policies=[],
        trust_policy={},
    )
    buckets = [
        S3BucketScan(
            name=name,
            arn=f"arn:aws:s3:::{name}",
            public_access_block=None,
            encryption=None,
            versioning="Disabled",
            logging_enabled=False,
        )
        for name in ["sensitive-data-bucket", "production-data", "backup-bucket"]
    ]
    scan = AWSScanResult(
        scan_id=scan_id,
        aws_account_id=account_id,
        scanned_at="2026-03-09T11:30:25Z",
        iam_roles=[iam_role],
        s3_buckets=buckets,
        rds_instances=[],
        ec2_instances=[],
        security_groups=[],
    )
    irsa_mappings = [
        IRSAMapping(
            sa_namespace="production",
            sa_name="api-server",
            iam_role_arn=f"arn:aws:iam::{account_id}:role/ApiServerRole",
            iam_role_name="ApiServerRole",
            account_id=account_id,
        )
    ]
    policy_results = [
        IAMPolicyAnalysisResult(
            role_name="ApiServerRole",
            role_arn=f"arn:aws:iam::{account_id}:role/ApiServerRole",
            account_id=account_id,
            tier=3,
            tier_reason="data_access",
            trust_analysis=TrustPolicyAnalysis(
                is_irsa_enabled=True,
                oidc_issuer="https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE",
                allows_all_sa=False,
                allowed_sa_patterns=[],
                allowed_sa_explicit=["system:serviceaccount:production:api-server"],
                allows_ec2=False,
                allows_lambda=False,
                cross_account_principals=[],
            ),
            resource_access=[
                ResourceAccess(
                    service="s3",
                    actions=["s3:GetObject", "s3:PutObject"],
                    resource_arns=["*"],
                    effect="Allow",
                    is_wildcard_action=False,
                    is_wildcard_resource=True,
                    policy_name=None,
                    policy_arn=None,
                    conditions=None,
                )
            ],
            has_privilege_escalation=False,
            has_data_exfiltration_risk=True,
            has_credential_access=False,
        )
    ]

    builder = AWSGraphBuilder(account_id, scan_id)
    result = builder.build(scan, irsa_mappings, [], policy_results)
    nodes, edges = result.nodes, result.edges

    nodes_by_id = {n.id: n for n in nodes}
    edges_as_pairs = [(e.source, e.target, e.type) for e in edges]

    iam_id = f"iam:{account_id}:ApiServerRole"
    sa_id = "sa:production:api-server"

    # SA → IAM edge exists
    assert (sa_id, iam_id, "service_account_assumes_iam_role") in edges_as_pairs

    # IAM → S3 edges: one per bucket (wildcard resource → all buckets)
    iam_to_s3_edges = [
        (src, tgt, typ) for src, tgt, typ in edges_as_pairs
        if src == iam_id and typ == "iam_role_access_resource"
    ]
    assert len(iam_to_s3_edges) == 3

    # Trust policy: not allows_all_sa, explicit SA listed
    iam_node = nodes_by_id[iam_id]
    assert iam_node.metadata["trust"]["allows_all_sa"] is False
    assert "system:serviceaccount:production:api-server" in iam_node.metadata["trust"]["allowed_sa_explicit"]


def test_iam_user_credential_secret_path():
    """Verify path: Secret (with injected IAM User key) → IAM User → S3 bucket."""
    account_id = "123456789012"
    scan_id = "20260309T113025-aws"

    # --- Setup ---
    user = IAMUserScan(
        username="web-app-deployer",
        arn=f"arn:aws:iam::{account_id}:user/web-app-deployer",
        access_keys=[
            AccessKeyScan(
                access_key_id="AKIAIOSFODNN7EXAMPLE",
                status="Active",
                create_date="2026-01-01T00:00:00Z",
            )
        ],
        attached_policies=[],
        inline_policies=[],
        has_mfa=False,
        last_used=None,
    )

    bucket = S3BucketScan(
        name="sensitive-data-bucket",
        arn="arn:aws:s3:::sensitive-data-bucket",
        public_access_block=None,
        encryption=None,
        versioning="Disabled",
        logging_enabled=False,
    )

    scan = AWSScanResult(
        scan_id=scan_id,
        aws_account_id=account_id,
        scanned_at="2026-03-09T11:30:25Z",
        iam_roles=[],
        s3_buckets=[bucket],
        rds_instances=[],
        ec2_instances=[],
        security_groups=[],
        iam_users=[user],
    )

    credential_fact = SecretContainsCredentialsFact(
        secret_namespace="production",
        secret_name="aws-credentials",
        target_type="iam_user",
        target_id="web-app-deployer",
        matched_keys=["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"],
        confidence="high",
    )

    user_policy_result = IAMUserPolicyAnalysisResult(
        username="web-app-deployer",
        user_arn=f"arn:aws:iam::{account_id}:user/web-app-deployer",
        account_id=account_id,
        tier=1,
        tier_reason="s3_wildcard_access",
        resource_access=[
            ResourceAccess(
                service="s3",
                actions=["s3:*"],
                resource_arns=["*"],
                effect="Allow",
                is_wildcard_action=True,
                is_wildcard_resource=True,
                policy_name="DeployerPolicy",
                policy_arn=None,
                conditions=None,
            )
        ],
        has_privilege_escalation=False,
        has_data_exfiltration_risk=True,
        has_credential_access=False,
    )

    # --- Execute ---
    builder = AWSGraphBuilder(account_id, scan_id)
    result = builder.build(
        scan,
        irsa_mappings=[],
        credential_facts=[credential_fact],
        user_policy_results=[user_policy_result],
    )
    nodes, edges = result.nodes, result.edges

    # --- Assert ---
    edges_as_pairs = [(e.source, e.target) for e in edges]
    edge_types_by_pair = {(e.source, e.target): e.type for e in edges}

    secret_id = "secret:production:aws-credentials"
    user_id = f"iam_user:{account_id}:web-app-deployer"
    s3_id = f"s3:{account_id}:sensitive-data-bucket"

    assert (secret_id, user_id) in edges_as_pairs, "Secret → IAM User edge should exist"
    assert edge_types_by_pair[(secret_id, user_id)] == "secret_contains_aws_credentials"
    assert (user_id, s3_id) in edges_as_pairs, "IAM User → S3 edge should exist"


def test_irsa_extractor_output_integrates_with_aws_graph_builder():
    account_id = "123456789012"
    scan_id = "20260309T113025-aws"
    role_arn = f"arn:aws:iam::{account_id}:role/WebAppRole"

    iam_role = IAMRoleScan(
        name="WebAppRole",
        arn=role_arn,
        is_irsa=True,
        irsa_oidc_issuer="https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE",
        attached_policies=[],
        inline_policies=[],
        trust_policy={
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Federated": (
                            f"arn:aws:iam::{account_id}:"
                            "oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE"
                        )
                    },
                    "Action": "sts:AssumeRoleWithWebIdentity",
                    "Condition": {
                        "StringEquals": {
                            "oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE:aud": "sts.amazonaws.com",
                            "oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE:sub": "system:serviceaccount:production:api-sa",
                        }
                    },
                }
            ]
        },
    )
    scan = AWSScanResult(
        scan_id=scan_id,
        aws_account_id=account_id,
        scanned_at="2026-03-09T11:30:25Z",
        iam_roles=[iam_role],
        s3_buckets=[],
        rds_instances=[],
        ec2_instances=[],
        security_groups=[],
    )
    service_accounts = [
        {
            "metadata": {
                "namespace": "production",
                "name": "api-sa",
                "annotations": {
                    "eks.amazonaws.com/role-arn": role_arn,
                },
            }
        }
    ]

    irsa_mappings = IRSAMappingExtractor().extract(service_accounts, scan.iam_roles)

    builder = AWSGraphBuilder(account_id, scan_id)
    result = builder.build(scan, irsa_mappings=irsa_mappings, credential_facts=[])
    edges = result.edges

    edge = next(e for e in edges if e.type == "service_account_assumes_iam_role")
    assert edge.source == "sa:production:api-sa"
    assert edge.target == f"iam:{account_id}:WebAppRole"
    assert edge.metadata["source_type"] == "irsa_mapper"
    assert edge.metadata["annotation_value"] == role_arn


def test_broad_irsa_trust_without_sub_integrates_with_aws_graph_builder():
    account_id = "123456789012"
    scan_id = "20260309T113025-aws"
    role_arn = f"arn:aws:iam::{account_id}:role/WebAppRole"

    iam_role = IAMRoleScan(
        name="WebAppRole",
        arn=role_arn,
        is_irsa=True,
        irsa_oidc_issuer="https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE",
        attached_policies=[],
        inline_policies=[],
        trust_policy={
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Federated": (
                            f"arn:aws:iam::{account_id}:"
                            "oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE"
                        )
                    },
                    "Action": "sts:AssumeRoleWithWebIdentity",
                    "Condition": {
                        "StringEquals": {
                            "oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE:aud": "sts.amazonaws.com",
                        }
                    },
                }
            ]
        },
    )
    scan = AWSScanResult(
        scan_id=scan_id,
        aws_account_id=account_id,
        scanned_at="2026-03-09T11:30:25Z",
        iam_roles=[iam_role],
        s3_buckets=[],
        rds_instances=[],
        ec2_instances=[],
        security_groups=[],
    )
    service_accounts = [
        {
            "metadata": {
                "namespace": "production",
                "name": "api-sa",
                "annotations": {
                    "eks.amazonaws.com/role-arn": role_arn,
                },
            }
        }
    ]

    irsa_mappings = IRSAMappingExtractor().extract(service_accounts, scan.iam_roles)
    policy_results = [IAMPolicyParser().parse(iam_role)]

    builder = AWSGraphBuilder(account_id, scan_id)
    result = builder.build(
        scan,
        irsa_mappings=irsa_mappings,
        credential_facts=[],
        policy_results=policy_results,
    )

    edge = next(e for e in result.edges if e.type == "service_account_assumes_iam_role")
    node = next(n for n in result.nodes if n.id == f"iam:{account_id}:WebAppRole")

    assert edge.source == "sa:production:api-sa"
    assert edge.target == f"iam:{account_id}:WebAppRole"
    assert node.metadata["trust"]["has_broad_irsa_trust"] is True
    assert node.metadata["trust"]["allowed_sa_explicit"] == []
    assert node.metadata["trust"]["allowed_sa_patterns"] == []


def test_secret_credentials_extractor_output_integrates_with_aws_graph_builder():
    account_id = "123456789012"
    scan_id = "20260309T113025-aws"

    user = IAMUserScan(
        username="web-app-deployer",
        arn=f"arn:aws:iam::{account_id}:user/web-app-deployer",
        access_keys=[
            AccessKeyScan(
                access_key_id="AKIAIOSFODNN7EXAMPLE",
                status="Active",
                create_date="2026-01-01T00:00:00Z",
            )
        ],
        attached_policies=[],
        inline_policies=[],
        has_mfa=False,
        last_used=None,
    )
    scan = AWSScanResult(
        scan_id=scan_id,
        aws_account_id=account_id,
        scanned_at="2026-03-09T11:30:25Z",
        iam_roles=[],
        s3_buckets=[],
        rds_instances=[],
        ec2_instances=[],
        security_groups=[],
        iam_users=[user],
    )
    secrets = [
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
    ]

    credential_facts = SecretCredentialsExtractor().extract(secrets, scan.iam_users)

    builder = AWSGraphBuilder(account_id, scan_id)
    result = builder.build(scan, irsa_mappings=[], credential_facts=credential_facts)
    edges = result.edges

    edge = next(e for e in edges if e.type == "secret_contains_aws_credentials")
    assert edge.source == "secret:production:aws-credentials"
    assert edge.target == f"iam_user:{account_id}:web-app-deployer"
    assert edge.metadata["source_type"] == "credential_matcher"
    assert edge.metadata["matched_keys"] == ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"]


def test_bridge_producer_outputs_coexist_in_single_aws_graph_build():
    account_id = "123456789012"
    scan_id = "20260309T113025-aws"
    role_arn = f"arn:aws:iam::{account_id}:role/WebAppRole"

    iam_role = IAMRoleScan(
        name="WebAppRole",
        arn=role_arn,
        is_irsa=True,
        irsa_oidc_issuer="https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE",
        attached_policies=[],
        inline_policies=[],
        trust_policy={
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Federated": (
                            f"arn:aws:iam::{account_id}:"
                            "oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE"
                        )
                    },
                    "Action": "sts:AssumeRoleWithWebIdentity",
                    "Condition": {
                        "StringEquals": {
                            "oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE:aud": "sts.amazonaws.com",
                            "oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE:sub": "system:serviceaccount:production:api-sa",
                        }
                    },
                }
            ]
        },
    )
    user = IAMUserScan(
        username="web-app-deployer",
        arn=f"arn:aws:iam::{account_id}:user/web-app-deployer",
        access_keys=[
            AccessKeyScan(
                access_key_id="AKIAIOSFODNN7EXAMPLE",
                status="Active",
                create_date="2026-01-01T00:00:00Z",
            )
        ],
        attached_policies=[],
        inline_policies=[],
        has_mfa=False,
        last_used=None,
    )
    scan = AWSScanResult(
        scan_id=scan_id,
        aws_account_id=account_id,
        scanned_at="2026-03-09T11:30:25Z",
        iam_roles=[iam_role],
        s3_buckets=[],
        rds_instances=[],
        ec2_instances=[],
        security_groups=[],
        iam_users=[user],
    )
    service_accounts = [
        {
            "metadata": {
                "namespace": "production",
                "name": "api-sa",
                "annotations": {
                    "eks.amazonaws.com/role-arn": role_arn,
                },
            }
        }
    ]
    secrets = [
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
    ]

    irsa_mappings = IRSAMappingExtractor().extract(service_accounts, scan.iam_roles)
    credential_facts = SecretCredentialsExtractor().extract(secrets, scan.iam_users)

    builder = AWSGraphBuilder(account_id, scan_id)
    result = builder.build(scan, irsa_mappings=irsa_mappings, credential_facts=credential_facts)
    edges = result.edges

    edges_as_triplets = {(e.source, e.target, e.type) for e in edges}
    assert (
        "sa:production:api-sa",
        f"iam:{account_id}:WebAppRole",
        "service_account_assumes_iam_role",
    ) in edges_as_triplets
    assert (
        "secret:production:aws-credentials",
        f"iam_user:{account_id}:web-app-deployer",
        "secret_contains_aws_credentials",
    ) in edges_as_triplets
