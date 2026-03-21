"""Unit tests for AWS Graph Builder edge builders."""
import pytest
from datetime import datetime
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
from src.graph.builders.iam_policy_types import IAMPolicyAnalysisResult, IAMUserPolicyAnalysisResult, ResourceAccess, TrustPolicyAnalysis


def make_scan(
    s3_buckets=None,
    rds_instances=None,
    ec2_instances=None,
    security_groups=None,
    iam_roles=None,
    iam_users=None,
) -> AWSScanResult:
    """Return an AWSScanResult populated with the provided test data."""
    return AWSScanResult(
        scan_id="scan-test-001",
        aws_account_id="account",
        scanned_at="2026-03-11T00:00:00Z",
        iam_roles=iam_roles or [],
        s3_buckets=s3_buckets or [],
        rds_instances=rds_instances or [],
        ec2_instances=ec2_instances or [],
        security_groups=security_groups or [],
        iam_users=iam_users or [],
    )


def build(scan: AWSScanResult, irsa_mappings=None, credential_facts=None, policy_results=None, user_policy_results=None):
    """Build graph from scan and return (nodes, edges)."""
    builder = AWSGraphBuilder(
        account_id=scan.aws_account_id,
        scan_id=scan.scan_id,
    )
    result = builder.build(
        scan,
        irsa_mappings=irsa_mappings or [],
        credential_facts=credential_facts or [],
        policy_results=policy_results,
        user_policy_results=user_policy_results,
    )
    return result.nodes, result.edges


# ---------------------------------------------------------------------------
# SG allows RDS
# ---------------------------------------------------------------------------

def test_sg_allows_rds_edge():
    rds = RDSInstanceScan(
        identifier="db-id",
        arn="arn:aws:rds:us-east-1:account:db:db-id",
        engine="mysql",
        storage_encrypted=True,
        publicly_accessible=False,
        vpc_security_groups=["sg-id"],
    )
    scan = make_scan(rds_instances=[rds])

    _, edges = build(scan)

    assert len(edges) == 1
    edge = edges[0]
    assert edge.type == "security_group_allows"
    assert edge.source == "sg:account:sg-id"
    assert edge.target == "rds:account:db-id"
    assert edge.metadata["resource_type"] == "rds"
    assert edge.metadata["rules"] == []
    assert edge.metadata["is_public"] is False
    assert edge.metadata["open_ports"] == []


# ---------------------------------------------------------------------------
# SG allows EC2
# ---------------------------------------------------------------------------

def test_sg_allows_ec2_edge():
    ec2 = EC2InstanceScan(
        instance_id="instance-id",
        instance_type="t3.micro",
        metadata_options={"HttpTokens": "required"},
        iam_instance_profile=None,
        security_groups=["sg-1", "sg-2"],
        tags={},
    )
    scan = make_scan(ec2_instances=[ec2])

    _, edges = build(scan)

    sg_edges = [e for e in edges if e.type == "security_group_allows"]
    assert len(sg_edges) == 2
    assert all(e.type == "security_group_allows" for e in sg_edges)


# ---------------------------------------------------------------------------
# Instance profile edge
# ---------------------------------------------------------------------------

def test_instance_profile_edge():
    ec2 = EC2InstanceScan(
        instance_id="instance-id",
        instance_type="t3.micro",
        metadata_options={"HttpTokens": "required"},
        iam_instance_profile={"Arn": "arn:aws:iam::account:instance-profile/role-name"},
        security_groups=[],
        tags={},
    )
    scan = make_scan(ec2_instances=[ec2])

    _, edges = build(scan)

    profile_edges = [e for e in edges if e.type == "instance_profile_assumes"]
    assert len(profile_edges) == 1
    edge = profile_edges[0]
    assert edge.type == "instance_profile_assumes"
    assert edge.source == "ec2:account:instance-id"
    assert edge.target == "iam:account:role-name"
    assert edge.metadata["via"] == "instance_profile"
    assert edge.metadata["profile_arn"] == "arn:aws:iam::account:instance-profile/role-name"
    assert edge.metadata["role_name"] == "role-name"


# ---------------------------------------------------------------------------
# IRSA edge
# ---------------------------------------------------------------------------

def test_irsa_edge():
    mapping = IRSAMapping(
        sa_namespace="namespace",
        sa_name="name",
        iam_role_arn="arn:aws:iam::account:role/role",
        iam_role_name="role",
        account_id="account",
    )
    scan = make_scan()

    _, edges = build(scan, irsa_mappings=[mapping])

    assert len(edges) == 1
    edge = edges[0]
    assert edge.type == "service_account_assumes_iam_role"
    assert edge.source == "sa:namespace:name"
    assert edge.target == "iam:account:role"
    assert edge.metadata["via"] == "irsa"
    assert edge.metadata["annotation_key"] == "eks.amazonaws.com/role-arn"
    assert edge.metadata["annotation_value"] == "arn:aws:iam::account:role/role"
    assert edge.metadata["source_type"] == "irsa_mapper"


# ---------------------------------------------------------------------------
# Credential edge
# ---------------------------------------------------------------------------

def test_credential_edge():
    fact = SecretContainsCredentialsFact(
        secret_namespace="namespace",
        secret_name="name",
        target_type="rds",
        target_id="db-id",
        matched_keys=["DB_PASSWORD", "DB_USER"],
        confidence="high",
    )
    scan = make_scan()

    _, edges = build(scan, credential_facts=[fact])

    assert len(edges) == 1
    edge = edges[0]
    assert edge.type == "secret_contains_credentials"
    assert edge.source == "secret:namespace:name"
    assert edge.target == "rds:account:db-id"
    assert "matched_keys" in edge.metadata
    assert edge.metadata["source_type"] == "credential_matcher"


def test_credential_edge_for_iam_user_uses_aws_specific_edge_type():
    fact = SecretContainsCredentialsFact(
        secret_namespace="namespace",
        secret_name="aws-creds",
        target_type="iam_user",
        target_id="deployer",
        matched_keys=["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"],
        confidence="high",
    )
    scan = make_scan()

    _, edges = build(scan, credential_facts=[fact])

    assert len(edges) == 1
    edge = edges[0]
    assert edge.type == "secret_contains_aws_credentials"
    assert edge.source == "secret:namespace:aws-creds"
    assert edge.target == "iam_user:account:deployer"


def test_credential_edge_for_s3_preserves_secret_contains_credentials_type():
    fact = SecretContainsCredentialsFact(
        secret_namespace="namespace",
        secret_name="s3-config",
        target_type="s3",
        target_id="data-bucket",
        matched_keys=["bucket", "region"],
        confidence="medium",
    )
    scan = make_scan()

    _, edges = build(scan, credential_facts=[fact])

    assert len(edges) == 1
    edge = edges[0]
    assert edge.type == "secret_contains_credentials"
    assert edge.source == "secret:namespace:s3-config"
    assert edge.target == "s3:account:data-bucket"


def test_no_cross_domain_edges_emitted_when_typed_bridge_inputs_absent():
    scan = make_scan()

    _, edges = build(scan, irsa_mappings=[], credential_facts=[])

    edge_types = {edge.type for edge in edges}
    assert "service_account_assumes_iam_role" not in edge_types
    assert "secret_contains_aws_credentials" not in edge_types
    assert "secret_contains_credentials" not in edge_types


# ---------------------------------------------------------------------------
# Dangling edge allowed
# ---------------------------------------------------------------------------

def test_dangling_edge_allowed():
    mapping = IRSAMapping(
        sa_namespace="namespace",
        sa_name="nonexistent-sa",
        iam_role_arn="arn:aws:iam::account:role/some-role",
        iam_role_name="some-role",
        account_id="account",
    )
    scan = make_scan()

    _, edges = build(scan, irsa_mappings=[mapping])

    assert len(edges) == 1
    assert edges[0].source == "sa:namespace:nonexistent-sa"


# ---------------------------------------------------------------------------
# Edge metadata completeness
# ---------------------------------------------------------------------------

def test_edge_metadata_completeness():
    mapping = IRSAMapping(
        sa_namespace="namespace",
        sa_name="name",
        iam_role_arn="arn:aws:iam::account:role/role",
        iam_role_name="role",
        account_id="account",
    )
    scan = make_scan()

    _, edges = build(scan, irsa_mappings=[mapping])

    edge = edges[0]
    assert "scan_id" in edge.metadata
    assert "source_type" in edge.metadata
    assert "created_at" in edge.metadata

    created_at = edge.metadata["created_at"]
    # Validate ISO 8601 format by parsing it (strip trailing Z for fromisoformat)
    datetime.fromisoformat(created_at.rstrip("Z"))


def test_build_result_includes_graph_metadata():
    scan = make_scan()
    builder = AWSGraphBuilder(
        account_id=scan.aws_account_id,
        scan_id=scan.scan_id,
    )

    result = builder.build(scan, [], [])

    assert isinstance(result, AWSBuildResult)
    assert result.nodes == []
    assert result.edges == []
    assert result.metadata == {
        "graph_id": f"{scan.scan_id}-graph",
        "scan_id": scan.scan_id,
        "account_id": scan.aws_account_id,
    }
    assert builder.graph_metadata is not None
    assert builder.graph_metadata.graph_id == f"{scan.scan_id}-graph"
    assert builder.graph_metadata.scan_id == scan.scan_id
    assert builder.graph_metadata.account_id == scan.aws_account_id
    datetime.fromisoformat(builder.graph_metadata.generated_at.rstrip("Z"))


# ---------------------------------------------------------------------------
# Helpers for IAM access edge tests
# ---------------------------------------------------------------------------

def make_iam_role(name: str = "role") -> IAMRoleScan:
    return IAMRoleScan(
        name=name,
        arn=f"arn:aws:iam::account:role/{name}",
        is_irsa=False,
        irsa_oidc_issuer=None,
        attached_policies=[],
        inline_policies=[],
        trust_policy={},
    )


def make_s3_bucket(name: str) -> S3BucketScan:
    return S3BucketScan(
        name=name,
        arn=f"arn:aws:s3:::{name}",
        public_access_block=None,
        encryption=None,
        versioning="Enabled",
        logging_enabled=False,
    )


def make_rds_instance(identifier: str) -> RDSInstanceScan:
    return RDSInstanceScan(
        identifier=identifier,
        arn=f"arn:aws:rds:us-east-1:account:db:{identifier}",
        engine="mysql",
        storage_encrypted=True,
        publicly_accessible=False,
        vpc_security_groups=[],
    )


def make_trust_analysis() -> TrustPolicyAnalysis:
    return TrustPolicyAnalysis(
        is_irsa_enabled=False,
        oidc_issuer=None,
        allows_all_sa=False,
        allowed_sa_patterns=[],
        allowed_sa_explicit=[],
        allows_ec2=False,
        allows_lambda=False,
        cross_account_principals=[],
    )


def make_policy_result(
    role_name: str,
    resource_access: list,
) -> IAMPolicyAnalysisResult:
    return IAMPolicyAnalysisResult(
        role_name=role_name,
        role_arn=f"arn:aws:iam::account:role/{role_name}",
        account_id="account",
        tier=None,
        tier_reason="",
        trust_analysis=make_trust_analysis(),
        resource_access=resource_access,
        has_privilege_escalation=False,
        has_data_exfiltration_risk=False,
        has_credential_access=False,
    )


def make_resource_access(
    service: str,
    is_wildcard_resource: bool = True,
    resource_arns: list | None = None,
    effect: str = "Allow",
    policy_name: str = "TestPolicy",
) -> ResourceAccess:
    return ResourceAccess(
        service=service,
        actions=["*"],
        resource_arns=resource_arns or [],
        effect=effect,
        is_wildcard_action=True,
        is_wildcard_resource=is_wildcard_resource,
        policy_name=policy_name,
        policy_arn=None,
        conditions=None,
    )


# ---------------------------------------------------------------------------
# IAM access edges
# ---------------------------------------------------------------------------

def test_iam_to_s3_wildcard_edge():
    bucket = make_s3_bucket("my-bucket")
    role = make_iam_role("role")
    resource_access = make_resource_access(service="s3", is_wildcard_resource=True)
    policy_result = make_policy_result("role", [resource_access])
    scan = make_scan(s3_buckets=[bucket], iam_roles=[role])
    _, edges = build(scan, policy_results=[policy_result])
    iam_edges = [e for e in edges if e.type == "iam_role_access_resource"]
    assert len(iam_edges) == 1
    edge = iam_edges[0]
    assert edge.source == "iam:account:role"
    assert edge.target == "s3:account:my-bucket"
    assert edge.type == "iam_role_access_resource"
    assert edge.metadata["is_wildcard_resource"] is True
    assert edge.metadata["policy_name"] == "TestPolicy"
    assert edge.metadata["source_type"] == "iam_policy_parser"


def test_iam_to_s3_specific_arn_edge():
    target_bucket = make_s3_bucket("target-bucket")
    other_bucket = make_s3_bucket("other-bucket")
    role = make_iam_role("role")
    resource_access = make_resource_access(
        service="s3",
        is_wildcard_resource=False,
        resource_arns=["arn:aws:s3:::target-bucket/*"],
    )
    policy_result = make_policy_result("role", [resource_access])
    scan = make_scan(s3_buckets=[target_bucket, other_bucket], iam_roles=[role])
    _, edges = build(scan, policy_results=[policy_result])
    iam_edges = [e for e in edges if e.type == "iam_role_access_resource"]
    assert len(iam_edges) == 1
    assert iam_edges[0].target == "s3:account:target-bucket"


def test_iam_to_rds_edge():
    rds = make_rds_instance("prod-db")
    role = make_iam_role("role")
    resource_access = make_resource_access(service="rds", is_wildcard_resource=True)
    policy_result = make_policy_result("role", [resource_access])
    scan = make_scan(rds_instances=[rds], iam_roles=[role])
    _, edges = build(scan, policy_results=[policy_result])
    iam_edges = [e for e in edges if e.type == "iam_role_access_resource"]
    assert len(iam_edges) == 1
    assert iam_edges[0].source == "iam:account:role"
    assert iam_edges[0].target == "rds:account:prod-db"


def test_iam_deny_effect_skipped():
    bucket = make_s3_bucket("my-bucket")
    role = make_iam_role("role")
    resource_access = make_resource_access(service="s3", effect="Deny")
    policy_result = make_policy_result("role", [resource_access])
    scan = make_scan(s3_buckets=[bucket], iam_roles=[role])
    _, edges = build(scan, policy_results=[policy_result])
    iam_edges = [e for e in edges if e.type == "iam_role_access_resource"]
    assert len(iam_edges) == 0


def test_iam_non_s3_rds_service_skipped():
    role = make_iam_role("role")
    resource_access = make_resource_access(service="ec2", is_wildcard_resource=True)
    policy_result = make_policy_result("role", [resource_access])
    scan = make_scan(iam_roles=[role])
    _, edges = build(scan, policy_results=[policy_result])
    iam_edges = [e for e in edges if e.type == "iam_role_access_resource"]
    assert len(iam_edges) == 0


def make_iam_user(username="web-app-deployer") -> IAMUserScan:
    """Return a minimal IAMUserScan for testing."""
    return IAMUserScan(
        username=username,
        arn=f"arn:aws:iam::account:user/{username}",
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


def make_iam_user_policy_result(username: str, resource_access: list) -> IAMUserPolicyAnalysisResult:
    """Return an IAMUserPolicyAnalysisResult for testing."""
    return IAMUserPolicyAnalysisResult(
        username=username,
        user_arn=f"arn:aws:iam::account:user/{username}",
        account_id="account",
        tier=None,
        tier_reason="",
        resource_access=resource_access,
        has_privilege_escalation=False,
        has_data_exfiltration_risk=False,
        has_credential_access=False,
    )


def test_iam_multiple_policies_multiple_edges():
    bucket_a = make_s3_bucket("bucket-a")
    bucket_b = make_s3_bucket("bucket-b")
    role_1 = make_iam_role("role-1")
    role_2 = make_iam_role("role-2")
    ra_1 = make_resource_access(service="s3", is_wildcard_resource=True, policy_name="Policy1")
    ra_2 = make_resource_access(service="s3", is_wildcard_resource=True, policy_name="Policy2")
    policy_result_1 = make_policy_result("role-1", [ra_1])
    policy_result_2 = make_policy_result("role-2", [ra_2])
    scan = make_scan(s3_buckets=[bucket_a, bucket_b], iam_roles=[role_1, role_2])
    _, edges = build(scan, policy_results=[policy_result_1, policy_result_2])
    iam_edges = [e for e in edges if e.type == "iam_role_access_resource"]
    assert len(iam_edges) == 4
    policy_names = {e.metadata["policy_name"] for e in iam_edges}
    assert "Policy1" in policy_names
    assert "Policy2" in policy_names


# ---------------------------------------------------------------------------
# IAM User access edges
# ---------------------------------------------------------------------------

def test_iam_user_to_s3_edge():
    # Arrange
    user = make_iam_user(username="web-app-deployer")
    bucket = make_s3_bucket("sensitive-data-bucket")
    resource_access = make_resource_access(service="s3", is_wildcard_resource=True)
    user_policy_result = make_iam_user_policy_result("web-app-deployer", [resource_access])
    scan = make_scan(s3_buckets=[bucket], iam_users=[user])
    # Act
    _, edges = build(scan, user_policy_results=[user_policy_result])
    # Assert
    iam_user_edges = [e for e in edges if e.type == "iam_user_access_resource"]
    assert len(iam_user_edges) == 1
    edge = iam_user_edges[0]
    assert edge.source == "iam_user:account:web-app-deployer"
    assert edge.target == "s3:account:sensitive-data-bucket"
    assert edge.type == "iam_user_access_resource"
    assert edge.metadata["source_type"] == "iam_policy_parser"
