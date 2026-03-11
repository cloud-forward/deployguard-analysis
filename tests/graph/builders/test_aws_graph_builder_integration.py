"""Integration tests for AWS Graph Builder — complete flow validation."""
import pytest
from src.graph.builders.aws_graph_builder import AWSGraphBuilder
from src.graph.builders.aws_scanner_types import (
    AWSScanResult,
    RDSInstanceScan,
    SecurityGroupScan,
)
from src.graph.builders.cross_domain_types import SecretContainsCredentialsFact


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
    nodes, edges = builder.build(scan, [], [credential_fact])

    # --- Helper lookups ---
    nodes_by_id = {n.id: n for n in nodes}
    edges_as_pairs = [(e.source, e.target) for e in edges]

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
