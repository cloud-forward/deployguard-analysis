"""Unit tests for IRSA bridge orchestration."""

from src.graph.builders.aws_graph_builder import AWSGraphBuilder
from src.graph.builders.aws_scanner_types import (
    AccessKeyScan,
    AWSScanResult,
    IAMRoleScan,
    IAMUserScan,
    RDSInstanceScan,
    S3BucketScan,
)
from src.graph.builders.irsa_bridge_builder import IRSABridgeBuilder


def make_aws_scan() -> AWSScanResult:
    account_id = "123456789012"
    return AWSScanResult(
        scan_id="20260309T113025-aws",
        aws_account_id=account_id,
        scanned_at="2026-03-09T11:30:25Z",
        iam_roles=[
            IAMRoleScan(
                name="WebAppRole",
                arn=f"arn:aws:iam::{account_id}:role/WebAppRole",
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
        ],
        s3_buckets=[
            S3BucketScan(
                name="sensitive-data-bucket",
                arn="arn:aws:s3:::sensitive-data-bucket",
                public_access_block=None,
                encryption=None,
                versioning="Disabled",
                logging_enabled=False,
            )
        ],
        rds_instances=[
            RDSInstanceScan(
                identifier="production-db",
                arn=f"arn:aws:rds:us-east-1:{account_id}:db:production-db",
                engine="postgres",
                storage_encrypted=True,
                publicly_accessible=False,
                vpc_security_groups=[],
                endpoint="prod-db.example.us-east-1.rds.amazonaws.com",
            )
        ],
        ec2_instances=[],
        security_groups=[],
        iam_users=[
            IAMUserScan(
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
        ],
    )


def test_bridge_builder_returns_irsa_and_credential_outputs():
    builder = IRSABridgeBuilder()
    aws_scan = make_aws_scan()
    k8s_scan = {
        "service_accounts": [
            {
                "metadata": {
                    "namespace": "production",
                    "name": "api-sa",
                    "annotations": {
                        "eks.amazonaws.com/role-arn": aws_scan.iam_roles[0].arn,
                    },
                }
            }
        ],
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

    result = builder.build(k8s_scan, aws_scan)

    assert len(result.irsa_mappings) == 1
    assert len(result.credential_facts) == 1
    assert result.irsa_mappings[0].iam_role_name == "WebAppRole"
    assert result.credential_facts[0].target_type == "iam_user"


def test_bridge_builder_combines_irsa_iam_user_rds_and_s3_outputs():
    builder = IRSABridgeBuilder()
    aws_scan = make_aws_scan()
    k8s_scan = {
        "service_accounts": [
            {
                "metadata": {
                    "namespace": "production",
                    "name": "api-sa",
                    "annotations": {
                        "eks.amazonaws.com/role-arn": aws_scan.iam_roles[0].arn,
                    },
                }
            }
        ],
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
            },
            {
                "metadata": {
                    "namespace": "production",
                    "name": "db-credentials",
                },
                "stringData": {
                    "host": "prod-db.example.us-east-1.rds.amazonaws.com",
                    "username": "appuser",
                    "password": "super-secret",
                },
            },
            {
                "metadata": {
                    "namespace": "production",
                    "name": "s3-config",
                },
                "stringData": {
                    "bucket": "sensitive-data-bucket",
                    "region": "us-east-1",
                },
            },
        ],
    }

    result = builder.build(k8s_scan, aws_scan)

    assert len(result.irsa_mappings) == 1
    assert len(result.credential_facts) == 3
    facts_by_type = {fact.target_type: fact for fact in result.credential_facts}
    assert facts_by_type["iam_user"].target_id == "web-app-deployer"
    assert facts_by_type["rds"].target_id == "production-db"
    assert facts_by_type["s3"].target_id == "sensitive-data-bucket"


def test_bridge_builder_credential_config_mapping_wins_for_iam_user_secret():
    builder = IRSABridgeBuilder()
    aws_scan = make_aws_scan()
    k8s_scan = {
        "secrets": [
            {
                "metadata": {
                    "namespace": "production",
                    "name": "aws-credentials",
                },
                "stringData": {
                    "AWS_ACCESS_KEY_ID": "AKIAUNKNOWNKEY000000",
                    "AWS_SECRET_ACCESS_KEY": "super-secret",
                },
            }
        ],
    }

    result = builder.build(
        k8s_scan,
        aws_scan,
        credential_config={"production/aws-credentials": "configured-user"},
    )

    assert len(result.credential_facts) == 1
    assert result.credential_facts[0].target_type == "iam_user"
    assert result.credential_facts[0].target_id == "configured-user"
    assert result.credential_facts[0].confidence == "high"


def test_bridge_builder_outputs_feed_directly_into_aws_graph_builder():
    bridge_builder = IRSABridgeBuilder()
    aws_scan = make_aws_scan()
    k8s_scan = {
        "service_accounts": [
            {
                "metadata": {
                    "namespace": "production",
                    "name": "api-sa",
                    "annotations": {
                        "eks.amazonaws.com/role-arn": aws_scan.iam_roles[0].arn,
                    },
                }
            }
        ],
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

    bridge_result = bridge_builder.build(k8s_scan, aws_scan)
    aws_builder = AWSGraphBuilder(aws_scan.aws_account_id, aws_scan.scan_id)
    build_result = aws_builder.build(
        aws_scan,
        irsa_mappings=bridge_result.irsa_mappings,
        credential_facts=bridge_result.credential_facts,
    )
    edges = build_result.edges

    edge_triplets = {(edge.source, edge.target, edge.type) for edge in edges}
    assert (
        "sa:production:api-sa",
        f"iam:{aws_scan.aws_account_id}:WebAppRole",
        "service_account_assumes_iam_role",
    ) in edge_triplets
    assert (
        "secret:production:aws-credentials",
        f"iam_user:{aws_scan.aws_account_id}:web-app-deployer",
        "secret_contains_aws_credentials",
    ) in edge_triplets


def test_bridge_builder_outputs_feed_directly_into_aws_builder_bridge_composition():
    bridge_builder = IRSABridgeBuilder()
    aws_scan = make_aws_scan()
    k8s_scan = {
        "service_accounts": [
            {
                "metadata": {
                    "namespace": "production",
                    "name": "api-sa",
                    "annotations": {
                        "eks.amazonaws.com/role-arn": aws_scan.iam_roles[0].arn,
                    },
                }
            }
        ],
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
            },
            {
                "metadata": {
                    "namespace": "production",
                    "name": "db-credentials",
                },
                "stringData": {
                    "host": "prod-db.example.us-east-1.rds.amazonaws.com",
                    "username": "appuser",
                    "password": "super-secret",
                },
            },
        ],
    }

    bridge_result = bridge_builder.build(k8s_scan, aws_scan)
    build_result = AWSGraphBuilder(
        aws_scan.aws_account_id,
        aws_scan.scan_id,
    ).build_with_bridge_result(aws_scan, bridge_result)

    edge_triplets = {(edge.source, edge.target, edge.type) for edge in build_result.edges}
    assert (
        "sa:production:api-sa",
        f"iam:{aws_scan.aws_account_id}:WebAppRole",
        "service_account_assumes_iam_role",
    ) in edge_triplets
    assert (
        "secret:production:aws-credentials",
        f"iam_user:{aws_scan.aws_account_id}:web-app-deployer",
        "secret_contains_aws_credentials",
    ) in edge_triplets
    assert (
        "secret:production:db-credentials",
        f"rds:{aws_scan.aws_account_id}:production-db",
        "secret_contains_credentials",
    ) in edge_triplets


def test_bridge_builder_handles_empty_inputs_safely():
    builder = IRSABridgeBuilder()
    aws_scan = AWSScanResult(
        scan_id="20260309T113025-aws",
        aws_account_id="123456789012",
        scanned_at="2026-03-09T11:30:25Z",
        iam_roles=[],
        s3_buckets=[],
        rds_instances=[],
        ec2_instances=[],
        security_groups=[],
        iam_users=[],
    )

    result = builder.build({}, aws_scan)

    assert result.irsa_mappings == []
    assert result.credential_facts == []
    assert result.warnings == []
    assert result.skipped_irsa == 0
    assert result.skipped_credentials == 0


def test_bridge_builder_emits_structured_warning_for_malformed_irsa_arn():
    builder = IRSABridgeBuilder()
    aws_scan = make_aws_scan()
    k8s_scan = {
        "service_accounts": [
            {
                "metadata": {
                    "namespace": "production",
                    "name": "api-sa",
                    "annotations": {
                        "eks.amazonaws.com/role-arn": "not-an-arn",
                    },
                }
            }
        ]
    }

    result = builder.build(k8s_scan, aws_scan)

    assert result.warnings == [
        {
            "level": "WARNING",
            "reason": "malformed_role_arn",
            "resource": "service_account:production/api-sa",
            "note": "annotated IRSA role ARN is malformed",
        }
    ]


def test_bridge_builder_emits_structured_warning_for_kube2iam_annotation():
    builder = IRSABridgeBuilder()
    aws_scan = make_aws_scan()
    k8s_scan = {
        "service_accounts": [
            {
                "metadata": {
                    "namespace": "production",
                    "name": "api-sa",
                    "annotations": {
                        "iam.amazonaws.com/role": "legacy-role",
                    },
                }
            }
        ]
    }

    result = builder.build(k8s_scan, aws_scan)

    assert result.warnings == [
        {
            "level": "INFO",
            "reason": "kube2iam_unsupported",
            "resource": "service_account:production/api-sa",
            "note": "kube2iam/kiam role annotations are unsupported",
        }
    ]


def test_bridge_builder_emits_structured_warning_for_unknown_iam_user_fallback():
    builder = IRSABridgeBuilder()
    aws_scan = make_aws_scan()
    k8s_scan = {
        "secrets": [
            {
                "metadata": {
                    "namespace": "production",
                    "name": "aws-credentials",
                },
                "stringData": {
                    "AWS_ACCESS_KEY_ID": "AKIAUNKNOWNKEY000000",
                    "AWS_SECRET_ACCESS_KEY": "super-secret",
                },
            }
        ]
    }

    result = builder.build(k8s_scan, aws_scan)

    assert len(result.credential_facts) == 1
    assert result.credential_facts[0].target_id == "unknown"
    assert result.warnings == [
        {
            "level": "WARNING",
            "reason": "iam_user_unresolved",
            "resource": "secret:production/aws-credentials",
            "note": "AWS credential keys found but IAM user could not be resolved",
        }
    ]


def test_bridge_builder_emits_structured_warnings_for_unresolved_rds_and_s3_targets():
    builder = IRSABridgeBuilder()
    aws_scan = make_aws_scan()
    k8s_scan = {
        "secrets": [
            {
                "metadata": {
                    "namespace": "production",
                    "name": "db-credentials",
                },
                "stringData": {
                    "host": "missing-db.example.us-east-1.rds.amazonaws.com",
                    "username": "appuser",
                    "password": "super-secret",
                },
            },
            {
                "metadata": {
                    "namespace": "production",
                    "name": "s3-config",
                },
                "stringData": {
                    "bucket": "missing-bucket",
                    "region": "us-east-1",
                },
            },
        ]
    }

    result = builder.build(k8s_scan, aws_scan)

    assert result.credential_facts == []
    assert result.warnings == [
        {
            "level": "WARNING",
            "reason": "rds_target_unresolved",
            "resource": "secret:production/db-credentials",
            "note": "RDS credential pattern found but no scanned endpoint matched",
        },
        {
            "level": "WARNING",
            "reason": "s3_target_unresolved",
            "resource": "secret:production/s3-config",
            "note": "S3 credential pattern found but no scanned bucket matched",
        },
    ]


# ---------------------------------------------------------------------------
# Flat scanner format regression tests
# ---------------------------------------------------------------------------


def test_bridge_builder_irsa_from_flat_format_service_account():
    """Service accounts without a 'metadata' wrapper must still produce IRSA edges."""
    builder = IRSABridgeBuilder()
    aws_scan = make_aws_scan()
    k8s_scan = {
        "service_accounts": [
            {
                "namespace": "production",
                "name": "api-sa",
                "annotations": {
                    "eks.amazonaws.com/role-arn": aws_scan.iam_roles[0].arn,
                },
            }
        ],
    }

    result = builder.build(k8s_scan, aws_scan)

    assert len(result.irsa_mappings) == 1
    assert result.irsa_mappings[0].sa_namespace == "production"
    assert result.irsa_mappings[0].sa_name == "api-sa"
    assert result.irsa_mappings[0].iam_role_name == "WebAppRole"
    assert result.skipped_irsa == 0


def test_bridge_builder_credentials_from_flat_format_secrets():
    """Secrets without a 'metadata' wrapper must still produce credential edges."""
    builder = IRSABridgeBuilder()
    aws_scan = make_aws_scan()
    k8s_scan = {
        "secrets": [
            {
                "namespace": "production",
                "name": "aws-credentials",
                "stringData": {
                    "AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE",
                    "AWS_SECRET_ACCESS_KEY": "super-secret",
                },
            },
            {
                "namespace": "production",
                "name": "db-credentials",
                "stringData": {
                    "host": "prod-db.example.us-east-1.rds.amazonaws.com",
                    "username": "appuser",
                    "password": "super-secret",
                },
            },
            {
                "namespace": "production",
                "name": "s3-config",
                "stringData": {
                    "bucket": "sensitive-data-bucket",
                    "region": "us-east-1",
                },
            },
        ],
    }

    result = builder.build(k8s_scan, aws_scan)

    assert len(result.credential_facts) == 3
    facts_by_type = {fact.target_type: fact for fact in result.credential_facts}
    assert facts_by_type["iam_user"].target_id == "web-app-deployer"
    assert facts_by_type["rds"].target_id == "production-db"
    assert facts_by_type["s3"].target_id == "sensitive-data-bucket"


def test_bridge_builder_flat_format_feeds_into_aws_graph_builder():
    """End-to-end: flat-format K8s scan -> bridge -> AWS graph edges."""
    bridge_builder = IRSABridgeBuilder()
    aws_scan = make_aws_scan()
    k8s_scan = {
        "service_accounts": [
            {
                "namespace": "production",
                "name": "api-sa",
                "annotations": {
                    "eks.amazonaws.com/role-arn": aws_scan.iam_roles[0].arn,
                },
            }
        ],
        "secrets": [
            {
                "namespace": "production",
                "name": "aws-credentials",
                "stringData": {
                    "AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE",
                    "AWS_SECRET_ACCESS_KEY": "super-secret",
                },
            },
            {
                "namespace": "production",
                "name": "db-credentials",
                "stringData": {
                    "host": "prod-db.example.us-east-1.rds.amazonaws.com",
                    "username": "appuser",
                    "password": "super-secret",
                },
            },
        ],
    }

    bridge_result = bridge_builder.build(k8s_scan, aws_scan)
    build_result = AWSGraphBuilder(
        aws_scan.aws_account_id,
        aws_scan.scan_id,
    ).build_with_bridge_result(aws_scan, bridge_result)

    edge_triplets = {(edge.source, edge.target, edge.type) for edge in build_result.edges}
    assert (
        "sa:production:api-sa",
        f"iam:{aws_scan.aws_account_id}:WebAppRole",
        "service_account_assumes_iam_role",
    ) in edge_triplets
    assert (
        "secret:production:aws-credentials",
        f"iam_user:{aws_scan.aws_account_id}:web-app-deployer",
        "secret_contains_aws_credentials",
    ) in edge_triplets
    assert (
        "secret:production:db-credentials",
        f"rds:{aws_scan.aws_account_id}:production-db",
        "secret_contains_credentials",
    ) in edge_triplets


def test_bridge_builder_flat_format_warnings_include_malformed_arn():
    """Warnings must work for flat-format SAs with bad ARNs."""
    builder = IRSABridgeBuilder()
    aws_scan = make_aws_scan()
    k8s_scan = {
        "service_accounts": [
            {
                "namespace": "production",
                "name": "api-sa",
                "annotations": {
                    "eks.amazonaws.com/role-arn": "not-an-arn",
                },
            }
        ],
    }

    result = builder.build(k8s_scan, aws_scan)

    assert result.irsa_mappings == []
    assert result.skipped_irsa == 1
    assert any(w["reason"] == "malformed_role_arn" for w in result.warnings)


def test_bridge_builder_flat_format_candidate_counts_are_accurate():
    """Candidate counts must reflect flat-format SAs and secrets."""
    builder = IRSABridgeBuilder()
    aws_scan = make_aws_scan()
    k8s_scan = {
        "service_accounts": [
            {
                "namespace": "production",
                "name": "api-sa",
                "annotations": {
                    "eks.amazonaws.com/role-arn": aws_scan.iam_roles[0].arn,
                },
            },
            {
                "namespace": "production",
                "name": "unannotated-sa",
            },
        ],
        "secrets": [
            {
                "namespace": "production",
                "name": "db-credentials",
                "stringData": {
                    "host": "prod-db.example.us-east-1.rds.amazonaws.com",
                    "username": "appuser",
                    "password": "super-secret",
                },
            },
            {
                "namespace": "production",
                "name": "inert-secret",
                "data": {
                    "config": "not-credential-data",
                },
            },
        ],
    }

    result = builder.build(k8s_scan, aws_scan)

    assert len(result.irsa_mappings) == 1
    assert result.skipped_irsa == 0
    assert len(result.credential_facts) == 1
    assert result.skipped_credentials == 0
