"""Unit tests for IRSA mapping extraction."""

import logging

from src.graph.builders.aws_scanner_types import IAMRoleScan
from src.graph.builders.irsa_mapping_extractor import IRSAMappingExtractor


OIDC_PROVIDER_ARN = (
    "arn:aws:iam::123456789012:"
    "oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE"
)


def make_role(name: str, trust_policy: dict) -> IAMRoleScan:
    return IAMRoleScan(
        name=name,
        arn=f"arn:aws:iam::123456789012:role/{name}",
        is_irsa=True,
        irsa_oidc_issuer="oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE",
        attached_policies=[],
        inline_policies=[],
        trust_policy=trust_policy,
    )


def make_service_account(namespace: str, name: str, role_arn: str | None) -> dict:
    annotations = {}
    if role_arn is not None:
        annotations["eks.amazonaws.com/role-arn"] = role_arn
    return {
        "metadata": {
            "namespace": namespace,
            "name": name,
            "annotations": annotations,
        }
    }


def trust_policy_for_subject(subject: str) -> dict:
    return {
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Federated": OIDC_PROVIDER_ARN},
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "StringEquals": {
                        "oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE:aud": "sts.amazonaws.com",
                        "oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE:sub": subject,
                    }
                },
            }
        ]
    }


def test_valid_irsa_annotation_with_matching_trust_policy_emits_mapping():
    extractor = IRSAMappingExtractor()
    service_accounts = [
        make_service_account(
            "production",
            "api-sa",
            "arn:aws:iam::123456789012:role/WebAppRole",
        )
    ]
    iam_roles = [
        make_role(
            "WebAppRole",
            trust_policy_for_subject("system:serviceaccount:production:api-sa"),
        )
    ]

    mappings = extractor.extract(service_accounts, iam_roles)

    assert len(mappings) == 1
    assert mappings[0].sa_namespace == "production"
    assert mappings[0].sa_name == "api-sa"
    assert mappings[0].iam_role_name == "WebAppRole"
    assert mappings[0].account_id == "123456789012"


def test_annotation_present_but_iam_role_missing_emits_no_mapping():
    extractor = IRSAMappingExtractor()
    service_accounts = [
        make_service_account(
            "production",
            "api-sa",
            "arn:aws:iam::123456789012:role/MissingRole",
        )
    ]

    mappings = extractor.extract(service_accounts, [])

    assert mappings == []


def test_malformed_role_arn_emits_no_mapping():
    extractor = IRSAMappingExtractor()
    service_accounts = [
        make_service_account("production", "api-sa", "not-an-arn"),
    ]
    iam_roles = [
        make_role(
            "WebAppRole",
            trust_policy_for_subject("system:serviceaccount:production:api-sa"),
        )
    ]

    mappings = extractor.extract(service_accounts, iam_roles)

    assert mappings == []


def test_trust_policy_mismatch_emits_no_mapping():
    extractor = IRSAMappingExtractor()
    service_accounts = [
        make_service_account(
            "production",
            "api-sa",
            "arn:aws:iam::123456789012:role/WebAppRole",
        )
    ]
    iam_roles = [
        make_role(
            "WebAppRole",
            trust_policy_for_subject("system:serviceaccount:production:other-sa"),
        )
    ]

    mappings = extractor.extract(service_accounts, iam_roles)

    assert mappings == []


def test_aud_mismatch_emits_no_mapping():
    extractor = IRSAMappingExtractor()
    service_accounts = [
        make_service_account(
            "production",
            "api-sa",
            "arn:aws:iam::123456789012:role/WebAppRole",
        )
    ]
    iam_roles = [
        make_role(
            "WebAppRole",
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Federated": OIDC_PROVIDER_ARN},
                        "Action": "sts:AssumeRoleWithWebIdentity",
                        "Condition": {
                            "StringEquals": {
                                "oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE:aud": "other-audience",
                                "oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE:sub": "system:serviceaccount:production:api-sa",
                            }
                        },
                    }
                ]
            },
        )
    ]

    mappings = extractor.extract(service_accounts, iam_roles)

    assert mappings == []


def test_wrong_action_emits_no_mapping():
    extractor = IRSAMappingExtractor()
    service_accounts = [
        make_service_account(
            "production",
            "api-sa",
            "arn:aws:iam::123456789012:role/WebAppRole",
        )
    ]
    iam_roles = [
        make_role(
            "WebAppRole",
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Federated": OIDC_PROVIDER_ARN},
                        "Action": "sts:AssumeRole",
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
    ]

    mappings = extractor.extract(service_accounts, iam_roles)

    assert mappings == []


def test_kube2iam_annotation_emits_no_mapping_and_logs_info(caplog):
    extractor = IRSAMappingExtractor()
    service_accounts = [
        {
            "metadata": {
                "namespace": "production",
                "name": "api-sa",
                "annotations": {
                    "iam.amazonaws.com/role": "webapp-role",
                },
            }
        }
    ]

    with caplog.at_level(logging.INFO):
        mappings = extractor.extract(service_accounts, [])

    assert mappings == []
    assert "kube2iam/kiam role annotations are unsupported" in caplog.text


def test_wildcard_trust_pattern_emits_mapping():
    extractor = IRSAMappingExtractor()
    service_accounts = [
        make_service_account(
            "production",
            "api-sa",
            "arn:aws:iam::123456789012:role/WebAppRole",
        )
    ]
    iam_roles = [
        make_role(
            "WebAppRole",
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Federated": OIDC_PROVIDER_ARN},
                        "Action": "sts:AssumeRoleWithWebIdentity",
                        "Condition": {
                            "StringLike": {
                                "oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE:aud": "sts.amazonaws.com",
                                "oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE:sub": "system:serviceaccount:production:*",
                            }
                        },
                    }
                ]
            },
        )
    ]

    mappings = extractor.extract(service_accounts, iam_roles)

    assert len(mappings) == 1
    assert mappings[0].sa_name == "api-sa"


def test_valid_irsa_annotation_with_broad_no_sub_trust_policy_emits_mapping():
    extractor = IRSAMappingExtractor()
    service_accounts = [
        make_service_account(
            "production",
            "api-sa",
            "arn:aws:iam::123456789012:role/WebAppRole",
        )
    ]
    iam_roles = [
        make_role(
            "WebAppRole",
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Federated": OIDC_PROVIDER_ARN},
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
    ]

    mappings = extractor.extract(service_accounts, iam_roles)

    assert len(mappings) == 1
    assert mappings[0].sa_name == "api-sa"


def test_no_sub_trust_without_sts_audience_emits_no_mapping():
    extractor = IRSAMappingExtractor()
    service_accounts = [
        make_service_account(
            "production",
            "api-sa",
            "arn:aws:iam::123456789012:role/WebAppRole",
        )
    ]
    iam_roles = [
        make_role(
            "WebAppRole",
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Federated": OIDC_PROVIDER_ARN},
                        "Action": "sts:AssumeRoleWithWebIdentity",
                        "Condition": {
                            "StringEquals": {
                                "oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE:iss": "issuer",
                            }
                        },
                    }
                ]
            },
        )
    ]

    mappings = extractor.extract(service_accounts, iam_roles)

    assert mappings == []


def test_multiple_service_accounts_only_valid_mappings_emitted():
    extractor = IRSAMappingExtractor()
    service_accounts = [
        make_service_account(
            "production",
            "api-sa",
            "arn:aws:iam::123456789012:role/WebAppRole",
        ),
        make_service_account(
            "production",
            "wrong-sa",
            "arn:aws:iam::123456789012:role/WebAppRole",
        ),
        make_service_account(
            "production",
            "missing-role-sa",
            "arn:aws:iam::123456789012:role/MissingRole",
        ),
        make_service_account("default", "no-irsa-sa", None),
    ]
    iam_roles = [
        make_role(
            "WebAppRole",
            trust_policy_for_subject("system:serviceaccount:production:api-sa"),
        )
    ]

    mappings = extractor.extract(service_accounts, iam_roles)

    assert len(mappings) == 1
    assert mappings[0].sa_name == "api-sa"
