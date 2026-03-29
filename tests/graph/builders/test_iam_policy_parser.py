"""Unit tests for IAMPolicyParser."""

import pytest

from src.graph.builders.aws_scanner_types import IAMRoleScan
from src.graph.builders.iam_policy_parser import IAMPolicyParser


def make_role(
    name="TestRole",
    arn="arn:aws:iam::123456789012:role/TestRole",
    trust_policy=None,
    attached_policies=None,
    inline_policies=None,
    is_irsa=False,
    irsa_oidc_issuer=None,
) -> IAMRoleScan:
    return IAMRoleScan(
        name=name,
        arn=arn,
        is_irsa=is_irsa,
        irsa_oidc_issuer=irsa_oidc_issuer,
        attached_policies=attached_policies or [],
        inline_policies=inline_policies or [],
        trust_policy=trust_policy or {"Statement": []},
    )


OIDC_FEDERATED = "arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE"


def irsa_trust_policy(condition_op: str, sub_value) -> dict:
    return {
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Federated": OIDC_FEDERATED},
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    condition_op: {
                        "oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE:sub": sub_value
                    }
                },
            }
        ]
    }


# ---------------------------------------------------------------------------
# Trust policy tests
# ---------------------------------------------------------------------------

class TestTrustPolicyParsing:

    def test_trust_policy_irsa_allows_all_sa(self):
        trust = irsa_trust_policy("StringLike", "system:serviceaccount:*:*")
        role = make_role(trust_policy=trust)
        result = IAMPolicyParser().parse(role)
        assert result.trust_analysis.is_irsa_enabled is True
        assert result.trust_analysis.allows_all_sa is True

    def test_trust_policy_irsa_specific_sa(self):
        trust = irsa_trust_policy("StringEquals", "system:serviceaccount:production:api-sa")
        role = make_role(trust_policy=trust)
        result = IAMPolicyParser().parse(role)
        assert result.trust_analysis.is_irsa_enabled is True
        assert result.trust_analysis.allows_all_sa is False
        assert "system:serviceaccount:production:api-sa" in result.trust_analysis.allowed_sa_explicit
        assert result.trust_analysis.has_broad_irsa_trust is False

    def test_trust_policy_irsa_without_sub_marks_broad_trust(self):
        trust = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Federated": OIDC_FEDERATED},
                    "Action": "sts:AssumeRoleWithWebIdentity",
                    "Condition": {
                        "StringEquals": {
                            "oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE:aud": "sts.amazonaws.com"
                        }
                    },
                }
            ]
        }
        role = make_role(trust_policy=trust)
        result = IAMPolicyParser().parse(role)
        assert result.trust_analysis.is_irsa_enabled is True
        assert result.trust_analysis.allowed_sa_explicit == []
        assert result.trust_analysis.allowed_sa_patterns == []
        assert result.trust_analysis.has_broad_irsa_trust is True

    def test_trust_policy_irsa_without_sub_and_without_aud_is_not_broad(self):
        trust = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Federated": OIDC_FEDERATED},
                    "Action": "sts:AssumeRoleWithWebIdentity",
                    "Condition": {
                        "StringEquals": {
                            "oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE:iss": "issuer"
                        }
                    },
                }
            ]
        }
        role = make_role(trust_policy=trust)
        result = IAMPolicyParser().parse(role)
        assert result.trust_analysis.has_broad_irsa_trust is False

    def test_trust_policy_ec2(self):
        trust = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "ec2.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ]
        }
        role = make_role(trust_policy=trust)
        result = IAMPolicyParser().parse(role)
        assert result.trust_analysis.allows_ec2 is True
        assert result.trust_analysis.is_irsa_enabled is False


# ---------------------------------------------------------------------------
# Tier classification tests
# ---------------------------------------------------------------------------

class TestTierClassification:

    def test_tier1_administrator_access(self):
        attached = [
            {
                "name": "AdministratorAccess",
                "arn": "arn:aws:iam::aws:policy/AdministratorAccess",
                "document": {
                    "Statement": [
                        {"Effect": "Allow", "Action": "*", "Resource": "*"}
                    ]
                },
            }
        ]
        role = make_role(attached_policies=attached)
        result = IAMPolicyParser().parse(role)
        assert result.tier == 1

    def test_tier1_wildcard_action_resource(self):
        attached = [
            {
                "name": "WildcardPolicy",
                "arn": "arn:aws:iam::123456789012:policy/WildcardPolicy",
                "document": {
                    "Statement": [
                        {"Effect": "Allow", "Action": "*", "Resource": "*"}
                    ]
                },
            }
        ]
        role = make_role(attached_policies=attached)
        result = IAMPolicyParser().parse(role)
        assert result.tier == 1

    def test_tier2_iam_create_attach(self):
        attached = [
            {
                "name": "IAMCreateAttach",
                "arn": "arn:aws:iam::123456789012:policy/IAMCreateAttach",
                "document": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": ["iam:CreateRole", "iam:AttachRolePolicy"],
                            "Resource": "*",
                        }
                    ]
                },
            }
        ]
        role = make_role(attached_policies=attached)
        result = IAMPolicyParser().parse(role)
        assert result.tier == 2

    def test_tier2_iam_pass_role(self):
        attached = [
            {
                "name": "PassRolePolicy",
                "arn": "arn:aws:iam::123456789012:policy/PassRolePolicy",
                "document": {
                    "Statement": [
                        {"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"}
                    ]
                },
            }
        ]
        role = make_role(attached_policies=attached)
        result = IAMPolicyParser().parse(role)
        assert result.tier is None

    def test_tier2_iam_pass_role_with_lambda_create_function(self):
        attached = [
            {
                "name": "PassRoleAndLambdaPolicy",
                "arn": "arn:aws:iam::123456789012:policy/PassRoleAndLambdaPolicy",
                "document": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": ["iam:PassRole", "lambda:CreateFunction"],
                            "Resource": "*",
                        }
                    ]
                },
            }
        ]
        role = make_role(attached_policies=attached)
        result = IAMPolicyParser().parse(role)
        assert result.tier == 2

    def test_tier3_s3_wildcard(self):
        attached = [
            {
                "name": "S3FullAccess",
                "arn": "arn:aws:iam::aws:policy/AmazonS3FullAccess",
                "document": {
                    "Statement": [
                        {"Effect": "Allow", "Action": "s3:*", "Resource": "*"}
                    ]
                },
            }
        ]
        role = make_role(attached_policies=attached)
        result = IAMPolicyParser().parse(role)
        assert result.tier == 3

    def test_tier_none_readonly(self):
        attached = [
            {
                "name": "S3ReadOnly",
                "arn": "arn:aws:iam::123456789012:policy/S3ReadOnly",
                "document": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": ["s3:GetObject"],
                            "Resource": "arn:aws:s3:::specific-bucket/*",
                        }
                    ]
                },
            }
        ]
        role = make_role(attached_policies=attached)
        result = IAMPolicyParser().parse(role)
        assert result.tier is None


# ---------------------------------------------------------------------------
# Resource access tests
# ---------------------------------------------------------------------------

class TestResourceAccess:

    def test_resource_access_service_grouping(self):
        attached = [
            {
                "name": "MultiServicePolicy",
                "arn": "arn:aws:iam::123456789012:policy/MultiServicePolicy",
                "document": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": ["s3:GetObject", "s3:PutObject", "rds:Connect"],
                            "Resource": "*",
                        }
                    ]
                },
            }
        ]
        role = make_role(attached_policies=attached)
        result = IAMPolicyParser().parse(role)
        services = {ra.service for ra in result.resource_access}
        assert "s3" in services
        assert "rds" in services
        assert len(result.resource_access) == 2

    def test_wildcard_action_detection(self):
        attached = [
            {
                "name": "S3Wildcard",
                "arn": "arn:aws:iam::123456789012:policy/S3Wildcard",
                "document": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "s3:*",
                            "Resource": "arn:aws:s3:::my-bucket/*",
                        }
                    ]
                },
            }
        ]
        role = make_role(attached_policies=attached)
        result = IAMPolicyParser().parse(role)
        s3_ra = next(ra for ra in result.resource_access if ra.service == "s3")
        assert s3_ra.is_wildcard_action is True
        assert s3_ra.is_wildcard_resource is False

    def test_inline_policy_parsing(self):
        inline = [
            {
                "name": "MyInlinePolicy",
                "document": {
                    "Statement": [
                        {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}
                    ]
                },
            }
        ]
        role = make_role(inline_policies=inline)
        result = IAMPolicyParser().parse(role)
        assert len(result.resource_access) == 1
        ra = result.resource_access[0]
        assert ra.policy_arn is None
        assert ra.policy_name == "MyInlinePolicy"


# ---------------------------------------------------------------------------
# Risk signal tests
# ---------------------------------------------------------------------------

class TestRiskSignals:

    def test_has_privilege_escalation(self):
        attached = [
            {
                "name": "EscalationPolicy",
                "arn": "arn:aws:iam::123456789012:policy/EscalationPolicy",
                "document": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": ["iam:PassRole", "lambda:CreateFunction"],
                            "Resource": "*",
                        }
                    ]
                },
            }
        ]
        role = make_role(attached_policies=attached)
        result = IAMPolicyParser().parse(role)
        assert result.has_privilege_escalation is True

    def test_has_credential_access(self):
        attached = [
            {
                "name": "SecretsPolicy",
                "arn": "arn:aws:iam::123456789012:policy/SecretsPolicy",
                "document": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "secretsmanager:GetSecretValue",
                            "Resource": "*",
                        }
                    ]
                },
            }
        ]
        role = make_role(attached_policies=attached)
        result = IAMPolicyParser().parse(role)
        assert result.has_credential_access is True

    def test_has_privilege_escalation_update_assume_role_policy(self):
        attached = [
            {
                "name": "TrustEscalationPolicy",
                "arn": "arn:aws:iam::123456789012:policy/TrustEscalationPolicy",
                "document": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "iam:UpdateAssumeRolePolicy",
                            "Resource": "*",
                        }
                    ]
                },
            }
        ]
        role = make_role(attached_policies=attached)
        result = IAMPolicyParser().parse(role)
        assert result.has_privilege_escalation is True

    def test_has_privilege_escalation_put_user_policy(self):
        attached = [
            {
                "name": "UserEscalationPolicy",
                "arn": "arn:aws:iam::123456789012:policy/UserEscalationPolicy",
                "document": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "iam:PutUserPolicy",
                            "Resource": "*",
                        }
                    ]
                },
            }
        ]
        role = make_role(attached_policies=attached)
        result = IAMPolicyParser().parse(role)
        assert result.has_privilege_escalation is True


# ---------------------------------------------------------------------------
# Integration / full-role tests
# ---------------------------------------------------------------------------

class TestFullRoleParsing:

    def test_parse_full_role_gp001(self):
        """WebAppRole from GP-001 scenario: IRSA + allows_all_sa + AmazonS3FullAccess."""
        trust = irsa_trust_policy("StringLike", "system:serviceaccount:*:*")
        attached = [
            {
                "name": "AmazonS3FullAccess",
                "arn": "arn:aws:iam::aws:policy/AmazonS3FullAccess",
                "document": {
                    "Statement": [
                        {"Effect": "Allow", "Action": "s3:*", "Resource": "*"}
                    ]
                },
            }
        ]
        role = make_role(
            name="WebAppRole",
            arn="arn:aws:iam::123456789012:role/WebAppRole",
            trust_policy=trust,
            attached_policies=attached,
            is_irsa=True,
            irsa_oidc_issuer="oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE",
        )
        result = IAMPolicyParser().parse(role)

        assert result.trust_analysis.is_irsa_enabled is True
        assert result.trust_analysis.allows_all_sa is True
        assert result.tier == 3

        services = {ra.service for ra in result.resource_access}
        assert "s3" in services

        s3_ra = next(ra for ra in result.resource_access if ra.service == "s3")
        assert s3_ra.is_wildcard_action is True
        assert s3_ra.is_wildcard_resource is True
