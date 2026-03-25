from src.facts.extractors.aws_extractor import AWSFactExtractor
from src.facts.types import FactType, NodeType
from src.graph.builders.cross_domain_types import (
    BridgeResult,
    SecretContainsCredentialsFact,
)
from src.graph.builders.aws_scanner_types import (
    AWSScanResult,
    IAMRoleScan,
    IAMUserScan,
)


def make_role(
    name: str,
    *,
    account_id: str = "123456789012",
    trust_policy: dict | None = None,
) -> IAMRoleScan:
    return IAMRoleScan(
        name=name,
        arn=f"arn:aws:iam::{account_id}:role/{name}",
        is_irsa=False,
        irsa_oidc_issuer=None,
        attached_policies=[],
        inline_policies=[],
        trust_policy=trust_policy or {"Statement": []},
    )


def make_user(
    username: str,
    *,
    account_id: str = "123456789012",
    attached_policies: list[dict] | None = None,
) -> IAMUserScan:
    return IAMUserScan(
        username=username,
        arn=f"arn:aws:iam::{account_id}:user/{username}",
        access_keys=[],
        attached_policies=attached_policies or [],
        inline_policies=[],
        has_mfa=True,
        last_used=None,
    )


def make_scan(
    *,
    account_id: str = "123456789012",
    iam_roles: list[IAMRoleScan] | None = None,
    iam_users: list[IAMUserScan] | None = None,
) -> AWSScanResult:
    return AWSScanResult(
        scan_id="aws-1",
        aws_account_id=account_id,
        scanned_at="2026-03-25T00:00:00Z",
        iam_roles=iam_roles or [],
        iam_users=iam_users or [],
        s3_buckets=[],
        rds_instances=[],
        ec2_instances=[],
        security_groups=[],
    )


def trust_allows_exact_principal(principal_arn: str) -> dict:
    return {
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": principal_arn},
                "Action": "sts:AssumeRole",
            }
        ]
    }


def assume_role_policy(target_role_arn: str) -> list[dict]:
    return [
        {
            "name": "AssumeTargetRole",
            "arn": "arn:aws:iam::123456789012:policy/AssumeTargetRole",
            "document": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "sts:AssumeRole",
                        "Resource": target_role_arn,
                    }
                ]
            },
        }
    ]


def test_extract_cross_domain_facts_keeps_iam_user_object_type():
    extractor = AWSFactExtractor()
    extractor.bridge_builder.build = lambda k8s_scan, aws_scan: BridgeResult(
        credential_facts=[
            SecretContainsCredentialsFact(
                secret_namespace="production",
                secret_name="aws-creds",
                target_type="iam_user",
                target_id="deployer",
                matched_keys=["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"],
                confidence="high",
            )
        ]
    )

    facts, _ = extractor._extract_cross_domain_facts({}, make_scan())

    assert len(facts) == 1
    assert facts[0].fact_type == FactType.SECRET_CONTAINS_AWS_CREDENTIALS.value
    assert facts[0].object_type == NodeType.IAM_USER.value


def test_extract_cross_domain_facts_keeps_rds_object_type():
    extractor = AWSFactExtractor()
    extractor.bridge_builder.build = lambda k8s_scan, aws_scan: BridgeResult(
        credential_facts=[
            SecretContainsCredentialsFact(
                secret_namespace="production",
                secret_name="db-creds",
                target_type="rds",
                target_id="production-db",
                matched_keys=["host", "password"],
                confidence="high",
            )
        ]
    )

    facts, _ = extractor._extract_cross_domain_facts({}, make_scan())

    assert len(facts) == 1
    assert facts[0].fact_type == FactType.SECRET_CONTAINS_CREDENTIALS.value
    assert facts[0].object_type == NodeType.RDS.value


def test_extract_cross_domain_facts_maps_s3_target_type_to_s3_bucket_object_type():
    extractor = AWSFactExtractor()
    extractor.bridge_builder.build = lambda k8s_scan, aws_scan: BridgeResult(
        credential_facts=[
            SecretContainsCredentialsFact(
                secret_namespace="production",
                secret_name="s3-config",
                target_type="s3",
                target_id="sensitive-data-bucket",
                matched_keys=["bucket", "region"],
                confidence="high",
            )
        ]
    )

    facts, _ = extractor._extract_cross_domain_facts({}, make_scan())

    assert len(facts) == 1
    assert facts[0].fact_type == FactType.SECRET_CONTAINS_CREDENTIALS.value
    assert facts[0].object_type == NodeType.S3_BUCKET.value


def test_extract_explicit_assume_role_facts_for_iam_user():
    extractor = AWSFactExtractor()
    target_role = make_role(
        "TargetRole",
        trust_policy=trust_allows_exact_principal("arn:aws:iam::123456789012:user/deployer"),
    )
    user = make_user(
        "deployer",
        attached_policies=assume_role_policy(target_role.arn),
    )

    facts = extractor._extract_explicit_assume_role_facts(
        make_scan(iam_roles=[target_role], iam_users=[user])
    )

    assert len(facts) == 1
    fact = facts[0]
    assert fact.fact_type == FactType.IAM_PRINCIPAL_ASSUMES_IAM_ROLE.value
    assert fact.subject_id == "iam_user:123456789012:deployer"
    assert fact.subject_type == NodeType.IAM_USER.value
    assert fact.object_id == "iam:123456789012:TargetRole"
    assert fact.object_type == NodeType.IAM_ROLE.value
    assert fact.metadata["source_principal_arn"] == user.arn
    assert fact.metadata["target_role_arn"] == target_role.arn
    assert fact.metadata["via"] == "explicit_sts_assumerole"


def test_extract_explicit_assume_role_facts_for_iam_role():
    extractor = AWSFactExtractor()
    source_role = make_role(
        "SourceRole",
        trust_policy={"Statement": []},
    )
    source_role.attached_policies = assume_role_policy("arn:aws:iam::123456789012:role/TargetRole")
    target_role = make_role(
        "TargetRole",
        trust_policy=trust_allows_exact_principal(source_role.arn),
    )

    facts = extractor._extract_explicit_assume_role_facts(
        make_scan(iam_roles=[source_role, target_role])
    )

    assert len(facts) == 1
    assert facts[0].subject_id == "iam:123456789012:SourceRole"
    assert facts[0].object_id == "iam:123456789012:TargetRole"


def test_extract_explicit_assume_role_facts_skips_when_trust_does_not_allow():
    extractor = AWSFactExtractor()
    target_role = make_role(
        "TargetRole",
        trust_policy=trust_allows_exact_principal("arn:aws:iam::123456789012:user:someone-else"),
    )
    user = make_user(
        "deployer",
        attached_policies=assume_role_policy(target_role.arn),
    )

    facts = extractor._extract_explicit_assume_role_facts(
        make_scan(iam_roles=[target_role], iam_users=[user])
    )

    assert facts == []


def test_extract_explicit_assume_role_facts_skips_when_permission_missing():
    extractor = AWSFactExtractor()
    target_role = make_role(
        "TargetRole",
        trust_policy=trust_allows_exact_principal("arn:aws:iam::123456789012:user/deployer"),
    )
    user = make_user("deployer")

    facts = extractor._extract_explicit_assume_role_facts(
        make_scan(iam_roles=[target_role], iam_users=[user])
    )

    assert facts == []


def test_extract_explicit_assume_role_facts_excludes_wildcard_resource():
    extractor = AWSFactExtractor()
    target_role = make_role(
        "TargetRole",
        trust_policy=trust_allows_exact_principal("arn:aws:iam::123456789012:user/deployer"),
    )
    user = make_user(
        "deployer",
        attached_policies=[
            {
                "name": "WildcardAssumeRole",
                "arn": "arn:aws:iam::123456789012:policy/WildcardAssumeRole",
                "document": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "sts:AssumeRole",
                            "Resource": "*",
                        }
                    ]
                },
            }
        ],
    )

    facts = extractor._extract_explicit_assume_role_facts(
        make_scan(iam_roles=[target_role], iam_users=[user])
    )

    assert facts == []


def test_extract_explicit_assume_role_facts_deduplicates_duplicate_policies():
    extractor = AWSFactExtractor()
    target_role = make_role(
        "TargetRole",
        trust_policy=trust_allows_exact_principal("arn:aws:iam::123456789012:user/deployer"),
    )
    user = make_user(
        "deployer",
        attached_policies=assume_role_policy(target_role.arn) + assume_role_policy(target_role.arn),
    )

    facts = extractor._extract_explicit_assume_role_facts(
        make_scan(iam_roles=[target_role], iam_users=[user])
    )

    assert len(facts) == 1


def test_extract_explicit_assume_role_facts_excludes_condition_dependent_trust():
    extractor = AWSFactExtractor()
    target_role = make_role(
        "TargetRole",
        trust_policy={
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::123456789012:user/deployer"},
                    "Action": "sts:AssumeRole",
                    "Condition": {"StringEquals": {"sts:ExternalId": "required"}},
                }
            ]
        },
    )
    user = make_user(
        "deployer",
        attached_policies=assume_role_policy(target_role.arn),
    )

    facts = extractor._extract_explicit_assume_role_facts(
        make_scan(iam_roles=[target_role], iam_users=[user])
    )

    assert facts == []


def test_extract_explicit_assume_role_facts_excludes_cross_account_target_role():
    extractor = AWSFactExtractor()
    target_role_arn = "arn:aws:iam::210987654321:role/TargetRole"
    target_role = make_role(
        "TargetRole",
        account_id="210987654321",
        trust_policy=trust_allows_exact_principal("arn:aws:iam::123456789012:user/deployer"),
    )
    user = make_user(
        "deployer",
        attached_policies=assume_role_policy(target_role_arn),
    )

    facts = extractor._extract_explicit_assume_role_facts(
        make_scan(iam_roles=[target_role], iam_users=[user])
    )

    assert facts == []


def test_extract_explicit_assume_role_facts_excludes_account_root_trust():
    extractor = AWSFactExtractor()
    target_role = make_role(
        "TargetRole",
        trust_policy={
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                    "Action": "sts:AssumeRole",
                }
            ]
        },
    )
    user = make_user(
        "deployer",
        attached_policies=assume_role_policy(target_role.arn),
    )

    facts = extractor._extract_explicit_assume_role_facts(
        make_scan(iam_roles=[target_role], iam_users=[user])
    )

    assert facts == []


def test_extract_explicit_assume_role_facts_excludes_wildcard_trust_principal():
    extractor = AWSFactExtractor()
    target_role = make_role(
        "TargetRole",
        trust_policy={
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "*"},
                    "Action": "sts:AssumeRole",
                }
            ]
        },
    )
    user = make_user(
        "deployer",
        attached_policies=assume_role_policy(target_role.arn),
    )

    facts = extractor._extract_explicit_assume_role_facts(
        make_scan(iam_roles=[target_role], iam_users=[user])
    )

    assert facts == []
