from src.facts.extractors.aws_extractor import AWSFactExtractor
from src.facts.types import FactType, NodeType
from src.graph.builders.cross_domain_types import (
    BridgeResult,
    SecretContainsCredentialsFact,
)


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

    facts = extractor._extract_cross_domain_facts({}, {"aws_account_id": "123456789012"})

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

    facts = extractor._extract_cross_domain_facts({}, {"aws_account_id": "123456789012"})

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

    facts = extractor._extract_cross_domain_facts({}, {"aws_account_id": "123456789012"})

    assert len(facts) == 1
    assert facts[0].fact_type == FactType.SECRET_CONTAINS_CREDENTIALS.value
    assert facts[0].object_type == NodeType.S3_BUCKET.value
