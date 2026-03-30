"""Unit tests for Secret credential extraction."""

from src.graph.builders.aws_scanner_types import AccessKeyScan, IAMUserScan, RDSInstanceScan, S3BucketScan
from src.graph.builders.secret_credentials_extractor import SecretCredentialsExtractor


def make_iam_user(username: str, access_key_id: str, status: str = "Active") -> IAMUserScan:
    return IAMUserScan(
        username=username,
        arn=f"arn:aws:iam::123456789012:user/{username}",
        access_keys=[
            AccessKeyScan(
                access_key_id=access_key_id,
                status=status,
                create_date="2026-01-01T00:00:00Z",
            )
        ],
        attached_policies=[],
        inline_policies=[],
        has_mfa=True,
        last_used=None,
    )


def make_secret(
    namespace: str,
    name: str,
    data: dict | None = None,
    string_data: dict | None = None,
) -> dict:
    secret = {
        "metadata": {
            "namespace": namespace,
            "name": name,
        },
        "data": data or {},
    }
    if string_data is not None:
        secret["stringData"] = string_data
    return secret


def test_secret_with_both_aws_keys_and_matching_iam_user_emits_fact():
    extractor = SecretCredentialsExtractor()
    secrets = [
        make_secret(
            "production",
            "aws-credentials",
            data={
                "AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE",
                "AWS_SECRET_ACCESS_KEY": "super-secret",
            },
        )
    ]
    iam_users = [make_iam_user("web-app-deployer", "AKIAIOSFODNN7EXAMPLE")]

    facts = extractor.extract(secrets, iam_users)

    assert len(facts) == 1
    assert facts[0].target_type == "iam_user"
    assert facts[0].target_id == "web-app-deployer"
    assert facts[0].matched_keys == ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"]
    assert facts[0].confidence == "high"


def test_secret_with_only_access_key_id_emits_no_fact():
    extractor = SecretCredentialsExtractor()
    secrets = [
        make_secret(
            "production",
            "partial-credentials",
            data={
                "AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE",
            },
        )
    ]

    facts = extractor.extract(secrets, [make_iam_user("web-app-deployer", "AKIAIOSFODNN7EXAMPLE")])

    assert facts == []


def test_secret_with_both_keys_but_no_matching_iam_user_emits_unknown_fact():
    extractor = SecretCredentialsExtractor()
    secrets = [
        make_secret(
            "production",
            "unknown-credentials",
            data={
                "AWS_ACCESS_KEY_ID": "AKIAUNKNOWNKEY000000",
                "AWS_SECRET_ACCESS_KEY": "super-secret",
            },
        )
    ]

    facts = extractor.extract(secrets, [make_iam_user("web-app-deployer", "AKIAIOSFODNN7EXAMPLE")])

    assert len(facts) == 1
    assert facts[0].target_type == "iam_user"
    assert facts[0].target_id == "unknown"
    assert facts[0].matched_keys == ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"]
    assert facts[0].confidence == "medium"


def test_secret_with_credential_config_mapping_emits_configured_iam_user():
    extractor = SecretCredentialsExtractor()
    secrets = [
        make_secret(
            "production",
            "aws-credentials",
            data={
                "AWS_ACCESS_KEY_ID": "AKIAUNKNOWNKEY000000",
                "AWS_SECRET_ACCESS_KEY": "super-secret",
            },
        )
    ]

    facts = extractor.extract(
        secrets,
        [make_iam_user("web-app-deployer", "AKIAIOSFODNN7EXAMPLE")],
        credential_config={"production/aws-credentials": "configured-user"},
    )

    assert len(facts) == 1
    assert facts[0].target_type == "iam_user"
    assert facts[0].target_id == "configured-user"
    assert facts[0].matched_keys == ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"]
    assert facts[0].confidence == "high"


def test_malformed_secret_does_not_crash():
    extractor = SecretCredentialsExtractor()
    secrets = [
        {"metadata": "not-a-dict"},
        {"metadata": {"namespace": "production"}, "data": {}},
        {"metadata": {"name": "broken-secret"}, "data": {}},
        {"metadata": {"namespace": "production", "name": "bad-data"}, "data": "not-a-dict"},
    ]

    facts = extractor.extract(secrets, [make_iam_user("web-app-deployer", "AKIAIOSFODNN7EXAMPLE")])

    assert facts == []


def test_multiple_secrets_only_valid_matches_emitted():
    extractor = SecretCredentialsExtractor()
    secrets = [
        make_secret(
            "production",
            "aws-credentials",
            data={
                "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
                "aws_secret_access_key": "super-secret",
            },
        ),
        make_secret(
            "production",
            "partial-credentials",
            data={
                "AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE",
            },
        ),
        make_secret(
            "production",
            "unknown-credentials",
            data={
                "AWS_ACCESS_KEY_ID": "AKIAUNKNOWNKEY000000",
                "AWS_SECRET_ACCESS_KEY": "super-secret",
            },
        ),
    ]
    iam_users = [
        make_iam_user("web-app-deployer", "AKIAIOSFODNN7EXAMPLE"),
        make_iam_user("inactive-user", "AKIAINACTIVEKEY0000", status="Inactive"),
    ]

    facts = extractor.extract(secrets, iam_users)

    assert len(facts) == 2
    facts_by_name = {fact.secret_name: fact for fact in facts}
    assert facts_by_name["aws-credentials"].target_id == "web-app-deployer"
    assert facts_by_name["unknown-credentials"].target_id == "unknown"


def test_secret_with_credential_keys_in_string_data_only_emits_fact():
    extractor = SecretCredentialsExtractor()
    secrets = [
        make_secret(
            "production",
            "aws-credentials",
            data=None,
            string_data={
                "AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE",
                "AWS_SECRET_ACCESS_KEY": "super-secret",
            },
        )
    ]
    iam_users = [make_iam_user("web-app-deployer", "AKIAIOSFODNN7EXAMPLE")]

    facts = extractor.extract(secrets, iam_users)

    assert len(facts) == 1
    assert facts[0].secret_name == "aws-credentials"
    assert facts[0].target_id == "web-app-deployer"
    assert facts[0].matched_keys == ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"]


def test_secret_with_data_and_string_data_present_behaves_consistently():
    extractor = SecretCredentialsExtractor()
    secrets = [
        make_secret(
            "production",
            "aws-credentials",
            data={
                "AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE",
            },
            string_data={
                "AWS_SECRET_ACCESS_KEY": "super-secret",
            },
        )
    ]
    iam_users = [make_iam_user("web-app-deployer", "AKIAIOSFODNN7EXAMPLE")]

    facts = extractor.extract(secrets, iam_users)

    assert len(facts) == 1
    assert facts[0].secret_name == "aws-credentials"
    assert facts[0].target_id == "web-app-deployer"
    assert facts[0].matched_keys == ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"]


def test_secret_with_rds_host_username_password_and_exact_matching_endpoint_emits_fact():
    extractor = SecretCredentialsExtractor()
    secrets = [
        make_secret(
            "production",
            "db-credentials",
            string_data={
                "host": "prod-db.example.us-east-1.rds.amazonaws.com",
                "username": "appuser",
                "password": "super-secret",
            },
        )
    ]
    rds_instances = [
        RDSInstanceScan(
            identifier="production-db",
            arn="arn:aws:rds:us-east-1:123456789012:db:production-db",
            engine="postgres",
            storage_encrypted=True,
            publicly_accessible=False,
            vpc_security_groups=[],
            endpoint="prod-db.example.us-east-1.rds.amazonaws.com",
        )
    ]

    facts = extractor.extract(secrets, iam_users=[], rds_instances=rds_instances)

    assert len(facts) == 1
    assert facts[0].target_type == "rds"
    assert facts[0].target_id == "production-db"
    assert facts[0].matched_keys == ["host", "username", "password"]
    assert facts[0].confidence == "high"


def test_secret_with_rds_host_but_no_matching_endpoint_and_one_scanned_rds_emits_fallback_fact():
    extractor = SecretCredentialsExtractor()
    secrets = [
        make_secret(
            "production",
            "db-credentials",
            string_data={
                "host": "unknown-db.example.us-east-1.rds.amazonaws.com",
                "username": "appuser",
                "password": "super-secret",
            },
        )
    ]
    rds_instances = [
        RDSInstanceScan(
            identifier="production-db",
            arn="arn:aws:rds:us-east-1:123456789012:db:production-db",
            engine="postgres",
            storage_encrypted=True,
            publicly_accessible=False,
            vpc_security_groups=[],
            endpoint="prod-db.example.us-east-1.rds.amazonaws.com",
        )
    ]

    facts = extractor.extract(secrets, iam_users=[], rds_instances=rds_instances)

    assert len(facts) == 1
    assert facts[0].target_type == "rds"
    assert facts[0].target_id == "production-db"
    assert facts[0].matched_keys == ["host", "username", "password"]
    assert facts[0].confidence == "medium"


def test_secret_with_demo_style_uppercase_rds_keys_and_exact_matching_endpoint_emits_fact():
    extractor = SecretCredentialsExtractor()
    secrets = [
        make_secret(
            "dg-demo",
            "db-credentials",
            string_data={
                "DB_HOST": "prod-db.example.us-east-1.rds.amazonaws.com",
                "DB_USER": "appuser",
                "DB_PASSWORD": "super-secret",
                "DB_PORT": "5432",
                "DB_NAME": "appdb",
            },
        )
    ]
    rds_instances = [
        RDSInstanceScan(
            identifier="production-db",
            arn="arn:aws:rds:us-east-1:123456789012:db:production-db",
            engine="postgres",
            storage_encrypted=True,
            publicly_accessible=False,
            vpc_security_groups=[],
            endpoint="prod-db.example.us-east-1.rds.amazonaws.com",
        )
    ]

    facts = extractor.extract(secrets, iam_users=[], rds_instances=rds_instances)

    assert len(facts) == 1
    assert facts[0].target_type == "rds"
    assert facts[0].target_id == "production-db"
    assert facts[0].matched_keys == ["DB_HOST", "DB_USER", "DB_PASSWORD", "DB_PORT"]
    assert facts[0].confidence == "high"


def test_secret_with_insufficient_rds_key_categories_emits_no_fact():
    extractor = SecretCredentialsExtractor()
    secrets = [
        make_secret(
            "production",
            "db-credentials",
            string_data={
                "host": "prod-db.example.us-east-1.rds.amazonaws.com",
            },
        )
    ]
    rds_instances = [
        RDSInstanceScan(
            identifier="production-db",
            arn="arn:aws:rds:us-east-1:123456789012:db:production-db",
            engine="postgres",
            storage_encrypted=True,
            publicly_accessible=False,
            vpc_security_groups=[],
            endpoint="prod-db.example.us-east-1.rds.amazonaws.com",
        )
    ]

    facts = extractor.extract(secrets, iam_users=[], rds_instances=rds_instances)

    assert facts == []


def test_mixed_iam_user_and_rds_style_secrets_emit_both_fact_types():
    extractor = SecretCredentialsExtractor()
    secrets = [
        make_secret(
            "production",
            "aws-credentials",
            string_data={
                "AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE",
                "AWS_SECRET_ACCESS_KEY": "super-secret",
            },
        ),
        make_secret(
            "production",
            "db-credentials",
            string_data={
                "endpoint": "prod-db.example.us-east-1.rds.amazonaws.com",
                "db_user": "appuser",
                "db_password": "super-secret",
            },
        ),
    ]
    iam_users = [make_iam_user("web-app-deployer", "AKIAIOSFODNN7EXAMPLE")]
    rds_instances = [
        RDSInstanceScan(
            identifier="production-db",
            arn="arn:aws:rds:us-east-1:123456789012:db:production-db",
            engine="postgres",
            storage_encrypted=True,
            publicly_accessible=False,
            vpc_security_groups=[],
            endpoint="prod-db.example.us-east-1.rds.amazonaws.com",
        )
    ]

    facts = extractor.extract(secrets, iam_users=iam_users, rds_instances=rds_instances)

    assert len(facts) == 2
    facts_by_type = {fact.target_type: fact for fact in facts}
    assert facts_by_type["iam_user"].target_id == "web-app-deployer"
    assert facts_by_type["rds"].target_id == "production-db"


def test_secret_with_rds_host_but_no_matching_endpoint_and_zero_scanned_rds_emits_no_fact():
    extractor = SecretCredentialsExtractor()
    secrets = [
        make_secret(
            "production",
            "db-credentials",
            string_data={
                "host": "prod-db.example.us-east-1.rds.amazonaws.com",
                "username": "appuser",
                "password": "super-secret",
            },
        )
    ]
    facts = extractor.extract(secrets, iam_users=[], rds_instances=[])

    assert facts == []


def test_secret_with_rds_host_but_no_matching_endpoint_and_multiple_scanned_rds_emits_no_fact():
    extractor = SecretCredentialsExtractor()
    secrets = [
        make_secret(
            "production",
            "db-credentials",
            string_data={
                "host": "unknown-db.example.us-east-1.rds.amazonaws.com",
                "username": "appuser",
                "password": "super-secret",
            },
        )
    ]
    rds_instances = [
        RDSInstanceScan(
            identifier="production-db",
            arn="arn:aws:rds:us-east-1:123456789012:db:production-db",
            engine="postgres",
            storage_encrypted=True,
            publicly_accessible=False,
            vpc_security_groups=[],
            endpoint="prod-db.example.us-east-1.rds.amazonaws.com",
        ),
        RDSInstanceScan(
            identifier="analytics-db",
            arn="arn:aws:rds:us-east-1:123456789012:db:analytics-db",
            engine="postgres",
            storage_encrypted=True,
            publicly_accessible=False,
            vpc_security_groups=[],
            endpoint="analytics-db.example.us-east-1.rds.amazonaws.com",
        ),
    ]

    facts = extractor.extract(secrets, iam_users=[], rds_instances=rds_instances)

    assert facts == []


def test_secret_with_rds_key_metadata_only_and_one_scanned_rds_emits_fallback_fact():
    extractor = SecretCredentialsExtractor()
    secrets = [
        {
            "metadata": {
                "namespace": "production",
                "name": "db-credentials",
            },
            "data_keys": ["database", "host", "password", "port", "username"],
        }
    ]
    rds_instances = [
        RDSInstanceScan(
            identifier="production-db",
            arn="arn:aws:rds:us-east-1:123456789012:db:production-db",
            engine="postgres",
            storage_encrypted=True,
            publicly_accessible=False,
            vpc_security_groups=[],
            endpoint="prod-db.example.us-east-1.rds.amazonaws.com",
        )
    ]

    facts = extractor.extract(secrets, iam_users=[], rds_instances=rds_instances)

    assert len(facts) == 1
    assert facts[0].target_type == "rds"
    assert facts[0].target_id == "production-db"
    assert facts[0].matched_keys == ["host", "password", "port", "username"]
    assert facts[0].confidence == "medium"


def test_secret_with_demo_style_uppercase_rds_key_metadata_only_and_one_scanned_rds_emits_fallback_fact():
    extractor = SecretCredentialsExtractor()
    secrets = [
        {
            "metadata": {
                "namespace": "dg-demo",
                "name": "db-credentials",
            },
            "data_keys": ["DB_HOST", "DB_NAME", "DB_PASSWORD", "DB_PORT", "DB_USER"],
        }
    ]
    rds_instances = [
        RDSInstanceScan(
            identifier="production-db",
            arn="arn:aws:rds:us-east-1:123456789012:db:production-db",
            engine="postgres",
            storage_encrypted=True,
            publicly_accessible=False,
            vpc_security_groups=[],
            endpoint="prod-db.example.us-east-1.rds.amazonaws.com",
        )
    ]

    facts = extractor.extract(secrets, iam_users=[], rds_instances=rds_instances)

    assert len(facts) == 1
    assert facts[0].target_type == "rds"
    assert facts[0].target_id == "production-db"
    assert facts[0].matched_keys == ["DB_HOST", "DB_PASSWORD", "DB_PORT", "DB_USER"]
    assert facts[0].confidence == "medium"


def test_typed_rds_model_without_endpoint_and_one_scanned_rds_emits_fallback_fact():
    extractor = SecretCredentialsExtractor()
    secrets = [
        make_secret(
            "production",
            "db-credentials",
            string_data={
                "host": "prod-db.example.us-east-1.rds.amazonaws.com",
                "username": "appuser",
                "password": "super-secret",
            },
        )
    ]
    rds_instances = [
        RDSInstanceScan(
            identifier="production-db",
            arn="arn:aws:rds:us-east-1:123456789012:db:production-db",
            engine="postgres",
            storage_encrypted=True,
            publicly_accessible=False,
            vpc_security_groups=[],
            endpoint=None,
        )
    ]

    facts = extractor.extract(secrets, iam_users=[], rds_instances=rds_instances)

    assert len(facts) == 1
    assert facts[0].target_type == "rds"
    assert facts[0].target_id == "production-db"
    assert facts[0].matched_keys == ["host", "username", "password"]
    assert facts[0].confidence == "medium"


def test_secret_with_exact_matching_bucket_name_emits_s3_fact():
    extractor = SecretCredentialsExtractor()
    secrets = [
        make_secret(
            "production",
            "s3-config",
            string_data={
                "bucket": "sensitive-data-bucket",
                "region": "us-east-1",
            },
        )
    ]
    s3_buckets = [
        S3BucketScan(
            name="sensitive-data-bucket",
            arn="arn:aws:s3:::sensitive-data-bucket",
            public_access_block=None,
            encryption=None,
            versioning="Disabled",
            logging_enabled=False,
        )
    ]

    facts = extractor.extract(secrets, iam_users=[], s3_buckets=s3_buckets)

    assert len(facts) == 1
    assert facts[0].target_type == "s3"
    assert facts[0].target_id == "sensitive-data-bucket"
    assert facts[0].matched_keys == ["bucket", "region"]
    assert facts[0].confidence == "high"


def test_secret_with_bucket_key_but_no_matching_s3_bucket_emits_no_fact():
    extractor = SecretCredentialsExtractor()
    secrets = [
        make_secret(
            "production",
            "s3-config",
            string_data={
                "bucket_name": "missing-bucket",
                "aws_region": "us-east-1",
            },
        )
    ]
    s3_buckets = [
        S3BucketScan(
            name="sensitive-data-bucket",
            arn="arn:aws:s3:::sensitive-data-bucket",
            public_access_block=None,
            encryption=None,
            versioning="Disabled",
            logging_enabled=False,
        )
    ]

    facts = extractor.extract(secrets, iam_users=[], s3_buckets=s3_buckets)

    assert facts == []


def test_secret_with_insufficient_s3_key_categories_emits_no_fact():
    extractor = SecretCredentialsExtractor()
    secrets = [
        make_secret(
            "production",
            "s3-config",
            string_data={
                "bucket": "sensitive-data-bucket",
            },
        )
    ]
    s3_buckets = [
        S3BucketScan(
            name="sensitive-data-bucket",
            arn="arn:aws:s3:::sensitive-data-bucket",
            public_access_block=None,
            encryption=None,
            versioning="Disabled",
            logging_enabled=False,
        )
    ]

    facts = extractor.extract(secrets, iam_users=[], s3_buckets=s3_buckets)

    assert facts == []


def test_mixed_iam_user_rds_and_s3_style_secrets_emit_all_supported_fact_types():
    extractor = SecretCredentialsExtractor()
    secrets = [
        make_secret(
            "production",
            "aws-credentials",
            string_data={
                "AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE",
                "AWS_SECRET_ACCESS_KEY": "super-secret",
            },
        ),
        make_secret(
            "production",
            "db-credentials",
            string_data={
                "endpoint": "prod-db.example.us-east-1.rds.amazonaws.com",
                "db_user": "appuser",
                "db_password": "super-secret",
            },
        ),
        make_secret(
            "production",
            "s3-config",
            string_data={
                "s3_bucket": "sensitive-data-bucket",
                "s3_endpoint": "https://s3.us-east-1.amazonaws.com",
            },
        ),
    ]
    iam_users = [make_iam_user("web-app-deployer", "AKIAIOSFODNN7EXAMPLE")]
    rds_instances = [
        RDSInstanceScan(
            identifier="production-db",
            arn="arn:aws:rds:us-east-1:123456789012:db:production-db",
            engine="postgres",
            storage_encrypted=True,
            publicly_accessible=False,
            vpc_security_groups=[],
            endpoint="prod-db.example.us-east-1.rds.amazonaws.com",
        )
    ]
    s3_buckets = [
        S3BucketScan(
            name="sensitive-data-bucket",
            arn="arn:aws:s3:::sensitive-data-bucket",
            public_access_block=None,
            encryption=None,
            versioning="Disabled",
            logging_enabled=False,
        )
    ]

    facts = extractor.extract(
        secrets,
        iam_users=iam_users,
        rds_instances=rds_instances,
        s3_buckets=s3_buckets,
    )

    assert len(facts) == 3
    facts_by_type = {fact.target_type: fact for fact in facts}
    assert facts_by_type["iam_user"].target_id == "web-app-deployer"
    assert facts_by_type["rds"].target_id == "production-db"
    assert facts_by_type["s3"].target_id == "sensitive-data-bucket"
