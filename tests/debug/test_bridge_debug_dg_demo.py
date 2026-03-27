"""
One-off debug pytest target for auditing cross-domain bridge generation for dg-demo entities.

Run with:
    pytest tests/debug/test_bridge_debug_dg_demo.py -s

No database, S3, or external services required — all fixtures are inline.
"""

from __future__ import annotations

import pprint

from src.graph.builders.aws_scanner_types import (
    IAMRoleScan,
    RDSInstanceScan,
    S3BucketScan,
    AWSScanResult,
    IAMUserScan,
    AccessKeyScan,
    EC2InstanceScan,
    SecurityGroupScan,
)
from src.graph.builders.irsa_mapping_extractor import IRSAMappingExtractor, IRSA_ROLE_ANNOTATION
from src.graph.builders.secret_credentials_extractor import SecretCredentialsExtractor
from src.graph.builders.irsa_bridge_builder import IRSABridgeBuilder
from src.facts.extractors.aws_extractor import AWSFactExtractor


# ---------------------------------------------------------------------------
# Shared fixture constants
# ---------------------------------------------------------------------------

ACCOUNT_ID = "244105859679"
ROLE_NAME = "dg-demo-app-role"
ROLE_ARN = f"arn:aws:iam::{ACCOUNT_ID}:role/{ROLE_NAME}"

SA_NAMESPACE = "dg-demo"
SA_NAME = "dg-demo-app-sa"

RDS_IDENTIFIER = "rds-for-eks"
RDS_ENDPOINT = "rds-for-eks.abc123.us-east-1.rds.amazonaws.com"

S3_BUCKET_NAME = "dg-demo-crown-bucket"

IRSA_TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Federated": (
                    "arn:aws:iam::244105859679:oidc-provider/"
                    "oidc.eks.us-east-1.amazonaws.com/id/ABCDEF1234567890"
                )
            },
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {
                    "oidc.eks.us-east-1.amazonaws.com/id/ABCDEF1234567890:aud": (
                        "sts.amazonaws.com"
                    ),
                    "oidc.eks.us-east-1.amazonaws.com/id/ABCDEF1234567890:sub": (
                        f"system:serviceaccount:{SA_NAMESPACE}:{SA_NAME}"
                    ),
                }
            },
        }
    ],
}

# ---------------------------------------------------------------------------
# Fixture builders
# ---------------------------------------------------------------------------


def _make_service_account() -> dict:
    return {
        "metadata": {
            "namespace": SA_NAMESPACE,
            "name": SA_NAME,
            "annotations": {
                IRSA_ROLE_ANNOTATION: ROLE_ARN,
            },
        }
    }


def _make_iam_role() -> IAMRoleScan:
    return IAMRoleScan(
        name=ROLE_NAME,
        arn=ROLE_ARN,
        is_irsa=True,
        irsa_oidc_issuer=(
            "oidc.eks.us-east-1.amazonaws.com/id/ABCDEF1234567890"
        ),
        attached_policies=[],
        inline_policies=[],
        trust_policy=IRSA_TRUST_POLICY,
    )


def _make_rds_instance() -> RDSInstanceScan:
    return RDSInstanceScan(
        identifier=RDS_IDENTIFIER,
        arn=f"arn:aws:rds:us-east-1:{ACCOUNT_ID}:db:{RDS_IDENTIFIER}",
        engine="postgres",
        storage_encrypted=True,
        publicly_accessible=False,
        vpc_security_groups=["sg-0abc123456"],
        endpoint=RDS_ENDPOINT,
        engine_version="14.5",
    )


def _make_s3_bucket() -> S3BucketScan:
    return S3BucketScan(
        name=S3_BUCKET_NAME,
        arn=f"arn:aws:s3:::{S3_BUCKET_NAME}",
        public_access_block={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
        encryption={"SSEAlgorithm": "aws:kms"},
        versioning="Enabled",
        logging_enabled=True,
    )


def _make_db_credentials_secret() -> dict:
    return {
        "metadata": {"namespace": "dg-demo", "name": "db-credentials"},
        "data": {
            "host": RDS_ENDPOINT,
            "username": "admin",
            "password": "supersecret",
            "port": "5432",
        },
    }


def _make_aws_scan_result() -> AWSScanResult:
    return AWSScanResult(
        scan_id="debug-scan-dg-demo",
        aws_account_id=ACCOUNT_ID,
        scanned_at="2026-03-27T00:00:00Z",
        region="us-east-1",
        iam_roles=[_make_iam_role()],
        iam_users=[],
        s3_buckets=[_make_s3_bucket()],
        rds_instances=[_make_rds_instance()],
        ec2_instances=[],
        security_groups=[],
    )


def _make_k8s_scan() -> dict:
    return {
        "service_accounts": [_make_service_account()],
        "secrets": [_make_db_credentials_secret()],
    }


# ---------------------------------------------------------------------------
# Test 1: IRSA bridge trace for dg-demo-app-sa
# ---------------------------------------------------------------------------


def test_irsa_bridge_trace_dg_demo_app_sa() -> None:
    """Step-by-step decision trace for IRSAMappingExtractor + IRSABridgeBuilder on the SA."""
    service_account = _make_service_account()
    iam_role = _make_iam_role()

    print("\n" + "=" * 70)
    print("TEST: test_irsa_bridge_trace_dg_demo_app_sa")
    print("=" * 70)

    # --- Input summary ---
    annotations = service_account["metadata"]["annotations"]
    role_arn_annotation = annotations.get(IRSA_ROLE_ANNOTATION)
    print(f"\n[INPUT] ServiceAccount: {SA_NAMESPACE}/{SA_NAME}")
    print(f"[INPUT] Annotation '{IRSA_ROLE_ANNOTATION}': {role_arn_annotation}")
    print(f"[INPUT] IAM Role ARN:    {iam_role.arn}")
    print(f"[INPUT] IAM Role name:   {iam_role.name}")
    print(f"[INPUT] Trust policy (abbreviated):")
    for stmt in IRSA_TRUST_POLICY["Statement"]:
        print(f"         Effect={stmt['Effect']}  Action={stmt['Action']}")
        for cond_op, cond_vals in stmt.get("Condition", {}).items():
            for k, v in cond_vals.items():
                print(f"         Condition[{cond_op}][{k}] = {v}")

    # --- Step 1: IRSAMappingExtractor.extract() ---
    print("\n[STEP 1] Running IRSAMappingExtractor.extract()")
    extractor = IRSAMappingExtractor()
    mappings = extractor.extract(
        service_accounts=[service_account],
        iam_roles=[iam_role],
    )

    if not mappings:
        print("[RESULT] extract() returned NO mappings — bridge will be skipped")
    else:
        print(f"[RESULT] extract() returned {len(mappings)} mapping(s)")
        for m in mappings:
            print(f"         sa_namespace={m.sa_namespace!r}")
            print(f"         sa_name={m.sa_name!r}")
            print(f"         iam_role_arn={m.iam_role_arn!r}")
            print(f"         iam_role_name={m.iam_role_name!r}")
            print(f"         account_id={m.account_id!r}")

    # --- Step 2: ARN parse check ---
    print("\n[STEP 2] ARN parse decision")
    parts = role_arn_annotation.split(":", 5)
    print(f"         ARN split (maxsplit=5): {parts}")
    print(f"         parts[1] (partition) = {parts[1]!r}  == 'aws'? {parts[1] == 'aws'}")
    print(f"         parts[2] (service)   = {parts[2]!r}  == 'iam'? {parts[2] == 'iam'}")
    print(f"         parts[3] (region)    = {parts[3]!r}  (empty is expected for IAM)")
    print(f"         parts[4] (account)   = {parts[4]!r}  .isdigit()? {parts[4].isdigit()}")
    print(f"         parts[5] (resource)  = {parts[5]!r}  starts with 'role/'? {parts[5].startswith('role/')}")

    # --- Step 3: Trust policy allows check ---
    print("\n[STEP 3] Trust policy allows check")
    sa_subject = f"system:serviceaccount:{SA_NAMESPACE}:{SA_NAME}"
    print(f"         Expected SA subject: {sa_subject!r}")
    trust_allows = extractor._trust_policy_allows(iam_role, SA_NAMESPACE, SA_NAME)
    print(f"         _trust_policy_allows() => {trust_allows}")

    # --- Step 4: IRSABridgeBuilder.build() ---
    print("\n[STEP 4] Running IRSABridgeBuilder.build()")
    k8s_scan = {"service_accounts": [service_account], "secrets": []}
    aws_scan = _make_aws_scan_result()

    builder = IRSABridgeBuilder()
    bridge_result = builder.build(k8s_scan, aws_scan)

    print(f"         irsa_mappings count:     {len(bridge_result.irsa_mappings)}")
    print(f"         credential_facts count:  {len(bridge_result.credential_facts)}")
    print(f"         skipped_irsa:            {bridge_result.skipped_irsa}")
    print(f"         skipped_credentials:     {bridge_result.skipped_credentials}")
    print(f"         warnings count:          {len(bridge_result.warnings)}")

    # --- Final output ---
    print("\n[FINAL] Full BridgeResult:")
    print(f"  irsa_mappings:")
    for m in bridge_result.irsa_mappings:
        pprint.pprint(m.__dict__, indent=4, width=80)
    print(f"  credential_facts: {bridge_result.credential_facts}")
    print(f"  warnings:")
    for w in bridge_result.warnings:
        pprint.pprint(w, indent=4)
    print(f"  skipped_irsa={bridge_result.skipped_irsa}, skipped_credentials={bridge_result.skipped_credentials}")

    # --- Assertions ---
    assert len(mappings) == 1, (
        f"Expected 1 IRSA mapping, got {len(mappings)}. "
        "Check ARN format and trust policy."
    )
    assert mappings[0].sa_namespace == SA_NAMESPACE
    assert mappings[0].sa_name == SA_NAME
    assert mappings[0].iam_role_arn == ROLE_ARN
    assert mappings[0].iam_role_name == ROLE_NAME
    assert mappings[0].account_id == ACCOUNT_ID

    assert len(bridge_result.irsa_mappings) == 1
    assert bridge_result.skipped_irsa == 0
    print("\n[PASS] All IRSA bridge assertions passed.")


# ---------------------------------------------------------------------------
# Test 2: Secret bridge trace for db-credentials
# ---------------------------------------------------------------------------


def test_secret_bridge_trace_db_credentials() -> None:
    """Step-by-step decision trace for SecretCredentialsExtractor + IRSABridgeBuilder on the secret."""
    secret = _make_db_credentials_secret()
    rds_instance = _make_rds_instance()
    s3_bucket = _make_s3_bucket()

    print("\n" + "=" * 70)
    print("TEST: test_secret_bridge_trace_db_credentials")
    print("=" * 70)

    # --- Input summary ---
    print(f"\n[INPUT] Secret: {secret['metadata']['namespace']}/{secret['metadata']['name']}")
    print(f"[INPUT] Secret data keys: {list(secret['data'].keys())}")
    print(f"[INPUT] Secret data['host']: {secret['data']['host']!r}")
    print(f"[INPUT] RDS identifier:  {rds_instance.identifier!r}")
    print(f"[INPUT] RDS endpoint:    {rds_instance.endpoint!r}")
    print(f"[INPUT] S3 bucket name:  {s3_bucket.name!r}")

    # --- Step 1: Key detection ---
    print("\n[STEP 1] Detected credential key categories")
    from src.graph.builders.secret_credentials_extractor import (
        RDS_HOST_KEYS, RDS_USERNAME_KEYS, RDS_PASSWORD_KEYS, RDS_PORT_KEYS,
        S3_BUCKET_KEYS, ACCESS_KEY_ID_KEYS, SECRET_ACCESS_KEY_KEYS,
    )
    data_keys = list(secret["data"].keys())
    print(f"         Data keys present: {data_keys}")
    print(f"         Matched RDS_HOST_KEYS:     {[k for k in data_keys if k in RDS_HOST_KEYS]}")
    print(f"         Matched RDS_USERNAME_KEYS: {[k for k in data_keys if k in RDS_USERNAME_KEYS]}")
    print(f"         Matched RDS_PASSWORD_KEYS: {[k for k in data_keys if k in RDS_PASSWORD_KEYS]}")
    print(f"         Matched RDS_PORT_KEYS:     {[k for k in data_keys if k in RDS_PORT_KEYS]}")
    print(f"         Matched S3_BUCKET_KEYS:    {[k for k in data_keys if k in S3_BUCKET_KEYS]}")
    print(f"         Matched IAM ACCESS_KEY_ID: {[k for k in data_keys if k in ACCESS_KEY_ID_KEYS]}")
    print(f"         Matched IAM SECRET_KEY:    {[k for k in data_keys if k in SECRET_ACCESS_KEY_KEYS]}")

    # --- Step 2: RDS endpoint index ---
    print("\n[STEP 2] RDS endpoint indexing")
    extractor = SecretCredentialsExtractor()
    rds_by_endpoint = extractor._index_rds_endpoints([rds_instance])
    print(f"         rds_by_endpoint: {rds_by_endpoint}")
    host_in_secret = secret["data"]["host"]
    matched = rds_by_endpoint.get(host_in_secret, [])
    print(f"         secret host {host_in_secret!r} maps to identifiers: {matched}")

    # --- Step 3: SecretCredentialsExtractor.extract() ---
    print("\n[STEP 3] Running SecretCredentialsExtractor.extract()")
    credential_facts = extractor.extract(
        secrets=[secret],
        iam_users=[],
        rds_instances=[rds_instance],
        s3_buckets=[s3_bucket],
    )

    if not credential_facts:
        print("[RESULT] extract() returned NO credential facts — bridge will be skipped")
    else:
        print(f"[RESULT] extract() returned {len(credential_facts)} fact(s)")
        for f in credential_facts:
            print(f"         secret_namespace={f.secret_namespace!r}")
            print(f"         secret_name={f.secret_name!r}")
            print(f"         target_type={f.target_type!r}")
            print(f"         target_id={f.target_id!r}")
            print(f"         matched_keys={f.matched_keys!r}")
            print(f"         confidence={f.confidence!r}")

    # --- Step 4: IRSABridgeBuilder.build() ---
    print("\n[STEP 4] Running IRSABridgeBuilder.build() (secret-only path)")
    k8s_scan = {"service_accounts": [], "secrets": [secret]}
    aws_scan = _make_aws_scan_result()

    builder = IRSABridgeBuilder()
    bridge_result = builder.build(k8s_scan, aws_scan)

    print(f"         irsa_mappings count:     {len(bridge_result.irsa_mappings)}")
    print(f"         credential_facts count:  {len(bridge_result.credential_facts)}")
    print(f"         skipped_irsa:            {bridge_result.skipped_irsa}")
    print(f"         skipped_credentials:     {bridge_result.skipped_credentials}")
    print(f"         warnings count:          {len(bridge_result.warnings)}")

    # --- Final output ---
    print("\n[FINAL] Full BridgeResult:")
    print("  credential_facts:")
    for cf in bridge_result.credential_facts:
        pprint.pprint(cf.__dict__, indent=4, width=80)
    print("  irsa_mappings: (none expected in this test)")
    print("  warnings:")
    for w in bridge_result.warnings:
        pprint.pprint(w, indent=4)
    print(f"  skipped_irsa={bridge_result.skipped_irsa}, skipped_credentials={bridge_result.skipped_credentials}")

    # --- Assertions ---
    assert len(credential_facts) >= 1, (
        f"Expected at least 1 credential fact for db-credentials secret, got {len(credential_facts)}. "
        "Check RDS endpoint matching logic."
    )
    rds_facts = [f for f in credential_facts if f.target_type == "rds"]
    assert rds_facts, (
        f"Expected an RDS credential fact but got: {[f.target_type for f in credential_facts]}"
    )
    assert rds_facts[0].target_id == RDS_IDENTIFIER, (
        f"Expected target_id={RDS_IDENTIFIER!r}, got {rds_facts[0].target_id!r}"
    )
    assert rds_facts[0].secret_name == "db-credentials"
    assert rds_facts[0].secret_namespace == "dg-demo"

    assert len(bridge_result.credential_facts) >= 1
    print("\n[PASS] All secret bridge assertions passed.")


# ---------------------------------------------------------------------------
# Test 3: Full pipeline — AWSFactExtractor.extract_with_debug()
# ---------------------------------------------------------------------------


def test_full_pipeline_bridge_dg_demo() -> None:
    """Run the full AWSFactExtractor.extract_with_debug() with both K8s and AWS scan data."""
    print("\n" + "=" * 70)
    print("TEST: test_full_pipeline_bridge_dg_demo")
    print("=" * 70)

    k8s_scan = _make_k8s_scan()
    aws_scan = _make_aws_scan_result()

    print("\n[INPUT] K8s scan:")
    print(f"         service_accounts: {len(k8s_scan['service_accounts'])}")
    for sa in k8s_scan["service_accounts"]:
        meta = sa["metadata"]
        print(f"           - {meta['namespace']}/{meta['name']}")
        for ann_key, ann_val in meta.get("annotations", {}).items():
            print(f"             annotation: {ann_key}={ann_val}")
    print(f"         secrets: {len(k8s_scan['secrets'])}")
    for sec in k8s_scan["secrets"]:
        meta = sec["metadata"]
        print(f"           - {meta['namespace']}/{meta['name']}, keys={list(sec['data'].keys())}")

    print("\n[INPUT] AWS scan:")
    print(f"         account_id:    {aws_scan.aws_account_id}")
    print(f"         iam_roles:     {[r.name for r in aws_scan.iam_roles]}")
    print(f"         rds_instances: {[r.identifier for r in aws_scan.rds_instances]}")
    print(f"         s3_buckets:    {[b.name for b in aws_scan.s3_buckets]}")
    print(f"         iam_users:     {[u.username for u in aws_scan.iam_users]}")

    # Run the full pipeline
    print("\n[STEP] Running AWSFactExtractor.extract_with_debug()")
    extractor = AWSFactExtractor()
    facts, bridge_output = extractor.extract_with_debug(aws_scan, k8s_scan=k8s_scan)

    # Bridge output
    print("\n[BRIDGE OUTPUT]")
    print(f"  irsa_mappings ({len(bridge_output['irsa_mappings'])}):")
    for m in bridge_output["irsa_mappings"]:
        pprint.pprint(m, indent=4, width=80)

    print(f"  credential_facts ({len(bridge_output['credential_facts'])}):")
    for cf in bridge_output["credential_facts"]:
        pprint.pprint(cf, indent=4, width=80)

    print(f"  skipped_irsa:        {bridge_output.get('skipped_irsa')}")
    print(f"  skipped_credentials: {bridge_output.get('skipped_credentials')}")
    print(f"  warnings ({len(bridge_output['warnings'])}):")
    for w in bridge_output["warnings"]:
        pprint.pprint(w, indent=4)

    # All generated facts
    print(f"\n[FACTS] Total facts generated: {len(facts)}")
    for i, fact in enumerate(facts):
        print(f"\n  Fact #{i + 1}:")
        print(f"    fact_type:    {fact.fact_type}")
        print(f"    subject_id:   {fact.subject_id}")
        print(f"    subject_type: {fact.subject_type}")
        print(f"    object_id:    {fact.object_id}")
        print(f"    object_type:  {fact.object_type}")
        if fact.metadata:
            print(f"    metadata:")
            pprint.pprint(fact.metadata, indent=6, width=80)

    # --- Assertions ---
    irsa_facts = [
        f for f in facts
        if "service_account" in f.fact_type.lower() or "assumes_iam_role" in f.fact_type.lower()
    ]
    print(f"\n[CHECK] IRSA-related facts: {[f.fact_type for f in irsa_facts]}")

    rds_credential_facts = [
        f for f in facts
        if "secret" in f.fact_type.lower() and "rds" in f.object_type.lower()
    ]
    print(f"[CHECK] RDS credential facts: {[f.fact_type for f in rds_credential_facts]}")

    assert bridge_output["irsa_mappings"], (
        "Expected at least one IRSA mapping in bridge_output. "
        f"Got: {bridge_output['irsa_mappings']}"
    )
    assert bridge_output["credential_facts"], (
        "Expected at least one credential fact in bridge_output. "
        f"Got: {bridge_output['credential_facts']}"
    )
    assert bridge_output["skipped_irsa"] == 0, (
        f"Expected skipped_irsa=0, got {bridge_output['skipped_irsa']}"
    )

    print("\n[PASS] Full pipeline assertions passed.")


# ---------------------------------------------------------------------------
# Test 4: Flat-format (real scanner output) — demonstrates the actual bug
# ---------------------------------------------------------------------------


def test_flat_format_bridge_now_works() -> None:
    """Verify that flat-format K8s scan data (actual scanner output) now produces bridge edges.

    The real K8s scanner produces service_accounts and secrets with top-level
    namespace/name/annotations (flat format), NOT nested under a "metadata" key.
    Both formats must produce identical bridge results.
    """
    print("\n" + "=" * 70)
    print("TEST: test_flat_format_bridge_now_works")
    print("=" * 70)

    # Flat format — exactly what the real scanner produces
    flat_service_account = {
        "namespace": SA_NAMESPACE,
        "name": SA_NAME,
        "annotations": {
            IRSA_ROLE_ANNOTATION: ROLE_ARN,
        },
    }
    flat_secret = {
        "namespace": "dg-demo",
        "name": "db-credentials",
        "type": "Opaque",
        "data": {
            "host": RDS_ENDPOINT,
            "username": "admin",
            "password": "supersecret",
            "port": "5432",
        },
    }

    # Nested format — K8s API style
    nested_service_account = _make_service_account()
    nested_secret = _make_db_credentials_secret()

    aws_scan = _make_aws_scan_result()

    # --- Test with flat format ---
    flat_k8s_scan = {
        "service_accounts": [flat_service_account],
        "secrets": [flat_secret],
    }
    flat_result = IRSABridgeBuilder().build(flat_k8s_scan, aws_scan)

    print(f"\n[FLAT]   IRSA mappings: {len(flat_result.irsa_mappings)}, "
          f"credential facts: {len(flat_result.credential_facts)}, "
          f"skipped_irsa: {flat_result.skipped_irsa}")

    # --- Test with nested format ---
    nested_k8s_scan = {
        "service_accounts": [nested_service_account],
        "secrets": [nested_secret],
    }
    nested_result = IRSABridgeBuilder().build(nested_k8s_scan, aws_scan)

    print(f"[NESTED] IRSA mappings: {len(nested_result.irsa_mappings)}, "
          f"credential facts: {len(nested_result.credential_facts)}, "
          f"skipped_irsa: {nested_result.skipped_irsa}")

    # Both formats must produce identical results
    assert len(flat_result.irsa_mappings) == 1
    assert len(flat_result.credential_facts) == 1
    assert flat_result.skipped_irsa == 0

    assert len(nested_result.irsa_mappings) == 1
    assert len(nested_result.credential_facts) == 1

    # Same mapping content
    assert flat_result.irsa_mappings[0].sa_name == nested_result.irsa_mappings[0].sa_name
    assert flat_result.irsa_mappings[0].iam_role_name == nested_result.irsa_mappings[0].iam_role_name
    assert flat_result.credential_facts[0].target_id == nested_result.credential_facts[0].target_id

    print("\n[PASS] Both formats produce identical bridge results.")
