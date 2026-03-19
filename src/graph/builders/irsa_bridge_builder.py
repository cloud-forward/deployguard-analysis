"""Bridge orchestration for IRSA mappings and secret credential facts."""

from __future__ import annotations

from typing import Any

from src.graph.builders.cross_domain_types import IRSABridgeResult
from src.graph.builders.irsa_mapping_extractor import (
    IRSA_ROLE_ANNOTATION,
    KUBE2IAM_ROLE_ANNOTATION,
    IRSAMappingExtractor,
)
from src.graph.builders.secret_credentials_extractor import (
    ACCESS_KEY_ID_KEYS,
    RDS_HOST_KEYS,
    RDS_PASSWORD_KEYS,
    RDS_PORT_KEYS,
    RDS_USERNAME_KEYS,
    S3_BUCKET_KEYS,
    S3_ENDPOINT_KEYS,
    S3_REGION_KEYS,
    SECRET_ACCESS_KEY_KEYS,
    SecretCredentialsExtractor,
)


class IRSABridgeBuilder:
    """Orchestrates bridge producers over K8s and AWS scan inputs."""

    def __init__(
        self,
        irsa_extractor: IRSAMappingExtractor | None = None,
        secret_extractor: SecretCredentialsExtractor | None = None,
    ) -> None:
        self._irsa_extractor = irsa_extractor or IRSAMappingExtractor()
        self._secret_extractor = secret_extractor or SecretCredentialsExtractor()

    def build(
        self,
        k8s_scan: dict[str, Any],
        aws_scan: Any,
        credential_config: dict | None = None,
    ) -> IRSABridgeResult:
        service_accounts = self._service_accounts(k8s_scan)
        secrets = self._secrets(k8s_scan)
        iam_roles = self._aws_list(aws_scan, "iam_roles")
        iam_users = self._aws_list(aws_scan, "iam_users")
        rds_instances = self._aws_list(aws_scan, "rds_instances")
        s3_buckets = self._aws_list(aws_scan, "s3_buckets")

        irsa_mappings = self._irsa_extractor.extract(service_accounts, iam_roles)
        credential_facts = self._secret_extractor.extract(
            secrets,
            iam_users=iam_users,
            rds_instances=rds_instances,
            s3_buckets=s3_buckets,
        )

        irsa_candidates = self._count_irsa_candidates(service_accounts)
        credential_candidates = self._count_credential_candidates(secrets)
        skipped_irsa = max(irsa_candidates - len(irsa_mappings), 0)
        skipped_credentials = max(credential_candidates - len(credential_facts), 0)

        warnings: list[str] = []
        if skipped_irsa:
            warnings.append(f"Skipped {skipped_irsa} IRSA bridge candidate(s)")
        if skipped_credentials:
            warnings.append(f"Skipped {skipped_credentials} credential bridge candidate(s)")

        return IRSABridgeResult(
            irsa_mappings=irsa_mappings,
            credential_facts=credential_facts,
            warnings=warnings,
            skipped_irsa=skipped_irsa,
            skipped_credentials=skipped_credentials,
        )

    def _service_accounts(self, k8s_scan: dict[str, Any]) -> list[dict[str, Any]]:
        service_accounts = k8s_scan.get("service_accounts")
        if isinstance(service_accounts, list):
            return service_accounts
        service_accounts = k8s_scan.get("serviceAccounts")
        return service_accounts if isinstance(service_accounts, list) else []

    def _secrets(self, k8s_scan: dict[str, Any]) -> list[dict[str, Any]]:
        secrets = k8s_scan.get("secrets")
        return secrets if isinstance(secrets, list) else []

    def _aws_list(self, aws_scan: Any, field_name: str) -> list[Any]:
        if isinstance(aws_scan, dict):
            value = aws_scan.get(field_name)
        else:
            value = getattr(aws_scan, field_name, None)
        return value if isinstance(value, list) else []

    def _count_irsa_candidates(self, service_accounts: list[dict[str, Any]]) -> int:
        count = 0
        for service_account in service_accounts:
            metadata = service_account.get("metadata")
            if not isinstance(metadata, dict):
                continue
            annotations = metadata.get("annotations")
            if not isinstance(annotations, dict):
                continue
            if annotations.get(IRSA_ROLE_ANNOTATION) or annotations.get(KUBE2IAM_ROLE_ANNOTATION):
                count += 1
        return count

    def _count_credential_candidates(self, secrets: list[dict[str, Any]]) -> int:
        candidates = 0
        for secret in secrets:
            detected_keys = self._secret_key_names(secret)
            if self._is_iam_candidate(detected_keys):
                candidates += 1
            if self._is_rds_candidate(detected_keys):
                candidates += 1
            if self._is_s3_candidate(detected_keys):
                candidates += 1
        return candidates

    def _secret_key_names(self, secret: dict[str, Any]) -> list[str]:
        keys: list[str] = []
        for field_name in ("data", "stringData"):
            value = secret.get(field_name)
            if not isinstance(value, dict):
                continue
            for key in value:
                if isinstance(key, str) and key not in keys:
                    keys.append(key)
        return keys

    def _is_iam_candidate(self, detected_keys: list[str]) -> bool:
        has_access = any(key in ACCESS_KEY_ID_KEYS for key in detected_keys)
        has_secret = any(key in SECRET_ACCESS_KEY_KEYS for key in detected_keys)
        return has_access and has_secret

    def _is_rds_candidate(self, detected_keys: list[str]) -> bool:
        if not any(key in RDS_HOST_KEYS for key in detected_keys):
            return False
        categories = 0
        for key_set in (RDS_HOST_KEYS, RDS_USERNAME_KEYS, RDS_PASSWORD_KEYS, RDS_PORT_KEYS):
            if any(key in key_set for key in detected_keys):
                categories += 1
        return categories >= 2

    def _is_s3_candidate(self, detected_keys: list[str]) -> bool:
        if not any(key in S3_BUCKET_KEYS for key in detected_keys):
            return False
        categories = 0
        for key_set in (S3_BUCKET_KEYS, S3_ENDPOINT_KEYS, S3_REGION_KEYS):
            if any(key in key_set for key in detected_keys):
                categories += 1
        return categories >= 2
