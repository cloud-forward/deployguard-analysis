"""Bridge orchestration for IRSA mappings and secret credential facts."""

from __future__ import annotations

from typing import Any

from src.graph.builders.cross_domain_types import BridgeResult
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
    ) -> BridgeResult:
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
            credential_config=credential_config,
        )

        irsa_candidates = self._count_irsa_candidates(service_accounts)
        credential_candidates = self._count_credential_candidates(secrets)
        skipped_irsa = max(irsa_candidates - len(irsa_mappings), 0)
        skipped_credentials = max(credential_candidates - len(credential_facts), 0)

        warnings = self._build_warnings(
            service_accounts=service_accounts,
            iam_roles=iam_roles,
            secrets=secrets,
            iam_users=iam_users,
            rds_instances=rds_instances,
            s3_buckets=s3_buckets,
            credential_config=credential_config or {},
        )

        return BridgeResult(
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
                metadata = service_account
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
        metadata = secret.get("metadata")
        if not isinstance(metadata, dict):
            metadata = {}

        for value in (
            secret.get("data"),
            secret.get("stringData"),
            secret.get("data_keys"),
            secret.get("string_data_keys"),
            metadata.get("data_keys"),
            metadata.get("string_data_keys"),
        ):
            if isinstance(value, dict):
                for key in value:
                    if isinstance(key, str) and key not in keys:
                        keys.append(key)
                continue
            if isinstance(value, list):
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

    def _build_warnings(
        self,
        service_accounts: list[dict[str, Any]],
        iam_roles: list[Any],
        secrets: list[dict[str, Any]],
        iam_users: list[Any],
        rds_instances: list[Any],
        s3_buckets: list[Any],
        credential_config: dict[str, Any],
    ) -> list[dict[str, str]]:
        warnings: list[dict[str, str]] = []
        warnings.extend(self._irsa_warnings(service_accounts, iam_roles))
        warnings.extend(
            self._credential_warnings(
                secrets=secrets,
                iam_users=iam_users,
                rds_instances=rds_instances,
                s3_buckets=s3_buckets,
                credential_config=credential_config,
            )
        )
        return warnings

    def _irsa_warnings(
        self,
        service_accounts: list[dict[str, Any]],
        iam_roles: list[Any],
    ) -> list[dict[str, str]]:
        warnings: list[dict[str, str]] = []
        roles_by_arn = {getattr(role, "arn", None): role for role in iam_roles}

        for service_account in service_accounts:
            metadata = service_account.get("metadata")
            if not isinstance(metadata, dict):
                metadata = service_account

            namespace = metadata.get("namespace")
            name = metadata.get("name")
            annotations = metadata.get("annotations")
            if not isinstance(namespace, str) or not namespace:
                namespace = "unknown"
            if not isinstance(name, str) or not name:
                name = "unknown"
            if not isinstance(annotations, dict):
                continue

            resource = f"service_account:{namespace}/{name}"
            if annotations.get(KUBE2IAM_ROLE_ANNOTATION):
                warnings.append(
                    self._warning(
                        level="INFO",
                        reason="kube2iam_unsupported",
                        resource=resource,
                        note="kube2iam/kiam role annotations are unsupported",
                    )
                )
                continue

            role_arn = annotations.get(IRSA_ROLE_ANNOTATION)
            if not role_arn:
                continue

            parsed = self._irsa_extractor._parse_role_arn(role_arn)
            if parsed is None:
                warnings.append(
                    self._warning(
                        level="WARNING",
                        reason="malformed_role_arn",
                        resource=resource,
                        note="annotated IRSA role ARN is malformed",
                    )
                )
                continue

            role = roles_by_arn.get(role_arn)
            if role is None:
                warnings.append(
                    self._warning(
                        level="WARNING",
                        reason="trust_mismatch",
                        resource=resource,
                        note="annotated IAM role was not found in the AWS scan",
                    )
                )
                continue

            if not self._irsa_extractor._trust_policy_allows(role, namespace, name):
                warnings.append(
                    self._warning(
                        level="WARNING",
                        reason="trust_mismatch",
                        resource=resource,
                        note="IAM role trust policy does not allow this service account",
                    )
                )

        return warnings

    def _credential_warnings(
        self,
        secrets: list[dict[str, Any]],
        iam_users: list[Any],
        rds_instances: list[Any],
        s3_buckets: list[Any],
        credential_config: dict[str, Any],
    ) -> list[dict[str, str]]:
        warnings: list[dict[str, str]] = []
        users_by_active_key = self._secret_extractor._index_active_access_keys(iam_users)
        rds_by_endpoint = self._secret_extractor._index_rds_endpoints(rds_instances)
        s3_by_name = self._secret_extractor._index_s3_buckets(s3_buckets)

        for secret in secrets:
            metadata = secret.get("metadata")
            if not isinstance(metadata, dict):
                metadata = secret

            namespace = metadata.get("namespace")
            name = metadata.get("name")
            if not isinstance(namespace, str) or not namespace:
                namespace = "unknown"
            if not isinstance(name, str) or not name:
                name = "unknown"

            resource = f"secret:{namespace}/{name}"
            detected_keys = self._secret_key_names(secret)

            if self._is_iam_candidate(detected_keys):
                configured_username = self._secret_extractor._configured_iam_username(
                    credential_config,
                    namespace,
                    name,
                )
                if configured_username is None:
                    matched_access_id_keys = [
                        key for key in detected_keys if key in ACCESS_KEY_ID_KEYS
                    ]
                    access_key_id = self._secret_extractor._find_access_key_id(
                        secret,
                        matched_access_id_keys,
                    )
                    if access_key_id is not None and access_key_id not in users_by_active_key:
                        warnings.append(
                            self._warning(
                                level="WARNING",
                                reason="iam_user_unresolved",
                                resource=resource,
                                note="AWS credential keys found but IAM user could not be resolved",
                            )
                        )

            if self._is_rds_candidate(detected_keys):
                host_value = self._secret_extractor._find_first_value(
                    secret,
                    [key for key in detected_keys if key in RDS_HOST_KEYS],
                )
                if host_value is not None:
                    matched_identifiers = rds_by_endpoint.get(host_value, [])
                    if not matched_identifiers:
                        warnings.append(
                            self._warning(
                                level="WARNING",
                                reason="rds_target_unresolved",
                                resource=resource,
                                note="RDS credential pattern found but no scanned endpoint matched",
                            )
                        )
                    elif len(matched_identifiers) != 1:
                        warnings.append(
                            self._warning(
                                level="WARNING",
                                reason="ambiguous_rds_target",
                                resource=resource,
                                note="RDS credential pattern matched multiple scanned endpoints",
                            )
                        )

            if self._is_s3_candidate(detected_keys):
                bucket_value = self._secret_extractor._find_first_value(
                    secret,
                    [key for key in detected_keys if key in S3_BUCKET_KEYS],
                )
                if bucket_value is not None:
                    matched_names = s3_by_name.get(bucket_value, [])
                    if not matched_names:
                        warnings.append(
                            self._warning(
                                level="WARNING",
                                reason="s3_target_unresolved",
                                resource=resource,
                                note="S3 credential pattern found but no scanned bucket matched",
                            )
                        )
                    elif len(matched_names) != 1:
                        warnings.append(
                            self._warning(
                                level="WARNING",
                                reason="ambiguous_s3_target",
                                resource=resource,
                                note="S3 credential pattern matched multiple scanned buckets",
                            )
                        )

        return warnings

    def _warning(
        self,
        level: str,
        reason: str,
        resource: str,
        note: str,
    ) -> dict[str, str]:
        return {
            "level": level,
            "reason": reason,
            "resource": resource,
            "note": note,
        }
