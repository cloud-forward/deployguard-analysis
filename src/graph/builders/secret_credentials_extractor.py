"""Secret credential extraction for AWS IAM users and narrow RDS/S3 matches."""

from __future__ import annotations

import logging
from typing import Any

from src.graph.builders.aws_scanner_types import IAMUserScan, RDSInstanceScan, S3BucketScan
from src.graph.builders.cross_domain_types import SecretContainsCredentialsFact

logger = logging.getLogger(__name__)

ACCESS_KEY_ID_KEYS = frozenset({"AWS_ACCESS_KEY_ID", "aws_access_key_id"})
SECRET_ACCESS_KEY_KEYS = frozenset({"AWS_SECRET_ACCESS_KEY", "aws_secret_access_key"})
RDS_HOST_KEYS = frozenset({"host", "endpoint", "db_host", "DB_HOST"})
RDS_USERNAME_KEYS = frozenset({"username", "user", "db_user", "DB_USER"})
RDS_PASSWORD_KEYS = frozenset({"password", "passwd", "db_password", "DB_PASSWORD"})
RDS_PORT_KEYS = frozenset({"port", "db_port", "DB_PORT"})
S3_BUCKET_KEYS = frozenset({"bucket", "bucket_name", "s3_bucket"})
S3_ENDPOINT_KEYS = frozenset({"endpoint", "s3_endpoint"})
S3_REGION_KEYS = frozenset({"region", "aws_region"})


class SecretCredentialsExtractor:
    """Extract IAM-user credential facts from raw Kubernetes Secret data."""

    def extract(
        self,
        secrets: list[dict[str, Any]],
        iam_users: list[IAMUserScan],
        rds_instances: list[RDSInstanceScan | dict[str, Any] | Any] | None = None,
        s3_buckets: list[S3BucketScan | dict[str, Any] | Any] | None = None,
        credential_config: dict[str, Any] | None = None,
    ) -> list[SecretContainsCredentialsFact]:
        """Return credential facts for Secrets that map to scanned IAM users."""
        facts: list[SecretContainsCredentialsFact] = []
        users_by_active_key = self._index_active_access_keys(iam_users)
        rds_by_endpoint = self._index_rds_endpoints(rds_instances or [])
        rds_identifiers = self._index_rds_identifiers(rds_instances or [])
        s3_by_name = self._index_s3_buckets(s3_buckets or [])

        for secret in secrets:
            facts.extend(
                self._extract_single(
                    secret,
                    users_by_active_key,
                    rds_by_endpoint,
                    rds_identifiers,
                    s3_by_name,
                    credential_config or {},
                )
            )

        return facts

    def _index_active_access_keys(
        self,
        iam_users: list[IAMUserScan],
    ) -> dict[str, IAMUserScan]:
        users_by_active_key: dict[str, IAMUserScan] = {}
        for user in iam_users:
            for key in user.access_keys:
                if key.status == "Active":
                    users_by_active_key[key.access_key_id] = user
        return users_by_active_key

    def _extract_single(
        self,
        secret: dict[str, Any],
        users_by_active_key: dict[str, IAMUserScan],
        rds_by_endpoint: dict[str, list[str]],
        rds_identifiers: list[str],
        s3_by_name: dict[str, list[str]],
        credential_config: dict[str, Any],
    ) -> list[SecretContainsCredentialsFact]:
        metadata = secret.get("metadata")
        if not isinstance(metadata, dict):
            # Flat scanner format: namespace/name live at top level.
            metadata = secret

        namespace = metadata.get("namespace")
        name = metadata.get("name")
        if not isinstance(namespace, str) or not namespace:
            logger.warning(
                "Skipping Secret with missing namespace: name=%s",
                name if isinstance(name, str) and name else "unknown",
            )
            return []
        if not isinstance(name, str) or not name:
            logger.warning("Skipping Secret with missing name in namespace %s", namespace)
            return []

        detected_keys = self._detected_key_names_for_secret(secret)
        if not detected_keys:
            logger.warning("Skipping Secret %s/%s with no usable key metadata", namespace, name)
            return []
        facts: list[SecretContainsCredentialsFact] = []

        iam_fact = self._extract_iam_user_fact(
            secret,
            namespace,
            name,
            detected_keys,
            users_by_active_key,
            credential_config,
        )
        if iam_fact is not None:
            facts.append(iam_fact)

        rds_fact = self._extract_rds_fact(
            secret,
            namespace,
            name,
            detected_keys,
            rds_by_endpoint,
            rds_identifiers,
        )
        if rds_fact is not None:
            facts.append(rds_fact)

        s3_fact = self._extract_s3_fact(
            secret,
            namespace,
            name,
            detected_keys,
            s3_by_name,
        )
        if s3_fact is not None:
            facts.append(s3_fact)

        return facts

    def _extract_iam_user_fact(
        self,
        secret: dict[str, Any],
        namespace: str,
        name: str,
        detected_keys: list[str],
        users_by_active_key: dict[str, IAMUserScan],
        credential_config: dict[str, Any],
    ) -> SecretContainsCredentialsFact | None:
        matched_access_id_keys = [key for key in detected_keys if key in ACCESS_KEY_ID_KEYS]
        matched_secret_keys = [key for key in detected_keys if key in SECRET_ACCESS_KEY_KEYS]

        if not matched_access_id_keys or not matched_secret_keys:
            return None

        matched_keys = matched_access_id_keys + matched_secret_keys

        configured_username = self._configured_iam_username(credential_config, namespace, name)
        if configured_username is not None:
            return SecretContainsCredentialsFact(
                secret_namespace=namespace,
                secret_name=name,
                target_type="iam_user",
                target_id=configured_username,
                matched_keys=matched_keys,
                confidence="high",
            )

        access_key_id = self._find_access_key_id(secret, matched_access_id_keys)
        if access_key_id is None:
            logger.warning(
                "Skipping Secret %s/%s because AWS access key ID value is missing or invalid",
                namespace,
                name,
            )
            return None

        user = users_by_active_key.get(access_key_id)
        if user is None:
            return SecretContainsCredentialsFact(
                secret_namespace=namespace,
                secret_name=name,
                target_type="iam_user",
                target_id="unknown",
                matched_keys=matched_keys,
                confidence="medium",
            )

        return SecretContainsCredentialsFact(
            secret_namespace=namespace,
            secret_name=name,
            target_type="iam_user",
            target_id=user.username,
            matched_keys=matched_keys,
            confidence="high",
        )

    def _configured_iam_username(
        self,
        credential_config: dict[str, Any],
        namespace: str,
        name: str,
    ) -> str | None:
        secret_key = f"{namespace}/{name}"
        for candidate in (
            credential_config.get(secret_key),
            credential_config.get("secrets", {}).get(secret_key)
            if isinstance(credential_config.get("secrets"), dict)
            else None,
            credential_config.get("secrets", {}).get(namespace, {}).get(name)
            if isinstance(credential_config.get("secrets"), dict)
            and isinstance(credential_config.get("secrets", {}).get(namespace), dict)
            else None,
        ):
            if isinstance(candidate, str) and candidate:
                return candidate
        return None

    def _extract_rds_fact(
        self,
        secret: dict[str, Any],
        namespace: str,
        name: str,
        detected_keys: list[str],
        rds_by_endpoint: dict[str, list[str]],
        rds_identifiers: list[str],
    ) -> SecretContainsCredentialsFact | None:
        matched_host_keys = [key for key in detected_keys if key in RDS_HOST_KEYS]
        if not matched_host_keys:
            return None

        categories_present = 0
        for key_set in (RDS_HOST_KEYS, RDS_USERNAME_KEYS, RDS_PASSWORD_KEYS, RDS_PORT_KEYS):
            if any(key in key_set for key in detected_keys):
                categories_present += 1
        if categories_present < 2:
            return None

        host_value = self._find_first_value(secret, matched_host_keys)
        if host_value is None:
            if self._has_precomputed_key_metadata(secret) and len(rds_identifiers) == 1:
                matched_keys = [
                    key for key in detected_keys
                    if key in RDS_HOST_KEYS
                    or key in RDS_USERNAME_KEYS
                    or key in RDS_PASSWORD_KEYS
                    or key in RDS_PORT_KEYS
                ]
                return SecretContainsCredentialsFact(
                    secret_namespace=namespace,
                    secret_name=name,
                    target_type="rds",
                    target_id=rds_identifiers[0],
                    matched_keys=matched_keys,
                    confidence="medium",
                )

            logger.warning(
                "Skipping Secret %s/%s because RDS host value is missing or invalid",
                namespace,
                name,
            )
            return None

        matched_identifiers = rds_by_endpoint.get(host_value, [])
        if not matched_identifiers:
            if len(rds_identifiers) == 1:
                matched_keys = [
                    key for key in detected_keys
                    if key in RDS_HOST_KEYS
                    or key in RDS_USERNAME_KEYS
                    or key in RDS_PASSWORD_KEYS
                    or key in RDS_PORT_KEYS
                ]
                return SecretContainsCredentialsFact(
                    secret_namespace=namespace,
                    secret_name=name,
                    target_type="rds",
                    target_id=rds_identifiers[0],
                    matched_keys=matched_keys,
                    confidence="medium",
                )
            logger.warning(
                "Skipping Secret %s/%s because no scanned RDS endpoint matched %s",
                namespace,
                name,
                host_value,
            )
            return None
        if len(matched_identifiers) != 1:
            logger.warning(
                "Skipping Secret %s/%s because RDS endpoint match is ambiguous for %s",
                namespace,
                name,
                host_value,
            )
            return None

        has_username = any(key in RDS_USERNAME_KEYS for key in detected_keys)
        has_password = any(key in RDS_PASSWORD_KEYS for key in detected_keys)
        confidence = "high" if has_username and has_password else "medium"

        matched_keys = [
            key for key in detected_keys
            if key in RDS_HOST_KEYS
            or key in RDS_USERNAME_KEYS
            or key in RDS_PASSWORD_KEYS
            or key in RDS_PORT_KEYS
        ]
        return SecretContainsCredentialsFact(
            secret_namespace=namespace,
            secret_name=name,
            target_type="rds",
            target_id=matched_identifiers[0],
            matched_keys=matched_keys,
            confidence=confidence,
        )

    def _extract_s3_fact(
        self,
        secret: dict[str, Any],
        namespace: str,
        name: str,
        detected_keys: list[str],
        s3_by_name: dict[str, list[str]],
    ) -> SecretContainsCredentialsFact | None:
        matched_bucket_keys = [key for key in detected_keys if key in S3_BUCKET_KEYS]
        if not matched_bucket_keys:
            return None

        categories_present = 0
        for key_set in (S3_BUCKET_KEYS, S3_ENDPOINT_KEYS, S3_REGION_KEYS):
            if any(key in key_set for key in detected_keys):
                categories_present += 1
        if categories_present < 2:
            return None

        bucket_value = self._find_first_value(secret, matched_bucket_keys)
        if bucket_value is None:
            logger.warning(
                "Skipping Secret %s/%s because S3 bucket value is missing or invalid",
                namespace,
                name,
            )
            return None

        matched_names = s3_by_name.get(bucket_value, [])
        if not matched_names:
            logger.warning(
                "Skipping Secret %s/%s because no scanned S3 bucket matched %s",
                namespace,
                name,
                bucket_value,
            )
            return None
        if len(matched_names) != 1:
            logger.warning(
                "Skipping Secret %s/%s because S3 bucket match is ambiguous for %s",
                namespace,
                name,
                bucket_value,
            )
            return None

        matched_keys = [
            key for key in detected_keys
            if key in S3_BUCKET_KEYS or key in S3_ENDPOINT_KEYS or key in S3_REGION_KEYS
        ]
        return SecretContainsCredentialsFact(
            secret_namespace=namespace,
            secret_name=name,
            target_type="s3",
            target_id=matched_names[0],
            matched_keys=matched_keys,
            confidence="high",
        )

    def _find_access_key_id(
        self,
        secret: dict[str, Any],
        matched_access_id_keys: list[str],
    ) -> str | None:
        return self._find_first_value(secret, matched_access_id_keys)

    def _find_first_value(
        self,
        secret: dict[str, Any],
        key_names: list[str],
    ) -> str | None:
        data = secret.get("data", {})
        string_data = secret.get("stringData", {})

        for key_name in key_names:
            for source in (string_data, data):
                if not isinstance(source, dict):
                    continue
                value = source.get(key_name)
                if isinstance(value, str) and value:
                    return value
        return None

    def _detected_key_names_for_secret(self, secret: dict[str, Any]) -> list[str]:
        metadata = secret.get("metadata")
        if not isinstance(metadata, dict):
            metadata = {}
        return self._detected_key_names(
            secret.get("data"),
            secret.get("stringData"),
            secret.get("data_keys"),
            secret.get("string_data_keys"),
            metadata.get("data_keys"),
            metadata.get("string_data_keys"),
        )

    def _has_precomputed_key_metadata(self, secret: dict[str, Any]) -> bool:
        metadata = secret.get("metadata")
        if not isinstance(metadata, dict):
            metadata = {}
        return any(
            isinstance(value, list) and any(isinstance(key, str) for key in value)
            for value in (
                secret.get("data_keys"),
                secret.get("string_data_keys"),
                metadata.get("data_keys"),
                metadata.get("string_data_keys"),
            )
        )

    def _index_rds_endpoints(
        self,
        rds_instances: list[RDSInstanceScan | dict[str, Any] | Any],
    ) -> dict[str, list[str]]:
        endpoints: dict[str, list[str]] = {}
        for instance in rds_instances:
            identifier = self._rds_identifier(instance)
            endpoint = self._rds_endpoint(instance)
            if not identifier or not endpoint:
                continue
            endpoints.setdefault(endpoint, []).append(identifier)
        return endpoints

    def _index_rds_identifiers(
        self,
        rds_instances: list[RDSInstanceScan | dict[str, Any] | Any],
    ) -> list[str]:
        identifiers: list[str] = []
        for instance in rds_instances:
            identifier = self._rds_identifier(instance)
            if identifier and identifier not in identifiers:
                identifiers.append(identifier)
        return identifiers

    def _rds_identifier(self, instance: Any) -> str | None:
        if isinstance(instance, dict):
            identifier = instance.get("identifier")
            return identifier if isinstance(identifier, str) and identifier else None

        identifier = getattr(instance, "identifier", None)
        return identifier if isinstance(identifier, str) and identifier else None

    def _rds_endpoint(self, instance: Any) -> str | None:
        if isinstance(instance, RDSInstanceScan):
            return instance.endpoint

        if isinstance(instance, dict):
            endpoint = instance.get("endpoint")
            if isinstance(endpoint, str) and endpoint:
                return endpoint
            endpoint_dict = instance.get("Endpoint")
            if isinstance(endpoint_dict, dict):
                address = endpoint_dict.get("Address")
                if isinstance(address, str) and address:
                    return address
            return None

        endpoint = getattr(instance, "endpoint", None)
        if isinstance(endpoint, str) and endpoint:
            return endpoint
        return None

    def _index_s3_buckets(
        self,
        s3_buckets: list[S3BucketScan | dict[str, Any] | Any],
    ) -> dict[str, list[str]]:
        bucket_names: dict[str, list[str]] = {}
        for bucket in s3_buckets:
            bucket_name = self._s3_bucket_name(bucket)
            if not bucket_name:
                continue
            bucket_names.setdefault(bucket_name, []).append(bucket_name)
        return bucket_names

    def _s3_bucket_name(self, bucket: Any) -> str | None:
        if isinstance(bucket, S3BucketScan):
            return bucket.name
        if isinstance(bucket, dict):
            name = bucket.get("name")
            return name if isinstance(name, str) and name else None

        name = getattr(bucket, "name", None)
        return name if isinstance(name, str) and name else None

    def _detected_key_names(
        self,
        *sources: Any,
    ) -> list[str]:
        keys: list[str] = []
        for source in sources:
            if not isinstance(source, dict):
                if isinstance(source, list):
                    for key in source:
                        if isinstance(key, str) and key not in keys:
                            keys.append(key)
                continue
            for key in source:
                if isinstance(key, str) and key not in keys:
                    keys.append(key)
        return keys
