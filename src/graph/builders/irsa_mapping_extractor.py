"""IRSA mapping extraction from raw Kubernetes service account data."""

from __future__ import annotations

import logging
from typing import Any

from src.graph.builders.aws_scanner_types import IAMRoleScan
from src.graph.builders.cross_domain_types import IRSAMapping
from src.graph.builders.iam_policy_parser import IAMPolicyParser

logger = logging.getLogger(__name__)

IRSA_ROLE_ANNOTATION = "eks.amazonaws.com/role-arn"
KUBE2IAM_ROLE_ANNOTATION = "iam.amazonaws.com/role"


class IRSAMappingExtractor:
    """Extract confirmed IRSA mappings from raw Kubernetes service accounts."""

    def __init__(self, policy_parser: IAMPolicyParser | None = None) -> None:
        self._policy_parser = policy_parser or IAMPolicyParser()

    def extract(
        self,
        service_accounts: list[dict[str, Any]],
        iam_roles: list[IAMRoleScan],
    ) -> list[IRSAMapping]:
        """Return confirmed IRSA mappings for annotated service accounts.

        Each mapping is confirmed only when:
        - the service account has an IRSA role annotation
        - the annotated ARN is well-formed
        - the corresponding IAM role exists in the provided scan data
        - the role trust policy allows the specific service account
        """
        mappings: list[IRSAMapping] = []
        roles_by_arn = {role.arn: role for role in iam_roles}

        for service_account in service_accounts:
            mapping = self._extract_single(service_account, roles_by_arn)
            if mapping is not None:
                mappings.append(mapping)

        return mappings

    def _extract_single(
        self,
        service_account: dict[str, Any],
        roles_by_arn: dict[str, IAMRoleScan],
    ) -> IRSAMapping | None:
        metadata = service_account.get("metadata")
        if not isinstance(metadata, dict):
            # Flat scanner format: namespace/name/annotations live at top level.
            metadata = service_account

        namespace = metadata.get("namespace")
        name = metadata.get("name")
        annotations = metadata.get("annotations")
        if not isinstance(annotations, dict):
            return None

        kube2iam_role = annotations.get(KUBE2IAM_ROLE_ANNOTATION)
        if kube2iam_role:
            logger.info(
                "Skipping service account %s/%s because kube2iam/kiam role annotations are unsupported: %s",
                namespace,
                name,
                kube2iam_role,
            )
            return None

        role_arn = annotations.get(IRSA_ROLE_ANNOTATION)
        if not role_arn:
            return None

        parsed = self._parse_role_arn(role_arn)
        if parsed is None:
            logger.warning(
                "Skipping service account %s/%s due to malformed IRSA role ARN: %s",
                namespace,
                name,
                role_arn,
            )
            return None

        account_id, role_name = parsed
        role = roles_by_arn.get(role_arn)
        if role is None:
            logger.warning(
                "Skipping service account %s/%s because annotated IAM role was not found: %s",
                namespace,
                name,
                role_arn,
            )
            return None

        if not self._trust_policy_allows(role, namespace, name):
            logger.warning(
                "Skipping service account %s/%s because IAM role trust policy does not allow it: %s",
                namespace,
                name,
                role_arn,
            )
            return None

        return IRSAMapping(
            sa_namespace=namespace,
            sa_name=name,
            iam_role_arn=role_arn,
            iam_role_name=role_name,
            account_id=account_id,
        )

    def _parse_role_arn(self, role_arn: Any) -> tuple[str, str] | None:
        if not isinstance(role_arn, str):
            return None

        parts = role_arn.split(":", 5)
        if len(parts) != 6:
            return None

        partition, service, account_id, resource = parts[1], parts[2], parts[4], parts[5]
        if partition != "aws" or service != "iam" or not account_id.isdigit():
            return None
        if not resource.startswith("role/"):
            return None

        role_name = resource[len("role/") :]
        if not role_name:
            return None

        return account_id, role_name

    def _trust_policy_allows(
        self,
        role: IAMRoleScan,
        namespace: Any,
        name: Any,
    ) -> bool:
        if not isinstance(namespace, str) or not namespace:
            return False
        if not isinstance(name, str) or not name:
            return False

        service_account_subject = f"system:serviceaccount:{namespace}:{name}"
        trust_analysis = self._policy_parser.parse(role).trust_analysis

        if not trust_analysis.is_irsa_enabled:
            return False
        if not self._has_confirming_irsa_statement(role.trust_policy, service_account_subject):
            return False
        if service_account_subject in trust_analysis.allowed_sa_explicit:
            return True
        if trust_analysis.allows_all_sa:
            return True

        return any(
            self._matches_pattern(service_account_subject, pattern)
            for pattern in trust_analysis.allowed_sa_patterns
        )

    def _has_confirming_irsa_statement(
        self,
        trust_policy: dict[str, Any],
        service_account_subject: str,
    ) -> bool:
        statements = self._policy_parser._normalize_statements(trust_policy)
        for statement in statements:
            if statement.get("Effect") != "Allow":
                continue
            if not self._statement_has_oidc_principal(statement):
                continue
            if not self._statement_allows_web_identity(statement):
                continue
            if not self._statement_has_sts_audience(statement):
                continue
            if self._statement_allows_subject(statement, service_account_subject):
                return True
        return False

    def _statement_has_oidc_principal(self, statement: dict[str, Any]) -> bool:
        principal = statement.get("Principal", {})
        if isinstance(principal, str):
            principal = {"AWS": principal}
        if not isinstance(principal, dict):
            return False

        federated = principal.get("Federated", [])
        if isinstance(federated, str):
            federated = [federated]
        return any(
            isinstance(fed, str) and "oidc-provider/" in fed
            for fed in federated
        )

    def _statement_allows_web_identity(self, statement: dict[str, Any]) -> bool:
        actions = statement.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        return "sts:AssumeRoleWithWebIdentity" in actions

    def _statement_has_sts_audience(self, statement: dict[str, Any]) -> bool:
        conditions = statement.get("Condition", {})
        if not isinstance(conditions, dict):
            return False

        for condition_op, condition_vals in conditions.items():
            if condition_op not in ("StringLike", "StringEquals"):
                continue
            if not isinstance(condition_vals, dict):
                continue
            for key, val in condition_vals.items():
                if not (key == "sts:aud" or key.endswith(":aud")):
                    continue
                values = [val] if isinstance(val, str) else val
                if any(v == "sts.amazonaws.com" for v in values):
                    return True
        return False

    def _statement_allows_subject(
        self,
        statement: dict[str, Any],
        service_account_subject: str,
    ) -> bool:
        conditions = statement.get("Condition", {})
        if not isinstance(conditions, dict):
            return False

        for condition_op, condition_vals in conditions.items():
            if condition_op not in ("StringLike", "StringEquals"):
                continue
            if not isinstance(condition_vals, dict):
                continue
            for key, val in condition_vals.items():
                if not (key == "sts:amazonaws.com:sub" or key.endswith(":sub")):
                    continue
                values = [val] if isinstance(val, str) else val
                for subject_or_pattern in values:
                    if not isinstance(subject_or_pattern, str):
                        continue
                    if self._matches_pattern(service_account_subject, subject_or_pattern):
                        return True
        return False

    def _matches_pattern(self, subject: str, pattern: str) -> bool:
        subject_parts = subject.split(":")
        pattern_parts = pattern.split(":")
        if len(subject_parts) != len(pattern_parts):
            return False
        return all(
            pattern_part == "*" or pattern_part == subject_part
            for subject_part, pattern_part in zip(subject_parts, pattern_parts)
        )
