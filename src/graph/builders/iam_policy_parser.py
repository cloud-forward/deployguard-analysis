"""IAM Policy Parser: parses IAM role scan data into structured analysis results."""

from typing import Any, Optional

from src.graph.builders.aws_scanner_types import IAMRoleScan, IAMUserScan
from src.graph.builders.iam_policy_types import (
    IAMPolicyAnalysisResult,
    IAMUserPolicyAnalysisResult,
    ResourceAccess,
    TrustPolicyAnalysis,
)


class IAMPolicyParser:
    """Parses IAM role scan data into structured IAMPolicyAnalysisResult."""

    def parse(self, role: IAMRoleScan) -> IAMPolicyAnalysisResult:
        """Parse an IAMRoleScan into a full IAMPolicyAnalysisResult."""
        account_id = self._extract_account_id(role.arn)
        trust_analysis = self._parse_trust_policy(role.trust_policy, account_id)
        resource_access = self._parse_permission_policies(
            role.attached_policies, role.inline_policies
        )
        tier, tier_reason = self._classify_tier(resource_access, role.attached_policies)
        risk_signals = self._detect_risk_signals(resource_access)

        return IAMPolicyAnalysisResult(
            role_name=role.name,
            role_arn=role.arn,
            account_id=account_id,
            tier=tier,
            tier_reason=tier_reason,
            trust_analysis=trust_analysis,
            resource_access=resource_access,
            has_privilege_escalation=risk_signals.get("has_privilege_escalation", False),
            has_data_exfiltration_risk=risk_signals.get("has_data_exfiltration_risk", False),
            has_credential_access=risk_signals.get("has_credential_access", False),
        )

    def _extract_account_id(self, arn: str) -> str:
        parts = arn.split(":")
        if len(parts) >= 5:
            return parts[4]
        return ""

    def _normalize_statements(self, document: dict[str, Any]) -> list[dict[str, Any]]:
        statements = document.get("Statement", [])
        if isinstance(statements, dict):
            return [statements]
        if isinstance(statements, list):
            return [s for s in statements if isinstance(s, dict)]
        return []

    def _get_policy_name(self, policy: dict[str, Any]) -> Optional[str]:
        return policy.get("name") or policy.get("PolicyName")

    def _get_policy_arn(self, policy: dict[str, Any]) -> Optional[str]:
        return policy.get("arn") or policy.get("PolicyArn")

    def _get_policy_document(self, policy: dict[str, Any]) -> Optional[dict[str, Any]]:
        document = (
            policy.get("document")
            or policy.get("Document")
            or policy.get("PolicyDocument")
        )
        return document if isinstance(document, dict) else None

    def _parse_trust_policy(
        self,
        trust_policy: dict[str, Any],
        current_account_id: str,
    ) -> TrustPolicyAnalysis:
        """Parse a trust policy document into a TrustPolicyAnalysis."""
        is_irsa_enabled = False
        oidc_issuer: Optional[str] = None
        allows_all_sa = False
        allowed_sa_patterns: list[str] = []
        allowed_sa_explicit: list[str] = []
        allows_ec2 = False
        allows_lambda = False
        cross_account_principals: list[str] = []
        has_broad_irsa_trust = False

        statements = self._normalize_statements(trust_policy)
        for statement in statements:
            if statement.get("Effect") != "Allow":
                continue

            principal = statement.get("Principal", {})

            # Normalize principal to a dict
            if isinstance(principal, str):
                principal = {"AWS": principal}

            federated = principal.get("Federated", "")
            if isinstance(federated, str):
                federated = [federated]
            for fed in federated:
                if "oidc-provider" in fed:
                    is_irsa_enabled = True
                    # Extract issuer from ARN: everything after "oidc-provider/"
                    if "oidc-provider/" in fed:
                        oidc_issuer = fed.split("oidc-provider/", 1)[1]

            # Check service principals
            service = principal.get("Service", [])
            if isinstance(service, str):
                service = [service]
            for svc in service:
                if "ec2.amazonaws.com" in svc:
                    allows_ec2 = True
                if "lambda.amazonaws.com" in svc:
                    allows_lambda = True

            # Check AWS principals for cross-account
            aws_principals = principal.get("AWS", [])
            if isinstance(aws_principals, str):
                aws_principals = [aws_principals]
            for arn in aws_principals:
                if not isinstance(arn, str) or arn == "*":
                    continue
                principal_account_id = self._extract_account_id(arn)
                if principal_account_id and principal_account_id != current_account_id:
                    cross_account_principals.append(arn)

            if is_irsa_enabled:
                sub_values = self._get_irsa_subject_values(statement)
                if sub_values:
                    for value in sub_values:
                        if value == "system:serviceaccount:*:*":
                            allows_all_sa = True
                            allowed_sa_patterns.append(value)
                        elif "*" in value:
                            allowed_sa_patterns.append(value)
                        else:
                            allowed_sa_explicit.append(value)
                elif (
                    self._statement_allows_web_identity(statement)
                    and self._statement_has_valid_irsa_audience(statement)
                ):
                    has_broad_irsa_trust = True

        return TrustPolicyAnalysis(
            is_irsa_enabled=is_irsa_enabled,
            oidc_issuer=oidc_issuer,
            allows_all_sa=allows_all_sa,
            allowed_sa_patterns=allowed_sa_patterns,
            allowed_sa_explicit=allowed_sa_explicit,
            allows_ec2=allows_ec2,
            allows_lambda=allows_lambda,
            cross_account_principals=cross_account_principals,
            has_broad_irsa_trust=has_broad_irsa_trust,
        )

    def _statement_allows_web_identity(self, statement: dict[str, Any]) -> bool:
        actions = statement.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        return "sts:AssumeRoleWithWebIdentity" in actions

    def _statement_has_valid_irsa_audience(self, statement: dict[str, Any]) -> bool:
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

    def _get_irsa_subject_values(self, statement: dict[str, Any]) -> list[str]:
        conditions = statement.get("Condition", {})
        if not isinstance(conditions, dict):
            return []

        subject_values: list[str] = []
        for condition_op, condition_vals in conditions.items():
            if condition_op not in ("StringLike", "StringEquals"):
                continue
            if not isinstance(condition_vals, dict):
                continue
            for key, val in condition_vals.items():
                if not (key == "sts:amazonaws.com:sub" or key.endswith(":sub")):
                    continue
                values = [val] if isinstance(val, str) else val
                subject_values.extend(v for v in values if isinstance(v, str))
        return subject_values

    def _parse_permission_policies(
        self, attached: list[dict], inline: list[dict]
    ) -> list[ResourceAccess]:
        """Parse attached and inline policies into a list of ResourceAccess entries."""
        results: list[ResourceAccess] = []

        for policy in attached:
            policy_name = self._get_policy_name(policy)
            policy_arn = self._get_policy_arn(policy)
            document = self._get_policy_document(policy)
            if document is None:
                continue
            results.extend(
                self._parse_single_document(document, policy_name, policy_arn)
            )

        for policy in inline:
            policy_name = self._get_policy_name(policy)
            document = self._get_policy_document(policy) or {}
            results.extend(
                self._parse_single_document(document, policy_name, None)
            )

        return results

    def _parse_single_document(
        self,
        document: dict,
        policy_name: Optional[str],
        policy_arn: Optional[str],
    ) -> list[ResourceAccess]:
        """Parse a single policy document into ResourceAccess entries."""
        results: list[ResourceAccess] = []
        statements = self._normalize_statements(document)

        for statement in statements:
            effect = statement.get("Effect", "Allow")
            actions = statement.get("Action", [])
            resources = statement.get("Resource", [])
            conditions = statement.get("Condition") or None

            if isinstance(actions, str):
                actions = [actions]
            if isinstance(resources, str):
                resources = [resources]

            is_wildcard_action = "*" in actions or any(
                a == "*" or a.endswith(":*") for a in actions
            )
            is_wildcard_resource = "*" in resources or any(r == "*" for r in resources)

            # Group actions by service
            service_actions: dict[str, list[str]] = {}
            for action in actions:
                if action == "*":
                    service_key = "*"
                elif ":" in action:
                    service_key = action.split(":")[0].lower()
                else:
                    service_key = action.lower()
                service_actions.setdefault(service_key, []).append(action)

            for service, svc_actions in service_actions.items():
                results.append(
                    ResourceAccess(
                        service=service,
                        actions=svc_actions,
                        resource_arns=resources,
                        effect=effect,
                        is_wildcard_action=is_wildcard_action,
                        is_wildcard_resource=is_wildcard_resource,
                        policy_name=policy_name,
                        policy_arn=policy_arn,
                        conditions=conditions,
                    )
                )

        return results

    def _classify_tier(
        self, resource_access: list[ResourceAccess], attached_policies: list[dict]
    ) -> tuple[Optional[int], str]:
        """Classify the role into a risk tier based on resource access patterns."""

        # Tier 1 — Explicit Admin
        for policy in attached_policies:
            if self._get_policy_name(policy) == "AdministratorAccess":
                return 1, "AdministratorAccess policy attached"

        for ra in resource_access:
            if (
                ra.effect == "Allow"
                and ra.is_wildcard_resource
                and any(a == "*" for a in ra.actions)
            ):
                return 1, "Action:* Resource:* in policy"

        # Tier 2 — Effective Admin (privilege escalation possible)
        iam_actions = set()
        lambda_actions = set()
        ec2_actions = set()
        all_allow_actions: set[str] = set()
        for ra in resource_access:
            if ra.effect != "Allow":
                continue
            action_set = {action.lower() for action in ra.actions}
            if ra.is_wildcard_action:
                action_set.add(f"{ra.service}:*")
            all_allow_actions |= action_set
            if ra.service == "iam":
                iam_actions |= action_set
            elif ra.service == "lambda":
                lambda_actions |= action_set
            elif ra.service == "ec2":
                ec2_actions |= action_set

        def has_iam_action(action: str) -> bool:
            return "iam:*" in iam_actions or action.lower() in iam_actions

        def has_action(action_set: set[str], action: str) -> bool:
            service = action.split(":")[0]
            return f"{service}:*" in action_set or action.lower() in action_set

        if has_iam_action("iam:createrole") and has_iam_action("iam:attachrolepolicy"):
            return 2, "iam:CreateRole + iam:AttachRolePolicy"

        if has_iam_action("iam:passrole") and (
            has_action(lambda_actions, "lambda:CreateFunction")
            or has_action(ec2_actions, "ec2:RunInstances")
            or has_action(all_allow_actions, "glue:CreateJob")
        ):
            return 2, "iam:PassRole + compute creation detected"

        if has_iam_action("iam:updateassumerolepolicy"):
            return 2, "iam:UpdateAssumeRolePolicy detected"

        # Tier 3 — Broad sensitive resource access
        sensitive_services = {"s3", "rds", "ec2", "secretsmanager"}
        for ra in resource_access:
            if (
                ra.effect == "Allow"
                and ra.is_wildcard_action
                and ra.is_wildcard_resource
                and ra.service in sensitive_services
            ):
                return 3, f"{ra.service}:* with Resource:*"

        return None, ""

    def _detect_risk_signals(self, resource_access: list[ResourceAccess]) -> dict[str, bool]:
        """Detect risk signals from resource access patterns."""
        # Collect all Allow actions per service
        iam_actions: set[str] = set()
        lambda_actions: set[str] = set()
        ec2_actions: set[str] = set()
        all_allow_actions: set[str] = set()
        s3_entries: list[ResourceAccess] = []

        for ra in resource_access:
            if ra.effect != "Allow":
                continue
            action_set = {a.lower() for a in ra.actions}
            if ra.is_wildcard_action:
                action_set.add(f"{ra.service}:*")
            all_allow_actions |= action_set
            if ra.service == "iam":
                iam_actions |= action_set
            elif ra.service == "lambda":
                lambda_actions |= action_set
            elif ra.service == "ec2":
                ec2_actions |= action_set
            elif ra.service == "s3":
                s3_entries.append(ra)

        def has_action(action_set: set[str], action: str) -> bool:
            service = action.split(":")[0]
            return f"{service}:*" in action_set or action.lower() in action_set

        # --- has_privilege_escalation ---
        has_privilege_escalation = False

        # iam:PassRole + (lambda:CreateFunction OR ec2:RunInstances OR glue:CreateJob)
        if has_action(iam_actions, "iam:PassRole") and (
            has_action(lambda_actions, "lambda:CreateFunction")
            or has_action(ec2_actions, "ec2:RunInstances")
            or has_action(all_allow_actions, "glue:CreateJob")
        ):
            has_privilege_escalation = True

        # iam:CreateRole + iam:AttachRolePolicy
        if has_action(iam_actions, "iam:CreateRole") and has_action(iam_actions, "iam:AttachRolePolicy"):
            has_privilege_escalation = True

        # iam:PutRolePolicy (can add arbitrary permissions)
        if has_action(iam_actions, "iam:PutRolePolicy"):
            has_privilege_escalation = True

        # iam:PutUserPolicy can directly grant broader user permissions
        if has_action(iam_actions, "iam:PutUserPolicy"):
            has_privilege_escalation = True

        # iam:UpdateAssumeRolePolicy can broaden role trust relationships
        if has_action(iam_actions, "iam:UpdateAssumeRolePolicy"):
            has_privilege_escalation = True

        # --- has_data_exfiltration_risk ---
        has_data_exfiltration_risk = False

        for ra in s3_entries:
            # S3 access with wildcard resource
            if ra.is_wildcard_resource:
                has_data_exfiltration_risk = True
                break

            # Cross-account S3 access: resource ARNs contain different account IDs
            account_ids = set()
            for arn in ra.resource_arns:
                parts = arn.split(":")
                if len(parts) >= 5 and parts[4]:
                    account_ids.add(parts[4])
            if len(account_ids) > 1:
                has_data_exfiltration_risk = True
                break

            # s3:GetObject + s3:PutObject on sensitive buckets
            action_set = {a.lower() for a in ra.actions}
            if ra.is_wildcard_action:
                action_set.add("s3:*")
            if has_action(action_set, "s3:GetObject") and has_action(action_set, "s3:PutObject"):
                sensitive_keywords = {"prod", "production", "backup", "secret", "credential", "config", "key", "data"}
                for arn in ra.resource_arns:
                    bucket_part = arn.split(":::")[-1].split("/")[0].lower()
                    if any(kw in bucket_part for kw in sensitive_keywords):
                        has_data_exfiltration_risk = True
                        break

        # --- has_credential_access ---
        credential_access_signals = {
            "iam:getuser",
            "iam:createaccesskey",
            "iam:updateaccesskey",
            "secretsmanager:getsecretvalue",
            "secretsmanager:listsecrets",
            "ssm:getparameter",
            "ssm:getparameters",
        }

        has_credential_access = bool(all_allow_actions & credential_access_signals)

        # sts:AssumeRole with wildcard resource
        if not has_credential_access:
            for ra in resource_access:
                if ra.effect != "Allow" or ra.service != "sts":
                    continue
                action_set = {a.lower() for a in ra.actions}
                if ("sts:assumerole" in action_set or ra.is_wildcard_action) and ra.is_wildcard_resource:
                    has_credential_access = True
                    break

        return {
            "has_privilege_escalation": has_privilege_escalation,
            "has_data_exfiltration_risk": has_data_exfiltration_risk,
            "has_credential_access": has_credential_access,
        }

    def parse_user(self, user: IAMUserScan) -> IAMUserPolicyAnalysisResult:
        """Parse an IAMUserScan into a full IAMUserPolicyAnalysisResult."""
        resource_access = self._parse_permission_policies(
            user.attached_policies, user.inline_policies
        )
        tier, tier_reason = self._classify_tier(resource_access, user.attached_policies)
        risk_signals = self._detect_risk_signals(resource_access)

        account_id = self._extract_account_id(user.arn)

        return IAMUserPolicyAnalysisResult(
            username=user.username,
            user_arn=user.arn,
            account_id=account_id,
            tier=tier,
            tier_reason=tier_reason,
            resource_access=resource_access,
            has_privilege_escalation=risk_signals.get("has_privilege_escalation", False),
            has_data_exfiltration_risk=risk_signals.get("has_data_exfiltration_risk", False),
            has_credential_access=risk_signals.get("has_credential_access", False),
        )


def parse_all_roles(roles: list[IAMRoleScan]) -> list[IAMPolicyAnalysisResult]:
    parser = IAMPolicyParser()
    return [parser.parse(role) for role in roles]


def parse_all_users(users: list[IAMUserScan]) -> list[IAMUserPolicyAnalysisResult]:
    parser = IAMPolicyParser()
    return [parser.parse_user(u) for u in users]
