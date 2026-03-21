"""Dedicated RBAC fact extraction for Kubernetes scans."""

from __future__ import annotations

from typing import Any

from src.facts.canonical_fact import Fact
from src.facts.id_generator import NodeIDGenerator
from src.facts.types import FactType, NodeType


class K8sRBACParser:
    """Extract schema-valid RBAC facts from Kubernetes scan data."""

    SUPPORTED_RULE_RESOURCES = {"secrets", "pods", "serviceaccounts"}

    def __init__(self) -> None:
        self.id_gen = NodeIDGenerator()

    def extract_bindings(self, scan: dict[str, Any]) -> list[Fact]:
        """Extract RBAC binding facts."""
        facts: list[Fact] = []

        for binding in scan.get("role_bindings", []):
            role_ref_kind = binding.get("role_ref_kind")
            role_ref_name = binding.get("role_ref_name")
            binding_namespace = binding.get("namespace")

            if not all([role_ref_kind, role_ref_name, binding_namespace]):
                continue

            for subject in binding.get("subjects", []):
                if subject.get("kind") != "ServiceAccount":
                    continue

                sa_name = subject.get("name")
                sa_namespace = subject.get("namespace", binding_namespace)
                if not sa_name:
                    continue

                if role_ref_kind == "ClusterRole":
                    fact_type = FactType.SERVICE_ACCOUNT_BOUND_CLUSTER_ROLE.value
                    object_id = self.id_gen.cluster_role(role_ref_name)
                    object_type = NodeType.CLUSTER_ROLE.value
                elif role_ref_kind == "Role":
                    fact_type = FactType.SERVICE_ACCOUNT_BOUND_ROLE.value
                    object_id = self.id_gen.role(binding_namespace, role_ref_name)
                    object_type = NodeType.ROLE.value
                else:
                    continue

                facts.append(
                    Fact(
                        fact_type=fact_type,
                        subject_id=self.id_gen.service_account(sa_namespace, sa_name),
                        subject_type=NodeType.SERVICE_ACCOUNT.value,
                        object_id=object_id,
                        object_type=object_type,
                        metadata={
                            "binding_name": binding.get("name"),
                            "binding_namespace": binding_namespace,
                        },
                    )
                )

        for binding in scan.get("cluster_role_bindings", []):
            role_ref_name = binding.get("role_ref_name")
            if not role_ref_name:
                continue

            for subject in binding.get("subjects", []):
                if subject.get("kind") != "ServiceAccount":
                    continue

                sa_name = subject.get("name")
                sa_namespace = subject.get("namespace")
                if not sa_name or not sa_namespace:
                    continue

                facts.append(
                    Fact(
                        fact_type=FactType.SERVICE_ACCOUNT_BOUND_CLUSTER_ROLE.value,
                        subject_id=self.id_gen.service_account(sa_namespace, sa_name),
                        subject_type=NodeType.SERVICE_ACCOUNT.value,
                        object_id=self.id_gen.cluster_role(role_ref_name),
                        object_type=NodeType.CLUSTER_ROLE.value,
                        metadata={
                            "binding_name": binding.get("name"),
                        },
                    )
                )

        return facts

    def extract_permissions(self, scan: dict[str, Any]) -> list[Fact]:
        """Extract RBAC permission facts."""
        facts: list[Fact] = []

        for role in scan.get("roles", []):
            role_namespace = role.get("namespace")
            role_name = role.get("name")
            if not role_namespace or not role_name:
                continue

            facts.extend(
                self._process_role_rules(
                    role_id=self.id_gen.role(role_namespace, role_name),
                    role_type=NodeType.ROLE.value,
                    rules=role.get("rules", []),
                    role_namespace=role_namespace,
                    scan=scan,
                )
            )
            if self._role_has_pod_exec(role.get("rules", [])):
                for pod in scan.get("pods", []):
                    if pod.get("namespace") != role_namespace or not pod.get("name"):
                        continue
                    facts.append(
                        Fact(
                            fact_type=FactType.ROLE_GRANTS_POD_EXEC.value,
                            subject_id=self.id_gen.role(role_namespace, role_name),
                            subject_type=NodeType.ROLE.value,
                            object_id=self.id_gen.pod(role_namespace, pod.get("name")),
                            object_type=NodeType.POD.value,
                            metadata={
                                "verbs": ["create"],
                                "resources": ["pods/exec"],
                            },
                        )
                    )

        for cluster_role in scan.get("cluster_roles", []):
            role_name = cluster_role.get("name")
            if not role_name:
                continue

            facts.extend(
                self._process_role_rules(
                    role_id=self.id_gen.cluster_role(role_name),
                    role_type=NodeType.CLUSTER_ROLE.value,
                    rules=cluster_role.get("rules", []),
                    role_namespace=None,
                    scan=scan,
                )
            )
            if self._role_has_pod_exec(cluster_role.get("rules", [])):
                for pod in scan.get("pods", []):
                    pod_namespace = pod.get("namespace")
                    pod_name = pod.get("name")
                    if not pod_namespace or not pod_name:
                        continue
                    facts.append(
                        Fact(
                            fact_type=FactType.ROLE_GRANTS_POD_EXEC.value,
                            subject_id=self.id_gen.cluster_role(role_name),
                            subject_type=NodeType.CLUSTER_ROLE.value,
                            object_id=self.id_gen.pod(pod_namespace, pod_name),
                            object_type=NodeType.POD.value,
                            metadata={
                                "verbs": ["create"],
                                "resources": ["pods/exec"],
                            },
                        )
                    )

        return facts

    def _process_role_rules(
        self,
        role_id: str,
        role_type: str,
        rules: list[dict[str, Any]],
        role_namespace: str | None,
        scan: dict[str, Any],
    ) -> list[Fact]:
        facts: list[Fact] = []

        for rule in rules:
            resources = rule.get("resources", [])
            verbs = rule.get("verbs", [])
            api_groups = rule.get("api_groups", [])
            resource_names = rule.get("resource_names", [])

            if not resources or not verbs:
                continue

            for resource in resources:
                if resource not in self.SUPPORTED_RULE_RESOURCES:
                    continue

                target_type = self._resource_to_node_type(resource)
                if not target_type:
                    continue

                if resource_names:
                    for resource_name in resource_names:
                        target_id = self._generate_resource_id(
                            target_type=target_type,
                            namespace=role_namespace,
                            name=resource_name,
                        )
                        if not target_id:
                            continue
                        facts.append(
                            self._create_role_grants_fact(
                                role_id=role_id,
                                role_type=role_type,
                                target_id=target_id,
                                target_type=target_type,
                                verbs=verbs,
                                api_groups=api_groups,
                                resource_names=[resource_name],
                            )
                        )
                else:
                    for target_id, _, _ in self._find_all_resources(scan, resource, role_namespace):
                        facts.append(
                            self._create_role_grants_fact(
                                role_id=role_id,
                                role_type=role_type,
                                target_id=target_id,
                                target_type=target_type,
                                verbs=verbs,
                                api_groups=api_groups,
                                resource_names=[],
                            )
                        )

        return facts

    def _resource_to_node_type(self, resource: str) -> str | None:
        mapping = {
            "secrets": NodeType.SECRET.value,
            "pods": NodeType.POD.value,
            "serviceaccounts": NodeType.SERVICE_ACCOUNT.value,
        }
        return mapping.get(resource)

    def _generate_resource_id(self, target_type: str, namespace: str | None, name: str) -> str | None:
        if not name:
            return None
        if target_type == NodeType.SECRET.value and namespace:
            return self.id_gen.secret(namespace, name)
        if target_type == NodeType.POD.value and namespace:
            return self.id_gen.pod(namespace, name)
        if target_type == NodeType.SERVICE_ACCOUNT.value and namespace:
            return self.id_gen.service_account(namespace, name)
        return None

    def _find_all_resources(
        self,
        scan: dict[str, Any],
        resource_type: str,
        namespace: str | None,
    ) -> list[tuple[str, str, str]]:
        results: list[tuple[str, str, str]] = []

        if resource_type == "secrets":
            for secret in scan.get("secrets", []):
                secret_ns = secret.get("namespace")
                secret_name = secret.get("name")
                if not secret_ns or not secret_name:
                    continue
                if namespace and secret_ns != namespace:
                    continue
                results.append((self.id_gen.secret(secret_ns, secret_name), secret_ns, secret_name))
        elif resource_type == "pods":
            for pod in scan.get("pods", []):
                pod_ns = pod.get("namespace")
                pod_name = pod.get("name")
                if not pod_ns or not pod_name:
                    continue
                if namespace and pod_ns != namespace:
                    continue
                results.append((self.id_gen.pod(pod_ns, pod_name), pod_ns, pod_name))
        elif resource_type == "serviceaccounts":
            for sa in scan.get("service_accounts", []):
                metadata = sa.get("metadata", {})
                sa_ns = metadata.get("namespace")
                sa_name = metadata.get("name")
                if not sa_ns or not sa_name:
                    continue
                if namespace and sa_ns != namespace:
                    continue
                results.append((self.id_gen.service_account(sa_ns, sa_name), sa_ns, sa_name))

        return results

    def _create_role_grants_fact(
        self,
        role_id: str,
        role_type: str,
        target_id: str,
        target_type: str,
        verbs: list[str],
        api_groups: list[str],
        resource_names: list[str],
    ) -> Fact:
        return Fact(
            fact_type=FactType.ROLE_GRANTS_RESOURCE.value,
            subject_id=role_id,
            subject_type=role_type,
            object_id=target_id,
            object_type=target_type,
            metadata={
                "verbs": verbs,
                "api_groups": api_groups,
                "resource_names": resource_names,
            },
        )

    def _role_has_pod_exec(self, rules: list[dict[str, Any]]) -> bool:
        for rule in rules:
            resources = rule.get("resources", [])
            verbs = rule.get("verbs", [])
            if "pods/exec" in resources and "create" in verbs:
                return True
        return False
