"""Minimal Kubernetes graph builder."""

from __future__ import annotations

from typing import Any

from src.facts.canonical_fact import Fact
from src.facts.id_generator import NodeIDGenerator
from src.facts.types import NodeType
from src.graph.graph_models import GraphEdge, GraphNode


class K8sGraphBuilder:
    """Build Kubernetes-internal graph nodes and edges."""

    INTERNAL_NODE_TYPES = {
        NodeType.POD.value,
        NodeType.SERVICE_ACCOUNT.value,
        NodeType.ROLE.value,
        NodeType.CLUSTER_ROLE.value,
        NodeType.SECRET.value,
        NodeType.SERVICE.value,
        NodeType.INGRESS.value,
        NodeType.NODE.value,
        NodeType.CONTAINER_IMAGE.value,
    }

    def __init__(self) -> None:
        self.id_gen = NodeIDGenerator()
        self.nodes: list[GraphNode] = []
        self.edges: list[GraphEdge] = []
        self._node_ids: set[str] = set()
        self._edge_keys: set[tuple[str, str, str]] = set()

    def build(
        self,
        facts: list[Fact],
        k8s_scan: dict[str, Any],
        scan_id: str,
    ) -> tuple[list[GraphNode], list[GraphEdge]]:
        self.nodes = []
        self.edges = []
        self._node_ids = set()
        self._edge_keys = set()

        self._build_nodes_from_scan(k8s_scan, scan_id)
        self._ensure_internal_fact_nodes(facts, scan_id)
        self._build_edges_from_facts(facts)

        return (self.nodes, self.edges)

    def _add_node(self, node: GraphNode) -> None:
        if node.id in self._node_ids:
            return
        self._node_ids.add(node.id)
        self.nodes.append(node)

    def _build_nodes_from_scan(self, k8s_scan: dict[str, Any], scan_id: str) -> None:
        for pod in k8s_scan.get("pods", []):
            namespace = pod.get("namespace")
            name = pod.get("name")
            if not namespace or not name:
                continue
            self._add_node(
                GraphNode(
                    id=self.id_gen.pod(namespace, name),
                    type=NodeType.POD.value,
                    metadata={
                        "namespace": namespace,
                        "name": name,
                        "service_account": pod.get("service_account"),
                        "node_name": pod.get("node_name"),
                        "labels": pod.get("labels", {}),
                        "containers": pod.get("containers", []),
                        "container_images": self._container_images(pod),
                        "scan_id": scan_id,
                    },
                )
            )

        for service_account in k8s_scan.get("service_accounts", []):
            metadata = service_account.get("metadata", {})
            namespace = metadata.get("namespace")
            name = metadata.get("name")
            if not namespace or not name:
                continue
            self._add_node(
                GraphNode(
                    id=self.id_gen.service_account(namespace, name),
                    type=NodeType.SERVICE_ACCOUNT.value,
                    metadata={
                        "namespace": namespace,
                        "name": name,
                        "annotations": metadata.get("annotations", {}),
                        "labels": metadata.get("labels", {}),
                        "scan_id": scan_id,
                    },
                )
            )

        for role in k8s_scan.get("roles", []):
            namespace = role.get("namespace")
            name = role.get("name")
            if not namespace or not name:
                continue
            self._add_node(
                GraphNode(
                    id=self.id_gen.role(namespace, name),
                    type=NodeType.ROLE.value,
                    metadata={
                        "namespace": namespace,
                        "name": name,
                        "rules": role.get("rules", []),
                        "labels": role.get("labels", {}),
                        "scan_id": scan_id,
                    },
                )
            )

        for cluster_role in k8s_scan.get("cluster_roles", []):
            name = cluster_role.get("name")
            if not name:
                continue
            self._add_node(
                GraphNode(
                    id=self.id_gen.cluster_role(name),
                    type=NodeType.CLUSTER_ROLE.value,
                    metadata={
                        "name": name,
                        "rules": cluster_role.get("rules", []),
                        "labels": cluster_role.get("labels", {}),
                        "scan_id": scan_id,
                    },
                )
            )

        for secret in k8s_scan.get("secrets", []):
            namespace = secret.get("namespace")
            name = secret.get("name")
            if not namespace or not name:
                continue
            self._add_node(
                GraphNode(
                    id=self.id_gen.secret(namespace, name),
                    type=NodeType.SECRET.value,
                    metadata={
                        "namespace": namespace,
                        "name": name,
                        "secret_type": secret.get("type"),
                        "data_keys": self._dict_keys(secret.get("data")),
                        "string_data_keys": self._dict_keys(secret.get("stringData")),
                        "scan_id": scan_id,
                    },
                )
            )

        for service in k8s_scan.get("services", []):
            namespace = service.get("namespace")
            name = service.get("name")
            if not namespace or not name:
                continue
            self._add_node(
                GraphNode(
                    id=self.id_gen.service(namespace, name),
                    type=NodeType.SERVICE.value,
                    metadata={
                        "namespace": namespace,
                        "name": name,
                        "selector": service.get("selector", {}),
                        "port": service.get("port"),
                        "service_type": service.get("type"),
                        "ports": service.get("ports", []),
                        "scan_id": scan_id,
                    },
                )
            )

        for ingress in k8s_scan.get("ingresses", []):
            namespace = ingress.get("namespace")
            name = ingress.get("name")
            if not namespace or not name:
                continue
            self._add_node(
                GraphNode(
                    id=self.id_gen.ingress(namespace, name),
                    type=NodeType.INGRESS.value,
                    metadata={
                        "namespace": namespace,
                        "name": name,
                        "rules": ingress.get("rules", []),
                        "ingress_class_name": ingress.get("ingress_class_name"),
                        "scan_id": scan_id,
                    },
                )
            )

    def _ensure_internal_fact_nodes(self, facts: list[Fact], scan_id: str) -> None:
        for fact in facts:
            if not self._is_internal_k8s_fact(fact):
                continue
            self._ensure_fact_node(fact.subject_id, fact.subject_type, scan_id)
            self._ensure_fact_node(fact.object_id, fact.object_type, scan_id)

    def _build_edges_from_facts(self, facts: list[Fact]) -> None:
        for fact in facts:
            if not self._is_internal_k8s_fact(fact):
                continue
            edge_key = (fact.subject_id, fact.object_id, fact.fact_type)
            if edge_key in self._edge_keys:
                continue
            self._edge_keys.add(edge_key)
            self.edges.append(
                GraphEdge(
                    source=fact.subject_id,
                    target=fact.object_id,
                    type=fact.fact_type,
                    metadata=dict(fact.metadata or {}),
                )
            )

    def _is_internal_k8s_fact(self, fact: Fact) -> bool:
        return (
            fact.subject_type in self.INTERNAL_NODE_TYPES
            and fact.object_type in self.INTERNAL_NODE_TYPES
        )

    def _ensure_fact_node(self, node_id: str, node_type: str, scan_id: str) -> None:
        if node_id in self._node_ids or node_type not in self.INTERNAL_NODE_TYPES:
            return
        self._add_node(
            GraphNode(
                id=node_id,
                type=node_type,
                metadata={
                    "scan_id": scan_id,
                    "discovered_from": "fact_fallback",
                },
            )
        )

    def _container_images(self, pod: dict[str, Any]) -> list[str]:
        images: list[str] = []
        for container in pod.get("containers", []):
            image = container.get("image")
            if image:
                images.append(image)
        return images

    def _dict_keys(self, value: Any) -> list[str]:
        if not isinstance(value, dict):
            return []
        return list(value.keys())
