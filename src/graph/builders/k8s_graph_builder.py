"""Minimal Kubernetes graph builder."""

from __future__ import annotations

from typing import Any

from src.facts.canonical_fact import Fact
from src.facts.id_generator import NodeIDGenerator
from src.facts.types import NodeType
from src.graph.builders.build_result_types import K8sBuildResult
from src.graph.graph_models import GraphEdge, GraphNode

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


class K8sGraphBuilder:
    """Build Kubernetes-internal graph nodes and edges."""

    def __init__(self) -> None:
        self.id_gen = NodeIDGenerator()
        self.nodes: list[GraphNode] = []
        self.edges: list[GraphEdge] = []
        self._node_ids: set[str] = set()
        self._edge_keys: set[tuple[str, str, str]] = set()
        self.graph_metadata: dict[str, Any] | None = None

    def build(
        self,
        facts: list[Fact],
        k8s_scan: dict[str, Any],
        scan_id: str,
    ) -> K8sBuildResult:
        self.nodes = []
        self.edges = []
        self._node_ids = set()
        self._edge_keys = set()

        self._build_nodes_from_scan(k8s_scan)
        self._ensure_internal_fact_nodes(facts)
        self._build_edges_from_facts(facts)

        cluster_id = k8s_scan.get("cluster_id", "unknown")
        self.graph_metadata = {
            "graph_id": f"{scan_id}-graph",
            "scan_id": scan_id,
            "cluster_id": cluster_id,
        }
        return K8sBuildResult(
            nodes=self.nodes,
            edges=self.edges,
            metadata=dict(self.graph_metadata),
        )

    def _add_node(self, node: GraphNode) -> None:
        if node.id in self._node_ids:
            return
        self._node_ids.add(node.id)
        self.nodes.append(node)

    def _build_nodes_from_scan(self, k8s_scan: dict[str, Any]) -> None:
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
                        "service_account": pod.get("service_account"),
                        "node_name": pod.get("node_name"),
                        "labels": pod.get("labels", {}),
                        "container_images": self._container_images(pod),
                    },
                )
            )

            node_name = pod.get("node_name")
            if isinstance(node_name, str) and node_name:
                self._add_node(
                    GraphNode(
                        id=self.id_gen.node(node_name),
                        type=NodeType.NODE.value,
                        metadata={"node_name": node_name},
                    )
                )

            for image in self._container_images(pod):
                self._add_node(
                    GraphNode(
                        id=self.id_gen.container_image(image),
                        type=NodeType.CONTAINER_IMAGE.value,
                        metadata={"image": image},
                    )
                )

        for service_account in k8s_scan.get("service_accounts", []):
            metadata = service_account.get("metadata", {})
            namespace = service_account.get("namespace") or metadata.get("namespace")
            name = service_account.get("name") or metadata.get("name")
            if not namespace or not name:
                continue
            self._add_node(
                GraphNode(
                    id=self.id_gen.service_account(namespace, name),
                    type=NodeType.SERVICE_ACCOUNT.value,
                    metadata={
                        "namespace": namespace,
                        "annotations": service_account.get("annotations", metadata.get("annotations", {})),
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
                    metadata={"namespace": namespace, "rules": role.get("rules", [])},
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
                    metadata={"rules": cluster_role.get("rules", [])},
                )
            )

        for secret in self._secrets(k8s_scan):
            metadata = secret.get("metadata", {})
            namespace = secret.get("namespace") or metadata.get("namespace")
            name = secret.get("name") or metadata.get("name")
            if not namespace or not name:
                continue
            self._add_node(
                GraphNode(
                    id=self.id_gen.secret(namespace, name),
                    type=NodeType.SECRET.value,
                    metadata={
                        "namespace": namespace,
                        "secret_type": secret.get("type"),
                        "data_keys": self._secret_key_list(
                            secret.get("data"),
                            secret.get("data_keys"),
                            metadata.get("data_keys"),
                        ),
                        "string_data_keys": self._secret_key_list(
                            secret.get("stringData"),
                            secret.get("string_data_keys"),
                            metadata.get("string_data_keys"),
                        ),
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
                        "selector": service.get("selector", {}),
                        "port": service.get("port"),
                        "ports": service.get("ports", []),
                        "service_type": service.get("type"),
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
                        "ingress_class_name": ingress.get("ingress_class_name"),
                    },
                )
            )

    def _ensure_internal_fact_nodes(self, facts: list[Fact]) -> None:
        for fact in facts:
            if not self._is_internal_k8s_fact(fact):
                continue
            self._ensure_fact_node(fact.subject_id, fact.subject_type)
            self._ensure_fact_node(fact.object_id, fact.object_type)

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
                    metadata=dict(fact.metadata),
                )
            )

    def _is_internal_k8s_fact(self, fact: Fact) -> bool:
        return (
            fact.subject_type in INTERNAL_NODE_TYPES
            and fact.object_type in INTERNAL_NODE_TYPES
        )

    def _ensure_fact_node(self, node_id: str, node_type: str) -> None:
        if node_id in self._node_ids:
            return
        self._add_node(
            GraphNode(
                id=node_id,
                type=node_type,
                metadata={"discovered_from": "fact_fallback"},
            )
        )

    @staticmethod
    def _secrets(k8s_scan: dict[str, Any]) -> list[dict[str, Any]]:
        secrets = k8s_scan.get("secrets")
        if isinstance(secrets, list):
            return secrets

        resources = k8s_scan.get("resources")
        if isinstance(resources, dict):
            nested = resources.get("secrets")
            if isinstance(nested, list):
                return nested

        return []

    def _container_images(self, pod: dict[str, Any]) -> list[str]:
        images: list[str] = []
        for container in pod.get("containers", []):
            image = container.get("image")
            if isinstance(image, str) and image and image not in images:
                images.append(image)
        return images

    def _dict_keys(self, value: Any) -> list[str]:
        if isinstance(value, dict):
            return list(value.keys())
        return []

    def _secret_key_list(self, value: Any, *fallback_sources: Any) -> list[str]:
        if isinstance(value, dict):
            return list(value.keys())
        for fallback_keys in fallback_sources:
            if isinstance(fallback_keys, list):
                return [key for key in fallback_keys if isinstance(key, str)]
        return []
