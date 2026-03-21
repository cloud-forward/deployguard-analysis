"""
Lateral Move Fact Extractor.
Extracts lateral movement facts based on NetworkPolicy analysis (Phase 4).
"""
from typing import Any, Dict, List

from src.facts.extractors.base_extractor import BaseExtractor
from src.facts.canonical_fact import Fact
from src.facts.types import FactType, NodeType
from src.facts.id_generator import NodeIDGenerator


class LateralMoveExtractor(BaseExtractor):
    """Extract lateral movement facts"""
    
    # Security-relevant ports
    SECURITY_PORTS = {
        5432,   # PostgreSQL
        3306,   # MySQL
        27017,  # MongoDB
        6379,   # Redis
        9200,   # Elasticsearch
        8080,   # HTTP alt
        8443,   # HTTPS alt
        9090,   # Prometheus
        3000,   # Grafana
    }
    
    # Security-relevant service name patterns
    SECURITY_PATTERNS = {
        "db", "database", "postgres", "mysql", "mongo",
        "redis", "elastic", "kafka", "rabbitmq",
        "api", "admin", "internal"
    }
    
    def __init__(self):
        super().__init__("lateral_move")
        self.id_gen = NodeIDGenerator()
    
    def extract(self, scan_data: Dict[str, Any], **kwargs) -> List[Fact]:
        """
        Extract lateral movement facts (Phase 4).
        
        Args:
            scan_data: K8s scanner output
        
        Returns:
            List of lateral_move Facts
        """
        scan_id = scan_data.get("scan_id", "unknown")
        self._log_extraction_start(scan_id)
        
        facts: List[Fact] = []
        
        try:
            facts.extend(self._extract_lateral_moves(scan_data))
            
            self._log_extraction_complete(scan_id, len(facts))
            
        except Exception as e:
            self._log_error(scan_id, e, {"phase": "lateral_move"})
            raise
        
        return facts
    
    def _extract_lateral_moves(self, scan: Dict[str, Any]) -> List[Fact]:
        """Extract lateral movement facts with namespace-scoped NetworkPolicy suppression."""
        facts: List[Fact] = []
        
        pods = scan.get("pods", [])
        services = scan.get("services", [])
        protected_namespaces = self._protected_namespaces(scan.get("network_policies", []))
        
        # Filter security-relevant services
        security_services = [
            svc for svc in services
            if self._is_security_relevant_service(svc)
        ]
        
        if not security_services:
            return facts
        
        # Generate lateral_move facts for each pod → security service
        for pod in pods:
            pod_namespace = pod.get("namespace")
            pod_name = pod.get("name")
            pod_labels = pod.get("labels", {})
            
            if not pod_namespace or not pod_name:
                continue
            
            for service in security_services:
                svc_namespace = service.get("namespace")
                svc_name = service.get("name")
                svc_port = service.get("port")
                
                if not svc_namespace or not svc_name:
                    continue

                if (
                    pod_namespace in protected_namespaces
                    or svc_namespace in protected_namespaces
                ):
                    continue

                if self._is_same_workload_service_target(
                    pod_namespace,
                    pod_labels,
                    svc_namespace,
                    service,
                ):
                    continue
                
                # Cross-namespace or same-namespace security service
                is_cross_namespace = pod_namespace != svc_namespace
                
                facts.append(Fact(
                    fact_type=FactType.LATERAL_MOVE.value,
                    subject_id=self.id_gen.pod(pod_namespace, pod_name),
                    subject_type=NodeType.POD.value,
                    object_id=self.id_gen.service(svc_namespace, svc_name),
                    object_type=NodeType.SERVICE.value,
                    metadata={
                        "reason": "no_network_policy",
                        "cross_namespace": is_cross_namespace,
                        "target_port": svc_port,
                        "compliance_violation": "PRCC-024",
                    },
                ))
        
        return facts

    def _protected_namespaces(
        self,
        network_policies: List[Dict[str, Any]],
    ) -> set[str]:
        namespaces: set[str] = set()

        for policy in network_policies:
            if not isinstance(policy, dict):
                continue

            namespace = policy.get("namespace")
            if not namespace:
                metadata = policy.get("metadata")
                if isinstance(metadata, dict):
                    namespace = metadata.get("namespace")

            if isinstance(namespace, str) and namespace:
                namespaces.add(namespace)

        return namespaces
    
    def _is_security_relevant_service(self, service: Dict[str, Any]) -> bool:
        """Check if service is security-relevant"""
        svc_name = service.get("name", "").lower()
        svc_port = service.get("port")
        
        # Check port
        if svc_port in self.SECURITY_PORTS:
            return True
        
        # Check name patterns
        for pattern in self.SECURITY_PATTERNS:
            if pattern in svc_name:
                return True
        
        return False

    def _is_same_workload_service_target(
        self,
        pod_namespace: str,
        pod_labels: Dict[str, Any],
        service_namespace: str,
        service: Dict[str, Any],
    ) -> bool:
        if pod_namespace != service_namespace:
            return False

        selector = service.get("selector")
        if not isinstance(selector, dict) or not selector:
            return False

        if not isinstance(pod_labels, dict) or not pod_labels:
            return False

        for key, value in selector.items():
            if pod_labels.get(key) != value:
                return False

        return True
