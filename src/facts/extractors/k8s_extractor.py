"""
K8s Fact Extractor.
Extracts facts from K8s scanner output (Phase 1-4).
"""
from typing import Any, Dict, List

from src.facts.extractors.base_extractor import BaseExtractor
from src.facts.extractors.k8s_rbac_parser import K8sRBACParser
from src.facts.canonical_fact import Fact
from src.facts.types import FactType, NodeType
from src.facts.id_generator import NodeIDGenerator


class K8sFactExtractor(BaseExtractor):
    """Extract K8s facts from scanner output"""
    
    def __init__(self):
        super().__init__("k8s")
        self.id_gen = NodeIDGenerator()
        self.rbac_parser = K8sRBACParser()
    
    def extract(self, scan_data: Dict[str, Any], **kwargs) -> List[Fact]:
        """
        Extract all K8s facts (Phase 1-4).
        
        Args:
            scan_data: K8s scanner output
        
        Returns:
            List of Facts
        """
        scan_id = scan_data.get("scan_id", "unknown")
        self._log_extraction_start(scan_id)
        
        facts: List[Fact] = []
        
        try:
            # Phase 1: Basic relationships
            facts.extend(self._phase1_basic(scan_data))
            
            # Phase 2: Permissions
            facts.extend(self._phase2_permissions(scan_data))
            
            # Phase 3: Container escape (needs Phase 1-2 results)
            facts.extend(self._phase3_escape(scan_data, facts))
            
            # Phase 4: Lateral movement (implemented in separate extractor)
            # facts.extend(self._phase4_lateral(scan_data))
            
            self._log_extraction_complete(scan_id, len(facts))
            
        except Exception as e:
            self._log_error(scan_id, e, {"phase": "extraction"})
            raise
        
        return facts
    
    # ========================================
    # Phase 1: Basic Relationships
    # ========================================
    
    def _phase1_basic(self, scan: Dict[str, Any]) -> List[Fact]:
        """Phase 1: Extract basic K8s relationships"""
        facts: List[Fact] = []
        
        facts.extend(self._extract_pod_uses_sa(scan))
        facts.extend(self.rbac_parser.extract_bindings(scan))
        facts.extend(self._extract_service_targets_pod(scan))
        facts.extend(self._extract_ingress_exposes_service(scan))
        facts.extend(self._extract_pod_mounts_secret(scan))
        facts.extend(self._extract_pod_uses_env_from_secret(scan))
        facts.extend(self._extract_uses_image(scan))
        
        return facts
    
    def _extract_pod_uses_sa(self, scan: Dict[str, Any]) -> List[Fact]:
        """Extract pod_uses_service_account facts"""
        facts: List[Fact] = []
        
        for pod in scan.get("pods", []):
            sa_name = pod.get("service_account")
            if not sa_name:
                continue
            
            namespace = pod.get("namespace")
            pod_name = pod.get("name")
            
            if not namespace or not pod_name:
                continue
            
            facts.append(Fact(
                fact_type=FactType.POD_USES_SERVICE_ACCOUNT.value,
                subject_id=self.id_gen.pod(namespace, pod_name),
                subject_type=NodeType.POD.value,
                object_id=self.id_gen.service_account(namespace, sa_name),
                object_type=NodeType.SERVICE_ACCOUNT.value,
                metadata={},
            ))
        
        return facts
    
    def _extract_service_targets_pod(self, scan: Dict[str, Any]) -> List[Fact]:
        """Extract service_targets_pod facts"""
        facts: List[Fact] = []
        
        services = scan.get("services", [])
        pods = scan.get("pods", [])
        
        for service in services:
            selector = service.get("selector", {})
            if not selector:
                continue
            
            service_namespace = service.get("namespace")
            service_name = service.get("name")
            
            if not service_namespace or not service_name:
                continue
            
            # Find matching pods
            for pod in pods:
                if pod.get("namespace") != service_namespace:
                    continue
                
                pod_labels = pod.get("labels", {})
                
                # Check if pod matches selector
                if self._labels_match_selector(pod_labels, selector):
                    facts.append(Fact(
                        fact_type=FactType.SERVICE_TARGETS_POD.value,
                        subject_id=self.id_gen.service(service_namespace, service_name),
                        subject_type=NodeType.SERVICE.value,
                        object_id=self.id_gen.pod(service_namespace, pod.get("name")),
                        object_type=NodeType.POD.value,
                        metadata={
                            "port": service.get("port"),
                            "selector": selector,
                        },
                    ))
        
        return facts
    
    def _extract_ingress_exposes_service(self, scan: Dict[str, Any]) -> List[Fact]:
        """Extract ingress_exposes_service facts"""
        facts: List[Fact] = []
        
        for ingress in scan.get("ingresses", []):
            ingress_namespace = ingress.get("namespace")
            ingress_name = ingress.get("name")
            
            if not ingress_namespace or not ingress_name:
                continue
            
            for rule in ingress.get("rules", []):
                host = rule.get("host", "*")
                
                for path in rule.get("paths", []):
                    backend_service = path.get("backend_service")
                    backend_port = path.get("backend_port")
                    path_str = path.get("path", "/")
                    
                    if not backend_service:
                        continue
                    
                    facts.append(Fact(
                        fact_type=FactType.INGRESS_EXPOSES_SERVICE.value,
                        subject_id=self.id_gen.ingress(ingress_namespace, ingress_name),
                        subject_type=NodeType.INGRESS.value,
                        object_id=self.id_gen.service(ingress_namespace, backend_service),
                        object_type=NodeType.SERVICE.value,
                        metadata={
                            "host": host,
                            "path": path_str,
                            "backend_port": backend_port,
                        },
                    ))
        
        return facts
    
    def _extract_pod_mounts_secret(self, scan: Dict[str, Any]) -> List[Fact]:
        """Extract pod_mounts_secret facts"""
        facts: List[Fact] = []
        
        for pod in scan.get("pods", []):
            namespace = pod.get("namespace")
            pod_name = pod.get("name")
            
            if not namespace or not pod_name:
                continue
            
            for container in pod.get("containers", []):
                for mount in container.get("volume_mounts", []):
                    if mount.get("source_type") != "secret":
                        continue
                    
                    secret_name = mount.get("source_name")
                    if not secret_name:
                        continue
                    
                    facts.append(Fact(
                        fact_type=FactType.POD_MOUNTS_SECRET.value,
                        subject_id=self.id_gen.pod(namespace, pod_name),
                        subject_type=NodeType.POD.value,
                        object_id=self.id_gen.secret(namespace, secret_name),
                        object_type=NodeType.SECRET.value,
                        metadata={
                            "mount_path": mount.get("mount_path"),
                            "read_only": mount.get("read_only", False),
                        },
                    ))
        
        return facts
    
    def _extract_pod_uses_env_from_secret(self, scan: Dict[str, Any]) -> List[Fact]:
        """Extract pod_uses_env_from_secret facts"""
        facts: List[Fact] = []
        
        for pod in scan.get("pods", []):
            namespace = pod.get("namespace")
            pod_name = pod.get("name")
            
            if not namespace or not pod_name:
                continue
            
            for container in pod.get("containers", []):
                for env_from in container.get("env_from_secrets", []):
                    secret_name = env_from.get("secret_name")
                    env_vars = env_from.get("env_vars", [])
                    
                    if not secret_name:
                        continue
                    
                    facts.append(Fact(
                        fact_type=FactType.POD_USES_ENV_FROM_SECRET.value,
                        subject_id=self.id_gen.pod(namespace, pod_name),
                        subject_type=NodeType.POD.value,
                        object_id=self.id_gen.secret(namespace, secret_name),
                        object_type=NodeType.SECRET.value,
                        metadata={
                            "env_vars": env_vars,
                        },
                    ))
        
        return facts
    
    def _extract_uses_image(self, scan: Dict[str, Any]) -> List[Fact]:
        """Extract uses_image facts"""
        facts: List[Fact] = []
        
        for pod in scan.get("pods", []):
            namespace = pod.get("namespace")
            pod_name = pod.get("name")
            
            if not namespace or not pod_name:
                continue
            
            for container in pod.get("containers", []):
                image = container.get("image")
                
                if not image:
                    continue
                
                facts.append(Fact(
                    fact_type=FactType.USES_IMAGE.value,
                    subject_id=self.id_gen.pod(namespace, pod_name),
                    subject_type=NodeType.POD.value,
                    object_id=self.id_gen.container_image(image),
                    object_type=NodeType.CONTAINER_IMAGE.value,
                    metadata={},
                ))
        
        return facts
    
    # ========================================
    # Phase 2: Permissions
    # ========================================
    
    def _phase2_permissions(self, scan: Dict[str, Any]) -> List[Fact]:
        """Phase 2: Extract permission facts"""
        facts: List[Fact] = []
        
        facts.extend(self.rbac_parser.extract_permissions(scan))
        
        return facts
    
    # ========================================
    # Phase 3: Container Escape
    # ========================================
    
    def _phase3_escape(
        self, scan: Dict[str, Any], existing_facts: List[Fact]
    ) -> List[Fact]:
        """Phase 3: Extract container escape facts"""
        facts: List[Fact] = []
        
        facts.extend(self._extract_escapes_to(scan))
        facts.extend(self._extract_exposes_token(scan, existing_facts))
        
        return facts
    
    def _extract_escapes_to(self, scan: Dict[str, Any]) -> List[Fact]:
        """Extract escapes_to facts"""
        facts: List[Fact] = []
        
        for pod in scan.get("pods", []):
            namespace = pod.get("namespace")
            pod_name = pod.get("name")
            node_name = pod.get("node_name")
            
            if not all([namespace, pod_name, node_name]):
                continue
            
            escape_methods = self._detect_escape_methods(pod)
            
            if not escape_methods:
                continue
            
            compliance_violations = self._get_compliance_violations(escape_methods)
            
            facts.append(Fact(
                fact_type=FactType.ESCAPES_TO.value,
                subject_id=self.id_gen.pod(namespace, pod_name),
                subject_type=NodeType.POD.value,
                object_id=self.id_gen.node(node_name),
                object_type=NodeType.NODE.value,
                metadata={
                    "escape_methods": escape_methods,
                    "compliance_violations": compliance_violations,
                },
            ))
        
        return facts
    
    def _extract_exposes_token(
        self, scan: Dict[str, Any], existing_facts: List[Fact]
    ) -> List[Fact]:
        """Extract exposes_token facts"""
        facts: List[Fact] = []
        
        # Find all nodes with escape paths
        escape_nodes = {
            fact.object_id for fact in existing_facts
            if fact.fact_type == FactType.ESCAPES_TO.value
        }
        
        if not escape_nodes:
            return facts
        
        # Find high-privilege SAs
        high_priv_sa = self._find_high_privilege_sa(existing_facts)
        
        # Generate exposes_token facts
        for node_id in escape_nodes:
            node_name = node_id.split(":", 1)[1]
            
            # Find pods on this node
            for pod in scan.get("pods", []):
                if pod.get("node_name") != node_name:
                    continue
                
                sa_name = pod.get("service_account")
                if not sa_name:
                    continue
                
                sa_id = self.id_gen.service_account(pod.get("namespace"), sa_name)
                
                if sa_id in high_priv_sa:
                    facts.append(Fact(
                        fact_type=FactType.EXPOSES_TOKEN.value,
                        subject_id=node_id,
                        subject_type=NodeType.NODE.value,
                        object_id=sa_id,
                        object_type=NodeType.SERVICE_ACCOUNT.value,
                        metadata={
                            "from_pod": self.id_gen.pod(pod.get("namespace"), pod.get("name")),
                            "via": "/var/lib/kubelet/pods/.../token",
                        },
                    ))
        
        return facts
    
    # ========================================
    # Helper Methods
    # ========================================
    
    def _labels_match_selector(
        self, labels: Dict[str, str], selector: Dict[str, str]
    ) -> bool:
        """Check if labels match selector"""
        if not selector:
            return False
        
        for key, value in selector.items():
            if labels.get(key) != value:
                return False
        
        return True
    
    
    def _detect_escape_methods(self, pod: Dict[str, Any]) -> List[str]:
        """Detect container escape methods"""
        methods = []
        
        # Check privileged mode
        for container in pod.get("containers", []):
            sec_ctx = container.get("security_context", {})
            
            if sec_ctx.get("privileged"):
                methods.append("privileged_mode")
            
            # Check dangerous capabilities
            caps = sec_ctx.get("capabilities", {}).get("add", [])
            for cap in caps:
                if cap in ("SYS_ADMIN", "SYS_PTRACE", "ALL"):
                    methods.append(f"capability:{cap}")
        
        # Check hostPID
        if pod.get("host_pid"):
            methods.append("hostpid")
        
        # Check dangerous hostPath mounts
        for container in pod.get("containers", []):
            for mount in container.get("volume_mounts", []):
                if mount.get("source_type") == "hostPath":
                    host_path = mount.get("host_path", "")
                    if host_path in ["/", "/etc", "/var/lib/kubelet", "/proc"]:
                        methods.append(f"hostpath_mount:{host_path}")
        
        return list(set(methods))
    
    def _get_compliance_violations(self, escape_methods: List[str]) -> List[str]:
        """Map escape methods to compliance violations"""
        violations = []
        
        for method in escape_methods:
            if method == "privileged_mode":
                violations.append("PRCC-026")
            elif method.startswith("capability:"):
                violations.append("PRCC-027")
            elif method == "hostpid":
                violations.append("PRCC-042")
            elif method.startswith("hostpath_mount:"):
                violations.append("PRCC-035")
        
        return list(set(violations))
    
    def _find_high_privilege_sa(self, facts: List[Fact]) -> set[str]:
        """Find high-privilege service accounts"""
        high_priv = set()
        
        for fact in facts:
            # Check cluster-admin binding
            if (
                fact.fact_type == FactType.SERVICE_ACCOUNT_BOUND_CLUSTER_ROLE.value
                and "cluster-admin" in fact.object_id
            ):
                high_priv.add(fact.subject_id)
            
            # Check secrets access
            if (
                fact.fact_type == FactType.ROLE_GRANTS_RESOURCE.value
                and fact.object_type == NodeType.SECRET.value
            ):
                verbs = fact.metadata.get("verbs", [])
                if any(v in verbs for v in ["get", "list", "watch", "*"]):
                    # This role/clusterrole has secret access
                    # Find SAs bound to it
                    for binding_fact in facts:
                        if (
                            binding_fact.fact_type in [
                                FactType.SERVICE_ACCOUNT_BOUND_ROLE.value,
                                FactType.SERVICE_ACCOUNT_BOUND_CLUSTER_ROLE.value,
                            ]
                            and binding_fact.object_id == fact.subject_id
                        ):
                            high_priv.add(binding_fact.subject_id)
        
        return high_priv
