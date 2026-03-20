"""
Integration test for fact pipeline.
"""
import pytest
from src.facts.orchestrator import FactOrchestrator


@pytest.mark.asyncio
async def test_fact_orchestrator_basic():
    """Test basic fact orchestration"""
    orchestrator = FactOrchestrator()
    
    # Mock scan data
    k8s_scan = {
        "scan_id": "test-k8s-001",
        "pods": [],
        "services": [],
        "ingresses": [],
        "secrets": [],
        "service_accounts": [],
        "roles": [],
        "cluster_roles": [],
        "role_bindings": [],
        "cluster_role_bindings": [],
        "network_policies": [],
    }
    
    aws_scan = {
        "scan_id": "test-aws-001",
        "aws_account_id": "123456789012",
        "iam_roles": [],
        "iam_users": [],
        "s3_buckets": [],
        "rds_instances": [],
        "ec2_instances": [],
        "security_groups": [],
    }
    
    # Execute
    result = await orchestrator.extract_all(k8s_scan, aws_scan)
    
    # Assertions
    assert result is not None
    assert result.scan_id == "test-k8s-001"
    assert isinstance(result.facts, list)