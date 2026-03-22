from typing import get_args

from src.facts.types import Confidence, FactType, NodeType
from src.facts.validation.rules import ValidationRules


def test_role_grants_resource_allows_service_account_targets():
    allowed = ValidationRules.ALLOWED_COMBINATIONS[FactType.ROLE_GRANTS_RESOURCE.value]

    assert (NodeType.ROLE.value, NodeType.SERVICE_ACCOUNT.value) in allowed
    assert (NodeType.CLUSTER_ROLE.value, NodeType.SERVICE_ACCOUNT.value) in allowed


def test_supported_node_type_prefixes_include_node_credential():
    assert "node_credential" in ValidationRules.TYPE_PREFIX_MAP
    assert ValidationRules.TYPE_PREFIX_MAP["node_credential"] == "node_cred:"


def test_exposes_token_allows_node_credential_targets():
    allowed = ValidationRules.ALLOWED_COMBINATIONS[FactType.EXPOSES_TOKEN.value]

    assert (NodeType.NODE.value, NodeType.NODE_CREDENTIAL.value) in allowed


def test_allowed_confidence_values_match_supported_contract():
    assert "high" in ValidationRules.ALLOWED_CONFIDENCE
    assert "medium" in ValidationRules.ALLOWED_CONFIDENCE
    assert "low" not in ValidationRules.ALLOWED_CONFIDENCE


def test_public_confidence_type_matches_supported_contract():
    assert set(get_args(Confidence)) == {"high", "medium"}
