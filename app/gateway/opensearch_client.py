"""
Infrastructure module for OpenSearch client.
Responsible for reading logs and writing analysis results (including risk scores).

TEMPORARILY DISABLED: OpenSearch is not configured yet.
"""
# DISABLED: OpenSearch not available - commenting out to allow app startup
# from opensearchpy import AsyncOpenSearch
from typing import Any
from app.config import settings


def get_opensearch_client() -> Any:
    """
    Returns an initialized async OpenSearch client.

    TEMPORARILY DISABLED: Returns None until OpenSearch is properly configured.
    """
    # DISABLED: Returning None to allow app to start without OpenSearch
    return None

    # Original implementation (commented out):
    # client = AsyncOpenSearch(
    #     hosts=[{'host': settings.OPENSEARCH_HOST, 'port': settings.OPENSEARCH_PORT}],
    #     http_auth=(settings.OPENSEARCH_USER, settings.OPENSEARCH_PASSWORD),
    #     use_ssl=False,  # Configure based on environment
    #     verify_certs=False,
    # )
    # return client
