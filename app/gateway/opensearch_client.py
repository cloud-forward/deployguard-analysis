"""
Infrastructure module for OpenSearch client.
Responsible for reading logs and writing analysis results (including risk scores).
"""
from opensearchpy import AsyncOpenSearch
from app.config import settings

def get_opensearch_client() -> AsyncOpenSearch:
    """
    Returns an initialized async OpenSearch client.
    """
    client = AsyncOpenSearch(
        hosts=[{'host': settings.OPENSEARCH_HOST, 'port': settings.OPENSEARCH_PORT}],
        http_auth=(settings.OPENSEARCH_USER, settings.OPENSEARCH_PASSWORD),
        use_ssl=False,  # Configure based on environment
        verify_certs=False,
    )
    return client
